from __future__ import annotations

import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from ..loader import load_package
from ..models import DynamicEvent, Finding, PackageContext, ScanResult
from ..scoring import calculate_confidence, calculate_score_with_breakdown, classify
from .dynamic_analyzer import analyze_dynamic_events
from .execution_plan import build_execution_command
from .sandbox_config import SandboxConfig
from .strace_parser import parse_strace_text


class SandboxUnavailable(RuntimeError):
    pass


@dataclass
class SandboxRunResult:
    events: list[DynamicEvent]
    findings: list[Finding]
    stdout: str
    stderr: str
    returncode: int | None
    trace_text: str
    timed_out: bool = False
    command: list[str] | None = None


def build_docker_command(package_dir: str | Path, trace_dir: str | Path, mode: str, config: SandboxConfig | None = None) -> list[str]:
    config = config or SandboxConfig()
    command = build_execution_command(mode)
    return ["docker", *config.docker_args(package_dir, trace_dir), "sh", "-lc", command]


def run_sandbox(
    path: str | Path,
    mode: str = "setup-py-install",
    config: SandboxConfig | None = None,
    max_files: int = 5000,
    max_size_mb: int = 100,
) -> SandboxRunResult:
    if shutil.which("docker") is None:
        raise SandboxUnavailable("Docker executable was not found. Install Docker and build the GuardChain sandbox image before using dynamic analysis.")
    config = config or SandboxConfig()
    context = load_package(path, max_files=max_files, max_size_mb=max_size_mb)
    with tempfile.TemporaryDirectory(prefix="guardchain_sandbox_") as tmp:
        trace_dir = Path(tmp)
        trace_dir.chmod(0o777)
        command = build_docker_command(context.root_path, trace_dir, mode, config)
        try:
            proc = subprocess.run(command, text=True, capture_output=True, timeout=config.timeout_seconds, check=False)
            timed_out = False
            stdout = proc.stdout
            stderr = proc.stderr
            returncode: int | None = proc.returncode
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            stdout = exc.stdout if isinstance(exc.stdout, str) else ""
            stderr = exc.stderr if isinstance(exc.stderr, str) else ""
            returncode = None
        trace_path = trace_dir / "trace.log"
        trace_text = trace_path.read_text(encoding="utf-8", errors="replace") if trace_path.exists() else ""
        events = parse_strace_text(trace_text)
        findings = analyze_dynamic_events(events)
        if timed_out:
            findings.append(
                Finding(
                    rule_id="Y009",
                    title="Sandbox execution timed out",
                    severity="HIGH",
                    category="dynamic",
                    message="Dynamic analysis exceeded the configured sandbox timeout",
                    evidence={"timeout_seconds": config.timeout_seconds},
                    score=30,
                    confidence=0.95,
                    source="dynamic",
                    evidence_strength="runtime_observed",
                )
            )
        elif returncode not in {0, None} and not trace_text:
            findings.append(
                Finding(
                    rule_id="Y009",
                    title="Sandbox execution failed before trace collection",
                    severity="LOW",
                    category="dynamic",
                    message="Dynamic analysis did not produce a strace log",
                    evidence={"returncode": returncode, "stderr": stderr[-1000:]},
                    score=5,
                    confidence=0.8,
                    source="dynamic",
                    evidence_strength="runtime_observed",
                )
            )
        return SandboxRunResult(events, findings, stdout, stderr, returncode, trace_text, timed_out=timed_out, command=command)


def run_sandbox_scan(
    path: str | Path,
    mode: str = "setup-py-install",
    config: SandboxConfig | None = None,
    max_files: int = 5000,
    max_size_mb: int = 100,
) -> ScanResult:
    context = load_package(path, max_files=max_files, max_size_mb=max_size_mb)
    run_result = run_sandbox(path, mode=mode, config=config, max_files=max_files, max_size_mb=max_size_mb)
    return build_sandbox_scan_result(path, context, run_result, mode, config)


def build_sandbox_scan_result(
    path: str | Path,
    context: PackageContext,
    run_result: SandboxRunResult,
    mode: str,
    config: SandboxConfig | None = None,
) -> ScanResult:
    score, breakdown = calculate_score_with_breakdown(run_result.findings)
    label = classify(score)
    graph = _dynamic_graph(context.package_name or context.root_path.name, run_result.events, run_result.findings)
    return ScanResult(
        target=str(path),
        package_name=context.package_name,
        score=score,
        label=label,
        findings=run_result.findings,
        analyzed_files=0,
        python_files=0,
        dependencies=[],
        metadata={},
        graph=graph,
        score_breakdown=breakdown,
        confidence=calculate_confidence(run_result.findings),
        analysis_mode="dynamic",
        analysis_features={
            "dependency_resolution": False,
            "dependency_scanning": False,
            "dynamic_sandbox": True,
            "integrity_comparison": False,
        },
        analysis_stats={
            "sandbox_mode": mode,
            "sandbox_image": (config or SandboxConfig()).image,
            "returncode": run_result.returncode,
            "timed_out": run_result.timed_out,
            "events": len(run_result.events),
            "stdout_preview": run_result.stdout[-1000:],
            "stderr_preview": run_result.stderr[-1000:],
        },
        limitations=[
            "Dynamic analysis executes package code only inside the configured sandbox.",
            "The sandbox trace depends on Docker and a sandbox image with strace installed.",
            "Runtime behavior can still be environment-dependent and incomplete.",
        ],
    )


def _dynamic_graph(package_name: str, events: list[DynamicEvent], findings: list[Finding]) -> dict[str, object]:
    nodes: list[dict[str, str]] = [{"id": f"package:{package_name}", "type": "package", "label": package_name}]
    edges: list[dict[str, str]] = []
    seen_nodes = {nodes[0]["id"]}

    def add_node(node_id: str, node_type: str, label: str) -> None:
        if node_id not in seen_nodes:
            seen_nodes.add(node_id)
            nodes.append({"id": node_id, "type": node_type, "label": label})

    def add_edge(source: str, target: str, edge_type: str) -> None:
        edge = {"source": source, "target": target, "type": edge_type}
        if edge not in edges:
            edges.append(edge)

    for index, event in enumerate(events, start=1):
        event_id = f"dynamic_event:{index}"
        add_node(event_id, "dynamic_event", f"{event.operation} {event.target}")
        add_edge(f"package:{package_name}", event_id, "observed")
    for finding in findings:
        finding_id = f"finding:{finding.rule_id}:{len(nodes)}"
        add_node(finding_id, "finding", f"{finding.rule_id} {finding.title}")
        target = str(finding.evidence.get("target")) if isinstance(finding.evidence, dict) else ""
        if target:
            event_node = next((node["id"] for node in nodes if node["id"].startswith("dynamic_event:") and target in node["label"]), None)
            if event_node:
                add_edge(event_node, finding_id, "triggers")
            else:
                add_edge(f"package:{package_name}", finding_id, "triggers")
    return {"nodes": nodes, "edges": edges}
