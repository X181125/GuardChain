from __future__ import annotations

import argparse
import json
import sys

from .dynamic import SandboxConfig, SandboxUnavailable, run_sandbox
from .dynamic.docker_runner import build_sandbox_scan_result
from .evaluator import evaluate_dataset
from .graph_builder import render_dot, render_mermaid
from .loader import load_package
from .models import ScanResult
from .report import format_terminal, write_json_report, write_markdown_report, write_sarif_report, write_text_artifact
from .rules.rule_registry import load_yaml_rules, validate_yaml_rules
from .scoring import calculate_confidence, calculate_score_with_breakdown, classify
from .scanner import scan


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="guardchain", description="Static scanner for Python supply chain malware patterns.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan_parser = subparsers.add_parser("scan", help="Scan a package directory or archive.")
    scan_parser.add_argument("--path", required=True, help="Path to package directory, .tar.gz, or .whl.")
    scan_parser.add_argument("--source", help="Optional source repository path for integrity comparison.")
    scan_parser.add_argument("--source-auto-fetch", action="store_true", help="Opt in to fetching a source repository hint from package metadata for integrity comparison.")
    scan_parser.add_argument("--source-fetch-timeout", type=int, default=30, help="Timeout in seconds for --source-auto-fetch git operations.")
    scan_parser.add_argument("--json", dest="json_path", help="Optional JSON report output path.")
    scan_parser.add_argument("--markdown", help="Optional Markdown report output path.")
    scan_parser.add_argument("--sarif", help="Optional SARIF report output path.")
    scan_parser.add_argument("--graph-dot", help="Optional Graphviz DOT behavior graph output path.")
    scan_parser.add_argument("--graph-mermaid", help="Optional Mermaid behavior graph output path.")
    scan_parser.add_argument("--strict", action="store_true", help="Fail on optional analyzer errors such as missing source repo.")
    scan_parser.add_argument("--max-files", type=int, default=5000, help="Maximum files to analyze or extract.")
    scan_parser.add_argument("--max-size-mb", type=int, default=100, help="Maximum package or extracted archive size in MiB.")
    scan_parser.add_argument("--max-python-file-size-mb", type=int, default=5, help="Maximum individual Python file size to parse in MiB.")
    scan_parser.add_argument("--fail-on-malicious", action="store_true", help="Return exit code 2 when the completed scan labels the target MALICIOUS.")
    scan_parser.add_argument("--fail-threshold", type=int, help="Return exit code 2 when risk score is greater than or equal to this threshold.")
    scan_parser.add_argument("--offline", action="store_true", default=True, help="Run without network enrichment. This is the default.")
    scan_parser.add_argument("--enrich", action="store_true", help="Reserved opt-in flag for future online metadata enrichment.")
    _add_dependency_resolution_arguments(scan_parser)
    scan_parser.add_argument("--quiet", action="store_true", help="Suppress terminal report output.")
    scan_parser.add_argument("--verbose", action="store_true", help="Print evidence details.")
    sandbox_parser = subparsers.add_parser("sandbox", help="Run explicit dynamic analysis in a hardened Docker sandbox.")
    _add_sandbox_arguments(sandbox_parser)
    analyze_parser = subparsers.add_parser("analyze", help="Run static analysis, optionally followed by explicit sandbox analysis.")
    analyze_parser.add_argument("--path", required=True, help="Path to package directory or archive.")
    analyze_parser.add_argument("--source", help="Optional source repository path for integrity comparison.")
    analyze_parser.add_argument("--source-auto-fetch", action="store_true", help="Opt in to fetching a source repository hint from package metadata for integrity comparison.")
    analyze_parser.add_argument("--source-fetch-timeout", type=int, default=30, help="Timeout in seconds for --source-auto-fetch git operations.")
    analyze_parser.add_argument("--with-sandbox", action="store_true", help="Opt in to dynamic Docker sandbox execution after static scan.")
    analyze_parser.add_argument("--json", dest="json_path", help="Optional JSON report output path.")
    analyze_parser.add_argument("--markdown", help="Optional Markdown report output path.")
    analyze_parser.add_argument("--sarif", help="Optional SARIF report output path.")
    analyze_parser.add_argument("--graph-dot", help="Optional Graphviz DOT behavior graph output path.")
    analyze_parser.add_argument("--graph-mermaid", help="Optional Mermaid behavior graph output path.")
    analyze_parser.add_argument("--trace", help="Optional sandbox strace log output path when --with-sandbox is used.")
    analyze_parser.add_argument("--sandbox-mode", default="setup-py-install", choices=["setup-py-metadata", "setup-py-install", "pip-install-no-deps"])
    analyze_parser.add_argument("--sandbox-timeout", type=int, default=30)
    analyze_parser.add_argument("--sandbox-image", default="guardchain-sandbox:latest")
    analyze_parser.add_argument("--max-files", type=int, default=5000)
    analyze_parser.add_argument("--max-size-mb", type=int, default=100)
    _add_dependency_resolution_arguments(analyze_parser)
    analyze_parser.add_argument("--quiet", action="store_true")
    analyze_parser.add_argument("--verbose", action="store_true")
    eval_parser = subparsers.add_parser("evaluate", help="Evaluate GuardChain against a labeled dataset.")
    eval_parser.add_argument("--dataset", required=True, help="Dataset root directory.")
    eval_parser.add_argument("--labels", required=True, help="CSV file with path,label columns.")
    eval_parser.add_argument("--json", dest="json_path", help="Optional JSON evaluation report output path.")
    eval_parser.add_argument("--markdown", help="Optional Markdown evaluation report output path.")
    eval_group = eval_parser.add_mutually_exclusive_group()
    eval_group.add_argument("--suspicious-as-positive", action="store_true", help="Treat SUSPICIOUS as positive when computing binary metrics.")
    eval_group.add_argument("--suspicious-as-negative", action="store_true", help="Treat SUSPICIOUS as negative when computing binary metrics.")
    eval_parser.add_argument("--max-files", type=int, default=5000)
    eval_parser.add_argument("--max-size-mb", type=int, default=100)
    rules_parser = subparsers.add_parser("rules", help="Inspect or validate GuardChain rule files.")
    rules_subparsers = rules_parser.add_subparsers(dest="rules_command", required=True)
    rules_subparsers.add_parser("list", help="List built-in YAML rules.")
    validate_parser = rules_subparsers.add_parser("validate", help="Validate built-in or custom YAML rules.")
    validate_parser.add_argument("path", nargs="?", help="Optional custom rules directory.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        try:
            result = scan(
                args.path,
                args.source,
                max_files=args.max_files,
                max_size_mb=args.max_size_mb,
                strict=args.strict,
                max_python_file_size_mb=args.max_python_file_size_mb,
                resolve_deps=args.resolve_deps,
                dependency_timeout=args.dependency_timeout,
                dependency_index_url=args.dependency_index_url,
                dependency_extra_index_url=args.dependency_extra_index_url,
                dependency_find_links=args.dependency_find_links,
                dependency_no_index=args.dependency_no_index,
                dependency_max_packages=args.dependency_max_packages,
                source_auto_fetch=args.source_auto_fetch,
                source_fetch_timeout=args.source_fetch_timeout,
            )
        except Exception as exc:
            print(f"guardchain: error: {exc}", file=sys.stderr)
            return 1
        artifacts = _write_scan_outputs(result, args)
        if not args.quiet:
            print(format_terminal(result, verbose=args.verbose, artifacts=artifacts), end="")
        if args.fail_on_malicious and result.label == "MALICIOUS":
            return 2
        if args.fail_threshold is not None and result.score >= args.fail_threshold:
            return 2
        return 0
    if args.command == "sandbox":
        config = SandboxConfig(image=args.image, timeout_seconds=args.timeout, network=args.network)
        try:
            context = load_package(args.path, max_files=args.max_files, max_size_mb=args.max_size_mb)
            sandbox_run = run_sandbox(args.path, mode=args.mode, config=config, max_files=args.max_files, max_size_mb=args.max_size_mb)
            result = build_sandbox_scan_result(args.path, context, sandbox_run, args.mode, config)
        except SandboxUnavailable as exc:
            print(f"guardchain: sandbox unavailable: {exc}", file=sys.stderr)
            return 3
        except Exception as exc:
            print(f"guardchain: sandbox error: {exc}", file=sys.stderr)
            return 3
        artifacts = _write_scan_outputs(result, args)
        if args.trace:
            write_text_artifact(sandbox_run.trace_text, args.trace)
            artifacts["Trace"] = args.trace
        if not args.quiet:
            print(format_terminal(result, verbose=args.verbose, artifacts=artifacts), end="")
        return 0
    if args.command == "analyze":
        try:
            static_result = scan(
                args.path,
                args.source,
                max_files=args.max_files,
                max_size_mb=args.max_size_mb,
                resolve_deps=args.resolve_deps,
                dependency_timeout=args.dependency_timeout,
                dependency_index_url=args.dependency_index_url,
                dependency_extra_index_url=args.dependency_extra_index_url,
                dependency_find_links=args.dependency_find_links,
                dependency_no_index=args.dependency_no_index,
                dependency_max_packages=args.dependency_max_packages,
                source_auto_fetch=args.source_auto_fetch,
                source_fetch_timeout=args.source_fetch_timeout,
            )
        except Exception as exc:
            print(f"guardchain: error: {exc}", file=sys.stderr)
            return 1
        result = static_result
        sandbox_run = None
        if args.with_sandbox:
            config = SandboxConfig(image=args.sandbox_image, timeout_seconds=args.sandbox_timeout)
            try:
                context = load_package(args.path, max_files=args.max_files, max_size_mb=args.max_size_mb)
                sandbox_run = run_sandbox(args.path, mode=args.sandbox_mode, config=config, max_files=args.max_files, max_size_mb=args.max_size_mb)
                dynamic_result = build_sandbox_scan_result(args.path, context, sandbox_run, args.sandbox_mode, config)
                result = _combine_scan_results(static_result, dynamic_result)
            except SandboxUnavailable as exc:
                print(f"guardchain: sandbox unavailable: {exc}", file=sys.stderr)
                return 3
            except Exception as exc:
                print(f"guardchain: sandbox error: {exc}", file=sys.stderr)
                return 3
        artifacts = _write_scan_outputs(result, args)
        if args.trace and sandbox_run:
            write_text_artifact(sandbox_run.trace_text, args.trace)
            artifacts["Trace"] = args.trace
        if not args.quiet:
            print(format_terminal(result, verbose=args.verbose, artifacts=artifacts), end="")
        return 0
    if args.command == "evaluate":
        suspicious_mode = "negative" if args.suspicious_as_negative else "positive"
        try:
            result = evaluate_dataset(args.dataset, args.labels, suspicious_mode=suspicious_mode, max_files=args.max_files, max_size_mb=args.max_size_mb)
        except Exception as exc:
            print(f"guardchain: error: {exc}", file=sys.stderr)
            return 1
        if args.json_path:
            write_text_artifact(json.dumps(result, indent=2, sort_keys=True), args.json_path)
        if args.markdown:
            write_text_artifact(_format_evaluation_markdown(result), args.markdown)
        print(
            "\n".join(
                [
                    f"Dataset: {result['dataset']}",
                    f"Suspicious mode: {result['suspicious_mode']}",
                    f"Accuracy: {result['accuracy']}",
                    f"Precision: {result['precision']}",
                    f"Recall: {result['recall']}",
                    f"F1 score: {result['f1_score']}",
                ]
            )
        )
        return 0
    if args.command == "rules":
        if args.rules_command == "list":
            for rule in load_yaml_rules():
                print(f"{rule.get('id')} {rule.get('severity')} {rule.get('category')} - {rule.get('name')}")
            return 0
        if args.rules_command == "validate":
            errors = validate_yaml_rules(args.path)
            if errors:
                for error in errors:
                    print(f"guardchain: rule error: {error}", file=sys.stderr)
                return 1
            print("Rules valid")
            return 0
    parser.print_help()
    return 1


def _add_sandbox_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--path", required=True, help="Path to package directory or archive.")
    parser.add_argument("--mode", default="setup-py-install", choices=["setup-py-metadata", "setup-py-install", "pip-install-no-deps"])
    parser.add_argument("--timeout", type=int, default=30, help="Sandbox timeout in seconds.")
    parser.add_argument("--network", default="none", help="Docker network mode. Default: none.")
    parser.add_argument("--image", default="guardchain-sandbox:latest", help="Docker image containing Python and strace.")
    parser.add_argument("--json", dest="json_path", help="Optional JSON report output path.")
    parser.add_argument("--markdown", help="Optional Markdown report output path.")
    parser.add_argument("--sarif", help="Optional SARIF report output path.")
    parser.add_argument("--graph-dot", help="Optional Graphviz DOT behavior graph output path.")
    parser.add_argument("--graph-mermaid", help="Optional Mermaid behavior graph output path.")
    parser.add_argument("--trace", help="Optional strace log output path.")
    parser.add_argument("--max-files", type=int, default=5000)
    parser.add_argument("--max-size-mb", type=int, default=100)
    parser.add_argument("--quiet", action="store_true")
    parser.add_argument("--verbose", action="store_true")


def _add_dependency_resolution_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--resolve-deps", action="store_true", help="Opt in to online dependency closure resolution and dependency artifact scanning.")
    parser.add_argument("--dependency-timeout", type=int, default=60, help="Dependency resolution/download timeout in seconds.")
    parser.add_argument("--dependency-index-url", help="Optional package index URL for dependency resolution.")
    parser.add_argument("--dependency-extra-index-url", action="append", default=[], help="Additional package index URL for dependency resolution.")
    parser.add_argument("--dependency-find-links", action="append", default=[], help="Directory or HTML page containing dependency artifacts for pip --find-links.")
    parser.add_argument("--dependency-no-index", action="store_true", help="Resolve/download dependencies without querying package indexes.")
    parser.add_argument("--dependency-max-packages", type=int, default=50, help="Maximum resolved dependency packages to download and scan.")


def _write_scan_outputs(result: ScanResult, args: argparse.Namespace) -> dict[str, str]:
    artifacts: dict[str, str] = {}
    if getattr(args, "json_path", None):
        write_json_report(result, args.json_path)
        artifacts["JSON report"] = args.json_path
    if getattr(args, "markdown", None):
        write_markdown_report(result, args.markdown)
        artifacts["Markdown report"] = args.markdown
    if getattr(args, "sarif", None):
        write_sarif_report(result, args.sarif)
        artifacts["SARIF report"] = args.sarif
    if getattr(args, "graph_dot", None):
        write_text_artifact(render_dot(result.graph or {"nodes": [], "edges": []}), args.graph_dot)
        artifacts["DOT graph"] = args.graph_dot
    if getattr(args, "graph_mermaid", None):
        write_text_artifact(render_mermaid(result.graph or {"nodes": [], "edges": []}), args.graph_mermaid)
        artifacts["Mermaid graph"] = args.graph_mermaid
    return artifacts


def _combine_scan_results(static_result: ScanResult, dynamic_result: ScanResult) -> ScanResult:
    findings = [*static_result.findings, *dynamic_result.findings]
    score, breakdown = calculate_score_with_breakdown(findings)
    graph = _merge_graphs(static_result.graph or {"nodes": [], "edges": []}, dynamic_result.graph or {"nodes": [], "edges": []})
    stats = dict(static_result.analysis_stats)
    stats["dynamic"] = dynamic_result.analysis_stats
    return ScanResult(
        target=static_result.target,
        package_name=static_result.package_name,
        score=score,
        label=classify(score),
        findings=findings,
        analyzed_files=static_result.analyzed_files,
        python_files=static_result.python_files,
        dependencies=static_result.dependencies,
        dependency_details=static_result.dependency_details,
        resolved_dependencies=static_result.resolved_dependencies,
        dependency_edges=static_result.dependency_edges,
        dependency_scan_results=static_result.dependency_scan_results,
        dependency_graph=static_result.dependency_graph,
        dependency_risk_paths=static_result.dependency_risk_paths,
        metadata=static_result.metadata,
        graph=graph,
        score_breakdown=breakdown,
        confidence=calculate_confidence(findings),
        analysis_stats=stats,
        analysis_features={**static_result.analysis_features, "dynamic_sandbox": True},
        analysis_mode=f"{static_result.analysis_mode}+dynamic" if "dynamic" not in static_result.analysis_mode else static_result.analysis_mode,
        limitations=[*static_result.limitations, *dynamic_result.limitations],
    )


def _merge_graphs(first: object, second: object) -> dict[str, object]:
    merged = {"nodes": [], "edges": []}
    seen_nodes: set[str] = set()
    seen_edges: set[tuple[str, str, str]] = set()
    for graph in (first, second):
        if not isinstance(graph, dict):
            continue
        for node in graph.get("nodes", []):
            node_id = str(node.get("id"))
            if node_id not in seen_nodes:
                seen_nodes.add(node_id)
                merged["nodes"].append(node)
        for edge in graph.get("edges", []):
            key = (str(edge.get("source")), str(edge.get("target")), str(edge.get("type")))
            if key not in seen_edges:
                seen_edges.add(key)
                merged["edges"].append(edge)
    return merged


def _format_evaluation_markdown(result: dict[str, object]) -> str:
    counts = result["counts"]
    return "\n".join(
        [
            "# GuardChain Evaluation Report",
            "",
            "## Summary",
            "",
            f"- Dataset: `{result['dataset']}`",
            f"- Suspicious mode: `{result['suspicious_mode']}`",
            f"- Accuracy: **{result['accuracy']}**",
            f"- Precision: **{result['precision']}**",
            f"- Recall: **{result['recall']}**",
            f"- F1 score: **{result['f1_score']}**",
            "",
            "## Confusion Matrix",
            "",
            f"- TP: {counts['tp']}",
            f"- FP: {counts['fp']}",
            f"- TN: {counts['tn']}",
            f"- FN: {counts['fn']}",
            "",
        ]
    )
