from __future__ import annotations

from pathlib import Path

from .ast_analyzer import analyze_ast
from .dependency_analyzer import analyze_dependencies, extract_dependencies, extract_dependency_details
from .graph_builder import build_behavior_graph
from .integrity_analyzer import analyze_integrity
from .loader import load_package
from .metadata_analyzer import analyze_metadata, extract_metadata
from .models import Finding, ScanResult
from .scoring import calculate_confidence, calculate_score_with_breakdown, classify
from .setup_analyzer import analyze_setup_py
from .taint_analyzer import analyze_taint


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def scan(
    path: str | Path,
    source_path: str | Path | None = None,
    max_files: int = 5000,
    max_size_mb: int = 100,
    strict: bool = False,
    max_python_file_size_mb: int = 5,
) -> ScanResult:
    context = load_package(path, max_files=max_files, max_size_mb=max_size_mb)
    findings = []
    max_python_size = max_python_file_size_mb * 1024 * 1024
    oversized = [python_file for python_file in context.python_files if python_file.stat().st_size > max_python_size]
    if oversized:
        filtered = [python_file for python_file in context.python_files if python_file.stat().st_size <= max_python_size]
        for python_file in oversized:
            findings.append(
                Finding(
                    rule_id="W001",
                    title="File could not be parsed",
                    severity="LOW",
                    category="warning",
                    message="Python file exceeds maximum per-file analysis size and was skipped",
                    file_path=python_file.relative_to(context.root_path).as_posix(),
                    evidence={"size": python_file.stat().st_size, "limit": max_python_size},
                    score=3,
                )
            )
        context.python_files = filtered
    metadata = extract_metadata(context)
    findings.extend(analyze_metadata(context))
    findings.extend(analyze_ast(context))
    findings.extend(analyze_setup_py(context))
    findings.extend(analyze_taint(context))
    dependency_findings, dependencies = analyze_dependencies(context)
    dependency_details = extract_dependency_details(context)
    findings.extend(dependency_findings)

    if source_path:
        try:
            findings.extend(analyze_integrity(context.root_path, source_path))
        except Exception:
            if strict:
                raise

    score, score_breakdown = calculate_score_with_breakdown(findings)
    label = classify(score)
    analyzed_files = len(context.python_files) + len(context.metadata_files)
    sorted_findings = sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f.severity.upper(), 9), -f.score, f.rule_id, f.file_path or "", f.line or 0))
    graph = build_behavior_graph(context, sorted_findings, dependencies or extract_dependencies(context))
    confidence = calculate_confidence(sorted_findings)
    return ScanResult(
        target=str(path),
        package_name=context.package_name,
        score=score,
        label=label,
        findings=sorted_findings,
        analyzed_files=analyzed_files,
        python_files=len(context.python_files),
        dependencies=dependencies or extract_dependencies(context),
        dependency_details=dependency_details,
        metadata=metadata,
        graph=graph,
        score_breakdown=score_breakdown,
        confidence=confidence,
        analysis_stats={
            "total_files": context.total_files,
            "python_files": len(context.python_files),
            "metadata_files": len(context.metadata_files),
            "total_size_bytes": context.total_size_bytes,
            "archive_type": context.archive_type,
            "findings": len(sorted_findings),
        },
    )
