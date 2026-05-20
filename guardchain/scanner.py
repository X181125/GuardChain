from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory

from .ast_analyzer import analyze_ast
from .dependency_analyzer import analyze_dependencies, extract_dependencies, extract_dependency_details
from .dependency_resolver import resolve_dependencies
from .dependency_scanner import scan_resolved_dependencies
from .graph_builder import build_behavior_graph, build_dependency_graph
from .integrity_analyzer import analyze_integrity, extract_source_repository_hint, fetch_source_repository
from .loader import load_package
from .metadata_analyzer import analyze_metadata, extract_metadata
from .models import Dependency, DependencyEdge, DependencyScanResult, Finding, ResolvedDependency, ScanResult
from .scoring import calculate_confidence, calculate_score_with_breakdown, classify
from .setup_analyzer import analyze_setup_py
from .taint_analyzer import analyze_taint


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
DEFAULT_LIMITATIONS = [
    "Static analysis can produce false positives and false negatives.",
    "GuardChain does not execute package code and cannot observe runtime-only behavior.",
    "GuardChain is a review aid, not a complete malware verdict.",
]


def scan(
    path: str | Path,
    source_path: str | Path | None = None,
    max_files: int = 5000,
    max_size_mb: int = 100,
    strict: bool = False,
    max_python_file_size_mb: int = 5,
    resolve_deps: bool = False,
    dependency_timeout: int = 60,
    dependency_index_url: str | None = None,
    dependency_extra_index_url: list[str] | None = None,
    dependency_find_links: list[str] | None = None,
    dependency_no_index: bool = False,
    dependency_max_packages: int = 50,
    source_auto_fetch: bool = False,
    source_fetch_timeout: int = 30,
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
    limitations = list(DEFAULT_LIMITATIONS)
    resolved_dependencies: list[ResolvedDependency] = []
    dependency_edges: list[DependencyEdge] = []
    dependency_scan_results: list[DependencyScanResult] = []
    dependency_warnings: list[str] = []

    effective_source_path = source_path
    source_tmp: TemporaryDirectory[str] | None = None
    if not effective_source_path and source_auto_fetch:
        source_hint = extract_source_repository_hint(metadata)
        if source_hint:
            source_tmp = TemporaryDirectory(prefix="guardchain_source_")
            fetched_source, fetch_warnings = fetch_source_repository(
                source_hint,
                Path(source_tmp.name),
                version=str(metadata.get("version")) if metadata.get("version") else None,
                timeout_seconds=source_fetch_timeout,
            )
            dependency_warnings.extend(fetch_warnings)
            effective_source_path = fetched_source
            if effective_source_path is None:
                source_tmp.cleanup()
                source_tmp = None
        else:
            dependency_warnings.append("Source auto-fetch was enabled, but no repository URL was found in package metadata.")

    if effective_source_path:
        try:
            findings.extend(analyze_integrity(context.root_path, effective_source_path))
        except Exception:
            if strict:
                raise
            dependency_warnings.append("Integrity source comparison failed; run with --strict to surface the exception.")
        finally:
            if source_tmp is not None:
                source_tmp.cleanup()

    if resolve_deps:
        requirements, skipped = _resolver_requirements(dependency_details)
        dependency_warnings.extend(skipped)
        if requirements:
            resolved_dependencies, dependency_edges, resolver_warnings = resolve_dependencies(
                requirements,
                timeout_seconds=dependency_timeout,
                index_url=dependency_index_url,
                extra_index_url=dependency_extra_index_url,
                find_links=dependency_find_links,
                no_index=dependency_no_index,
            )
            dependency_warnings.extend(resolver_warnings)
            if len(resolved_dependencies) > dependency_max_packages:
                dependency_warnings.append(f"Resolved dependency list truncated to {dependency_max_packages} packages.")
                allowed = {dep.name for dep in resolved_dependencies[:dependency_max_packages]}
                resolved_dependencies = resolved_dependencies[:dependency_max_packages]
                dependency_edges = [
                    edge
                    for edge in dependency_edges
                    if (edge.parent == "__root__" and edge.child in allowed) or (edge.parent in allowed and edge.child in allowed)
                ]
            dependency_scan_results = scan_resolved_dependencies(
                resolved_dependencies,
                dependency_edges,
                context.package_name or context.root_path.name,
                timeout_seconds=max(dependency_timeout, 1),
                max_packages=dependency_max_packages,
                find_links=dependency_find_links,
                no_index=dependency_no_index,
            )
            for dependency_result in dependency_scan_results:
                findings.extend(dependency_result.findings)
                dependency_warnings.extend(
                    f"{dependency_result.dependency.name}: {warning}"
                    for warning in dependency_result.warnings
                    if warning
                )
        else:
            dependency_warnings.append("Dependency resolution was enabled, but no resolvable declared dependencies were found.")
    limitations.extend(f"Dependency analysis warning: {warning}" for warning in dependency_warnings)

    score, score_breakdown = calculate_score_with_breakdown(findings)
    label = classify(score)
    analyzed_files = len(context.python_files) + len(context.metadata_files)
    sorted_findings = sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f.severity.upper(), 9), -f.score, f.rule_id, f.file_path or "", f.line or 0))
    root_package = context.package_name or context.root_path.name
    dependency_risk_paths = _dependency_risk_paths(sorted_findings)
    dependency_graph = build_dependency_graph(root_package, dependency_edges, sorted_findings) if resolve_deps else {}
    graph = build_behavior_graph(context, sorted_findings, dependencies or extract_dependencies(context), dependency_edges if resolve_deps else None)
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
        resolved_dependencies=resolved_dependencies,
        dependency_edges=dependency_edges,
        dependency_scan_results=dependency_scan_results,
        dependency_graph=dependency_graph,
        dependency_risk_paths=dependency_risk_paths,
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
            "dependency_resolution": {
                "enabled": resolve_deps,
                "resolved_dependencies": len(resolved_dependencies),
                "dependency_edges": len(dependency_edges),
                "warnings": dependency_warnings,
                "find_links": dependency_find_links or [],
                "no_index": dependency_no_index,
            },
            "dependency_scanning": {
                "enabled": resolve_deps,
                "scanned_dependencies": sum(1 for item in dependency_scan_results if item.artifact_path),
                "max_packages": dependency_max_packages,
            },
        },
        analysis_features={
            "dependency_resolution": resolve_deps,
            "dependency_scanning": resolve_deps,
            "dynamic_sandbox": False,
            "integrity_comparison": effective_source_path is not None,
        },
        analysis_mode="static+dependency-closure" if resolve_deps else "static",
        limitations=limitations,
    )


def _resolver_requirements(dependencies: list[Dependency]) -> tuple[list[str], list[str]]:
    requirements: list[str] = []
    warnings: list[str] = []
    for dependency in dependencies:
        if dependency.is_local_path or dependency.is_vcs or dependency.is_direct_url:
            warnings.append(f"Skipped non-index dependency during resolution: {dependency.raw}")
            continue
        requirements.append(dependency.raw)
    return requirements, warnings


def _dependency_risk_paths(findings: list[Finding]) -> list[dict[str, object]]:
    paths: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()
    for finding in findings:
        evidence = finding.evidence if isinstance(finding.evidence, dict) else {}
        chain = evidence.get("dependency_chain")
        package = evidence.get("dependency_package")
        if not chain or not package:
            continue
        key = (" -> ".join(str(item) for item in chain), finding.rule_id)
        if key in seen:
            continue
        seen.add(key)
        paths.append(
            {
                "path": list(chain) if isinstance(chain, list) else [str(chain)],
                "display_path": [*(list(chain) if isinstance(chain, list) else [str(chain)]), finding.rule_id],
                "dependency": package,
                "finding": finding.rule_id,
                "title": finding.title,
                "severity": finding.severity,
                "evidence": evidence,
            }
        )
    return paths
