from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

from .graph_builder import find_dependency_chains
from .models import DependencyEdge, DependencyScanResult, DownloadedDependency, Finding, ResolvedDependency
from .scoring import classify
from .utils import normalize_package_name


def download_dependency_artifacts(
    resolved: list[ResolvedDependency],
    output_dir: Path,
    timeout_seconds: int = 120,
    only_binary: bool = True,
    max_packages: int = 50,
    find_links: list[str] | None = None,
    no_index: bool = False,
) -> list[DownloadedDependency]:
    output_dir.mkdir(parents=True, exist_ok=True)
    downloads: list[DownloadedDependency] = []
    seen: set[tuple[str, str | None]] = set()
    for dependency in resolved:
        key = (normalize_package_name(dependency.name), dependency.version)
        if key in seen:
            continue
        seen.add(key)
        if len(downloads) >= max_packages:
            downloads.append(DownloadedDependency(dependency.name, dependency.version, warning=f"Skipped after max dependency package limit ({max_packages})."))
            continue
        if not dependency.version:
            downloads.append(DownloadedDependency(dependency.name, dependency.version, warning="Skipped dependency without resolved version."))
            continue

        before = {path.resolve() for path in output_dir.iterdir() if path.is_file()}
        command = [
            sys.executable,
            "-m",
            "pip",
            "download",
            "--no-deps",
            "--dest",
            str(output_dir),
        ]
        if only_binary:
            command.append("--only-binary=:all:")
        if no_index:
            command.append("--no-index")
        for path in find_links or []:
            command.extend(["--find-links", path])
        command.append(f"{dependency.name}=={dependency.version}")

        try:
            completed = subprocess.run(command, text=True, capture_output=True, timeout=timeout_seconds, check=False)
        except subprocess.TimeoutExpired:
            downloads.append(DownloadedDependency(dependency.name, dependency.version, warning=f"Download timed out after {timeout_seconds} seconds."))
            continue
        except OSError as exc:
            downloads.append(DownloadedDependency(dependency.name, dependency.version, warning=f"Download could not start: {exc}"))
            continue

        if completed.returncode != 0:
            message = (completed.stderr or completed.stdout or "pip download failed").strip()
            downloads.append(DownloadedDependency(dependency.name, dependency.version, warning=message))
            continue

        created = [path for path in output_dir.iterdir() if path.is_file() and path.resolve() not in before]
        artifact = _select_artifact(created, dependency)
        if artifact is None:
            downloads.append(DownloadedDependency(dependency.name, dependency.version, warning="pip download completed but no artifact was found."))
            continue
        downloads.append(DownloadedDependency(dependency.name, dependency.version, str(artifact), artifact.stat().st_size))
    return downloads


def scan_resolved_dependencies(
    resolved_dependencies: list[ResolvedDependency],
    dependency_edges: list[DependencyEdge],
    root_package: str,
    timeout_seconds: int = 120,
    max_packages: int = 50,
    max_files: int = 1000,
    max_size_mb: int = 50,
    max_python_file_size_mb: int = 2,
    find_links: list[str] | None = None,
    no_index: bool = False,
) -> list[DependencyScanResult]:
    results: list[DependencyScanResult] = []
    if not resolved_dependencies:
        return results
    with tempfile.TemporaryDirectory(prefix="guardchain_deps_") as tmp:
        downloads = download_dependency_artifacts(
            resolved_dependencies,
            Path(tmp),
            timeout_seconds=timeout_seconds,
            max_packages=max_packages,
            find_links=find_links,
            no_index=no_index,
        )
        resolved_by_key = {(normalize_package_name(dep.name), dep.version): dep for dep in resolved_dependencies}
        for download in downloads:
            dependency = resolved_by_key.get((normalize_package_name(download.name), download.version)) or ResolvedDependency(download.name, download.version, [], False)
            if download.warning or not download.path:
                results.append(DependencyScanResult(dependency=dependency, findings=[], artifact_path=download.path, warnings=[download.warning or "Dependency artifact was not downloaded."]))
                continue
            try:
                from .scanner import scan

                scan_result = scan(
                    download.path,
                    max_files=max_files,
                    max_size_mb=max_size_mb,
                    max_python_file_size_mb=max_python_file_size_mb,
                    resolve_deps=False,
                )
            except Exception as exc:
                results.append(DependencyScanResult(dependency=dependency, findings=[], artifact_path=download.path, warnings=[f"Dependency scan failed: {exc}"]))
                continue
            annotated = [
                _dependency_finding(finding, dependency, root_package, dependency_edges)
                for finding in scan_result.findings
            ]
            results.append(
                DependencyScanResult(
                    dependency=dependency,
                    findings=annotated,
                    score=scan_result.score,
                    label=classify(scan_result.score),
                    artifact_path=download.path,
                    warnings=[],
                )
            )
    return results


def _dependency_finding(
    finding: Finding,
    dependency: ResolvedDependency,
    root_package: str,
    dependency_edges: list[DependencyEdge],
) -> Finding:
    evidence = finding.evidence if isinstance(finding.evidence, dict) else {"details": finding.evidence}
    chains = find_dependency_chains(root_package, dependency_edges, dependency.name)
    chain = chains[0] if chains else [root_package, dependency.name]
    nested_strength = finding.evidence_strength
    dependency_strength = _dependency_evidence_strength(nested_strength)
    return Finding(
        rule_id=finding.rule_id,
        title=finding.title,
        severity=finding.severity,
        category=finding.category,
        message=finding.message,
        file_path=finding.file_path,
        line=finding.line,
        evidence={
            **evidence,
            "dependency_package": dependency.name,
            "dependency_version": dependency.version,
            "dependency_chain": chain,
            "nested_evidence_strength": nested_strength,
        },
        score=finding.score,
        column=finding.column,
        confidence=finding.confidence,
        function=finding.function,
        tags=[*finding.tags, "dependency"],
        source="dependency",
        evidence_strength=dependency_strength,
    )


def _dependency_evidence_strength(nested_strength: str) -> str:
    stronger_nested = {"taint_confirmed", "runtime_observed", "integrity_confirmed"}
    if nested_strength in stronger_nested:
        return nested_strength
    return "dependency_confirmed"


def _select_artifact(paths: list[Path], dependency: ResolvedDependency) -> Path | None:
    if not paths:
        return None
    normalized = normalize_package_name(dependency.name).replace("-", "_")
    wheel_or_zip = [path for path in paths if path.suffix in {".whl", ".zip"} or path.name.endswith(".tar.gz")]
    for path in wheel_or_zip:
        if normalize_package_name(path.name).replace("-", "_").startswith(normalized):
            return path
    return wheel_or_zip[0] if wheel_or_zip else paths[0]
