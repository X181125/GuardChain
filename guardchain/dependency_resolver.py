from __future__ import annotations

import json
import subprocess
import sys
from collections import defaultdict
from packaging.requirements import InvalidRequirement, Requirement

from .models import DependencyEdge, ResolvedDependency
from .utils import normalize_package_name, strip_requirement_name

ROOT_DEPENDENCY = "__root__"


def resolve_dependencies(
    requirements: list[str],
    timeout_seconds: int = 60,
    index_url: str | None = None,
    extra_index_url: list[str] | None = None,
    find_links: list[str] | None = None,
    no_index: bool = False,
    only_binary: bool = True,
) -> tuple[list[ResolvedDependency], list[DependencyEdge], list[str]]:
    cleaned = [requirement.strip() for requirement in requirements if requirement and requirement.strip()]
    if not cleaned:
        return [], [], []

    command = [
        sys.executable,
        "-m",
        "pip",
        "install",
        "--dry-run",
        "--ignore-installed",
        "--report",
        "-",
        "--quiet",
    ]
    if only_binary:
        command.append("--only-binary=:all:")
    if index_url:
        command.extend(["--index-url", index_url])
    for url in extra_index_url or []:
        command.extend(["--extra-index-url", url])
    if no_index:
        command.append("--no-index")
    for path in find_links or []:
        command.extend(["--find-links", path])
    command.extend(cleaned)

    warnings: list[str] = []
    try:
        completed = subprocess.run(command, text=True, capture_output=True, timeout=timeout_seconds, check=False)
    except subprocess.TimeoutExpired:
        return [], [], [f"Dependency resolution timed out after {timeout_seconds} seconds."]
    except OSError as exc:
        return [], [], [f"Dependency resolution could not start: {exc}"]

    if completed.returncode != 0:
        message = (completed.stderr or completed.stdout or "pip dependency resolution failed").strip()
        return [], [], [message]

    report_text = _extract_json_report(completed.stdout)
    if not report_text:
        return [], [], ["pip did not return a dependency resolution report."]
    try:
        report = json.loads(report_text)
    except json.JSONDecodeError as exc:
        return [], [], [f"pip dependency resolution report was not valid JSON: {exc}"]

    return _dependencies_from_report(report, cleaned, warnings)


def _dependencies_from_report(
    report: dict[str, object],
    requirements: list[str],
    warnings: list[str],
) -> tuple[list[ResolvedDependency], list[DependencyEdge], list[str]]:
    requested_names = {_requirement_name(requirement) for requirement in requirements}
    requested_names.discard("")
    install_items = report.get("install", [])
    if not isinstance(install_items, list):
        return [], [], ["pip report did not contain an install list."]

    resolved: dict[str, ResolvedDependency] = {}
    metadata_requires: dict[str, list[str]] = {}
    for item in install_items:
        if not isinstance(item, dict):
            continue
        metadata = item.get("metadata") if isinstance(item.get("metadata"), dict) else {}
        name = normalize_package_name(str(metadata.get("name") or item.get("name") or ""))
        if not name:
            continue
        version = metadata.get("version")
        requires_dist = metadata.get("requires_dist", [])
        if isinstance(requires_dist, list):
            metadata_requires[name] = [str(requirement) for requirement in requires_dist]
        direct = bool(item.get("requested")) or name in requested_names
        resolved[name] = ResolvedDependency(
            name=name,
            version=str(version) if version is not None else None,
            requested_by=[ROOT_DEPENDENCY] if direct else [],
            direct=direct,
            download_info=item.get("download_info") if isinstance(item.get("download_info"), dict) else None,
            metadata={key: value for key, value in metadata.items() if key in {"name", "version", "summary", "requires_dist"}},
        )

    edges: list[DependencyEdge] = []
    for requirement in requirements:
        name = _requirement_name(requirement)
        if not name:
            warnings.append(f"Could not parse declared dependency requirement: {requirement}")
            continue
        if name in resolved:
            _append_edge(edges, DependencyEdge(ROOT_DEPENDENCY, name, requirement))
        else:
            warnings.append(f"Declared dependency was not resolved: {requirement}")

    children_by_parent: dict[str, set[str]] = defaultdict(set)
    for parent, requires_dist in metadata_requires.items():
        for requirement in requires_dist:
            child = _requirement_name(requirement)
            if child and child in resolved:
                children_by_parent[parent].add(child)
                _append_edge(edges, DependencyEdge(parent, child, requirement))

    requested_by: dict[str, set[str]] = defaultdict(set)
    for edge in edges:
        requested_by[edge.child].add(edge.parent)
    for name, dependency in resolved.items():
        parents = requested_by.get(name, set())
        if parents:
            dependency.requested_by = sorted(parents)
        elif not dependency.direct:
            warnings.append(f"Resolved dependency has no relationship data in pip report: {name}")

    if not any(edge.parent != ROOT_DEPENDENCY for edge in edges) and len(resolved) > len(requested_names):
        warnings.append("pip report did not include enough metadata to reconstruct full transitive dependency edges.")

    return sorted(resolved.values(), key=lambda dep: dep.name), edges, warnings


def _append_edge(edges: list[DependencyEdge], edge: DependencyEdge) -> None:
    key = (edge.parent, edge.child, edge.requirement)
    if key not in {(item.parent, item.child, item.requirement) for item in edges}:
        edges.append(edge)


def _requirement_name(requirement: str) -> str:
    raw = requirement.strip()
    try:
        return normalize_package_name(Requirement(raw).name)
    except InvalidRequirement:
        return normalize_package_name(strip_requirement_name(raw))


def _extract_json_report(stdout: str) -> str:
    text = stdout.strip()
    if not text:
        return ""
    if text.startswith("{"):
        return text
    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        return text[start : end + 1]
    return ""
