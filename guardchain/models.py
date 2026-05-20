from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: str
    category: str
    message: str
    file_path: str | None = None
    line: int | None = None
    evidence: str | dict[str, Any] | None = None
    score: int = 0
    column: int | None = None
    confidence: float = 1.0
    function: str | None = None
    tags: list[str] = field(default_factory=list)
    source: str = "static"
    evidence_strength: str = "pattern"

    @property
    def description(self) -> str:
        return self.message

    @property
    def file(self) -> str | None:
        return self.file_path

    def to_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["description"] = self.description
        data["file"] = self.file_path
        data["why_it_matters"] = self.message
        return data


@dataclass(frozen=True)
class Dependency:
    name: str
    raw: str
    version_spec: str | None = None
    source: str | None = None
    is_direct_url: bool = False
    is_vcs: bool = False
    is_local_path: bool = False
    is_pinned: bool = False
    extras: list[str] = field(default_factory=list)
    marker: str | None = None


@dataclass
class PythonFile:
    path: str
    relative_path: str
    content: str
    size: int


@dataclass
class GraphNode:
    id: str
    label: str
    type: str
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphEdge:
    source: str
    target: str
    type: str
    label: str | None = None
    attributes: dict[str, Any] = field(default_factory=dict)


@dataclass
class BehaviorGraph:
    nodes: list[GraphNode] = field(default_factory=list)
    edges: list[GraphEdge] = field(default_factory=list)


@dataclass
class ScoreItem:
    rule_id: str
    base_score: int
    multiplier: float
    final_score: int
    reason: str
    file: str | None = None
    line: int | None = None
    confidence: float = 1.0
    root_key: tuple[str, str | None, int | None, str] | None = None


@dataclass
class ResolvedDependency:
    name: str
    version: str | None
    requested_by: list[str]
    direct: bool
    download_info: dict[str, object] | None = None
    metadata: dict[str, object] = field(default_factory=dict)


@dataclass
class DependencyEdge:
    parent: str
    child: str
    requirement: str | None = None


@dataclass
class DownloadedDependency:
    name: str
    version: str | None
    path: str | None = None
    size_bytes: int = 0
    warning: str | None = None


@dataclass
class DependencyScanResult:
    dependency: ResolvedDependency
    findings: list[Finding]
    score: int = 0
    label: str = "BENIGN"
    artifact_path: str | None = None
    warnings: list[str] = field(default_factory=list)


@dataclass
class DynamicEvent:
    event_type: str
    operation: str
    target: str
    process: str | None = None
    pid: int | None = None
    timestamp: str | None = None
    raw: str = ""
    severity_hint: str | None = None


# Backward-compatible alias used by earlier code/tests.
ScoreBreakdown = ScoreItem


def dataclass_to_dict(value: Any) -> Any:
    if hasattr(value, "to_dict"):
        return value.to_dict()
    if isinstance(value, list):
        return [dataclass_to_dict(item) for item in value]
    if isinstance(value, dict):
        return {key: dataclass_to_dict(item) for key, item in value.items()}
    if hasattr(value, "__dataclass_fields__"):
        return {key: dataclass_to_dict(item) for key, item in asdict(value).items()}
    return value


@dataclass
class ScanResult:
    target: str
    package_name: str | None
    score: int
    label: str
    findings: list[Finding]
    analyzed_files: int
    python_files: int
    dependencies: list[str]
    metadata: dict[str, Any] = field(default_factory=dict)
    dependency_details: list[Dependency] = field(default_factory=list)
    resolved_dependencies: list[ResolvedDependency] = field(default_factory=list)
    dependency_edges: list[DependencyEdge] = field(default_factory=list)
    dependency_scan_results: list[DependencyScanResult] = field(default_factory=list)
    dependency_graph: dict[str, Any] = field(default_factory=dict)
    dependency_risk_paths: list[dict[str, Any]] = field(default_factory=list)
    graph: dict[str, Any] | BehaviorGraph | None = None
    score_breakdown: list[ScoreItem] = field(default_factory=list)
    confidence: float = 0.0
    analysis_stats: dict[str, Any] = field(default_factory=dict)
    analysis_features: dict[str, bool] = field(default_factory=dict)
    schema_version: str = "1.0"
    tool_version: str = "0.1.0"
    analysis_mode: str = "static"
    limitations: list[str] = field(
        default_factory=lambda: [
            "Static analysis can produce false positives and false negatives.",
            "GuardChain does not execute package code and cannot observe runtime-only behavior.",
            "GuardChain is a review aid, not a complete malware verdict.",
        ]
    )

    @property
    def risk_score(self) -> int:
        return self.score

    @property
    def python_files_analyzed(self) -> int:
        return self.python_files

    def to_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["findings"] = [finding.to_dict() for finding in self.findings]
        data["score_breakdown"] = [dataclass_to_dict(item) for item in self.score_breakdown]
        data["dependency_details"] = [dataclass_to_dict(item) for item in self.dependency_details]
        data["resolved_dependencies"] = [dataclass_to_dict(item) for item in self.resolved_dependencies]
        data["dependency_edges"] = [dataclass_to_dict(item) for item in self.dependency_edges]
        data["dependency_scan_results"] = [dataclass_to_dict(item) for item in self.dependency_scan_results]
        data["graph"] = dataclass_to_dict(self.graph)
        data["graphs"] = {"behavior": data["graph"]}
        data["dependency_graph"] = dataclass_to_dict(self.dependency_graph)
        data["dependency_risk_paths"] = dataclass_to_dict(self.dependency_risk_paths)
        data["analysis_features"] = dict(self.analysis_features)
        data["static_findings"] = [finding.to_dict() for finding in self.findings if finding.source != "dynamic"]
        data["dynamic_findings"] = [finding.to_dict() for finding in self.findings if finding.source == "dynamic"]
        data["risk_score"] = self.risk_score
        data["python_files_analyzed"] = self.python_files_analyzed
        return data


@dataclass
class PackageContext:
    root_path: Path
    package_name: str | None
    python_files: list[Path]
    metadata_files: list[Path]
    dependency_files: list[Path]
    setup_py: Path | None
    pyproject_toml: Path | None
    total_files: int = 0
    total_size_bytes: int = 0
    target: str | None = None
    archive_type: str | None = None

    @property
    def root_dir(self) -> str:
        return str(self.root_path)
