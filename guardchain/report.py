from __future__ import annotations

import json
from pathlib import Path

from .models import ScanResult


def format_terminal(result: ScanResult, verbose: bool = False, artifacts: dict[str, str] | None = None) -> str:
    dependencies = ", ".join(result.dependencies) if result.dependencies else "none"
    lines = [
        f"Target: {result.target}",
        f"Package: {result.package_name or 'unknown'}",
        f"Label: {result.label}",
        f"Risk score: {result.score}/100",
        f"Analysis mode: {result.analysis_mode}",
        f"Python files analyzed: {result.python_files}",
        f"Dependencies: {dependencies}",
        f"Evidence strength: {_summary_inline(_evidence_strength_counts(result))}",
        "",
        "Top findings:",
    ]
    if not result.findings:
        lines.append("None")
    else:
        for finding in result.findings[:10]:
            location = finding.file_path or "<package>"
            if finding.line is not None:
                location = f"{location}:{finding.line}"
            lines.append(f"[{finding.severity}] {finding.rule_id} {location}")
            lines.append(finding.message)
            lines.append(f"Evidence strength: {finding.evidence_strength}")
            if verbose and finding.evidence:
                lines.append(f"Evidence: {finding.evidence}")
            lines.append("")
    lines.append("Dependency risk paths:")
    if result.dependency_risk_paths:
        for item in result.dependency_risk_paths[:5]:
            path = item.get("display_path") or item.get("path", [])
            lines.append(" -> ".join(str(part) for part in path))
    elif result.analysis_features.get("dependency_resolution"):
        lines.append("None")
    else:
        lines.append("Dependency chain analysis was not performed.")
    if artifacts:
        lines.append("Artifacts:")
        for label, path in artifacts.items():
            if path:
                lines.append(f"{label}: {path}")
    return "\n".join(lines).rstrip() + "\n"


def write_json_report(result: ScanResult, output_path: str | Path) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result.to_dict(), indent=2, sort_keys=True), encoding="utf-8")


def build_sarif_report(result: ScanResult) -> dict[str, object]:
    rules: dict[str, dict[str, object]] = {}
    results: list[dict[str, object]] = []
    for finding in result.findings:
        rules.setdefault(
            finding.rule_id,
            {
                "id": finding.rule_id,
                "name": finding.title,
                "shortDescription": {"text": finding.title},
                "fullDescription": {"text": finding.message},
                "properties": {
                    "category": finding.category,
                    "severity": finding.severity.lower(),
                    "confidence": finding.confidence,
                    "evidence_strength": finding.evidence_strength,
                    "tags": finding.tags,
                },
            },
        )
        location: dict[str, object] = {
            "physicalLocation": {
                "artifactLocation": {"uri": finding.file_path or result.target},
            }
        }
        if finding.line is not None:
            region: dict[str, int] = {"startLine": finding.line}
            if finding.column is not None:
                region["startColumn"] = finding.column + 1
            location["physicalLocation"]["region"] = region
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": _sarif_level(finding.severity),
                "message": {"text": finding.message},
                "locations": [location],
                "properties": {
                    "score": finding.score,
                    "confidence": finding.confidence,
                    "evidence_strength": finding.evidence_strength,
                    "evidence": finding.evidence,
                },
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "GuardChain",
                        "informationUri": "https://github.com/guardchain/guardchain",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def write_sarif_report(result: ScanResult, output_path: str | Path) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(build_sarif_report(result), indent=2, sort_keys=True), encoding="utf-8")


def write_markdown_report(result: ScanResult, output_path: str | Path) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# GuardChain Scan Report",
        "",
        "## Summary",
        "",
        f"- Target: `{result.target}`",
        f"- Package: `{result.package_name or 'unknown'}`",
        f"- Label: **{result.label}**",
        f"- Confidence: **{result.confidence:.2f}**",
        f"- Python files analyzed: {result.python_files}",
        f"- Analysis mode: `{result.analysis_mode}`",
        "",
        "## Analysis Mode",
        "",
        _analysis_mode_text(result),
        "",
        "## Evidence Strength Summary",
        "",
        "| Strength | Count |",
        "| --- | ---: |",
    ]
    for strength, count in _evidence_strength_counts(result).items():
        lines.append(f"| {strength} | {count} |")
    lines.extend(
        [
            "",
            "## Risk Score",
            "",
            f"**{result.score}/100**",
            "",
            "## Score Breakdown",
            "",
        ]
    )
    if result.score_breakdown:
        lines.extend(["| Rule | Base | Multiplier | Final | Reason |", "| --- | ---: | ---: | ---: | --- |"])
        for item in result.score_breakdown:
            lines.append(f"| {item.rule_id} | {item.base_score} | {item.multiplier:.2f} | {item.final_score} | {item.reason} |")
    else:
        lines.append("No score contributions.")
    lines.extend(["", "## Findings", ""])
    if result.findings:
        for finding in result.findings:
            location = finding.file_path or "<package>"
            if finding.line is not None:
                location += f":{finding.line}"
            lines.extend(
                [
                    f"### {finding.rule_id}: {finding.title}",
                    "",
                    f"- Severity: `{finding.severity}`",
                    f"- Evidence strength: `{finding.evidence_strength}`",
                    f"- Source: `{finding.source}`",
                    f"- Location: `{location}`",
                    f"- Description: {finding.message}",
                ]
            )
            if finding.evidence:
                lines.append(f"- Evidence: `{finding.evidence}`")
            lines.append("")
    else:
        lines.append("No findings.")
    lines.extend(["## Dependency Risk Paths", ""])
    if result.dependency_risk_paths:
        for item in result.dependency_risk_paths:
            chain_text = " -> ".join(str(part) for part in (item.get("display_path") or item.get("path", [])))
            lines.append(f"- {chain_text}")
            lines.append(f"  - Finding: {item.get('finding')} {item.get('title')}")
            if item.get("evidence"):
                lines.append(f"  - Evidence: `{item.get('evidence')}`")
    elif result.analysis_features.get("dependency_resolution"):
        lines.append("No dependency-origin findings were reported.")
    else:
        lines.append("Dependency chain analysis was not performed.")
    lines.extend(["", "## Root Cause Groups", ""])
    if result.score_breakdown:
        grouped: dict[str, int] = {}
        for item in result.score_breakdown:
            root = str(item.root_key[0] if item.root_key else item.rule_id)
            grouped[root] = grouped.get(root, 0) + 1
        for root, count in sorted(grouped.items()):
            lines.append(f"- `{root}`: {count}")
    else:
        lines.append("No scored findings.")
    lines.append("")
    lines.extend(["## Dependencies", "", ", ".join(result.dependencies) if result.dependencies else "None", "", "## Metadata", "", "```json", json.dumps(result.metadata, indent=2, sort_keys=True), "```", ""])
    lines.extend(["## Evidence Paths", ""])
    evidence_paths = []
    for finding in result.findings:
        if isinstance(finding.evidence, dict) and finding.evidence.get("flow"):
            evidence_paths.append(f"- `{finding.rule_id}`: {' -> '.join(str(item) for item in finding.evidence['flow'])}")
    lines.extend(evidence_paths or ["No explicit source-to-sink paths were reported."])
    lines.extend(["", "## Integrity Analysis", "", "See findings with rule IDs starting with `I`.", "", "## Behavior Graph", "", "Graph artifacts can be generated with `--graph-dot` or `--graph-mermaid`.", "", "## Limitations", ""])
    lines.extend(f"- {item}" for item in result.limitations)
    path.write_text("\n".join(lines), encoding="utf-8")


def write_text_artifact(content: str, output_path: str | Path) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _sarif_level(severity: str) -> str:
    severity = severity.upper()
    if severity in {"CRITICAL", "HIGH"}:
        return "error"
    if severity == "MEDIUM":
        return "warning"
    return "note"


def _evidence_strength_counts(result: ScanResult) -> dict[str, int]:
    counts: dict[str, int] = {}
    for finding in result.findings:
        counts[finding.evidence_strength] = counts.get(finding.evidence_strength, 0) + 1
    return dict(sorted(counts.items()))


def _summary_inline(values: dict[str, int]) -> str:
    if not values:
        return "none"
    return ", ".join(f"{key}={value}" for key, value in values.items())


def _analysis_mode_text(result: ScanResult) -> str:
    features = result.analysis_features or {}
    parts = [] if result.analysis_mode == "dynamic" else ["static"]
    if features.get("dependency_resolution"):
        parts.append("dependency closure")
    if features.get("dynamic_sandbox"):
        parts.append("dynamic sandbox")
    if features.get("integrity_comparison"):
        parts.append("integrity comparison")
    return " + ".join(parts)
