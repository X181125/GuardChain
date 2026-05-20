from __future__ import annotations

from pathlib import Path

from ..models import DynamicEvent, Finding

SHELLS = {"sh", "bash", "zsh", "cmd.exe", "powershell", "pwsh"}
NETWORK_TOOLS = {"curl", "wget", "nc", "netcat"}
PACKAGE_MANAGERS = {"pip", "pip3", "python -m pip"}
SUSPICIOUS_WRITE_SUFFIXES = {".exe", ".dll", ".so", ".bat", ".ps1", ".sh", ".scr"}


def analyze_dynamic_events(events: list[DynamicEvent]) -> list[Finding]:
    findings: list[Finding] = []
    for event in events:
        if event.event_type == "process" and event.operation == "execve":
            process = (event.process or Path(event.target).name).lower()
            if process:
                _append(findings, _finding("Y001", "Runtime process execution", "MEDIUM", 15, event, {"process": process}))
            if process in SHELLS:
                _append(findings, _finding("Y002", "Runtime shell spawn", "HIGH", 30, event, {"process": process}))
            if process in NETWORK_TOOLS:
                _append(findings, _finding("Y003", "Runtime network-capable tool execution", "HIGH", 30, event, {"process": process}))
            if process in {"pip", "pip3"} or "pip" in event.target.lower():
                _append(findings, _finding("Y007", "Runtime package manager invocation", "HIGH", 30, event, {"process": process}))
        if event.event_type == "network" and event.operation == "connect":
            _append(findings, _finding("Y003", "Runtime network connection attempt", "HIGH", 30, event, {"address": event.target}))
        if event.severity_hint == "sensitive_file":
            _append(findings, _finding("Y004", "Runtime sensitive file access", "CRITICAL", 50, event, {"path": event.target}))
        if event.severity_hint == "file_write":
            _append(findings, _finding("Y005", "Runtime suspicious file write", "MEDIUM", 15, event, {"path": event.target}))
            if Path(event.target).suffix.lower() in SUSPICIOUS_WRITE_SUFFIXES:
                _append(findings, _finding("Y008", "Runtime binary or script drop", "HIGH", 30, event, {"path": event.target}))
        if event.severity_hint == "persistence_path":
            _append(findings, _finding("Y006", "Runtime persistence-like file access", "CRITICAL", 50, event, {"path": event.target}))
        if event.severity_hint == "sandbox_restriction":
            _append(findings, _finding("Y009", "Runtime attempt blocked by sandbox policy", "MEDIUM", 15, event, {"raw": event.raw}))
    return findings


def _finding(rule_id: str, title: str, severity: str, score: int, event: DynamicEvent, evidence: dict[str, object]) -> Finding:
    evidence = {
        **evidence,
        "event_type": event.event_type,
        "operation": event.operation,
        "target": event.target,
        "pid": event.pid,
        "timestamp": event.timestamp,
        "raw": event.raw,
    }
    return Finding(
        rule_id=rule_id,
        title=title,
        severity=severity,
        category="dynamic",
        message=title,
        evidence=evidence,
        score=score,
        confidence=0.95,
        source="dynamic",
        evidence_strength="runtime_observed",
    )


def _append(findings: list[Finding], finding: Finding) -> None:
    key = (finding.rule_id, str(finding.evidence.get("operation")), str(finding.evidence.get("target")))
    existing = {(item.rule_id, str(item.evidence.get("operation") if isinstance(item.evidence, dict) else ""), str(item.evidence.get("target") if isinstance(item.evidence, dict) else "")) for item in findings}
    if key not in existing:
        findings.append(finding)
