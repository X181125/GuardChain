from __future__ import annotations

from .models import Finding, ScoreBreakdown

SEVERITY_WEIGHTS = {"INFO": 0, "LOW": 5, "MEDIUM": 15, "HIGH": 30, "CRITICAL": 50}


def calculate_score(findings: list[Finding]) -> int:
    score, _ = calculate_score_with_breakdown(findings)
    return score


def calculate_score_with_breakdown(findings: list[Finding]) -> tuple[int, list[ScoreBreakdown]]:
    total = 0
    breakdown: list[ScoreBreakdown] = []
    unique_findings = _dedupe_findings(findings)
    high_categories = {finding.category for finding in unique_findings if finding.severity.upper() in {"HIGH", "CRITICAL"}}
    category_multiplier = 1.2 if len(high_categories) >= 2 else 1.0
    category_reason = "multiple independent high-severity categories" if category_multiplier > 1 else ""
    for finding in unique_findings:
        base = finding.score or SEVERITY_WEIGHTS.get(finding.severity.upper(), 0)
        multiplier, reason = _multiplier(finding)
        if category_multiplier > 1 and finding.severity.upper() in {"HIGH", "CRITICAL"}:
            multiplier *= category_multiplier
            reason = "; ".join(part for part in [reason, category_reason] if part)
        confidence = max(0.0, min(float(getattr(finding, "confidence", 1.0)), 1.0))
        final = round(base * confidence * multiplier)
        total += final
        breakdown.append(ScoreBreakdown(finding.rule_id, base, multiplier, final, reason, finding.file_path, finding.line, confidence))
    score = max(0, min(total, 100))
    if any(finding.severity.upper() == "CRITICAL" for finding in findings):
        score = max(score, 60)
    return score, breakdown


def calculate_confidence(findings: list[Finding]) -> float:
    if not findings:
        return 0.0
    weighted = sum((finding.score or SEVERITY_WEIGHTS.get(finding.severity.upper(), 0)) * finding.confidence for finding in findings)
    total = sum(finding.score or SEVERITY_WEIGHTS.get(finding.severity.upper(), 0) for finding in findings)
    return round(weighted / total, 3) if total else 0.0


def classify(score: int) -> str:
    if score >= 60:
        return "MALICIOUS"
    if score >= 30:
        return "SUSPICIOUS"
    return "BENIGN"


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str | None, int | None, str]] = set()
    unique: list[Finding] = []
    for finding in findings:
        key = (finding.rule_id, finding.file_path, finding.line, str(finding.evidence))
        if key not in seen:
            seen.add(key)
            unique.append(finding)
    return unique


def _multiplier(finding: Finding) -> tuple[float, str]:
    multiplier = 1.0
    reasons: list[str] = []
    if finding.file_path and finding.file_path.endswith("setup.py") and finding.category == "behavior":
        multiplier *= 1.5
        reasons.append("dangerous behavior in setup.py")
    if finding.category == "taint":
        multiplier *= 1.5
        reasons.append("taint-confirmed behavior")
    if finding.category == "integrity" and finding.evidence and "True" in str(finding.evidence):
        multiplier *= 1.5
        reasons.append("integrity violation with dangerous behavior")
    if finding.rule_id == "D001":
        multiplier *= 1.3
        reasons.append("known suspicious demo dependency")
    return multiplier, "; ".join(reasons) if reasons else "base rule score"
