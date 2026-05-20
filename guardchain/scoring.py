from __future__ import annotations

from .models import Finding, ScoreBreakdown

SEVERITY_WEIGHTS = {"INFO": 0, "LOW": 5, "MEDIUM": 15, "HIGH": 30, "CRITICAL": 50}
EVIDENCE_STRENGTH_MULTIPLIERS = {
    "pattern": 0.8,
    "correlated_pattern": 1.0,
    "taint_confirmed": 1.5,
    "runtime_observed": 1.4,
    "integrity_confirmed": 1.4,
    "dependency_confirmed": 1.3,
}
DUPLICATE_ROOT_MULTIPLIER = 0.25


def calculate_score(findings: list[Finding]) -> int:
    score, _ = calculate_score_with_breakdown(findings)
    return score


def calculate_score_with_breakdown(findings: list[Finding]) -> tuple[int, list[ScoreBreakdown]]:
    total = 0
    breakdown: list[ScoreBreakdown] = []
    exact_duplicate_indexes = _exact_duplicate_indexes(findings)
    root_keys = [finding_root_key(finding) for finding in findings]
    root_primary_indexes = _primary_indexes_by_root(findings, root_keys, exact_duplicate_indexes)
    high_categories = {
        finding.category
        for index, finding in enumerate(findings)
        if index not in exact_duplicate_indexes and finding.severity.upper() in {"HIGH", "CRITICAL"}
    }
    category_multiplier = 1.2 if len(high_categories) >= 2 else 1.0
    category_reason = "multiple independent high-severity categories" if category_multiplier > 1 else ""
    for index, finding in enumerate(findings):
        base = finding.score or SEVERITY_WEIGHTS.get(finding.severity.upper(), 0)
        multiplier, reason = _multiplier(finding)
        if category_multiplier > 1 and finding.severity.upper() in {"HIGH", "CRITICAL"}:
            multiplier *= category_multiplier
            reason = "; ".join(part for part in [reason, category_reason] if part)
        root_key = root_keys[index]
        if index in exact_duplicate_indexes:
            multiplier = 0.0
            reason = "duplicate finding already scored"
        elif root_primary_indexes.get(root_key) != index:
            multiplier *= DUPLICATE_ROOT_MULTIPLIER
            duplicate_reason = f"duplicate evidence for {root_key[0]} in {finding.file_path or '<package>'}"
            reason = "; ".join(part for part in [reason, duplicate_reason] if part)
        confidence = max(0.0, min(float(getattr(finding, "confidence", 1.0)), 1.0))
        final = round(base * confidence * multiplier)
        total += final
        breakdown.append(ScoreBreakdown(finding.rule_id, base, multiplier, final, reason, finding.file_path, finding.line, confidence, root_key))
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


def finding_root_key(finding: Finding) -> tuple[str, str | None, int | None, str]:
    family = _behavior_family(finding)
    sink = _normalized_sink(finding, family)
    line_bucket = _line_bucket(finding)
    return (family, finding.file_path, line_bucket, sink)


def _exact_duplicate_indexes(findings: list[Finding]) -> set[int]:
    seen: set[tuple[str, str | None, int | None, str]] = set()
    duplicates: set[int] = set()
    for index, finding in enumerate(findings):
        key = (finding.rule_id, finding.file_path, finding.line, str(finding.evidence))
        if key in seen:
            duplicates.add(index)
        else:
            seen.add(key)
    return duplicates


def _primary_indexes_by_root(
    findings: list[Finding],
    root_keys: list[tuple[str, str | None, int | None, str]],
    exact_duplicate_indexes: set[int],
) -> dict[tuple[str, str | None, int | None, str], int]:
    primary: dict[tuple[str, str | None, int | None, str], int] = {}
    strength_rank = {name: index for index, name in enumerate(EVIDENCE_STRENGTH_MULTIPLIERS)}
    for index, finding in enumerate(findings):
        if index in exact_duplicate_indexes:
            continue
        key = root_keys[index]
        current = primary.get(key)
        if current is None:
            primary[key] = index
            continue
        if _primary_rank(finding, strength_rank) > _primary_rank(findings[current], strength_rank):
            primary[key] = index
    return primary


def _primary_rank(finding: Finding, strength_rank: dict[str, int]) -> tuple[float, int, int]:
    base = finding.score or SEVERITY_WEIGHTS.get(finding.severity.upper(), 0)
    strength = strength_rank.get(getattr(finding, "evidence_strength", "pattern"), 0)
    return (finding.confidence, strength, base)


def _multiplier(finding: Finding) -> tuple[float, str]:
    strength = getattr(finding, "evidence_strength", "pattern") or "pattern"
    multiplier = EVIDENCE_STRENGTH_MULTIPLIERS.get(strength, 1.0)
    reasons: list[str] = []
    if strength in EVIDENCE_STRENGTH_MULTIPLIERS:
        reasons.append(f"evidence strength: {strength}")
    if finding.file_path and finding.file_path.endswith("setup.py") and finding.category == "behavior":
        multiplier *= 1.5
        reasons.append("dangerous behavior in setup.py")
    if finding.category == "taint" and strength != "taint_confirmed":
        multiplier *= 1.5
        reasons.append("taint-confirmed behavior")
    if finding.category == "integrity" and strength != "integrity_confirmed" and finding.evidence and "True" in str(finding.evidence):
        multiplier *= 1.5
        reasons.append("integrity violation with dangerous behavior")
    if finding.rule_id == "D001":
        multiplier *= 1.3
        reasons.append("known suspicious demo dependency")
    return multiplier, "; ".join(reasons) if reasons else "base rule score"


def _behavior_family(finding: Finding) -> str:
    rule = finding.rule_id.upper()
    if rule in {"B002", "S001"}:
        return "command_execution"
    if rule in {"B001", "B006", "S004", "T004", "T006"}:
        return "dynamic_execution"
    if rule in {"B003", "S003", "T002"}:
        return "network_access"
    if rule in {"B005"}:
        return "obfuscation"
    if rule in {"B008", "T001", "T005"}:
        return "exfiltration"
    if rule.startswith("S"):
        return "setup_install_behavior"
    if rule.startswith("D"):
        return "dependency_risk"
    if rule.startswith("I"):
        return "integrity_mismatch"
    if rule.startswith("Y"):
        return "runtime_behavior"
    if rule == "M004":
        return _metadata_setup_family(finding)
    if finding.category == "taint":
        return "taint_flow"
    if finding.category == "behavior":
        return "behavior_pattern"
    return finding.category or "finding"


def _metadata_setup_family(finding: Finding) -> str:
    text = str(finding.evidence or "").lower()
    if "subprocess" in text or "os.system" in text:
        return "command_execution"
    if "exec" in text or "eval" in text:
        return "dynamic_execution"
    if "requests" in text or "urllib" in text or "socket" in text:
        return "network_access"
    if "base64" in text:
        return "obfuscation"
    return "setup_install_behavior"


def _normalized_sink(finding: Finding, family: str) -> str:
    evidence = finding.evidence if isinstance(finding.evidence, dict) else {}
    candidates: list[object] = []
    if evidence:
        for key in ("sink", "call", "source"):
            if evidence.get(key):
                candidates.append(evidence[key])
        calls = evidence.get("calls")
        if isinstance(calls, list):
            candidates.extend(calls)
    elif finding.evidence:
        candidates.append(finding.evidence)
    text = " ".join(str(item).lower() for item in candidates)
    if family == "command_execution" or any(token in text for token in ("subprocess", "os.system", "os.popen")):
        return "command_execution"
    if family == "dynamic_execution" or any(token in text for token in ("exec", "eval", "compile")):
        return "dynamic_execution"
    if family == "network_access" or any(token in text for token in ("requests", "urllib", "socket", "http.client")):
        return "network"
    if family == "exfiltration":
        return str(evidence.get("sink") or "exfiltration")
    if family == "dependency_risk":
        return str(evidence.get("dependency") or evidence.get("import") or finding.evidence or finding.rule_id).lower()
    if family == "integrity_mismatch":
        return str(evidence.get("integrity_rule") or finding.rule_id)
    return text or finding.rule_id


def _line_bucket(finding: Finding) -> int | None:
    if finding.file_path and finding.file_path.endswith("setup.py") and _behavior_family(finding) in {"command_execution", "dynamic_execution", "setup_install_behavior"}:
        return None
    if finding.line is None:
        return None
    return max(1, ((finding.line - 1) // 3) * 3 + 1)
