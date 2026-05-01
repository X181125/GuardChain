from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from importlib.resources import files
from pathlib import Path

import yaml


@dataclass(frozen=True)
class RuleInfo:
    rule_id: str
    title: str
    severity: str
    score: int
    category: str


@lru_cache(maxsize=1)
def load_rule_registry() -> dict[str, RuleInfo]:
    raw = json.loads(files("guardchain.rules").joinpath("suspicious_rules.json").read_text(encoding="utf-8"))
    registry: dict[str, RuleInfo] = {}
    for category, rules in raw.items():
        for rule_id, (title, severity, score) in rules.items():
            registry[rule_id] = RuleInfo(rule_id=rule_id, title=title, severity=severity, score=int(score), category=category)
    return registry


def get_rule(rule_id: str) -> RuleInfo | None:
    return load_rule_registry().get(rule_id)


def load_yaml_rules(rule_dir: str | Path | None = None) -> list[dict[str, object]]:
    if rule_dir is None:
        package_files = files("guardchain.rules")
        paths = [
            package_files.joinpath(name)
            for name in [
                "behavior_rules.yaml",
                "taint_rules.yaml",
                "dependency_rules.yaml",
                "metadata_rules.yaml",
                "integrity_rules.yaml",
                "dynamic_rules.yaml",
            ]
        ]
        raw_rules: list[dict[str, object]] = []
        for path in paths:
            raw_rules.extend(yaml.safe_load(path.read_text(encoding="utf-8")) or [])
        return raw_rules
    raw_rules = []
    for path in sorted(Path(rule_dir).glob("*.y*ml")):
        raw_rules.extend(yaml.safe_load(path.read_text(encoding="utf-8")) or [])
    return raw_rules


def validate_yaml_rules(rule_dir: str | Path | None = None) -> list[str]:
    errors: list[str] = []
    required = {"id", "name", "severity", "category", "description"}
    for index, rule in enumerate(load_yaml_rules(rule_dir), start=1):
        missing = required - set(rule)
        if missing:
            errors.append(f"rule #{index} missing fields: {', '.join(sorted(missing))}")
        if str(rule.get("severity", "")).lower() not in {"info", "low", "medium", "high", "critical"}:
            errors.append(f"rule {rule.get('id', index)} has invalid severity")
    return errors
