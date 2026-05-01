from __future__ import annotations

import ast
from pathlib import Path

from .models import Finding
from .utils import relative_path, safe_read_text

SUSPICIOUS_SCRIPT_EXTENSIONS = {".exe", ".dll", ".so", ".bat", ".ps1", ".sh", ".scr"}
DANGEROUS_TOKENS = {"subprocess.", "os.system", "exec(", "eval(", "requests.post", "socket.socket", "base64.b64decode"}


def analyze_integrity(package_root: str | Path, source_root: str | Path) -> list[Finding]:
    package_root = Path(package_root).resolve()
    source_root = Path(source_root).expanduser().resolve()
    if not source_root.exists() or not source_root.is_dir():
        raise ValueError(f"Source path must be an existing directory: {source_root}")

    findings: list[Finding] = []
    package_py_files = sorted(package_root.rglob("*.py"))
    source_py_files = sorted(source_root.rglob("*.py"))
    for package_file in package_py_files:
        rel = package_file.relative_to(package_root)
        source_file = source_root / rel
        if not source_file.exists():
            dangerous = _contains_dangerous_behavior(package_file)
            findings.append(
                Finding(
                    rule_id="I001",
                    title="New Python file in distributed package",
                    severity="HIGH" if dangerous else "MEDIUM",
                    category="integrity",
                    message="Python file exists in distributed package but not in source repository",
                    file_path=rel.as_posix(),
                    evidence={"dangerous_behavior": dangerous},
                    score=30 if dangerous else 20,
                )
            )
            if dangerous:
                findings.append(
                    Finding(
                        rule_id="I004",
                        title="Integrity violation combined with dangerous behavior",
                        severity="HIGH",
                        category="integrity",
                        message="New Python file is absent from source repository and contains dangerous behavior",
                        file_path=rel.as_posix(),
                        evidence={"dangerous_behavior": True, "integrity_rule": "I001"},
                        score=30,
                    )
                )
            continue
        if _ast_dump(package_file) != _ast_dump(source_file):
            dangerous = _contains_dangerous_behavior(package_file)
            findings.append(
                Finding(
                    rule_id="I002",
                    title="Modified Python file",
                    severity="HIGH" if dangerous else "MEDIUM",
                    category="integrity",
                    message="Python file differs from source repository at AST level",
                    file_path=relative_path(package_file, package_root),
                    evidence={"dangerous_behavior": dangerous},
                    score=25 if dangerous else 15,
                )
            )
            if dangerous:
                findings.append(
                    Finding(
                        rule_id="I004",
                        title="Integrity violation combined with dangerous behavior",
                        severity="HIGH",
                        category="integrity",
                        message="Modified Python file differs from source repository and contains dangerous behavior",
                        file_path=relative_path(package_file, package_root),
                        evidence={"dangerous_behavior": True, "integrity_rule": "I002"},
                        score=30,
                    )
                )
    package_rels = {path.relative_to(package_root) for path in package_py_files}
    for source_file in source_py_files:
        rel = source_file.relative_to(source_root)
        if rel not in package_rels:
            findings.append(
                Finding(
                    rule_id="I005",
                    title="Missing Python file in distributed package",
                    severity="LOW",
                    category="integrity",
                    message="Python file exists in source repository but is missing from distributed package",
                    file_path=rel.as_posix(),
                    score=5,
                )
            )
    for package_file in sorted(package_root.rglob("*")):
        if package_file.is_file() and package_file.suffix.lower() in SUSPICIOUS_SCRIPT_EXTENSIONS:
            rel = package_file.relative_to(package_root)
            if not (source_root / rel).exists():
                findings.append(
                    Finding(
                        rule_id="I003",
                        title="Suspicious new binary or script file",
                        severity="HIGH",
                        category="integrity",
                        message="Distributed package contains a new binary or script file not present in source",
                        file_path=rel.as_posix(),
                        score=30,
                    )
                )
    return findings


def _ast_dump(path: Path) -> str:
    try:
        tree = ast.parse(safe_read_text(path), filename=str(path))
        _strip_docstrings(tree)
        return ast.dump(tree, include_attributes=False)
    except SyntaxError:
        return safe_read_text(path)


def _strip_docstrings(node: ast.AST) -> None:
    for child in ast.walk(node):
        body = getattr(child, "body", None)
        if isinstance(body, list) and body and isinstance(body[0], ast.Expr):
            value = body[0].value
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                body.pop(0)


def _contains_dangerous_behavior(path: Path) -> bool:
    text = safe_read_text(path)
    return any(token in text for token in DANGEROUS_TOKENS)
