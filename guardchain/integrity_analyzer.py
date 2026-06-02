from __future__ import annotations

import ast
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .call_resolver import CallResolver
from .models import Finding
from .utils import relative_path, safe_read_text

SUSPICIOUS_SCRIPT_EXTENSIONS = {".exe", ".dll", ".so", ".bat", ".ps1", ".sh", ".scr"}
DANGEROUS_TOKENS = {
    "subprocess.",
    "os.system",
    "os.popen",
    "exec(",
    "eval(",
    "compile(",
    "requests.post",
    "requests.put",
    "httpx.post",
    "socket.socket",
    "base64.b64decode",
    "marshal.loads",
}
SUSPICIOUS_CALLS = {
    "eval",
    "exec",
    "compile",
    "execfile",
    "runpy.run_path",
    "runpy.run_module",
    "types.FunctionType",
    "os.system",
    "os.popen",
    "os.execl",
    "os.execv",
    "os.execve",
    "os.spawnl",
    "os.spawnv",
    "pty.spawn",
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.getoutput",
    "commands.getoutput",
    "requests.post",
    "requests.put",
    "requests.request",
    "urllib.request.urlopen",
    "socket.socket",
    "socket.send",
    "socket.sendall",
    "httpx.post",
    "httpx.request",
    "base64.b64decode",
    "marshal.loads",
    "zlib.decompress",
}


@dataclass
class _FileSummary:
    imports: set[str] = field(default_factory=set)
    functions: set[str] = field(default_factory=set)
    classes: set[str] = field(default_factory=set)
    calls: set[str] = field(default_factory=set)
    top_level_calls: set[str] = field(default_factory=set)
    suspicious_calls: set[str] = field(default_factory=set)
    suspicious_top_level_calls: set[str] = field(default_factory=set)
    suspicious_strings: set[str] = field(default_factory=set)


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
            dangerous_tokens = _dangerous_tokens(package_file)
            package_summary = _summarize_python_file(package_file)
            dangerous = bool(dangerous_tokens or package_summary.suspicious_calls or package_summary.suspicious_strings)
            findings.append(
                Finding(
                    rule_id="I001",
                    title="New Python file in distributed package",
                    severity="HIGH" if dangerous else "MEDIUM",
                    category="integrity",
                    message="Python file exists in distributed package but not in source repository",
                    file_path=rel.as_posix(),
                    evidence={
                        "dangerous_behavior": dangerous,
                        "dangerous_tokens": dangerous_tokens,
                        "suspicious_calls": sorted(package_summary.suspicious_calls),
                        "top_level_calls": sorted(package_summary.top_level_calls),
                        "imports": sorted(package_summary.imports),
                    },
                    score=30 if dangerous else 20,
                    evidence_strength="integrity_confirmed",
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
                        evidence_strength="integrity_confirmed",
                    )
                )
            continue
        if _ast_dump(package_file) != _ast_dump(source_file):
            dangerous_tokens = _dangerous_tokens(package_file)
            source_tokens = _dangerous_tokens(source_file)
            new_dangerous_tokens = sorted(set(dangerous_tokens) - set(source_tokens))
            package_summary = _summarize_python_file(package_file)
            source_summary = _summarize_python_file(source_file)
            added_suspicious_calls = sorted(package_summary.suspicious_calls - source_summary.suspicious_calls)
            added_imports = sorted(package_summary.imports - source_summary.imports)
            added_top_level_calls = sorted(package_summary.top_level_calls - source_summary.top_level_calls)
            dangerous = bool(new_dangerous_tokens or added_suspicious_calls)
            findings.append(
                Finding(
                    rule_id="I002",
                    title="Modified Python file",
                    severity="HIGH" if dangerous else "MEDIUM",
                    category="integrity",
                    message="Python file differs from source repository at AST level",
                    file_path=relative_path(package_file, package_root),
                    evidence={
                        "dangerous_behavior": dangerous,
                        "changed_functions": _changed_functions(package_file, source_file),
                        "dangerous_tokens": dangerous_tokens,
                        "new_dangerous_tokens": new_dangerous_tokens,
                        "added_imports": added_imports,
                        "added_suspicious_calls": added_suspicious_calls,
                        "added_top_level_calls": added_top_level_calls,
                        "top_level_behavior": bool(package_summary.suspicious_top_level_calls - source_summary.suspicious_top_level_calls),
                    },
                    score=25 if dangerous else 15,
                    evidence_strength="integrity_confirmed",
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
                        evidence={
                            "dangerous_behavior": True,
                            "integrity_rule": "I002",
                            "added_suspicious_calls": added_suspicious_calls,
                            "new_dangerous_tokens": new_dangerous_tokens,
                        },
                        score=30,
                        evidence_strength="integrity_confirmed",
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
                    evidence_strength="integrity_confirmed",
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
                        evidence_strength="integrity_confirmed",
                    )
                )
    return findings


def extract_source_repository_hint(metadata: dict[str, object]) -> str | None:
    candidates: list[str] = []
    for key, value in metadata.items():
        lowered_key = key.lower()
        values = value.values() if isinstance(value, dict) else [value]
        for item in values:
            text = str(item).strip()
            lowered = text.lower()
            if not text:
                continue
            if any(marker in lowered_key for marker in ("repository", "source", "home-page", "homepage", "url")) or any(
                marker in lowered for marker in ("github.com", "gitlab.com")
            ):
                candidates.extend(re.findall(r"https://[^\s,'\")\]]+", text))
    for candidate in candidates:
        cleaned = candidate.rstrip(".")
        if "github.com" in cleaned or "gitlab.com" in cleaned:
            return cleaned
    return candidates[0] if candidates else None


def fetch_source_repository(
    source_url: str,
    output_dir: Path,
    version: str | None = None,
    timeout_seconds: int = 30,
) -> tuple[Path | None, list[str]]:
    warnings: list[str] = []
    if not _supported_source_url(source_url):
        return None, [f"Automatic source fetch only supports GitHub/GitLab HTTPS repository URLs: {source_url}"]
    output_dir.mkdir(parents=True, exist_ok=True)
    destination = output_dir / "source"
    clone_url = source_url if source_url.endswith(".git") else f"{source_url}.git"
    try:
        completed = subprocess.run(["git", "clone", "--depth", "1", clone_url, str(destination)], text=True, capture_output=True, timeout=timeout_seconds, check=False)
    except subprocess.TimeoutExpired:
        return None, [f"Automatic source fetch timed out after {timeout_seconds} seconds."]
    except OSError as exc:
        return None, [f"Automatic source fetch could not start git: {exc}"]
    if completed.returncode != 0:
        message = (completed.stderr or completed.stdout or "git clone failed").strip()
        return None, [f"Automatic source fetch failed: {message}"]
    if version:
        checked_out = _checkout_version_tag(destination, version, timeout_seconds)
        if not checked_out:
            warnings.append(f"No matching source tag found for version {version}; using repository default branch.")
    return destination, warnings


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
    summary = _summarize_python_file(path)
    return bool(_dangerous_tokens(path) or summary.suspicious_calls or summary.suspicious_strings)


def _dangerous_tokens(path: Path) -> list[str]:
    text = safe_read_text(path)
    return sorted(token for token in DANGEROUS_TOKENS if token in text)


def _changed_functions(package_file: Path, source_file: Path) -> list[str]:
    package_functions = _function_ast_dumps(package_file)
    source_functions = _function_ast_dumps(source_file)
    changed: list[str] = []
    for name, dump in package_functions.items():
        if source_functions.get(name) != dump:
            changed.append(name)
    return sorted(changed)


def _function_ast_dumps(path: Path) -> dict[str, str]:
    try:
        tree = ast.parse(safe_read_text(path), filename=str(path))
    except SyntaxError:
        return {}
    functions: dict[str, str] = {}
    class_stack: list[str] = []

    class Visitor(ast.NodeVisitor):
        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            class_stack.append(node.name)
            self.generic_visit(node)
            class_stack.pop()

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            name = ".".join([*class_stack, node.name]) if class_stack else node.name
            functions[name] = ast.dump(node, include_attributes=False)
            self.generic_visit(node)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            self.visit_FunctionDef(node)

    Visitor().visit(tree)
    return functions


def _summarize_python_file(path: Path) -> _FileSummary:
    try:
        tree = ast.parse(safe_read_text(path), filename=str(path))
    except SyntaxError:
        return _FileSummary(suspicious_strings=set(_dangerous_tokens(path)))
    _strip_docstrings(tree)
    summary = _FileSummary()
    resolver = CallResolver()
    function_stack: list[str] = []
    class_stack: list[str] = []

    class Visitor(ast.NodeVisitor):
        def visit_Import(self, node: ast.Import) -> None:
            resolver.record_import(node)
            for alias in node.names:
                summary.imports.add(alias.name)
            self.generic_visit(node)

        def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
            resolver.record_import_from(node)
            module = node.module or ""
            if module:
                summary.imports.add(module)
            self.generic_visit(node)

        def visit_Assign(self, node: ast.Assign) -> None:
            for target in node.targets:
                resolver.record_assignment(target, node.value)
            self.generic_visit(node)

        def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
            if node.value:
                resolver.record_assignment(node.target, node.value)
            self.generic_visit(node)

        def visit_ClassDef(self, node: ast.ClassDef) -> None:
            name = ".".join([*class_stack, node.name]) if class_stack else node.name
            summary.classes.add(name)
            class_stack.append(node.name)
            self.generic_visit(node)
            class_stack.pop()

        def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
            name = ".".join([*class_stack, node.name]) if class_stack else node.name
            summary.functions.add(name)
            function_stack.append(name)
            self.generic_visit(node)
            function_stack.pop()

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
            self.visit_FunctionDef(node)

        def visit_Call(self, node: ast.Call) -> None:
            call = resolver.resolve(node.func)
            if call:
                summary.calls.add(call)
                if not function_stack and not class_stack:
                    summary.top_level_calls.add(call)
                if call in SUSPICIOUS_CALLS:
                    summary.suspicious_calls.add(call)
                    if not function_stack and not class_stack:
                        summary.suspicious_top_level_calls.add(call)
            self.generic_visit(node)

        def visit_Constant(self, node: ast.Constant) -> None:
            if isinstance(node.value, str):
                for token in DANGEROUS_TOKENS:
                    if token in node.value:
                        summary.suspicious_strings.add(token)

    Visitor().visit(tree)
    return summary


def _supported_source_url(source_url: str) -> bool:
    return source_url.startswith("https://") and ("github.com/" in source_url or "gitlab.com/" in source_url)


def _checkout_version_tag(repo: Path, version: str, timeout_seconds: int) -> bool:
    for tag in (f"v{version}", version):
        try:
            subprocess.run(["git", "-C", str(repo), "fetch", "--depth", "1", "origin", f"refs/tags/{tag}:refs/tags/{tag}"], text=True, capture_output=True, timeout=timeout_seconds, check=False)
            completed = subprocess.run(["git", "-C", str(repo), "checkout", "--quiet", tag], text=True, capture_output=True, timeout=timeout_seconds, check=False)
        except (OSError, subprocess.TimeoutExpired):
            continue
        if completed.returncode == 0:
            return True
    return False
