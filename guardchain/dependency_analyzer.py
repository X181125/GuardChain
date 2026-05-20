from __future__ import annotations

import configparser
import re
import ast
import sys
from email.parser import Parser
from importlib.resources import files

import yaml
from packaging.requirements import InvalidRequirement, Requirement

from .models import Dependency, Finding, PackageContext
from .utils import find_similar_popular, is_pinned_requirement, normalize_package_name, relative_path, safe_read_text, strip_requirement_name

URL_MARKERS = ("git+http", "http://", "https://")
VCS_MARKERS = ("git+", "hg+", "svn+", "bzr+")
LOCAL_MARKERS = ("./", "../", "/", "file:")
FALLBACK_STDLIB_MODULES = {
    "os",
    "sys",
    "pathlib",
    "json",
    "base64",
    "subprocess",
    "socket",
    "platform",
    "getpass",
    "urllib",
    "http",
    "marshal",
    "zlib",
    "codecs",
    "binascii",
    "typing",
    "setuptools",
}


def analyze_dependencies(context: PackageContext) -> tuple[list[Finding], list[str]]:
    entries = _dependency_entries(context)
    dependencies = sorted({entry.name for entry in entries if entry.name})
    findings: list[Finding] = []

    seen_rules: set[tuple[str, str, str]] = set()
    for entry in entries:
        name = entry.name
        if not name:
            continue
        normalized = name.lower().replace("_", "-")
        if normalized in _known_malicious_packages():
            _append_once(
                findings,
                seen_rules,
                Finding(
                    rule_id="D001",
                    title="Known malicious dependency",
                    severity="CRITICAL",
                    category="dependency",
                    message="Package depends on a known malicious/suspicious dependency",
                    file_path=entry.file_path,
                    line=entry.line,
                    evidence=entry.raw,
                    score=60,
                    evidence_strength="dependency_confirmed",
                ),
            )
        similar = find_similar_popular(normalized)
        if similar:
            _append_once(
                findings,
                seen_rules,
                Finding(
                    rule_id="D002",
                    title="Typosquatting dependency",
                    severity="HIGH",
                    category="dependency",
                    message=f"Dependency name is similar to popular package '{similar}'",
                    file_path=entry.file_path,
                    line=entry.line,
                    evidence=entry.raw,
                    score=30,
                    evidence_strength="dependency_confirmed",
                ),
            )
        if any(marker in entry.raw.lower() for marker in URL_MARKERS):
            _append_once(
                findings,
                seen_rules,
                Finding(
                    rule_id="D003",
                    title="Suspicious direct URL dependency",
                    severity="MEDIUM",
                    category="dependency",
                    message="Direct URL dependency detected",
                    file_path=entry.file_path,
                    line=entry.line,
                    evidence=entry.raw,
                    score=20,
                    evidence_strength="dependency_confirmed",
                ),
            )
        if entry.raw.strip().startswith(LOCAL_MARKERS):
            _append_once(
                findings,
                seen_rules,
                Finding(
                    rule_id="D006",
                    title="Local path dependency",
                    severity="MEDIUM",
                    category="dependency",
                    message="Dependency uses a local filesystem path",
                    file_path=entry.file_path,
                    line=entry.line,
                    evidence=entry.raw,
                    score=15,
                    evidence_strength="dependency_confirmed",
                ),
            )
        if any(marker in entry.raw.lower() for marker in VCS_MARKERS):
            _append_once(
                findings,
                seen_rules,
                Finding(
                    rule_id="D005",
                    title="VCS dependency",
                    severity="MEDIUM",
                    category="dependency",
                    message="Dependency uses a version-control URL",
                    file_path=entry.file_path,
                    line=entry.line,
                    evidence=entry.raw,
                    score=15,
                    evidence_strength="dependency_confirmed",
                ),
            )
        if any(token in normalized for token in _suspicious_name_tokens()):
            _append_once(
                findings,
                seen_rules,
                Finding(
                    rule_id="D009",
                    title="Suspicious dependency name pattern",
                    severity="MEDIUM",
                    category="dependency",
                    message="Dependency name contains words commonly used in suspicious demo payloads",
                    file_path=entry.file_path,
                    line=entry.line,
                    evidence=entry.raw,
                    score=15,
                    evidence_strength="dependency_confirmed",
                ),
            )
        if not is_pinned_requirement(entry.raw) and not any(marker in entry.raw.lower() for marker in URL_MARKERS):
            _append_once(
                findings,
                seen_rules,
                Finding(
                    rule_id="D004",
                    title="Unpinned dependency",
                    severity="LOW",
                    category="dependency",
                    message="Unpinned dependency version",
                    file_path=entry.file_path,
                    line=entry.line,
                    evidence=entry.raw,
                    score=5,
                    evidence_strength="dependency_confirmed",
                ),
            )
    imported = _infer_imports(context)
    declared = {normalize_package_name(dep) for dep in dependencies}
    declared_imports = _declared_import_names(declared)
    for package in sorted(imported - declared_imports):
        findings.append(
            Finding(
                rule_id="D007",
                title="Imported but not declared dependency",
                severity="LOW",
                category="dependency",
                message="Package appears to import a third-party module that is not declared as a dependency",
                evidence={"import": package},
                score=5,
                evidence_strength="dependency_confirmed",
            )
        )
    for package in sorted(declared):
        if package in _known_malicious_packages():
            continue
        if _allowed_import_names(package) & imported:
            continue
        findings.append(
            Finding(
                rule_id="D008",
                title="Declared but not imported dependency",
                severity="LOW",
                category="dependency",
                message="Dependency is declared but not imported by scanned Python files",
                evidence={"dependency": package},
                score=3,
                evidence_strength="dependency_confirmed",
            )
        )
    return findings, dependencies


def extract_dependencies(context: PackageContext) -> list[str]:
    return sorted({entry.name for entry in _dependency_entries(context) if entry.name})


def extract_dependency_details(context: PackageContext) -> list[Dependency]:
    return sorted((_entry_to_dependency(entry) for entry in _dependency_entries(context) if entry.name), key=lambda dep: (dep.name, dep.raw, dep.source or ""))


class _DependencyEntry:
    def __init__(self, name: str, raw: str, file_path: str, line: int | None = None) -> None:
        self.name = name
        self.raw = raw
        self.file_path = file_path
        self.line = line


def _dependency_entries(context: PackageContext) -> list[_DependencyEntry]:
    entries: list[_DependencyEntry] = []
    for path in context.dependency_files:
        rel = relative_path(path, context.root_path)
        text = safe_read_text(path)
        if path.name == "requirements.txt":
            for index, line in enumerate(text.splitlines(), start=1):
                name = strip_requirement_name(line)
                if name:
                    entries.append(_DependencyEntry(name, line.strip(), rel, index))
        elif path.name == "pyproject.toml":
            entries.extend(_from_pyproject(text, rel))
        elif path.name == "setup.cfg":
            entries.extend(_from_setup_cfg(text, rel))
        elif path.name == "setup.py":
            entries.extend(_from_setup_py_text(text, rel))
        elif path.name in {"PKG-INFO", "METADATA"}:
            entries.extend(_from_email_metadata(text, rel))
    return entries


def _entry_to_dependency(entry: _DependencyEntry) -> Dependency:
    raw = entry.raw.strip()
    parsed = _parse_requirement(raw)
    if parsed:
        name = parsed.name
        version_spec = str(parsed.specifier) or None
        extras = sorted(parsed.extras)
        marker = str(parsed.marker) if parsed.marker else None
        direct_url = parsed.url is not None
    else:
        name = entry.name
        version_spec = None
        extras = []
        marker = None
        direct_url = any(marker in raw.lower() for marker in URL_MARKERS)
    lowered = raw.lower()
    return Dependency(
        name=name,
        raw=raw,
        version_spec=version_spec,
        source=entry.file_path,
        is_direct_url=direct_url or lowered.startswith(("http://", "https://")),
        is_vcs=any(marker in lowered for marker in VCS_MARKERS),
        is_local_path=raw.startswith(LOCAL_MARKERS),
        is_pinned=is_pinned_requirement(raw),
        extras=extras,
        marker=marker,
    )


def _parse_requirement(raw: str) -> Requirement | None:
    line = raw.strip()
    if line.startswith("-e "):
        line = line[3:].strip()
    if line.startswith(("git+", "http://", "https://")):
        return None
    try:
        return Requirement(line)
    except InvalidRequirement:
        return None


def _from_pyproject(text: str, rel: str) -> list[_DependencyEntry]:
    try:
        import tomllib

        raw = tomllib.loads(text)
    except Exception:
        return []
    entries: list[_DependencyEntry] = []
    dependencies = raw.get("project", {}).get("dependencies", [])
    if isinstance(dependencies, list):
        for item in dependencies:
            if isinstance(item, str):
                entries.append(_DependencyEntry(strip_requirement_name(item), item, rel))
    optional = raw.get("project", {}).get("optional-dependencies", {})
    if isinstance(optional, dict):
        for values in optional.values():
            if isinstance(values, list):
                for item in values:
                    if isinstance(item, str):
                        entries.append(_DependencyEntry(strip_requirement_name(item), item, rel))
    return entries


def _from_setup_cfg(text: str, rel: str) -> list[_DependencyEntry]:
    parser = configparser.ConfigParser()
    try:
        parser.read_string(text)
    except configparser.Error:
        return []
    entries: list[_DependencyEntry] = []
    if parser.has_section("options") and parser.has_option("options", "install_requires"):
        raw = parser.get("options", "install_requires")
        for line in raw.splitlines():
            name = strip_requirement_name(line)
            if name:
                entries.append(_DependencyEntry(name, line.strip(), rel))
    return entries


def _from_setup_py_text(text: str, rel: str) -> list[_DependencyEntry]:
    entries: list[_DependencyEntry] = []
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return entries
    for node in ast.walk(tree):
        if isinstance(node, ast.keyword) and node.arg == "install_requires":
            entries.extend(_literal_dependency_entries(node.value, rel))
    return entries


def _literal_dependency_entries(node: ast.AST, rel: str) -> list[_DependencyEntry]:
    entries: list[_DependencyEntry] = []
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        for item in node.elts:
            if isinstance(item, ast.Constant) and isinstance(item.value, str):
                entries.append(_DependencyEntry(strip_requirement_name(item.value), item.value, rel, getattr(item, "lineno", None)))
    return entries


def _from_email_metadata(text: str, rel: str) -> list[_DependencyEntry]:
    parsed = Parser().parsestr(text)
    entries: list[_DependencyEntry] = []
    for item in parsed.get_all("Requires-Dist", []):
        entries.append(_DependencyEntry(strip_requirement_name(item), item, rel))
    return entries


def _infer_imports(context: PackageContext) -> set[str]:
    imports: set[str] = set()
    local_names = {path.parent.name for path in context.python_files if path.name == "__init__.py"}
    for path in context.python_files:
        try:
            tree = ast.parse(safe_read_text(path), filename=str(path))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.add(alias.name.split(".")[0].replace("_", "-").lower())
            elif isinstance(node, ast.ImportFrom) and node.module:
                imports.add(node.module.split(".")[0].replace("_", "-").lower())
    stdlib_or_local = _stdlib_modules() | {"setuptools"}
    local_normalized = {normalize_package_name(local) for local in local_names}
    return {name for name in imports if name and name not in stdlib_or_local and name not in local_normalized}


def _append_once(findings: list[Finding], seen: set[tuple[str, str, str]], finding: Finding) -> None:
    key = (finding.rule_id, finding.file_path or "", finding.evidence or "")
    if key not in seen:
        seen.add(key)
        findings.append(finding)


def _known_malicious_packages() -> set[str]:
    # This is a demo blacklist for educational testing, not a complete malware intelligence feed.
    data = yaml.safe_load(files("guardchain.data").joinpath("malicious_packages.yaml").read_text(encoding="utf-8")) or {}
    return {item.lower().replace("_", "-") for item in data.get("packages", [])}


def _suspicious_name_tokens() -> set[str]:
    data = yaml.safe_load(files("guardchain.data").joinpath("suspicious_names.yaml").read_text(encoding="utf-8")) or {}
    return {str(item).lower() for item in data.get("tokens", [])}


def _stdlib_modules() -> set[str]:
    names = getattr(sys, "stdlib_module_names", None)
    if names:
        return {normalize_package_name(name.split(".")[0]) for name in names} | FALLBACK_STDLIB_MODULES
    return set(FALLBACK_STDLIB_MODULES)


def _declared_import_names(declared: set[str]) -> set[str]:
    imports: set[str] = set()
    for package in declared:
        imports.update(_allowed_import_names(package))
    return imports


def _allowed_import_names(package: str) -> set[str]:
    normalized = normalize_package_name(package)
    mapping = _import_name_map()
    return {normalized, *mapping.get(normalized, set())}


def _import_name_map() -> dict[str, set[str]]:
    data = yaml.safe_load(files("guardchain.data").joinpath("import_name_map.yaml").read_text(encoding="utf-8")) or {}
    mapping: dict[str, set[str]] = {}
    for distribution, imports in data.items():
        values = imports if isinstance(imports, list) else []
        mapping[normalize_package_name(str(distribution))] = {normalize_package_name(str(name)) for name in values}
    return mapping
