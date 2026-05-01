from __future__ import annotations

import ast
import configparser
import re
from email.parser import Parser

from .models import Finding, PackageContext
from .utils import find_similar_popular, relative_path, safe_read_text

REPOSITORY_KEYS = {"homepage", "home-page", "home_page", "repository", "source", "source_url", "project_urls", "url:repository"}
SUSPICIOUS_SETUP_TOKENS = ["os.system", "subprocess", "requests.get", "urllib.request", "exec", "eval", "base64", "socket"]
SUSPICIOUS_ENTRYPOINT_WORDS = {"install", "update", "payload", "agent", "loader", "postinstall", "bootstrap"}
SUSPICIOUS_URL_DOMAINS = {"pastebin.com", "raw.githubusercontent.com", "gist.githubusercontent.com", "bit.ly", "tinyurl.com"}


def analyze_metadata(context: PackageContext) -> list[Finding]:
    metadata = extract_metadata(context)
    findings: list[Finding] = []

    if not _has_repository_url(metadata):
        findings.append(
            Finding(
                rule_id="M001",
                title="Missing repository URL",
                severity="LOW",
                category="metadata",
                message="Package has no repository or homepage URL",
                file_path=_metadata_location(context),
                score=5,
            )
        )

    description = (metadata.get("description") or metadata.get("summary") or "").strip()
    if len(description) < 20:
        findings.append(
            Finding(
                rule_id="M002",
                title="Very short description",
                severity="LOW",
                category="metadata",
                message="Package description is too short",
                file_path=_metadata_location(context),
                evidence=description or "<missing>",
                score=5,
            )
        )

    package_name = context.package_name or metadata.get("name")
    if package_name:
        similar = find_similar_popular(package_name)
        if similar:
            findings.append(
                Finding(
                    rule_id="M003",
                    title="Suspicious package name similarity",
                    severity="MEDIUM",
                    category="metadata",
                    message=f"Package name is similar to popular package '{similar}'",
                    file_path=_metadata_location(context),
                    evidence=package_name,
                    score=20,
                )
            )

    entry_points = metadata.get("console_scripts", [])
    if isinstance(entry_points, list):
        suspicious = [entry for entry in entry_points if any(word in str(entry).lower() for word in SUSPICIOUS_ENTRYPOINT_WORDS)]
        if suspicious:
            findings.append(
                Finding(
                    rule_id="M005",
                    title="Suspicious console script entrypoint",
                    severity="MEDIUM",
                    category="metadata",
                    message="Console script entrypoint name or target looks suspicious",
                    file_path=_metadata_location(context),
                    evidence={"entry_points": suspicious},
                    score=15,
                )
            )

    version = str(metadata.get("version", "")).strip()
    if version and not re.match(r"^\d+(\.\d+){0,3}([a-zA-Z0-9_.+-]+)?$", version):
        findings.append(
            Finding(
                rule_id="M006",
                title="Unusual version pattern",
                severity="LOW",
                category="metadata",
                message="Package version has an unusual format",
                file_path=_metadata_location(context),
                evidence={"version": version},
                score=5,
            )
        )

    if not metadata.get("author") and not metadata.get("author_email"):
        findings.append(
            Finding(
                rule_id="M007",
                title="Missing author contact",
                severity="LOW",
                category="metadata",
                message="Package metadata is missing author or contact information",
                file_path=_metadata_location(context),
                score=5,
            )
        )

    suspicious_urls = _suspicious_project_urls(metadata)
    if suspicious_urls:
        findings.append(
            Finding(
                rule_id="M008",
                title="Suspicious project URL domain",
                severity="MEDIUM",
                category="metadata",
                message="Project URL points to a domain commonly abused for payload hosting or redirects",
                file_path=_metadata_location(context),
                evidence={"urls": suspicious_urls},
                score=15,
            )
        )

    mismatches = _metadata_mismatches(context)
    if mismatches:
        findings.append(
            Finding(
                rule_id="M009",
                title="Metadata mismatch across files",
                severity="MEDIUM",
                category="metadata",
                message="Package metadata fields differ across metadata files",
                file_path=_metadata_location(context),
                evidence=mismatches,
                score=15,
            )
        )

    if context.setup_py:
        text = safe_read_text(context.setup_py)
        matched = [token for token in SUSPICIOUS_SETUP_TOKENS if token in text]
        if matched:
            findings.append(
                Finding(
                    rule_id="M004",
                    title="Suspicious setup.py content",
                    severity="HIGH",
                    category="metadata",
                    message="setup.py contains suspicious executable logic",
                    file_path=relative_path(context.setup_py, context.root_path),
                    evidence=", ".join(matched),
                    score=30,
                )
            )
    return findings


def extract_metadata(context: PackageContext) -> dict[str, object]:
    data: dict[str, object] = {}
    if context.pyproject_toml:
        data.update(_read_pyproject(context.pyproject_toml))
    for metadata_file in context.metadata_files:
        if metadata_file.name == "setup.cfg":
            data.update(_read_setup_cfg(metadata_file))
        elif metadata_file.name in {"PKG-INFO", "METADATA"}:
            data.update(_read_email_metadata(metadata_file))
    if context.setup_py:
        for key, value in _read_setup_py_metadata(context.setup_py).items():
            data.setdefault(key, value)
    if context.package_name:
        data.setdefault("name", context.package_name)
    return data


def _read_pyproject(path) -> dict[str, str]:
    try:
        import tomllib

        raw = tomllib.loads(safe_read_text(path))
    except Exception:
        return {}
    project = raw.get("project", {})
    data: dict[str, object] = {key: str(value) for key, value in project.items() if isinstance(value, (str, int, float))}
    if isinstance(project.get("dependencies"), list):
        data["requires_dist"] = list(project["dependencies"])
    authors = project.get("authors")
    if isinstance(authors, list) and authors:
        first = authors[0]
        if isinstance(first, dict):
            if first.get("name"):
                data["author"] = str(first["name"])
            if first.get("email"):
                data["author_email"] = str(first["email"])
    urls = project.get("urls")
    if isinstance(urls, dict):
        data["project_urls"] = dict(urls)
        for key, value in urls.items():
            data[f"url:{key.lower()}"] = str(value)
    return data


def _read_setup_cfg(path) -> dict[str, str]:
    parser = configparser.ConfigParser()
    parser.read_string(safe_read_text(path))
    data: dict[str, object] = {}
    if parser.has_section("metadata"):
        for key, value in parser.items("metadata"):
            data[key] = value
    if parser.has_section("options"):
        if parser.has_option("options", "python_requires"):
            data["requires_python"] = parser.get("options", "python_requires")
        if parser.has_option("options", "install_requires"):
            data["requires_dist"] = [line.strip() for line in parser.get("options", "install_requires").splitlines() if line.strip()]
    if parser.has_section("options.entry_points") and parser.has_option("options.entry_points", "console_scripts"):
        data["console_scripts"] = [line.strip() for line in parser.get("options.entry_points", "console_scripts").splitlines() if line.strip()]
    return data


def _read_email_metadata(path) -> dict[str, str]:
    parsed = Parser().parsestr(safe_read_text(path))
    data: dict[str, object] = {key.lower().replace("-", "_"): value for key, value in parsed.items()}
    data["requires_dist"] = parsed.get_all("Requires-Dist", [])
    return data


def _read_setup_py_metadata(path) -> dict[str, object]:
    try:
        tree = ast.parse(safe_read_text(path), filename=str(path))
    except SyntaxError:
        return {}
    data: dict[str, object] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and (getattr(node.func, "id", None) == "setup" or getattr(node.func, "attr", None) == "setup"):
            for keyword in node.keywords:
                if keyword.arg in {"name", "version", "description", "author", "author_email", "license", "python_requires"}:
                    if isinstance(keyword.value, ast.Constant) and isinstance(keyword.value.value, str):
                        key = "requires_python" if keyword.arg == "python_requires" else keyword.arg
                        data[key] = keyword.value.value
                if keyword.arg == "entry_points" and isinstance(keyword.value, ast.Dict):
                    data["entry_points"] = ast.unparse(keyword.value)
    return data


def _has_repository_url(metadata: dict[str, object]) -> bool:
    for key, value in metadata.items():
        lowered_key = key.lower()
        lowered_value = str(value).lower()
        if any(repo_key in lowered_key for repo_key in REPOSITORY_KEYS) and re.search(r"https?://", lowered_value):
            return True
        if re.search(r"https?://", lowered_value) and any(word in lowered_value for word in ("github", "gitlab", "source", "repo")):
            return True
    return False


def _suspicious_project_urls(metadata: dict[str, object]) -> list[str]:
    urls: list[str] = []
    for value in metadata.values():
        values = value.values() if isinstance(value, dict) else [value]
        for item in values:
            text = str(item).lower()
            if any(domain in text for domain in SUSPICIOUS_URL_DOMAINS):
                urls.append(str(item))
    return urls


def _metadata_location(context: PackageContext) -> str | None:
    if context.pyproject_toml:
        return relative_path(context.pyproject_toml, context.root_path)
    if context.metadata_files:
        return relative_path(context.metadata_files[0], context.root_path)
    return None


def _metadata_mismatches(context: PackageContext) -> dict[str, list[str]]:
    values_by_field: dict[str, set[str]] = {"name": set(), "version": set()}
    readers = []
    if context.pyproject_toml:
        readers.append(_read_pyproject(context.pyproject_toml))
    for metadata_file in context.metadata_files:
        if metadata_file.name == "setup.cfg":
            readers.append(_read_setup_cfg(metadata_file))
        elif metadata_file.name in {"PKG-INFO", "METADATA"}:
            readers.append(_read_email_metadata(metadata_file))
    if context.setup_py:
        readers.append(_read_setup_py_metadata(context.setup_py))
    for data in readers:
        for field in values_by_field:
            value = data.get(field)
            if value:
                values_by_field[field].add(str(value).strip())
    return {field: sorted(values) for field, values in values_by_field.items() if len(values) > 1}
