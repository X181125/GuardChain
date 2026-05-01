from __future__ import annotations

import ast
import re
from functools import lru_cache
from importlib.resources import files
from pathlib import Path


def relative_path(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.as_posix()


def safe_read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def normalize_package_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.strip().lower())


@lru_cache(maxsize=1)
def load_popular_packages() -> tuple[str, ...]:
    text = files("guardchain.data").joinpath("popular_packages.txt").read_text(encoding="utf-8")
    return tuple(normalize_package_name(line) for line in text.splitlines() if line.strip() and not line.startswith("#"))


def strip_requirement_name(requirement: str) -> str:
    line = requirement.split("#", 1)[0].strip()
    if not line or line.startswith(("-r ", "--")):
        return ""
    if line.startswith("-e "):
        line = line[3:].strip()
    if line.startswith(("./", "../", "/", "file:")):
        return Path(line.replace("file:", "")).name
    if " @ " in line:
        return line.split(" @ ", 1)[0].strip()
    if line.startswith(("git+", "http://", "https://")):
        tail = line.rstrip("/").split("/")[-1]
        return re.sub(r"(\.git|\.zip|\.tar\.gz|\.whl)$", "", tail)
    match = re.match(r"\s*([A-Za-z0-9_.-]+)", line)
    return match.group(1) if match else ""


def is_pinned_requirement(requirement: str) -> bool:
    return "==" in requirement or "===" in requirement


def preview_node(node: ast.AST, max_len: int = 80) -> str:
    try:
        text = ast.unparse(node)
    except Exception:
        text = node.__class__.__name__
    text = " ".join(text.split())
    return text if len(text) <= max_len else text[: max_len - 3] + "..."


def parse_ast(path: Path) -> ast.AST:
    return ast.parse(safe_read_text(path), filename=str(path))


def find_similar_popular(name: str, threshold: float = 0.82) -> str | None:
    import difflib

    normalized = normalize_package_name(name)
    for popular in load_popular_packages():
        if normalized == popular:
            continue
        ratio = difflib.SequenceMatcher(None, normalized, popular).ratio()
        length_gap = abs(len(normalized) - len(popular))
        if ratio >= threshold and length_gap <= 3:
            return popular
    return None
