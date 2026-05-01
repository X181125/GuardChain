from __future__ import annotations

import atexit
import os
import shutil
import tarfile
import tempfile
import zipfile
from pathlib import Path

from .models import PackageContext
from .utils import safe_read_text

METADATA_NAMES = {"pyproject.toml", "setup.cfg", "PKG-INFO", "METADATA"}
DEPENDENCY_NAMES = {"requirements.txt", "setup.cfg", "pyproject.toml", "PKG-INFO", "METADATA", "setup.py"}
IGNORED_DIRS = {".git", ".venv", "venv", "__pycache__", "node_modules", "dist", "build", ".eggs", ".tox", ".mypy_cache", ".pytest_cache"}
DEFAULT_MAX_FILES = 5000
DEFAULT_MAX_SIZE_MB = 100


def load_package(path: str | Path, max_files: int = DEFAULT_MAX_FILES, max_size_mb: int = DEFAULT_MAX_SIZE_MB) -> PackageContext:
    """Load a package path or archive for static analysis without executing it."""
    input_path = Path(path).expanduser().resolve()
    if not input_path.exists():
        raise FileNotFoundError(f"Target path does not exist: {input_path}")

    max_size_bytes = max_size_mb * 1024 * 1024
    root, archive_type = _prepare_root(input_path, max_files=max_files, max_size_bytes=max_size_bytes)
    all_files = _discover_files(root)
    if len(all_files) > max_files:
        raise ValueError(f"Package has too many files ({len(all_files)} > {max_files})")
    total_size = sum(p.stat().st_size for p in all_files)
    if total_size > max_size_bytes:
        raise ValueError(f"Package is too large ({total_size} bytes > {max_size_bytes} bytes)")

    python_files = sorted(p for p in all_files if p.suffix == ".py")
    metadata_files = sorted(p for p in all_files if p.name in METADATA_NAMES)
    dependency_files = sorted(p for p in all_files if p.name in DEPENDENCY_NAMES)
    setup_py = next((p for p in dependency_files if p.name == "setup.py"), None)
    pyproject_toml = next((p for p in metadata_files if p.name == "pyproject.toml"), None)

    package_name = _detect_package_name(root, pyproject_toml, metadata_files)
    return PackageContext(
        root_path=root,
        package_name=package_name,
        python_files=python_files,
        metadata_files=metadata_files,
        dependency_files=dependency_files,
        setup_py=setup_py,
        pyproject_toml=pyproject_toml,
        total_files=len(all_files),
        total_size_bytes=total_size,
        target=str(input_path),
        archive_type=archive_type,
    )


def _prepare_root(path: Path, max_files: int, max_size_bytes: int) -> tuple[Path, str | None]:
    if path.is_dir():
        return path, None
    if path.name.endswith(".tar.gz") or path.suffix in {".tgz", ".tar"}:
        return _extract_tar(path, max_files=max_files, max_size_bytes=max_size_bytes), "tar"
    if path.suffix == ".whl" or path.suffix == ".zip":
        return _extract_zip(path, max_files=max_files, max_size_bytes=max_size_bytes), "wheel" if path.suffix == ".whl" else "zip"
    raise ValueError("Unsupported target. Expected a directory, .tar.gz, .tgz, .tar, .whl, or .zip file.")


def _make_temp_root(prefix: str) -> Path:
    temp_root = Path(tempfile.mkdtemp(prefix=prefix))
    atexit.register(shutil.rmtree, temp_root, ignore_errors=True)
    return temp_root


def _extract_tar(path: Path, max_files: int, max_size_bytes: int) -> Path:
    temp_root = _make_temp_root("guardchain_tar_")
    total_size = 0
    with tarfile.open(path, "r:*") as archive:
        members = archive.getmembers()
        if len(members) > max_files:
            raise ValueError(f"Archive has too many entries ({len(members)} > {max_files})")
        for member in members:
            _validate_archive_member(member.name)
            if member.issym() or member.islnk():
                raise ValueError(f"Archive contains unsupported link entry: {member.name}")
            if not member.isfile():
                continue
            total_size += max(0, member.size)
            if total_size > max_size_bytes:
                raise ValueError("Archive exceeds maximum extracted size")
            destination = _safe_destination(temp_root, member.name)
            destination.parent.mkdir(parents=True, exist_ok=True)
            source = archive.extractfile(member)
            if source is None:
                continue
            with source, destination.open("wb") as out:
                shutil.copyfileobj(source, out)
            os.chmod(destination, 0o600)
    return _single_child_or_root(temp_root)


def _extract_zip(path: Path, max_files: int, max_size_bytes: int) -> Path:
    temp_root = _make_temp_root("guardchain_zip_")
    with zipfile.ZipFile(path) as archive:
        infos = archive.infolist()
        if len(infos) > max_files:
            raise ValueError(f"Archive has too many entries ({len(infos)} > {max_files})")
        total_size = 0
        for info in infos:
            _validate_archive_member(info.filename)
            if info.is_dir():
                continue
            if _is_zip_symlink(info):
                raise ValueError(f"Archive contains unsupported symlink entry: {info.filename}")
            total_size += max(0, info.file_size)
            if total_size > max_size_bytes:
                raise ValueError("Archive exceeds maximum extracted size")
            destination = _safe_destination(temp_root, info.filename)
            destination.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info) as source, destination.open("wb") as out:
                shutil.copyfileobj(source, out)
            os.chmod(destination, 0o600)
    return _single_child_or_root(temp_root)


def _validate_archive_member(name: str) -> None:
    normalized = name.replace("\\", "/")
    if normalized.startswith("/") or re_drive_absolute(normalized):
        raise ValueError(f"Archive contains absolute path: {name}")
    parts = [part for part in normalized.split("/") if part]
    if any(part == ".." for part in parts):
        raise ValueError(f"Archive contains unsafe path traversal entry: {name}")


def re_drive_absolute(path: str) -> bool:
    return len(path) >= 3 and path[1] == ":" and path[2] == "/"


def _is_zip_symlink(info: zipfile.ZipInfo) -> bool:
    return ((info.external_attr >> 16) & 0o170000) == 0o120000


def _safe_destination(root: Path, name: str) -> Path:
    destination = (root / name).resolve()
    root_resolved = root.resolve()
    if root_resolved != destination and root_resolved not in destination.parents:
        raise ValueError(f"Archive entry escapes extraction root: {name}")
    return destination


def _discover_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for current_root, dirs, filenames in os.walk(root):
        dirs[:] = [directory for directory in dirs if directory not in IGNORED_DIRS]
        base = Path(current_root)
        for filename in filenames:
            files.append(base / filename)
    return files


def _single_child_or_root(root: Path) -> Path:
    children = [p for p in root.iterdir() if p.is_dir()]
    files = [p for p in root.iterdir() if p.is_file()]
    if len(children) == 1 and not files:
        return children[0]
    return root


def _detect_package_name(root: Path, pyproject: Path | None, metadata_files: list[Path]) -> str | None:
    if pyproject:
        try:
            import tomllib

            data = tomllib.loads(safe_read_text(pyproject))
            project_name = data.get("project", {}).get("name")
            if isinstance(project_name, str) and project_name.strip():
                return project_name.strip()
        except Exception:
            pass

    for metadata in metadata_files:
        if metadata.name in {"PKG-INFO", "METADATA"}:
            for line in safe_read_text(metadata).splitlines():
                if line.lower().startswith("name:"):
                    name = line.split(":", 1)[1].strip()
                    if name:
                        return name
    return root.name
