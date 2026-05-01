from pathlib import Path
from tempfile import TemporaryDirectory
import tarfile
import unittest
import zipfile

from guardchain.loader import load_package


class LoaderTests(unittest.TestCase):
    def test_folder_loading(self) -> None:
        context = load_package(Path(__file__).resolve().parents[1] / "samples" / "benign_pkg")
        self.assertEqual(len(context.python_files), 1)

    def test_zip_loading(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "pkg"
            source.mkdir()
            (source / "a.py").write_text("x = 1", encoding="utf-8")
            archive = root / "pkg.zip"
            with zipfile.ZipFile(archive, "w") as zf:
                zf.write(source / "a.py", "pkg/a.py")
            context = load_package(archive)
        self.assertEqual(len(context.python_files), 1)

    def test_wheel_loading(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "pkg-0.1.0-py3-none-any.whl"
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr("pkg/__init__.py", "x = 1")
                zf.writestr("pkg-0.1.0.dist-info/METADATA", "Name: pkg\nVersion: 0.1.0\n")
            context = load_package(archive)
        self.assertEqual(len(context.python_files), 1)

    def test_tar_loading(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "pkg"
            source.mkdir()
            (source / "a.py").write_text("x = 1", encoding="utf-8")
            archive = root / "pkg.tar.gz"
            with tarfile.open(archive, "w:gz") as tf:
                tf.add(source / "a.py", "pkg/a.py")
            context = load_package(archive)
        self.assertEqual(len(context.python_files), 1)

    def test_zip_path_traversal_is_blocked(self) -> None:
        with TemporaryDirectory() as tmp:
            archive = Path(tmp) / "bad.zip"
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr("../evil.py", "x = 1")
            with self.assertRaises(ValueError):
                load_package(archive)

    def test_zip_absolute_path_is_blocked(self) -> None:
        with TemporaryDirectory() as tmp:
            archive = Path(tmp) / "bad.zip"
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr("/absolute.py", "x = 1")
            with self.assertRaises(ValueError):
                load_package(archive)

    def test_max_files_limit(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a.py").write_text("x = 1", encoding="utf-8")
            (root / "b.py").write_text("y = 2", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_package(root, max_files=1)

    def test_max_size_limit(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "big.py").write_text("x = 'large'\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_package(root, max_size_mb=0)

    def test_invalid_archive_raises_clear_error(self) -> None:
        with TemporaryDirectory() as tmp:
            archive = Path(tmp) / "bad.zip"
            archive.write_text("not a zip", encoding="utf-8")
            with self.assertRaises(Exception):
                load_package(archive)


if __name__ == "__main__":
    unittest.main()
