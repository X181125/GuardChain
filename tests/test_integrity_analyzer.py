from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from guardchain.integrity_analyzer import analyze_integrity


class IntegrityAnalyzerTests(unittest.TestCase):
    def test_new_file_detection(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            dist = root / "dist"
            source.mkdir()
            dist.mkdir()
            (dist / "payload.py").write_text("x = 1", encoding="utf-8")
            rules = {finding.rule_id for finding in analyze_integrity(dist, source)}
        self.assertIn("I001", rules)

    def test_comment_only_change_ignored(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            dist = root / "dist"
            source.mkdir()
            dist.mkdir()
            (source / "a.py").write_text("x = 1\n", encoding="utf-8")
            (dist / "a.py").write_text("# comment\nx = 1\n", encoding="utf-8")
            rules = {finding.rule_id for finding in analyze_integrity(dist, source)}
        self.assertNotIn("I002", rules)


if __name__ == "__main__":
    unittest.main()
