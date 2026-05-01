from pathlib import Path
from tempfile import TemporaryDirectory
import json
import unittest

from guardchain.report import format_terminal, write_json_report, write_markdown_report, write_sarif_report
from guardchain.scanner import scan


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class ReportTests(unittest.TestCase):
    def test_json_and_markdown_reports(self) -> None:
        result = scan(PROJECT_ROOT / "samples" / "malicious_like_pkg")
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            json_path = root / "result.json"
            md_path = root / "report.md"
            sarif_path = root / "result.sarif"
            write_json_report(result, json_path)
            write_markdown_report(result, md_path)
            write_sarif_report(result, sarif_path)
            data = json.loads(json_path.read_text(encoding="utf-8"))
            sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
            self.assertEqual(data["label"], "MALICIOUS")
            self.assertIn("tool_version", data)
            self.assertEqual(sarif["version"], "2.1.0")
            self.assertEqual(sarif["runs"][0]["tool"]["driver"]["name"], "GuardChain")
            self.assertIn("# GuardChain Scan Report", md_path.read_text(encoding="utf-8"))

    def test_terminal_includes_label_and_score(self) -> None:
        result = scan(PROJECT_ROOT / "samples" / "benign_pkg")
        text = format_terminal(result)
        self.assertIn("Label:", text)
        self.assertIn("Risk score:", text)

    def test_findings_sorted_by_severity(self) -> None:
        result = scan(PROJECT_ROOT / "samples" / "malicious_like_pkg")
        severities = [finding.severity for finding in result.findings[:3]]
        self.assertTrue(all(severity in {"CRITICAL", "HIGH"} for severity in severities))


if __name__ == "__main__":
    unittest.main()
