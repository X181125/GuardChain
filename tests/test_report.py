from pathlib import Path
from tempfile import TemporaryDirectory
import json
import unittest
from unittest.mock import patch

from guardchain.models import DependencyEdge, DependencyScanResult, Finding, ResolvedDependency
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

    def test_reports_include_dependency_risk_paths(self) -> None:
        resolved = [ResolvedDependency("hidden-payload-dep", "0.1.0", ["__root__"], True)]
        edges = [DependencyEdge("__root__", "hidden-payload-dep", "hidden-payload-dep==0.1.0")]
        finding = Finding(
            "T004",
            "Obfuscation source flows into dynamic execution",
            "CRITICAL",
            "taint",
            "Obfuscation source flows into dynamic execution",
            evidence={
                "dependency_package": "hidden-payload-dep",
                "dependency_version": "0.1.0",
                "dependency_chain": ["root-pkg", "hidden-payload-dep"],
            },
            score=50,
            source="dependency",
            evidence_strength="dependency_confirmed",
        )
        with patch("guardchain.scanner.resolve_dependencies", return_value=(resolved, edges, [])):
            with patch("guardchain.scanner.scan_resolved_dependencies", return_value=[DependencyScanResult(resolved[0], [finding])]):
                result = scan(PROJECT_ROOT / "samples" / "divide_and_hide" / "root_pkg", resolve_deps=True)
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            json_path = root / "result.json"
            md_path = root / "report.md"
            write_json_report(result, json_path)
            write_markdown_report(result, md_path)
            data = json.loads(json_path.read_text(encoding="utf-8"))
            markdown = md_path.read_text(encoding="utf-8")
        self.assertEqual(data["dependency_risk_paths"][0]["path"], ["root-pkg", "hidden-payload-dep"])
        self.assertIn("root-pkg -> hidden-payload-dep", markdown)


if __name__ == "__main__":
    unittest.main()
