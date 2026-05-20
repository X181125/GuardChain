from pathlib import Path
import unittest
from unittest.mock import patch

from guardchain.models import DependencyEdge, DependencyScanResult, Finding, ResolvedDependency
from guardchain.scanner import scan


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class ScannerEndToEndTests(unittest.TestCase):
    def test_benign_sample(self) -> None:
        result = scan(PROJECT_ROOT / "samples" / "benign_pkg")
        self.assertEqual(result.label, "BENIGN")

    def test_suspicious_sample(self) -> None:
        result = scan(PROJECT_ROOT / "samples" / "suspicious_pkg")
        self.assertEqual(result.label, "SUSPICIOUS")

    def test_malicious_like_sample(self) -> None:
        result = scan(PROJECT_ROOT / "samples" / "malicious_like_pkg")
        self.assertEqual(result.label, "MALICIOUS")
        self.assertGreaterEqual(result.score, 70)

    def test_default_scan_does_not_resolve_dependencies(self) -> None:
        with patch("guardchain.scanner.resolve_dependencies") as resolve:
            result = scan(PROJECT_ROOT / "samples" / "benign_pkg")
        resolve.assert_not_called()
        self.assertFalse(result.analysis_features["dependency_resolution"])

    def test_scan_with_mocked_dependency_resolution(self) -> None:
        resolved = [ResolvedDependency("requests", "2.32.0", ["__root__"], True)]
        edges = [DependencyEdge("__root__", "requests", "requests>=2")]
        with patch("guardchain.scanner.resolve_dependencies", return_value=(resolved, edges, [])) as resolve:
            with patch("guardchain.scanner.scan_resolved_dependencies", return_value=[]):
                result = scan(PROJECT_ROOT / "samples" / "typosquat_like_pkg", resolve_deps=True)
        resolve.assert_called_once()
        self.assertTrue(result.analysis_features["dependency_resolution"])
        self.assertEqual(result.analysis_stats["dependency_resolution"]["resolved_dependencies"], 1)

    def test_divide_and_hide_dependency_chain(self) -> None:
        resolved = [ResolvedDependency("hidden-payload-dep", "0.1.0", ["__root__"], True)]
        edges = [DependencyEdge("__root__", "hidden-payload-dep", "hidden-payload-dep==0.1.0")]
        dependency_finding = Finding(
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
        dep_result = DependencyScanResult(resolved[0], [dependency_finding], score=65, label="MALICIOUS")
        with patch("guardchain.scanner.resolve_dependencies", return_value=(resolved, edges, [])):
            with patch("guardchain.scanner.scan_resolved_dependencies", return_value=[dep_result]):
                result = scan(PROJECT_ROOT / "samples" / "divide_and_hide" / "root_pkg", resolve_deps=True)
        self.assertEqual(result.label, "MALICIOUS")
        self.assertEqual(result.dependency_risk_paths[0]["path"], ["root-pkg", "hidden-payload-dep"])


if __name__ == "__main__":
    unittest.main()
