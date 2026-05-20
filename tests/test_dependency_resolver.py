import json
import subprocess
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from guardchain.dependency_resolver import ROOT_DEPENDENCY, resolve_dependencies


class DependencyResolverTests(unittest.TestCase):
    def test_resolves_pip_report_and_edges(self) -> None:
        report = {
            "install": [
                {
                    "requested": True,
                    "metadata": {"name": "requests", "version": "2.32.0", "requires_dist": ["urllib3>=1.0"]},
                    "download_info": {"url": "https://example.invalid/requests.whl"},
                },
                {"requested": False, "metadata": {"name": "urllib3", "version": "2.0.0"}},
            ]
        }
        with patch("guardchain.dependency_resolver.subprocess.run") as run:
            run.return_value = SimpleNamespace(returncode=0, stdout=json.dumps(report), stderr="")
            resolved, edges, warnings = resolve_dependencies(["requests>=2"], timeout_seconds=5)

        command = run.call_args.args[0]
        self.assertIn("--dry-run", command)
        self.assertIn("--only-binary=:all:", command)
        self.assertIn("--report", command)
        self.assertEqual(warnings, [])
        self.assertEqual([dependency.name for dependency in resolved], ["requests", "urllib3"])
        self.assertIn((ROOT_DEPENDENCY, "requests"), {(edge.parent, edge.child) for edge in edges})
        self.assertIn(("requests", "urllib3"), {(edge.parent, edge.child) for edge in edges})

    def test_no_index_and_find_links_are_passed_to_pip(self) -> None:
        report = {"install": [{"requested": True, "metadata": {"name": "hidden-payload-dep", "version": "0.1.0"}}]}
        with patch("guardchain.dependency_resolver.subprocess.run") as run:
            run.return_value = SimpleNamespace(returncode=0, stdout=json.dumps(report), stderr="")
            resolve_dependencies(["hidden-payload-dep==0.1.0"], find_links=["samples/divide_and_hide/dist"], no_index=True)

        command = run.call_args.args[0]
        self.assertIn("--no-index", command)
        self.assertIn("--find-links", command)
        self.assertIn("samples/divide_and_hide/dist", command)

    def test_timeout_returns_warning(self) -> None:
        with patch("guardchain.dependency_resolver.subprocess.run", side_effect=subprocess.TimeoutExpired("pip", 1)):
            resolved, edges, warnings = resolve_dependencies(["requests"], timeout_seconds=1)
        self.assertEqual(resolved, [])
        self.assertEqual(edges, [])
        self.assertTrue(any("timed out" in warning for warning in warnings))


if __name__ == "__main__":
    unittest.main()
