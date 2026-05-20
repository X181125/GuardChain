from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
import zipfile

from guardchain.dependency_scanner import scan_resolved_dependencies
from guardchain.models import DependencyEdge, DownloadedDependency, ResolvedDependency


class DependencyScannerTests(unittest.TestCase):
    def test_scans_local_dependency_artifact_and_annotates_findings(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            archive = root / "hidden_payload_dep-0.1.0.zip"
            with zipfile.ZipFile(archive, "w") as zf:
                zf.writestr("hidden_payload_dep-0.1.0/hidden_payload_dep/__init__.py", "")
                zf.writestr(
                    "hidden_payload_dep-0.1.0/hidden_payload_dep/payload.py",
                    "import base64\npayload = base64.b64decode('cHJpbnQoMSk=')\nexec(payload)\n",
                )
                zf.writestr("hidden_payload_dep-0.1.0/METADATA", "Name: hidden-payload-dep\nVersion: 0.1.0\n")
            resolved = [ResolvedDependency("hidden-payload-dep", "0.1.0", ["__root__"], True)]
            edges = [DependencyEdge("__root__", "hidden-payload-dep", "hidden-payload-dep==0.1.0")]
            with patch("guardchain.dependency_scanner.download_dependency_artifacts") as download:
                download.return_value = [DownloadedDependency("hidden-payload-dep", "0.1.0", str(archive), archive.stat().st_size)]
                results = scan_resolved_dependencies(resolved, edges, "root-pkg")

        findings = results[0].findings
        self.assertTrue(findings)
        self.assertTrue(all(finding.source == "dependency" for finding in findings))
        self.assertTrue(any(finding.evidence.get("dependency_chain") == ["root-pkg", "hidden-payload-dep"] for finding in findings if isinstance(finding.evidence, dict)))


if __name__ == "__main__":
    unittest.main()
