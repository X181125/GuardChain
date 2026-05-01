from pathlib import Path
from tempfile import TemporaryDirectory
import shutil
import unittest

from guardchain.scanner import scan


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class NoHardcodedOutputTests(unittest.TestCase):
    def test_malicious_detection_not_based_on_folder_name(self) -> None:
        with TemporaryDirectory() as tmp:
            copied = Path(tmp) / "random_project_alpha"
            shutil.copytree(PROJECT_ROOT / "samples" / "malicious_like_pkg", copied)
            result = scan(copied)
        self.assertEqual(result.label, "MALICIOUS")
        self.assertTrue(any(finding.rule_id in {"B006", "T004", "D001"} for finding in result.findings))

    def test_benign_detection_not_based_on_folder_name(self) -> None:
        with TemporaryDirectory() as tmp:
            copied = Path(tmp) / "random_project_beta"
            shutil.copytree(PROJECT_ROOT / "samples" / "benign_pkg", copied)
            result = scan(copied)
        self.assertEqual(result.label, "BENIGN")
        self.assertLess(result.score, 30)

    def test_behavior_wins_over_package_metadata_name(self) -> None:
        with TemporaryDirectory() as tmp:
            copied = Path(tmp) / "renamed_safe_sounding_project"
            shutil.copytree(PROJECT_ROOT / "samples" / "malicious_like_pkg", copied)
            setup_py = copied / "setup.py"
            setup_py.write_text(setup_py.read_text(encoding="utf-8").replace("malicious-like-pkg", "boring-utility-package"), encoding="utf-8")
            result = scan(copied)
        self.assertEqual(result.label, "MALICIOUS")
        self.assertTrue(any(finding.category in {"behavior", "taint", "dependency"} for finding in result.findings))


if __name__ == "__main__":
    unittest.main()
