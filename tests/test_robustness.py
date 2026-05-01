from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from guardchain.scanner import scan


class RobustnessTests(unittest.TestCase):
    def test_invalid_syntax_does_not_crash(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "bad.py").write_text("def nope(:\n", encoding="utf-8")
            result = scan(root)
        self.assertTrue(any(finding.rule_id == "W001" for finding in result.findings))

    def test_huge_python_file_skipped(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "huge.py").write_text("x = 1\n", encoding="utf-8")
            result = scan(root, max_python_file_size_mb=0)
        self.assertTrue(any("exceeds maximum" in finding.message for finding in result.findings))

    def test_results_are_deterministic(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a.py").write_text("import base64\nexec(base64.b64decode('eA=='))\n", encoding="utf-8")
            first = scan(root).to_dict()
            second = scan(root).to_dict()
        self.assertEqual(first["label"], second["label"])
        self.assertEqual(first["risk_score"], second["risk_score"])
        self.assertEqual(first["findings"], second["findings"])


if __name__ == "__main__":
    unittest.main()
