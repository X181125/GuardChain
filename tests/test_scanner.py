from pathlib import Path
import unittest

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


if __name__ == "__main__":
    unittest.main()
