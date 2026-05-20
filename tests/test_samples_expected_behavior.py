from pathlib import Path
import unittest

from guardchain.scanner import scan


SAMPLES = Path(__file__).resolve().parents[1] / "samples"


class SamplesExpectedBehaviorTests(unittest.TestCase):
    def test_expected_sample_behaviors(self) -> None:
        cases = [
            ("benign_pkg", "BENIGN", {"max_score": 29, "rules": set()}),
            ("suspicious_pkg", "SUSPICIOUS", {"rules": {"B004"}}),
            ("malicious_like_pkg", "MALICIOUS", {"rules": {"B006", "D001"}}),
            ("setup_time_malicious_like_pkg", "MALICIOUS", {"rules": {"S001", "S002"}}),
            ("exfiltration_like_pkg", None, {"rules": {"T001", "B008"}}),
            ("download_execute_like_pkg", None, {"rules": {"B007"}}),
            ("typosquat_like_pkg", "SUSPICIOUS", {"rules": {"M003", "D002"}}),
            ("divide_and_hide/root_pkg", "BENIGN", {"rules": set(), "max_score": 29}),
            ("divide_and_hide/hidden_payload_dep", "MALICIOUS", {"rules": {"B006", "T004"}}),
        ]
        for sample, expected_label, expectation in cases:
            with self.subTest(sample=sample):
                result = scan(SAMPLES / sample)
                if expected_label:
                    self.assertEqual(result.label, expected_label)
                if "max_score" in expectation:
                    self.assertLessEqual(result.score, expectation["max_score"])
                rule_ids = {finding.rule_id for finding in result.findings}
                self.assertTrue(expectation["rules"].issubset(rule_ids))

    def test_integrity_sample(self) -> None:
        result = scan(SAMPLES / "integrity" / "dist_pkg", source_path=SAMPLES / "integrity" / "source_repo")
        self.assertTrue(any(finding.rule_id in {"I001", "I002", "I004"} for finding in result.findings))


if __name__ == "__main__":
    unittest.main()
