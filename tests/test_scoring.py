import unittest

from guardchain.models import Finding
from guardchain.scoring import calculate_score, calculate_score_with_breakdown, classify


class ScoringTests(unittest.TestCase):
    def test_clamps_score_to_100(self) -> None:
        findings = [
            Finding("T001", "one", "HIGH", "behavior", "one", score=80),
            Finding("T002", "two", "HIGH", "behavior", "two", score=80),
        ]
        self.assertEqual(calculate_score(findings), 100)

    def test_critical_minimum_score(self) -> None:
        findings = [Finding("T003", "critical", "CRITICAL", "behavior", "critical", score=10)]
        self.assertEqual(calculate_score(findings), 60)

    def test_label_thresholds(self) -> None:
        self.assertEqual(classify(0), "BENIGN")
        self.assertEqual(classify(30), "SUSPICIOUS")
        self.assertEqual(classify(60), "MALICIOUS")

    def test_duplicates_not_double_counted(self) -> None:
        finding = Finding("B001", "dynamic", "HIGH", "behavior", "dynamic", file_path="a.py", line=1, evidence={"call": "exec"}, score=30)
        self.assertEqual(calculate_score([finding, finding]), 30)

    def test_breakdown_generated(self) -> None:
        findings = [Finding("T004", "flow", "CRITICAL", "taint", "flow", file_path="a.py", line=2, score=50)]
        score, breakdown = calculate_score_with_breakdown(findings)
        self.assertEqual(score, 75)
        self.assertEqual(breakdown[0].rule_id, "T004")
        self.assertEqual(breakdown[0].file, "a.py")


if __name__ == "__main__":
    unittest.main()
