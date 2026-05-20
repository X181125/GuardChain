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
        finding = Finding(
            "B001",
            "dynamic",
            "HIGH",
            "behavior",
            "dynamic",
            file_path="a.py",
            line=1,
            evidence={"call": "exec"},
            score=30,
            evidence_strength="correlated_pattern",
        )
        self.assertEqual(calculate_score([finding, finding]), 30)

    def test_breakdown_generated(self) -> None:
        findings = [Finding("T004", "flow", "CRITICAL", "taint", "flow", file_path="a.py", line=2, score=50, evidence_strength="taint_confirmed")]
        score, breakdown = calculate_score_with_breakdown(findings)
        self.assertEqual(score, 75)
        self.assertEqual(breakdown[0].rule_id, "T004")
        self.assertEqual(breakdown[0].file, "a.py")

    def test_duplicate_root_causes_are_reduced(self) -> None:
        findings = [
            Finding("B002", "command", "HIGH", "behavior", "command", file_path="setup.py", line=3, evidence={"calls": ["subprocess.run"]}, score=30),
            Finding("S001", "setup", "CRITICAL", "setup", "setup", file_path="setup.py", line=3, evidence={"call": "subprocess.run"}, score=50),
        ]
        _, breakdown = calculate_score_with_breakdown(findings)
        self.assertTrue(any("duplicate evidence for command_execution" in item.reason for item in breakdown))


if __name__ == "__main__":
    unittest.main()
