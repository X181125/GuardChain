from __future__ import annotations

import json
from pathlib import Path
import unittest

from guardchain.scanner import scan


FIXTURE_ROOT = Path(__file__).parent / "fixtures" / "packages"


class RegressionFixtureTests(unittest.TestCase):
    def test_manifest_fixtures_match_expected_findings(self) -> None:
        manifest = json.loads((FIXTURE_ROOT / "manifest.json").read_text(encoding="utf-8"))
        self.assertGreaterEqual(len(manifest), 20)
        for item in manifest:
            with self.subTest(item=item["name"]):
                path = FIXTURE_ROOT / item["path"]
                source = FIXTURE_ROOT / item["source_path"] if item.get("source_path") else None
                result = scan(path, source_path=source)
                rule_ids = {finding.rule_id for finding in result.findings}
                for rule_id in item.get("expected_rule_ids", []):
                    self.assertIn(rule_id, rule_ids)
                for rule_id in item.get("expected_absent_rule_ids", []):
                    self.assertNotIn(rule_id, rule_ids)
                if item.get("expected_label"):
                    self.assertEqual(result.label, item["expected_label"])


if __name__ == "__main__":
    unittest.main()
