from pathlib import Path
from tempfile import TemporaryDirectory
import json
import unittest

from guardchain.evaluator import evaluate_dataset


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class EvaluateTests(unittest.TestCase):
    def test_metrics_computed(self) -> None:
        with TemporaryDirectory() as tmp:
            labels = Path(tmp) / "labels.csv"
            labels.write_text("path,label\nbenign_pkg,BENIGN\nmalicious_like_pkg,MALICIOUS\n", encoding="utf-8")
            result = evaluate_dataset(PROJECT_ROOT / "samples", labels)
        json.dumps(result)
        self.assertEqual(result["counts"]["tp"], 1)
        self.assertEqual(result["counts"]["tn"], 1)
        self.assertEqual(result["accuracy"], 1.0)

    def test_missing_label_path_reported(self) -> None:
        with TemporaryDirectory() as tmp:
            labels = Path(tmp) / "labels.csv"
            labels.write_text("path,label\nmissing_pkg,BENIGN\n", encoding="utf-8")
            result = evaluate_dataset(PROJECT_ROOT / "samples", labels)
        self.assertIn("missing_pkg", result["missing"])


if __name__ == "__main__":
    unittest.main()
