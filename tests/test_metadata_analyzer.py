from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from guardchain.loader import load_package
from guardchain.metadata_analyzer import analyze_metadata, extract_metadata


class MetadataAnalyzerTests(unittest.TestCase):
    def test_missing_url_short_description_and_typo_name(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pyproject.toml").write_text(
                """
[project]
name = "reqeusts"
version = "0.1.0"
description = "tiny"
""",
                encoding="utf-8",
            )
            context = load_package(root)
            rule_ids = {finding.rule_id for finding in analyze_metadata(context)}

        self.assertIn("M001", rule_ids)
        self.assertIn("M002", rule_ids)
        self.assertIn("M003", rule_ids)

    def test_pyproject_setup_cfg_and_metadata_parsed(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pyproject.toml").write_text("[project]\nname='demo'\nversion='1.0.0'\ndescription='A useful demo package.'\n", encoding="utf-8")
            (root / "setup.cfg").write_text("[metadata]\nauthor = GuardChain\n", encoding="utf-8")
            (root / "METADATA").write_text("Name: demo\nVersion: 1.0.0\nSummary: A useful demo package.\n", encoding="utf-8")
            context = load_package(root)
            metadata = extract_metadata(context)
        self.assertEqual(metadata["name"], "demo")
        self.assertEqual(metadata["version"], "1.0.0")
        self.assertEqual(metadata["author"], "GuardChain")

    def test_setup_py_suspicious_logic_emits_m004(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "setup.py").write_text("import subprocess\nsubprocess.run(['echo', 'demo'])\n", encoding="utf-8")
            context = load_package(root)
            rule_ids = {finding.rule_id for finding in analyze_metadata(context)}
        self.assertIn("M004", rule_ids)


if __name__ == "__main__":
    unittest.main()
