from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from guardchain.dependency_analyzer import analyze_dependencies, extract_dependency_details
from guardchain.loader import load_package


class DependencyAnalyzerTests(unittest.TestCase):
    def test_requirements_rules(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "requirements.txt").write_text(
                "\n".join(
                    [
                        "requests",
                        "reqeusts==1.0.0",
                        "bot-package==0.0.1",
                        "git+http://example.invalid/repo.git",
                        "../local-package",
                    ]
                ),
                encoding="utf-8",
            )
            context = load_package(root)
            findings, dependencies = analyze_dependencies(context)
            rule_ids = {finding.rule_id for finding in findings}

        self.assertIn("requests", dependencies)
        self.assertIn("D001", rule_ids)
        self.assertIn("D002", rule_ids)
        self.assertIn("D003", rule_ids)
        self.assertIn("D004", rule_ids)
        self.assertIn("D005", rule_ids)
        self.assertIn("D006", rule_ids)

    def test_parse_pyproject_setup_cfg_and_metadata(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pyproject.toml").write_text("[project]\nname='x'\ndependencies=['flask==3.0.0']\n", encoding="utf-8")
            (root / "setup.cfg").write_text("[options]\ninstall_requires =\n    pydantic==2.0.0\n", encoding="utf-8")
            (root / "METADATA").write_text("Name: x\nRequires-Dist: fastapi==0.1.0\n", encoding="utf-8")
            context = load_package(root)
            _, dependencies = analyze_dependencies(context)
        self.assertTrue({"flask", "pydantic", "fastapi"}.issubset(set(dependencies)))

    def test_imported_but_not_declared_detected(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pkg.py").write_text("import requests\n", encoding="utf-8")
            context = load_package(root)
            findings, _ = analyze_dependencies(context)
        self.assertIn("D007", {finding.rule_id for finding in findings})

    def test_dependency_details_use_packaging_metadata(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "requirements.txt").write_text("requests[security]>=2.0; python_version >= '3.11'\n", encoding="utf-8")
            context = load_package(root)
            details = extract_dependency_details(context)
        self.assertEqual(details[0].name, "requests")
        self.assertEqual(details[0].version_spec, ">=2.0")
        self.assertEqual(details[0].extras, ["security"])
        self.assertIn("python_version", details[0].marker or "")

    def test_common_distribution_import_mapping(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pyproject.toml").write_text("[project]\nname='x'\ndependencies=['PyYAML==6.0']\n", encoding="utf-8")
            (root / "pkg.py").write_text("import yaml\n", encoding="utf-8")
            context = load_package(root)
            findings, _ = analyze_dependencies(context)
        rule_ids = {finding.rule_id for finding in findings}
        self.assertNotIn("D007", rule_ids)
        self.assertNotIn("D008", rule_ids)

    def test_stdlib_imports_do_not_trigger_dependency_warning(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pkg.py").write_text(
                "import email\nimport asyncio\nimport sqlite3\nimport hashlib\nimport ssl\nimport logging\nimport tempfile\nimport shutil\nimport re\nimport configparser\n",
                encoding="utf-8",
            )
            context = load_package(root)
            findings, _ = analyze_dependencies(context)
        self.assertNotIn("D007", {finding.rule_id for finding in findings})


if __name__ == "__main__":
    unittest.main()
