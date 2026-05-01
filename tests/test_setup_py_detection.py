from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from guardchain.loader import load_package
from guardchain.setup_analyzer import analyze_setup_py


class SetupPyDetectionTests(unittest.TestCase):
    def _rules_for(self, setup_code: str) -> set[str]:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "setup.py").write_text(setup_code, encoding="utf-8")
            context = load_package(root)
            return {finding.rule_id for finding in analyze_setup_py(context)}

    def test_top_level_os_system_detected(self) -> None:
        rules = self._rules_for("import os\nos.system('echo simulated')\n")
        self.assertIn("S001", rules)

    def test_custom_install_run_detected(self) -> None:
        rules = self._rules_for(
            "from setuptools import setup\nfrom setuptools.command.install import install\n"
            "class CustomInstall(install):\n    def run(self):\n        pass\n"
            "setup(name='x', cmdclass={'install': CustomInstall})\n"
        )
        self.assertIn("S002", rules)

    def test_setup_py_not_executed(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            marker = root / "marker.txt"
            (root / "setup.py").write_text(f"open(r'{marker}', 'w').write('executed')\n", encoding="utf-8")
            context = load_package(root)
            analyze_setup_py(context)
            self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
