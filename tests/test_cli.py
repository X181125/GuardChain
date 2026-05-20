from pathlib import Path
from tempfile import TemporaryDirectory
import json
import subprocess
import sys
import unittest


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class CliTests(unittest.TestCase):
    def test_cli_artifacts(self) -> None:
        with TemporaryDirectory() as tmp:
            out = Path(tmp)
            json_path = out / "result.json"
            dot_path = out / "graph.dot"
            mmd_path = out / "graph.mmd"
            md_path = out / "report.md"
            sarif_path = out / "report.sarif"
            proc = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "guardchain",
                    "scan",
                    "--path",
                    str(PROJECT_ROOT / "samples" / "malicious_like_pkg"),
                    "--json",
                    str(json_path),
                    "--markdown",
                    str(md_path),
                    "--sarif",
                    str(sarif_path),
                    "--graph-dot",
                    str(dot_path),
                    "--graph-mermaid",
                    str(mmd_path),
                ],
                cwd=PROJECT_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertTrue(json_path.exists())
            self.assertTrue(dot_path.exists())
            self.assertTrue(mmd_path.exists())
            self.assertTrue(md_path.exists())
            self.assertTrue(sarif_path.exists())
            self.assertEqual(json.loads(json_path.read_text(encoding="utf-8"))["label"], "MALICIOUS")

    def test_fail_on_malicious_returns_2(self) -> None:
        proc = subprocess.run(
            [
                sys.executable,
                "-m",
                "guardchain",
                "scan",
                "--path",
                str(PROJECT_ROOT / "samples" / "malicious_like_pkg"),
                "--fail-on-malicious",
                "--quiet",
            ],
            cwd=PROJECT_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 2, proc.stderr)

    def test_divide_and_hide_resolves_local_fixture_dependency(self) -> None:
        with TemporaryDirectory() as tmp:
            out = Path(tmp)
            json_path = out / "result.json"
            proc = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "guardchain",
                    "scan",
                    "--path",
                    str(PROJECT_ROOT / "samples" / "divide_and_hide" / "root_pkg"),
                    "--resolve-deps",
                    "--dependency-no-index",
                    "--dependency-find-links",
                    str(PROJECT_ROOT / "samples" / "divide_and_hide" / "dist"),
                    "--json",
                    str(json_path),
                ],
                cwd=PROJECT_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertIn("root-pkg -> hidden-payload-dep", proc.stdout)
            data = json.loads(json_path.read_text(encoding="utf-8"))
        self.assertIn(data["label"], {"SUSPICIOUS", "MALICIOUS"})
        self.assertTrue(data["dependency_risk_paths"])
        self.assertTrue(any(item["dependency"] == "hidden-payload-dep" for item in data["dependency_risk_paths"]))
        dependency_findings = [finding for finding in data["findings"] if finding["source"] == "dependency"]
        self.assertTrue(any(finding["rule_id"].startswith(("B", "T")) for finding in dependency_findings))
        self.assertTrue(
            any(
                finding["evidence"].get("dependency_chain") == ["root-pkg", "hidden-payload-dep"]
                and finding["evidence"].get("dependency_version") == "0.1.0"
                for finding in dependency_findings
            )
        )

    def test_evaluate_command_writes_json(self) -> None:
        with TemporaryDirectory() as tmp:
            out = Path(tmp)
            labels = out / "labels.csv"
            report = out / "eval.json"
            labels.write_text("path,label\nbenign_pkg,BENIGN\nmalicious_like_pkg,MALICIOUS\n", encoding="utf-8")
            proc = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "guardchain",
                    "evaluate",
                    "--dataset",
                    str(PROJECT_ROOT / "samples"),
                    "--labels",
                    str(labels),
                    "--json",
                    str(report),
                ],
                cwd=PROJECT_ROOT,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            self.assertTrue(report.exists())
            self.assertEqual(json.loads(report.read_text(encoding="utf-8"))["accuracy"], 1.0)

    def test_rules_commands(self) -> None:
        list_proc = subprocess.run(
            [sys.executable, "-m", "guardchain", "rules", "list"],
            cwd=PROJECT_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(list_proc.returncode, 0, list_proc.stderr)
        self.assertIn("B002", list_proc.stdout)
        validate_proc = subprocess.run(
            [sys.executable, "-m", "guardchain", "rules", "validate"],
            cwd=PROJECT_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(validate_proc.returncode, 0, validate_proc.stderr)

    def test_dynamic_command_help(self) -> None:
        proc = subprocess.run(
            [sys.executable, "-m", "guardchain", "sandbox", "--help"],
            cwd=PROJECT_ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("--mode", proc.stdout)
        self.assertIn("--trace", proc.stdout)


if __name__ == "__main__":
    unittest.main()
