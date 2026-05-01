import unittest

from guardchain.dynamic.dynamic_analyzer import analyze_dynamic_events
from guardchain.dynamic.execution_plan import build_execution_command
from guardchain.dynamic.sandbox_config import SandboxConfig
from guardchain.dynamic.strace_parser import parse_strace_line, parse_strace_text


class DynamicAnalysisTests(unittest.TestCase):
    def test_sandbox_config_uses_hardening_flags(self) -> None:
        args = SandboxConfig().security_args()
        self.assertIn("--network", args)
        self.assertIn("none", args)
        self.assertIn("--read-only", args)
        self.assertIn("--cap-drop", args)
        self.assertIn("ALL", args)
        self.assertIn("--security-opt", args)
        self.assertIn("no-new-privileges", args)

    def test_execution_plan_wraps_command_with_strace(self) -> None:
        command = build_execution_command("pip-install-no-deps")
        self.assertIn("strace -f", command)
        self.assertIn("--no-deps", command)
        self.assertIn("/guardchain-output/trace.log", command)

    def test_strace_parser_extracts_file_process_and_network_events(self) -> None:
        text = "\n".join(
            [
                '123 12:00:00.100 openat(AT_FDCWD, "/tmp/home/.ssh/id_rsa", O_RDONLY) = 3',
                '123 12:00:00.200 execve("/bin/sh", ["sh", "-c", "echo simulated"], 0x7fff) = 0',
                '123 12:00:00.300 connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("203.0.113.10")}, 16) = -1 ENETUNREACH',
            ]
        )
        events = parse_strace_text(text)
        self.assertEqual([event.event_type for event in events], ["file", "process", "network"])
        self.assertEqual(events[0].severity_hint, "sensitive_file")
        self.assertEqual(events[1].process, "sh")
        self.assertEqual(events[2].target, "203.0.113.10:443")

    def test_dynamic_analyzer_emits_runtime_findings(self) -> None:
        events = [
            parse_strace_line('123 12:00:00.100 openat(AT_FDCWD, "/tmp/home/.ssh/id_rsa", O_RDONLY) = 3'),
            parse_strace_line('123 12:00:00.200 execve("/bin/sh", ["sh", "-c", "echo simulated"], 0x7fff) = 0'),
            parse_strace_line('123 12:00:00.300 connect(3, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("203.0.113.10")}, 16) = -1 ENETUNREACH'),
        ]
        findings = analyze_dynamic_events([event for event in events if event is not None])
        rule_ids = {finding.rule_id for finding in findings}
        self.assertTrue({"Y002", "Y003", "Y004"}.issubset(rule_ids))


if __name__ == "__main__":
    unittest.main()
