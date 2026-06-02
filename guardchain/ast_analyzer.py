from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

from .call_resolver import CallResolver, get_call_name
from .models import Finding, PackageContext
from .utils import preview_node, relative_path, safe_read_text

DYNAMIC_CALLS = {
    "eval",
    "exec",
    "compile",
    "execfile",
    "__import__",
    "importlib.import_module",
    "runpy.run_path",
    "runpy.run_module",
    "types.FunctionType",
}
OS_COMMAND_CALLS = {
    "os.system",
    "os.popen",
    "os.execl",
    "os.execle",
    "os.execlp",
    "os.execlpe",
    "os.execv",
    "os.execve",
    "os.execvp",
    "os.execvpe",
    "os.spawnl",
    "os.spawnle",
    "os.spawnlp",
    "os.spawnlpe",
    "os.spawnv",
    "os.spawnve",
    "os.spawnvp",
    "os.spawnvpe",
    "pty.spawn",
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.getoutput",
    "commands.getoutput",
}
SUBPROCESS_SHELL_CALLS = {
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
}
NETWORK_CALLS = {
    "requests.get",
    "requests.post",
    "requests.put",
    "requests.request",
    "urllib.request.urlopen",
    "urllib.request.Request",
    "http.client.HTTPConnection",
    "http.client.HTTPSConnection",
    "socket.socket",
    "socket.create_connection",
    "socket.connect",
    "socket.send",
    "socket.sendall",
    "ftplib.FTP",
    "smtplib.SMTP",
    "telnetlib.Telnet",
    "paramiko.SSHClient",
    "httpx.get",
    "httpx.post",
    "httpx.put",
    "httpx.request",
    "aiohttp.ClientSession",
    "websocket.create_connection",
}
NETWORK_POST_CALLS = {
    "requests.post",
    "requests.put",
    "requests.request",
    "httpx.post",
    "httpx.put",
    "httpx.request",
    "socket.send",
    "socket.sendall",
}
SENSITIVE_CALLS = {
    "os.getenv",
    "getpass.getuser",
    "socket.gethostname",
    "platform.node",
    "platform.platform",
    "uuid.getnode",
    "pathlib.Path.home",
    "Path.home",
}
SENSITIVE_ATTRIBUTES = {"os.environ"}
SENSITIVE_STRINGS = {
    ".env",
    ".ssh",
    "id_rsa",
    "id_dsa",
    ".aws",
    "credentials",
    ".pypirc",
    ".npmrc",
    "token",
    "secret",
    "gcloud",
    "kube",
    "config.json",
}
OBFUSCATION_CALLS = {
    "base64.b64decode",
    "base64.urlsafe_b64decode",
    "base64.b64encode",
    "marshal.loads",
    "zlib.decompress",
    "codecs.decode",
    "binascii.unhexlify",
}
SUSPICIOUS_IMPORTS = {
    "ctypes",
    "winreg",
    "pynput",
    "keyboard",
    "pyautogui",
    "paramiko",
    "ftplib",
    "telnetlib",
    "subprocess",
    "socket",
    "httpx",
    "aiohttp",
    "httpx",
    "websocket",
    "smtplib",
    "base64",
    "marshal",
    "zlib",
    "runpy",
    "types",
    "requests",
    "urllib",
    "http.client",
}
PERSISTENCE_MARKERS = {"crontab", "startup", "bashrc", "zshrc", "profile", "systemd", "run", "runonce", "currentversion\\run"}
BINARY_DROP_EXTENSIONS = {".exe", ".dll", ".so", ".bat", ".ps1", ".sh", ".scr"}


@dataclass
class _Hit:
    line: int | None
    column: int | None
    value: str
    function: str | None = None
    args_preview: list[str] | None = None


def analyze_ast(context: PackageContext) -> list[Finding]:
    findings: list[Finding] = []
    for path in context.python_files:
        rel_path = relative_path(path, context.root_path)
        try:
            tree = ast.parse(safe_read_text(path), filename=str(path))
        except SyntaxError as exc:
            findings.append(
                Finding(
                    rule_id="W001",
                    title="File could not be parsed",
                    severity="LOW",
                    category="warning",
                    message="Python file could not be parsed; analysis continued for other files",
                    file_path=rel_path,
                    line=exc.lineno,
                    column=exc.offset,
                    evidence={"error": str(exc)},
                    score=3,
                )
            )
            continue
        analyzer = _FileAnalyzer(rel_path)
        analyzer.visit(tree)
        findings.extend(analyzer.findings())
    return findings


class _FileAnalyzer(ast.NodeVisitor):
    def __init__(self, rel_path: str) -> None:
        self.rel_path = rel_path
        self.resolver = CallResolver()
        self.write_handles: set[str] = set()
        self.current_function: list[str] = []
        self.current_class: list[str] = []
        self.hits: dict[str, list[_Hit]] = {
            "dynamic": [],
            "os_command": [],
            "shell_execution": [],
            "network": [],
            "network_post": [],
            "sensitive": [],
            "obfuscation": [],
            "file_write": [],
            "suspicious_import": [],
            "persistence": [],
            "binary_drop": [],
        }
        self.function_hits: dict[str, set[str]] = {}

    def visit_Import(self, node: ast.Import) -> None:
        self.resolver.record_import(node)
        for alias in node.names:
            if alias.name in SUSPICIOUS_IMPORTS or alias.name.split(".")[0] in SUSPICIOUS_IMPORTS:
                self.hits["suspicious_import"].append(self._hit(node, alias.name))
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        self.resolver.record_import_from(node)
        module = node.module or ""
        for alias in node.names:
            if module in SUSPICIOUS_IMPORTS or module.split(".")[0] in SUSPICIOUS_IMPORTS:
                self.hits["suspicious_import"].append(self._hit(node, module))
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            self.resolver.record_assignment(target, node.value)
            if self._is_open_write_call(node.value):
                self.write_handles.update(self._target_names(target))
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value:
            self.resolver.record_assignment(node.target, node.value)
            if self._is_open_write_call(node.value):
                self.write_handles.update(self._target_names(node.target))
        self.generic_visit(node)

    def visit_With(self, node: ast.With) -> None:
        for item in node.items:
            if item.optional_vars and self._is_open_write_call(item.context_expr):
                self.write_handles.update(self._target_names(item.optional_vars))
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.current_class.append(node.name)
        self.generic_visit(node)
        self.current_class.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.current_function.append(self._qualified_function_name(node.name))
        self.generic_visit(node)
        self.current_function.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.visit_FunctionDef(node)

    def visit_Call(self, node: ast.Call) -> None:
        call_name = self.resolve_call_name(node.func)
        if call_name in DYNAMIC_CALLS:
            self._record("dynamic", node, call_name)
        if call_name in OS_COMMAND_CALLS:
            self._record("os_command", node, call_name)
        if call_name in SUBPROCESS_SHELL_CALLS and _has_true_keyword(node, "shell"):
            self._record("shell_execution", node, call_name)
        if call_name in NETWORK_CALLS:
            self._record("network", node, call_name)
            if call_name in NETWORK_POST_CALLS:
                self._record("network_post", node, call_name)
        if call_name in SENSITIVE_CALLS:
            self._record("sensitive", node, call_name)
        if call_name in OBFUSCATION_CALLS:
            self._record("obfuscation", node, call_name)
        if self._is_file_write_call(node, call_name):
            self._record("file_write", node, call_name or "open/write")
            self._detect_binary_drop(node)
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        attr_name = self.resolve_call_name(node)
        if attr_name in SENSITIVE_ATTRIBUTES:
            self.hits["sensitive"].append(self._hit(node, attr_name))
            self._mark_function("sensitive")
        self.generic_visit(node)

    def visit_Constant(self, node: ast.Constant) -> None:
        if isinstance(node.value, str):
            lowered = node.value.lower()
            if any(marker in lowered for marker in SENSITIVE_STRINGS):
                self.hits["sensitive"].append(self._hit(node, next(marker for marker in SENSITIVE_STRINGS if marker in lowered)))
                self._mark_function("sensitive")
            if any(marker in lowered for marker in PERSISTENCE_MARKERS):
                self.hits["persistence"].append(self._hit(node, node.value))
            if any(lowered.endswith(ext) or ext in lowered for ext in BINARY_DROP_EXTENSIONS):
                self.hits["binary_drop"].append(self._hit(node, node.value))

    def resolve_call_name(self, node: ast.AST) -> str | None:
        return self.resolver.resolve(node)

    def findings(self) -> list[Finding]:
        findings: list[Finding] = []
        is_setup = Path(self.rel_path).name == "setup.py"
        if self.hits["dynamic"]:
            findings.append(self._finding("B001", "Dynamic code execution", "HIGH", 25, "Dynamic code execution detected", self.hits["dynamic"]))
        if self.hits["os_command"]:
            score = 45 if is_setup else 30
            severity = "CRITICAL" if is_setup else "HIGH"
            message = "System command execution detected"
            if is_setup:
                message += " in setup.py"
            findings.append(self._finding("B002", "System command execution", severity, score, message, self.hits["os_command"]))
        if self.hits["shell_execution"]:
            findings.append(
                self._finding(
                    "B014",
                    "Shell-enabled subprocess execution",
                    "CRITICAL",
                    45,
                    "Subprocess command execution uses shell=True",
                    self.hits["shell_execution"],
                )
            )
        if self.hits["network"]:
            findings.append(self._finding("B003", "Network communication", "MEDIUM", 15, "Network operation detected", self.hits["network"]))
        if self.hits["sensitive"]:
            findings.append(
                self._finding(
                    "B004",
                    "Sensitive environment access",
                    "HIGH",
                    25,
                    "Sensitive environment or credential access detected",
                    self.hits["sensitive"],
                )
            )
        if self.hits["obfuscation"]:
            findings.append(
                self._finding(
                    "B005",
                    "Obfuscation or encoding",
                    "MEDIUM",
                    15,
                    "Obfuscation or encoded payload handling detected",
                    self.hits["obfuscation"],
                )
            )
        if self.hits["obfuscation"] and self.hits["dynamic"]:
            findings.append(
                self._finding(
                    "B006",
                    "Obfuscated execution pattern",
                    "CRITICAL",
                    45,
                    "Encoded or obfuscated content may be dynamically executed",
                    self.hits["obfuscation"][:1] + self.hits["dynamic"][:1],
                    evidence_strength="correlated_pattern",
                )
            )
        if self.hits["network"] and self.hits["file_write"] and (self.hits["os_command"] or self.hits["dynamic"]):
            findings.append(
                self._finding(
                    "B007",
                    "Download and execute pattern",
                    "CRITICAL",
                    50,
                    "Possible download-and-execute behavior detected",
                    self.hits["network"][:1] + self.hits["file_write"][:1] + (self.hits["os_command"] or self.hits["dynamic"])[:1],
                    evidence_strength="correlated_pattern",
                )
            )
        if self.hits["sensitive"] and self.hits["network_post"]:
            findings.append(
                self._finding(
                    "B008",
                    "Possible exfiltration pattern",
                    "CRITICAL",
                    50,
                    "Possible data exfiltration behavior detected",
                    self.hits["sensitive"][:1] + self.hits["network_post"][:1],
                    evidence_strength="correlated_pattern",
                )
            )
        if self.hits["suspicious_import"]:
            findings.append(self._finding("B009", "Suspicious import", "LOW", 5, "Suspicious module imported", self.hits["suspicious_import"]))
        if self.hits["persistence"]:
            findings.append(self._finding("B010", "Persistence-like behavior", "HIGH", 30, "Persistence-like path or registry marker detected", self.hits["persistence"]))
        if self.hits["binary_drop"]:
            findings.append(self._finding("B011", "Suspicious binary drop", "HIGH", 30, "Suspicious binary or script file write detected", self.hits["binary_drop"]))
        top_level_hits = [
            hit
            for bucket in ("dynamic", "os_command", "network", "file_write")
            for hit in self.hits[bucket]
            if hit.function == "<module>"
        ]
        if top_level_hits and not is_setup:
            findings.append(
                self._finding(
                    "B013",
                    "Import-time side effect",
                    "HIGH",
                    25,
                    "Suspicious network, file, command, or dynamic behavior occurs at module import time",
                    top_level_hits,
                    evidence_strength="correlated_pattern",
                )
            )
        for function, kinds in self.function_hits.items():
            if "network" in kinds and ("os_command" in kinds or "dynamic" in kinds):
                findings.append(
                    Finding(
                        rule_id="B012",
                        title="Remote command execution pattern",
                        severity="CRITICAL",
                        category="behavior",
                        message="Network input appears in the same function as command or dynamic execution",
                        file_path=self.rel_path,
                        evidence={"function": function, "patterns": sorted(kinds)},
                        score=50,
                        evidence_strength="correlated_pattern",
                    )
                )
        return findings

    def _record(self, bucket: str, node: ast.Call, value: str) -> None:
        self.hits[bucket].append(self._hit(node, value, [preview_node(arg) for arg in node.args[:3]]))
        self._mark_function(bucket)

    def _hit(self, node: ast.AST, value: str, args_preview: list[str] | None = None) -> _Hit:
        return _Hit(
            line=getattr(node, "lineno", None),
            column=getattr(node, "col_offset", None),
            value=value,
            function=self.current_function[-1] if self.current_function else "<module>",
            args_preview=args_preview,
        )

    def _mark_function(self, kind: str) -> None:
        function = self.current_function[-1] if self.current_function else "<module>"
        self.function_hits.setdefault(function, set()).add(kind)

    def _finding(
        self,
        rule_id: str,
        title: str,
        severity: str,
        score: int,
        message: str,
        hits: list[_Hit],
        evidence_strength: str = "pattern",
    ) -> Finding:
        line_numbers = [hit.line for hit in hits if hit.line is not None]
        columns = [hit.column for hit in hits if hit.column is not None]
        evidence = {
            "calls": list(dict.fromkeys(hit.value for hit in hits)),
            "function": hits[0].function if hits else None,
            "args_preview": [item for hit in hits for item in (hit.args_preview or [])],
        }
        return Finding(
            rule_id=rule_id,
            title=title,
            severity=severity,
            category="behavior",
            message=message,
            file_path=self.rel_path,
            line=min(line_numbers) if line_numbers else None,
            column=min(columns) if columns else None,
            evidence=evidence,
            score=score,
            evidence_strength=evidence_strength,
        )

    def _qualified_function_name(self, name: str) -> str:
        if self.current_class:
            return ".".join([*self.current_class, name])
        return name

    def _detect_binary_drop(self, node: ast.Call) -> None:
        for arg in node.args[:1]:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                lowered = arg.value.lower()
                if any(lowered.endswith(ext) for ext in BINARY_DROP_EXTENSIONS):
                    self.hits["binary_drop"].append(self._hit(node, arg.value, [preview_node(arg)]))

    def _is_open_write_call(self, node: ast.AST) -> bool:
        if not isinstance(node, ast.Call):
            return False
        call_name = self.resolve_call_name(node.func)
        if call_name == "open" and len(node.args) >= 2:
            mode = node.args[1]
            return isinstance(mode, ast.Constant) and isinstance(mode.value, str) and any(flag in mode.value for flag in ("w", "a", "+"))
        if call_name and call_name.endswith(".open") and node.args:
            mode = node.args[0]
            return isinstance(mode, ast.Constant) and isinstance(mode.value, str) and any(flag in mode.value for flag in ("w", "a", "+"))
        return False

    def _is_file_write_call(self, node: ast.Call, call_name: str | None) -> bool:
        if call_name == "open" and self._is_open_write_call(node):
            return True
        if call_name and (
            call_name.endswith(".write_text")
            or call_name.endswith(".write_bytes")
            or call_name in {"Path.write_text", "shutil.copy", "shutil.move"}
        ):
            return True
        if call_name and call_name.endswith(".write"):
            if isinstance(node.func, ast.Attribute):
                receiver = node.func.value
                if isinstance(receiver, ast.Name) and receiver.id in self.write_handles:
                    return True
                if self._is_open_write_call(receiver):
                    return True
            return False
        return False

    def _target_names(self, node: ast.AST) -> list[str]:
        if isinstance(node, ast.Name):
            return [node.id]
        if isinstance(node, (ast.Tuple, ast.List)):
            names: list[str] = []
            for item in node.elts:
                names.extend(self._target_names(item))
            return names
        return []


def _has_true_keyword(node: ast.Call, name: str) -> bool:
    for keyword in node.keywords:
        if keyword.arg == name and isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
            return True
    return False
