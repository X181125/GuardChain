from __future__ import annotations

import ast
from pathlib import Path

from .call_resolver import CallResolver, get_call_name
from .models import Finding, PackageContext
from .utils import preview_node, relative_path, safe_read_text

DANGEROUS_CALLS = {
    "os.system",
    "os.popen",
    "os.execl",
    "os.execv",
    "os.execve",
    "os.spawnl",
    "os.spawnv",
    "pty.spawn",
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.getoutput",
    "commands.getoutput",
    "eval",
    "exec",
    "compile",
    "execfile",
    "runpy.run_path",
    "runpy.run_module",
    "types.FunctionType",
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
    "httpx.get",
    "httpx.post",
    "httpx.request",
    "aiohttp.ClientSession",
}
OBFUSCATION_CALLS = {"base64.b64decode", "base64.urlsafe_b64decode", "marshal.loads", "zlib.decompress", "codecs.decode", "binascii.unhexlify"}
FILE_OR_ENV_CALLS = {"open", "Path.write_text", "Path.write_bytes", "shutil.copy", "shutil.move", "os.environ", "os.getenv"}
COMMAND_BASES = {
    "install",
    "develop",
    "build_py",
    "egg_info",
    "sdist",
    "bdist_wheel",
    "setuptools.command.install.install",
    "setuptools.command.develop.develop",
    "setuptools.command.build_py.build_py",
    "setuptools.command.egg_info.egg_info",
    "setuptools.command.sdist.sdist",
    "wheel.bdist_wheel.bdist_wheel",
}


def analyze_setup_py(context: PackageContext) -> list[Finding]:
    if not context.setup_py:
        return []
    rel = relative_path(context.setup_py, context.root_path)
    try:
        tree = ast.parse(safe_read_text(context.setup_py), filename=str(context.setup_py))
    except SyntaxError as exc:
        return [
            Finding(
                rule_id="W001",
                title="File could not be parsed",
                severity="LOW",
                category="warning",
                message="setup.py could not be parsed for install-time behavior",
                file_path=rel,
                line=exc.lineno,
                column=exc.offset,
                evidence={"error": str(exc)},
                score=3,
            )
        ]
    analyzer = _SetupVisitor(rel)
    analyzer.visit(tree)
    return analyzer.findings


class _SetupVisitor(ast.NodeVisitor):
    def __init__(self, rel_path: str) -> None:
        self.rel_path = rel_path
        self.resolver = CallResolver()
        self.class_stack: list[str] = []
        self.function_stack: list[str] = []
        self.findings: list[Finding] = []
        self.has_obfuscation = False
        self.has_dynamic = False
        self.custom_command_classes: set[str] = set()

    def visit_Import(self, node: ast.Import) -> None:
        self.resolver.record_import(node)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        self.resolver.record_import_from(node)
        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        for target in node.targets:
            self.resolver.record_assignment(target, node.value)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value:
            self.resolver.record_assignment(node.target, node.value)
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        bases = {self._resolve(base) or get_call_name(base) or "" for base in node.bases}
        if bases & COMMAND_BASES or {base.split(".")[-1] for base in bases} & {"install", "develop", "build_py"}:
            self.custom_command_classes.add(node.name)
            self._emit("S002", "Custom install/build/develop command", "HIGH", 30, node, {"class": node.name, "bases": sorted(bases)})
        self.class_stack.append(node.name)
        self.generic_visit(node)
        self.class_stack.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.function_stack.append(node.name)
        self.generic_visit(node)
        self.function_stack.pop()

    def visit_Call(self, node: ast.Call) -> None:
        call = self._resolve(node.func)
        if call in DANGEROUS_CALLS and not self.function_stack and not self.class_stack:
            self._emit("S001", "Dangerous top-level setup.py behavior", "CRITICAL", 50, node, {"call": call, "args_preview": [preview_node(arg) for arg in node.args]})
        if call in DANGEROUS_CALLS and self._inside_custom_run():
            self._emit(
                "S006",
                "Custom setup command contains suspicious behavior",
                "CRITICAL",
                45,
                node,
                {
                    "class": self.class_stack[-1] if self.class_stack else None,
                    "function": self.function_stack[-1] if self.function_stack else None,
                    "call": call,
                    "args_preview": [preview_node(arg) for arg in node.args],
                },
            )
        if call in NETWORK_CALLS:
            self._emit("S003", "setup.py network access", "HIGH", 30, node, {"call": call, "args_preview": [preview_node(arg) for arg in node.args]})
            if self._inside_custom_run():
                self._emit(
                    "S006",
                    "Custom setup command contains suspicious behavior",
                    "HIGH",
                    35,
                    node,
                    {
                        "class": self.class_stack[-1] if self.class_stack else None,
                        "function": self.function_stack[-1] if self.function_stack else None,
                        "call": call,
                        "args_preview": [preview_node(arg) for arg in node.args],
                    },
                )
        if call in OBFUSCATION_CALLS:
            self.has_obfuscation = True
        if call in {"eval", "exec", "compile"}:
            self.has_dynamic = True
        if self._is_file_or_env_change(node, call):
            self._emit("S005", "setup.py modifies environment or files", "MEDIUM", 15, node, {"call": call, "args_preview": [preview_node(arg) for arg in node.args]})
        if call and call.endswith("setup"):
            self._detect_cmdclass(node)
        self.generic_visit(node)

    def visit_Module(self, node: ast.Module) -> None:
        self.generic_visit(node)
        if self.has_obfuscation and self.has_dynamic:
            self.findings.append(
                Finding(
                    rule_id="S004",
                    title="setup.py obfuscated dynamic execution",
                    severity="CRITICAL",
                    category="setup",
                    message="setup.py combines obfuscation handling with dynamic execution",
                    file_path=self.rel_path,
                    evidence={"patterns": ["obfuscation", "dynamic_execution"]},
                    score=50,
                    evidence_strength="correlated_pattern",
                )
            )

    def _detect_cmdclass(self, node: ast.Call) -> None:
        for keyword in node.keywords:
            if keyword.arg == "cmdclass" and isinstance(keyword.value, ast.Dict):
                for key, value in zip(keyword.value.keys, keyword.value.values):
                    key_text = preview_node(key) if key else ""
                    value_text = preview_node(value)
                    if any(command in key_text.lower() for command in ("install", "develop", "build")) or value_text in self.custom_command_classes:
                        self._emit("S002", "Custom install/build/develop command", "HIGH", 30, node, {"cmdclass": f"{key_text}: {value_text}"})

    def _resolve(self, node: ast.AST) -> str | None:
        return self.resolver.resolve(node)

    def _inside_custom_run(self) -> bool:
        return bool(self.class_stack and self.function_stack and self.class_stack[-1] in self.custom_command_classes and self.function_stack[-1] == "run")

    def _emit(self, rule_id: str, title: str, severity: str, score: int, node: ast.AST, evidence: dict[str, object]) -> None:
        self.findings.append(
            Finding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                category="setup",
                message=title,
                file_path=self.rel_path,
                line=getattr(node, "lineno", None),
                column=getattr(node, "col_offset", None),
                evidence=evidence,
                score=score,
            )
        )

    def _is_file_or_env_change(self, node: ast.Call, call: str | None) -> bool:
        if call in {"Path.write_text", "Path.write_bytes", "shutil.copy", "shutil.move"} or (call and call.endswith(".write")):
            return True
        if call == "open" and len(node.args) >= 2:
            mode = node.args[1]
            return isinstance(mode, ast.Constant) and isinstance(mode.value, str) and any(flag in mode.value for flag in ("w", "a", "+"))
        return False
