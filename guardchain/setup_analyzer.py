from __future__ import annotations

import ast
from pathlib import Path

from .ast_analyzer import get_call_name
from .models import Finding, PackageContext
from .utils import preview_node, relative_path, safe_read_text

DANGEROUS_CALLS = {
    "os.system",
    "os.popen",
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.getoutput",
    "eval",
    "exec",
    "compile",
}
NETWORK_CALLS = {"requests.get", "requests.post", "requests.request", "urllib.request.urlopen", "urllib.request.Request", "socket.socket"}
OBFUSCATION_CALLS = {"base64.b64decode", "base64.urlsafe_b64decode", "marshal.loads", "zlib.decompress", "codecs.decode", "binascii.unhexlify"}
FILE_OR_ENV_CALLS = {"open", "Path.write_text", "Path.write_bytes", "shutil.copy", "shutil.move", "os.environ", "os.getenv"}
COMMAND_BASES = {"install", "develop", "build_py", "setuptools.command.install.install", "setuptools.command.develop.develop", "setuptools.command.build_py.build_py"}


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
        self.aliases: dict[str, str] = {}
        self.class_stack: list[str] = []
        self.function_stack: list[str] = []
        self.findings: list[Finding] = []
        self.has_obfuscation = False
        self.has_dynamic = False
        self.custom_command_classes: set[str] = set()

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.aliases[alias.asname or alias.name.split(".")[0]] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for alias in node.names:
            self.aliases[alias.asname or alias.name] = f"{module}.{alias.name}" if module else alias.name
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
        if call in NETWORK_CALLS:
            self._emit("S003", "setup.py network access", "HIGH", 30, node, {"call": call, "args_preview": [preview_node(arg) for arg in node.args]})
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
        raw = get_call_name(node)
        if raw is None:
            return None
        parts = raw.split(".")
        if parts[0] in self.aliases:
            return ".".join([self.aliases[parts[0]], *parts[1:]])
        return raw

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
