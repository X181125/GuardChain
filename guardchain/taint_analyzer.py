from __future__ import annotations

import ast
from dataclasses import dataclass

from .ast_analyzer import get_call_name
from .models import Finding, PackageContext
from .utils import preview_node, relative_path, safe_read_text

SENSITIVE_SOURCES = {"os.environ", "os.getenv", "getpass.getuser", "socket.gethostname", "platform.node", "pathlib.Path.home", "Path.home"}
NETWORK_SOURCES = {"requests.get", "requests.request", "urllib.request.urlopen", "socket.recv"}
OBFUSCATION_SOURCES = {"base64.b64decode", "marshal.loads", "zlib.decompress", "codecs.decode", "binascii.unhexlify"}
NETWORK_SINKS = {"requests.post", "requests.put", "urllib.request.Request", "socket.send", "socket.sendall"}
COMMAND_SINKS = {"os.system", "subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_output"}
DYNAMIC_SINKS = {"eval", "exec", "compile"}
FILE_WRITE_SINKS = {"open", "Path.write_text", "Path.write_bytes"}
SECRET_PATH_MARKERS = {".env", "id_rsa", "credentials", "token", "secret"}


@dataclass
class _Taint:
    kind: str
    source: str
    variable: str
    line: int | None


@dataclass
class _ParamSink:
    param: str
    rule_id: str
    title: str
    severity: str
    score: int
    sink: str
    line: int | None
    sink_kind: str = ""


def analyze_taint(context: PackageContext) -> list[Finding]:
    findings: list[Finding] = []
    for path in context.python_files:
        rel_path = relative_path(path, context.root_path)
        try:
            tree = ast.parse(safe_read_text(path), filename=str(path))
        except SyntaxError:
            continue
        function_returns: dict[str, _Taint] = {}
        function_param_returns: dict[str, set[str]] = {}
        function_param_sinks: dict[str, list[_ParamSink]] = {}
        function_params: dict[str, list[str]] = {}
        for _ in range(4):
            analyzer = _TaintVisitor(
                rel_path,
                function_returns=function_returns,
                function_param_returns=function_param_returns,
                function_param_sinks=function_param_sinks,
                function_params=function_params,
                collect_summaries=True,
                emit_findings=False,
            )
            analyzer.visit(tree)
            stable = (
                _taint_signature(function_returns) == _taint_signature(analyzer.function_returns)
                and function_param_returns == analyzer.function_param_returns
                and _param_sink_signature(function_param_sinks) == _param_sink_signature(analyzer.function_param_sinks)
                and function_params == analyzer.function_params
            )
            function_returns = analyzer.function_returns
            function_param_returns = analyzer.function_param_returns
            function_param_sinks = analyzer.function_param_sinks
            function_params = analyzer.function_params
            if stable:
                break
        analyzer = _TaintVisitor(
            rel_path,
            function_returns=function_returns,
            function_param_returns=function_param_returns,
            function_param_sinks=function_param_sinks,
            function_params=function_params,
        )
        analyzer.visit(tree)
        findings.extend(_dedupe_findings(analyzer.findings))
    return _dedupe_findings(findings)


class _TaintVisitor(ast.NodeVisitor):
    def __init__(
        self,
        rel_path: str,
        function_returns: dict[str, _Taint] | None = None,
        function_param_returns: dict[str, set[str]] | None = None,
        function_param_sinks: dict[str, list[_ParamSink]] | None = None,
        function_params: dict[str, list[str]] | None = None,
        collect_summaries: bool = False,
        emit_findings: bool = True,
    ) -> None:
        self.rel_path = rel_path
        self.aliases: dict[str, str] = {}
        self.function_stack: list[str] = []
        self.tainted: dict[str, _Taint] = {}
        self.findings: list[Finding] = []
        self.function_returns: dict[str, _Taint] = dict(function_returns or {})
        self.function_param_returns: dict[str, set[str]] = {name: set(params) for name, params in (function_param_returns or {}).items()}
        self.function_param_sinks: dict[str, list[_ParamSink]] = {name: list(sinks) for name, sinks in (function_param_sinks or {}).items()}
        self.function_params: dict[str, list[str]] = {name: list(params) for name, params in (function_params or {}).items()}
        self.collect_summaries = collect_summaries
        self.emit_findings = emit_findings

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.aliases[alias.asname or alias.name.split(".")[0]] = alias.name
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for alias in node.names:
            self.aliases[alias.asname or alias.name] = f"{module}.{alias.name}" if module else alias.name
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        old_tainted = self.tainted
        params = [arg.arg for arg in [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]]
        self.function_params[node.name] = params
        if self.collect_summaries:
            self.tainted = {param: _Taint("param", f"param:{param}", param, getattr(node, "lineno", None)) for param in params}
        else:
            self.tainted = {}
        self.function_stack.append(node.name)
        self.generic_visit(node)
        self.function_stack.pop()
        self.tainted = old_tainted

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.visit_FunctionDef(node)

    def visit_Assign(self, node: ast.Assign) -> None:
        taint = self._expr_taint(node.value)
        if taint:
            for target in node.targets:
                for name in self._target_names(target):
                    self.tainted[name] = _Taint(taint.kind, taint.source, name, getattr(node, "lineno", None))
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        if node.value:
            taint = self._expr_taint(node.value)
            if taint:
                for name in self._target_names(node.target):
                    self.tainted[name] = _Taint(taint.kind, taint.source, name, getattr(node, "lineno", None))
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        sink = self._resolve(node.func)
        arg_taints = [self._expr_taint(arg) for arg in [*node.args, *[kw.value for kw in node.keywords]]]
        arg_taints = [taint for taint in arg_taints if taint is not None]

        for taint in arg_taints:
            if taint.kind in {"sensitive", "local_secret"} and sink in NETWORK_SINKS:
                self._emit("T001", "Sensitive source flows into network sink", "HIGH", 30, taint, sink, node)
            if taint.kind == "network" and self._is_file_write_sink(node, sink):
                self._emit("T002", "Network source flows into file write", "HIGH", 30, taint, sink or "file_write", node)
            if taint.kind == "network" and sink in COMMAND_SINKS:
                self._emit("T003", "Network source flows into command execution", "CRITICAL", 50, taint, sink, node)
            if taint.kind == "obfuscation" and sink in DYNAMIC_SINKS:
                self._emit("T004", "Obfuscation source flows into dynamic execution", "CRITICAL", 50, taint, sink, node)
            if taint.kind == "local_secret" and sink in NETWORK_SINKS:
                self._emit("T005", "Local file secret flows into network sink", "HIGH", 30, taint, sink, node)
            if taint.kind == "network" and sink in DYNAMIC_SINKS:
                self._emit("T006", "Network source flows into dynamic execution", "CRITICAL", 50, taint, sink, node)
            if taint.kind in {"sensitive", "local_secret"} and sink in COMMAND_SINKS:
                self._emit("T007", "Sensitive source flows into command execution", "HIGH", 30, taint, sink, node)
            if self.collect_summaries and taint.kind == "param":
                self._record_param_sink_kind(taint, sink, node)
        self._emit_interprocedural_sinks(node, sink)
        self.generic_visit(node)

    def visit_Return(self, node: ast.Return) -> None:
        if node.value and self.function_stack:
            taint = self._expr_taint(node.value)
            if taint:
                function = self.function_stack[-1]
                if taint.kind == "param" and taint.variable:
                    self.function_param_returns.setdefault(function, set()).add(taint.variable)
                else:
                    self.function_returns[function] = taint
        self.generic_visit(node)

    def _expr_taint(self, node: ast.AST) -> _Taint | None:
        if isinstance(node, ast.Name) and node.id in self.tainted:
            return self.tainted[node.id]
        if isinstance(node, ast.Call):
            call = self._resolve(node.func)
            interprocedural = self._call_return_taint(node, call)
            if interprocedural:
                return interprocedural
            if call in SENSITIVE_SOURCES or self._is_sensitive_open(node, call):
                return _Taint("local_secret" if self._is_sensitive_open(node, call) else "sensitive", call or "sensitive_source", "", getattr(node, "lineno", None))
            if call in NETWORK_SOURCES:
                return _Taint("network", call, "", getattr(node, "lineno", None))
            if call in OBFUSCATION_SOURCES:
                return _Taint("obfuscation", call, "", getattr(node, "lineno", None))
            if isinstance(node.func, ast.Attribute):
                receiver_taint = self._expr_taint(node.func.value)
                if receiver_taint:
                    return receiver_taint
            for arg in node.args:
                taint = self._expr_taint(arg)
                if taint:
                    return taint
            for keyword in node.keywords:
                taint = self._expr_taint(keyword.value)
                if taint:
                    return taint
        if isinstance(node, ast.Attribute):
            resolved = self._resolve(node)
            if resolved in SENSITIVE_SOURCES:
                return _Taint("sensitive", resolved or "sensitive_source", "", getattr(node, "lineno", None))
            value_taint = self._expr_taint(node.value)
            if value_taint:
                return value_taint
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and any(marker in node.value.lower() for marker in SECRET_PATH_MARKERS):
            return _Taint("local_secret", node.value, "", getattr(node, "lineno", None))
        if isinstance(node, (ast.JoinedStr, ast.BinOp, ast.Dict, ast.List, ast.Tuple, ast.Set)):
            for child in ast.iter_child_nodes(node):
                taint = self._expr_taint(child)
                if taint:
                    return taint
        return None

    def _call_return_taint(self, node: ast.Call, call: str | None) -> _Taint | None:
        if not call:
            return None
        local_name = call.split(".")[-1]
        if call in self.function_returns:
            taint = self.function_returns[call]
            return _Taint(taint.kind, taint.source, "", getattr(node, "lineno", None))
        if local_name in self.function_returns:
            taint = self.function_returns[local_name]
            return _Taint(taint.kind, taint.source, "", getattr(node, "lineno", None))
        returned_params = self.function_param_returns.get(call) or self.function_param_returns.get(local_name)
        if not returned_params:
            return None
        params = self.function_params.get(call) or self.function_params.get(local_name) or []
        for param in returned_params:
            arg = self._argument_for_param(node, params, param)
            if arg is None:
                continue
            taint = self._expr_taint(arg)
            if taint:
                return taint
        return None

    def _emit_interprocedural_sinks(self, node: ast.Call, call: str | None) -> None:
        if not call:
            return
        local_name = call.split(".")[-1]
        summaries = self.function_param_sinks.get(call) or self.function_param_sinks.get(local_name) or []
        if not summaries:
            return
        params = self.function_params.get(call) or self.function_params.get(local_name) or []
        for summary in summaries:
            arg = self._argument_for_param(node, params, summary.param)
            if arg is None:
                continue
            taint = self._expr_taint(arg)
            if not taint:
                continue
            rule = self._interprocedural_rule(taint.kind, summary.sink_kind)
            if rule is None:
                continue
            rule_id, title, severity, score = rule
            self._emit(
                rule_id,
                title,
                severity,
                score,
                taint,
                summary.sink,
                node,
                extra_flow=[f"{call}({summary.param})", summary.sink],
            )

    def _argument_for_param(self, node: ast.Call, params: list[str], param: str) -> ast.AST | None:
        if param in params:
            index = params.index(param)
            if index < len(node.args):
                return node.args[index]
        for keyword in node.keywords:
            if keyword.arg == param:
                return keyword.value
        return None

    def _resolve(self, node: ast.AST) -> str | None:
        raw = get_call_name(node)
        if raw is None:
            return None
        parts = raw.split(".")
        if parts[0] in self.aliases:
            return ".".join([self.aliases[parts[0]], *parts[1:]])
        return raw

    def _target_names(self, node: ast.AST) -> list[str]:
        if isinstance(node, ast.Name):
            return [node.id]
        if isinstance(node, (ast.Tuple, ast.List)):
            names: list[str] = []
            for item in node.elts:
                names.extend(self._target_names(item))
            return names
        return []

    def _emit(
        self,
        rule_id: str,
        title: str,
        severity: str,
        score: int,
        taint: _Taint,
        sink: str | None,
        node: ast.Call,
        extra_flow: list[str] | None = None,
    ) -> None:
        if self.collect_summaries and taint.kind == "param" and self.function_stack and taint.variable:
            self._record_param_sink(self.function_stack[-1], taint.variable, rule_id, title, severity, score, sink or "<sink>", getattr(node, "lineno", None))
            return
        if not self.emit_findings:
            return
        flow = [taint.source, taint.variable or "<direct>"]
        if extra_flow:
            flow.extend(extra_flow)
        else:
            flow.append(sink or "<sink>")
        self.findings.append(
            Finding(
                rule_id=rule_id,
                title=title,
                severity=severity,
                category="taint",
                message=title,
                file_path=self.rel_path,
                line=getattr(node, "lineno", None),
                column=getattr(node, "col_offset", None),
                evidence={
                    "source": taint.source,
                    "sink": sink,
                    "variable": taint.variable,
                    "flow": flow,
                    "function": self.function_stack[-1] if self.function_stack else "<module>",
                    "sink_preview": preview_node(node),
                },
                score=score,
            )
        )

    def _record_param_sink(self, function: str, param: str, rule_id: str, title: str, severity: str, score: int, sink: str, line: int | None) -> None:
        sink_kind = self._sink_kind(sink)
        sink_summary = _ParamSink(param, rule_id, title, severity, score, sink, line, sink_kind)
        bucket = self.function_param_sinks.setdefault(function, [])
        if sink_summary not in bucket:
            bucket.append(sink_summary)

    def _record_param_sink_kind(self, taint: _Taint, sink: str | None, node: ast.Call) -> None:
        if not self.function_stack or not taint.variable:
            return
        sink_kind = self._sink_kind_for_call(node, sink)
        if not sink_kind:
            return
        rule = self._interprocedural_rule("sensitive", sink_kind)
        if rule is None:
            return
        rule_id, title, severity, score = rule
        sink_summary = _ParamSink(taint.variable, rule_id, title, severity, score, sink or sink_kind, getattr(node, "lineno", None), sink_kind)
        bucket = self.function_param_sinks.setdefault(self.function_stack[-1], [])
        if sink_summary not in bucket:
            bucket.append(sink_summary)

    def _sink_kind(self, sink: str) -> str:
        if sink in NETWORK_SINKS:
            return "network"
        if sink in COMMAND_SINKS:
            return "command"
        if sink in DYNAMIC_SINKS:
            return "dynamic"
        if sink in FILE_WRITE_SINKS or sink.endswith(".write") or sink.endswith(".write_text") or sink.endswith(".write_bytes"):
            return "file_write"
        return ""

    def _sink_kind_for_call(self, node: ast.Call, sink: str | None) -> str:
        if sink in NETWORK_SINKS:
            return "network"
        if sink in COMMAND_SINKS:
            return "command"
        if sink in DYNAMIC_SINKS:
            return "dynamic"
        if self._is_file_write_sink(node, sink):
            return "file_write"
        return ""

    def _interprocedural_rule(self, taint_kind: str, sink_kind: str) -> tuple[str, str, str, int] | None:
        if taint_kind in {"sensitive", "local_secret"} and sink_kind == "network":
            return ("T001", "Sensitive source flows into network sink", "HIGH", 30)
        if taint_kind == "network" and sink_kind == "file_write":
            return ("T002", "Network source flows into file write", "HIGH", 30)
        if taint_kind == "network" and sink_kind == "command":
            return ("T003", "Network source flows into command execution", "CRITICAL", 50)
        if taint_kind == "obfuscation" and sink_kind == "dynamic":
            return ("T004", "Obfuscation source flows into dynamic execution", "CRITICAL", 50)
        if taint_kind == "local_secret" and sink_kind == "network":
            return ("T005", "Local file secret flows into network sink", "HIGH", 30)
        if taint_kind == "network" and sink_kind == "dynamic":
            return ("T006", "Network source flows into dynamic execution", "CRITICAL", 50)
        if taint_kind in {"sensitive", "local_secret"} and sink_kind == "command":
            return ("T007", "Sensitive source flows into command execution", "HIGH", 30)
        return None

    def _is_sensitive_open(self, node: ast.Call, call: str | None) -> bool:
        if call != "open" or not node.args:
            return False
        first = node.args[0]
        return isinstance(first, ast.Constant) and isinstance(first.value, str) and any(marker in first.value.lower() for marker in SECRET_PATH_MARKERS)

    def _is_file_write_sink(self, node: ast.Call, sink: str | None) -> bool:
        if sink in FILE_WRITE_SINKS or (sink and (sink.endswith(".write_text") or sink.endswith(".write_bytes") or sink.endswith(".write") or sink == "write")):
            if sink == "open" and len(node.args) >= 2:
                mode = node.args[1]
                return isinstance(mode, ast.Constant) and isinstance(mode.value, str) and any(flag in mode.value for flag in ("w", "a", "+"))
            if sink == "write" and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Call):
                open_call = node.func.value
                if self._resolve(open_call.func) == "open" and len(open_call.args) >= 2:
                    mode = open_call.args[1]
                    return isinstance(mode, ast.Constant) and isinstance(mode.value, str) and any(flag in mode.value for flag in ("w", "a", "+"))
            return True
        return False


def _taint_signature(values: dict[str, _Taint]) -> dict[str, tuple[str, str]]:
    return {name: (taint.kind, taint.source) for name, taint in values.items()}


def _param_sink_signature(values: dict[str, list[_ParamSink]]) -> dict[str, list[tuple[str, str, str]]]:
    return {name: sorted((sink.param, sink.rule_id, sink.sink, sink.sink_kind) for sink in sinks) for name, sinks in values.items()}


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    seen: set[tuple[str, str | None, int | None, str]] = set()
    unique: list[Finding] = []
    for finding in findings:
        key = (finding.rule_id, finding.file_path, finding.line, str(finding.evidence))
        if key in seen:
            continue
        seen.add(key)
        unique.append(finding)
    return unique
