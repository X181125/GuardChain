from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any

from .ast_analyzer import get_call_name
from .models import Finding, PackageContext
from .utils import relative_path, safe_read_text


def build_behavior_graph(context: PackageContext, findings: list[Finding], dependencies: list[str]) -> dict[str, Any]:
    nodes: dict[str, dict[str, str]] = {}
    edges: list[dict[str, str]] = []

    def node(node_id: str, node_type: str, label: str | None = None) -> None:
        nodes.setdefault(node_id, {"id": node_id, "type": node_type, "label": label or node_id})

    def edge(source: str, target: str, edge_type: str) -> None:
        item = {"source": source, "target": target, "type": edge_type}
        if item not in edges:
            edges.append(item)

    package_id = f"package:{context.package_name or context.root_path.name}"
    node(package_id, "package", context.package_name or context.root_path.name)
    for dependency in dependencies:
        dep_id = f"dependency:{dependency}"
        node(dep_id, "dependency", dependency)
        edge(package_id, dep_id, "depends_on")

    for path in context.python_files:
        rel = relative_path(path, context.root_path)
        file_id = f"file:{rel}"
        node(file_id, "file", rel)
        edge(package_id, file_id, "contains")
        _add_file_graph(path, rel, file_id, nodes, edges, node, edge)

    for finding in findings:
        finding_id = f"finding:{finding.rule_id}:{finding.file_path or 'package'}:{finding.line or 0}"
        node(finding_id, "finding", f"{finding.rule_id} {finding.title}")
        if finding.file_path:
            edge(f"file:{finding.file_path}", finding_id, "triggers")
        evidence = finding.evidence if isinstance(finding.evidence, dict) else {}
        source = evidence.get("source")
        sink = evidence.get("sink")
        function = evidence.get("function")
        function_id = f"function:{finding.file_path}:{function}" if finding.file_path and function else None
        if function_id:
            node(function_id, "function", f"{function}()")
            edge(f"file:{finding.file_path}", function_id, "contains")
        if source and sink:
            source_id = f"api:{source}"
            sink_id = f"api:{sink}"
            node(source_id, "sensitive_source", str(source))
            node(sink_id, "dangerous_sink", str(sink))
            if function_id:
                edge(function_id, source_id, "reads")
                edge(function_id, sink_id, "calls")
            edge(source_id, sink_id, "suspicious_flow")
            edge(finding_id, sink_id, "reported_by")
        for call in evidence.get("calls", []) if isinstance(evidence.get("calls"), list) else []:
            api_id = f"api:{call}"
            node(api_id, "api_call", str(call))
            edge(finding_id, api_id, "reported_by")

    return {"nodes": list(nodes.values()), "edges": edges}


def render_dot(graph: dict[str, Any]) -> str:
    lines = ["digraph GuardChain {"]
    for node in graph.get("nodes", []):
        lines.append(f'  "{_esc(node["id"])}" [label="{_esc(node.get("label", node["id"]))}\\n{_esc(node.get("type", ""))}"];')
    for edge in graph.get("edges", []):
        lines.append(f'  "{_esc(edge["source"])}" -> "{_esc(edge["target"])}" [label="{_esc(edge["type"])}"];')
    lines.append("}")
    return "\n".join(lines) + "\n"


def render_mermaid(graph: dict[str, Any]) -> str:
    lines = ["graph TD"]
    node_ids = {node["id"]: f"N{index}" for index, node in enumerate(graph.get("nodes", []), start=1)}
    for node in graph.get("nodes", []):
        label = str(node.get("label", node["id"])).replace('"', "'")
        lines.append(f'  {node_ids[node["id"]]}["{label}"]')
    for edge in graph.get("edges", []):
        source = node_ids.get(edge["source"])
        target = node_ids.get(edge["target"])
        if source and target:
            lines.append(f'  {source} -->|{edge["type"]}| {target}')
    return "\n".join(lines) + "\n"


def _add_file_graph(path: Path, rel: str, file_id: str, nodes, edges, node, edge) -> None:
    try:
        tree = ast.parse(safe_read_text(path), filename=str(path))
    except SyntaxError:
        return
    current_function = "<module>"
    for item in ast.walk(tree):
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
            function_id = f"function:{rel}:{item.name}"
            node(function_id, "function", f"{item.name}()")
            edge(file_id, function_id, "contains")
        elif isinstance(item, ast.Import):
            for alias in item.names:
                import_id = f"import:{alias.name}"
                node(import_id, "import", alias.name)
                edge(file_id, import_id, "imports")
        elif isinstance(item, ast.ImportFrom) and item.module:
            import_id = f"import:{item.module}"
            node(import_id, "import", item.module)
            edge(file_id, import_id, "imports")
        elif isinstance(item, ast.Call):
            call = get_call_name(item.func)
            if call:
                api_id = f"api:{call}"
                node(api_id, "api_call", call)
                edge(file_id, api_id, "calls")


def _esc(value: object) -> str:
    return re.sub(r"([\\\"])", r"\\\1", str(value))
