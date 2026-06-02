from __future__ import annotations

import ast


def get_call_name(node: ast.AST) -> str | None:
    """Return a syntactic dotted name such as os.system, when one is explicit."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = get_call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return None


class CallResolver:
    """Resolve simple aliases and indirect call forms without executing code."""

    def __init__(self) -> None:
        self.aliases: dict[str, str] = {}

    def record_import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.aliases[alias.asname or alias.name.split(".")[0]] = alias.name

    def record_import_from(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for alias in node.names:
            local = alias.asname or alias.name
            self.aliases[local] = f"{module}.{alias.name}" if module else alias.name

    def record_assignment(self, target: ast.AST, value: ast.AST) -> None:
        resolved = self.resolve_alias_value(value)
        if not resolved:
            return
        for name in self._target_names(target):
            self.aliases[name] = resolved

    def resolve_alias_value(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id)
        if isinstance(node, ast.Attribute):
            return self.resolve(node)
        if isinstance(node, ast.Call):
            return self._resolve_special_call(node)
        return None

    def resolve(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            parent = self.resolve(node.value)
            return f"{parent}.{node.attr}" if parent else node.attr
        if isinstance(node, ast.Call):
            return self._resolve_special_call(node)
        return None

    def _resolve_special_call(self, node: ast.Call) -> str | None:
        call = self.resolve(node.func)
        if call == "getattr" and len(node.args) >= 2:
            target = self.resolve(node.args[0])
            attr = self._literal_string(node.args[1])
            if target and attr:
                return f"{target}.{attr}"
            return None
        if call == "__import__" and node.args:
            return self._literal_string(node.args[0])
        if call == "importlib.import_module" and node.args:
            return self._literal_string(node.args[0])
        return None

    def _target_names(self, node: ast.AST) -> list[str]:
        if isinstance(node, ast.Name):
            return [node.id]
        if isinstance(node, (ast.Tuple, ast.List)):
            names: list[str] = []
            for item in node.elts:
                names.extend(self._target_names(item))
            return names
        return []

    def _literal_string(self, node: ast.AST) -> str | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        return None
