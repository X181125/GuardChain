from pathlib import Path
import unittest

from guardchain.graph_builder import render_dot, render_mermaid
from guardchain.scanner import scan


class GraphBuilderTests(unittest.TestCase):
    def test_graph_contains_suspicious_flow(self) -> None:
        result = scan(Path(__file__).resolve().parents[1] / "samples" / "exfiltration_like_pkg")
        edge_types = {edge["type"] for edge in (result.graph or {}).get("edges", [])}
        node_types = {node["type"] for node in (result.graph or {}).get("nodes", [])}
        self.assertIn("suspicious_flow", edge_types)
        self.assertIn("finding", node_types)
        self.assertIn("digraph GuardChain", render_dot(result.graph or {}))
        self.assertIn("suspicious_flow", render_dot(result.graph or {}))
        self.assertIn("graph TD", render_mermaid(result.graph or {}))


if __name__ == "__main__":
    unittest.main()
