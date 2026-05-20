import unittest

from guardchain.graph_builder import build_dependency_graph, find_dependency_chains
from guardchain.models import DependencyEdge, Finding


class DependencyGraphTests(unittest.TestCase):
    def test_dependency_chains(self) -> None:
        edges = [DependencyEdge("__root__", "helper-lib", "helper-lib"), DependencyEdge("helper-lib", "payload-lib", "payload-lib")]
        self.assertEqual(find_dependency_chains("root-pkg", edges, "payload-lib"), [["root-pkg", "helper-lib", "payload-lib"]])

    def test_dependency_graph_includes_findings(self) -> None:
        edges = [DependencyEdge("__root__", "payload-lib", "payload-lib")]
        finding = Finding(
            "T004",
            "flow",
            "CRITICAL",
            "taint",
            "flow",
            evidence={"dependency_package": "payload-lib"},
            source="dependency",
            evidence_strength="dependency_confirmed",
        )
        graph = build_dependency_graph("root-pkg", edges, [finding])
        node_ids = {node["id"] for node in graph["nodes"]}
        edge_types = {edge["type"] for edge in graph["edges"]}
        self.assertIn("dependency:payload-lib", node_ids)
        self.assertIn("triggers", edge_types)


if __name__ == "__main__":
    unittest.main()
