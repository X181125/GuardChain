# Report Format

GuardChain supports terminal, JSON, Markdown, SARIF, Graphviz DOT, and Mermaid outputs.

JSON reports include:

- `target`
- `package_name`
- `label`
- `risk_score`
- `confidence`
- `metadata`
- `dependencies`
- `dependency_details`
- `resolved_dependencies`
- `dependency_edges`
- `dependency_graph`
- `dependency_risk_paths`
- `dependency_scan_results`
- `findings`
- `static_findings`
- `dynamic_findings`
- `score_breakdown`
- `graph`
- `graphs`
- `analysis_stats`
- `analysis_features`
- `tool_version`
- `schema_version`
- `analysis_mode`
- `limitations`

Each finding includes `evidence_strength`, which distinguishes syntactic pattern matches from correlated patterns, taint-confirmed flows, runtime observations, integrity-confirmed findings, and dependency-confirmed findings.

SARIF reports use SARIF 2.1.0 and include GuardChain rule metadata, result locations, severity mapping, evidence strength, and evidence properties.

Markdown reports are intended for human triage and include summary, analysis mode, evidence strength summary, risk score, score breakdown, findings, dependency risk paths, root cause groups, evidence paths, metadata, dependencies, integrity notes, graph notes, and limitations.
