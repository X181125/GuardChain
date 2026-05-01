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
- `findings`
- `static_findings`
- `dynamic_findings`
- `score_breakdown`
- `graph`
- `graphs`
- `analysis_stats`
- `tool_version`
- `schema_version`
- `analysis_mode`
- `limitations`

SARIF reports use SARIF 2.1.0 and include GuardChain rule metadata, result locations, severity mapping, and evidence properties.

Markdown reports are intended for human triage and include summary, risk score, score breakdown, findings, evidence paths, metadata, dependencies, integrity notes, graph notes, and limitations.
