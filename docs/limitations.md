# Limitations

GuardChain is a HERCULE-inspired educational prototype, not a full reimplementation of HERCULE. It does not prove a package is safe. It provides static evidence-based risk assessment.

Known limitations:

- Static analysis can miss behavior constructed dynamically at runtime.
- GuardChain uses Python AST traversal instead of CodeQL.
- Lightweight taint analysis can miss complex interprocedural flows.
- The taint analyzer is not a full CFG/data-flow database.
- Rule-based detection can produce false positives.
- Dependency closure is optional, bounded, and not ecosystem-scale analysis.
- pip report metadata may not contain enough information to reconstruct every dependency edge.
- Binary/native payloads are not reverse engineered.
- Online enrichment is intentionally not enabled by default.
- Source repository auto-fetch is disabled by default and only supports conservative HTTPS GitHub/GitLab hints.

Use GuardChain as a triage and research aid alongside sandboxing, code review, and other security controls.
