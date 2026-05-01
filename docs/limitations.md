# Limitations

GuardChain does not prove a package is safe. It provides static evidence-based risk assessment.

Known limitations:

- Static analysis can miss behavior constructed dynamically at runtime.
- Lightweight taint analysis can miss complex interprocedural flows.
- Rule-based detection can produce false positives.
- Dependency parsing does not fully resolve dependency graphs like `pip`.
- Binary/native payloads are not reverse engineered.
- Online enrichment is intentionally not enabled by default.

Use GuardChain as a triage and research aid alongside sandboxing, code review, and other security controls.
