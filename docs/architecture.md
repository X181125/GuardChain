# GuardChain Architecture

GuardChain is a HERCULE-inspired educational prototype, not a full reimplementation of HERCULE. It analyzes packages without executing untrusted code by default.

```text
Package input
  -> Loader
  -> Metadata analyzer
  -> AST analyzer
  -> Taint analyzer
  -> Dependency analyzer
  -> Optional dependency resolver/scanner
  -> Integrity analyzer
  -> Graph builder
  -> Scoring
  -> Report
```

Dynamic analysis is a separate opt-in path:

```text
Package input
  -> Safe loader
  -> Docker sandbox
  -> strace collection
  -> Dynamic analyzer
  -> Scoring
  -> Report
```

The loader supports directories, `.tar.gz`, `.tgz`, `.tar`, `.whl`, and `.zip`. Archives are extracted into temporary directories with path traversal checks and size/file limits.

The AST analyzer resolves common import aliases, detects dangerous calls, records line/column data, and adds setup-time context. The taint analyzer tracks lightweight variable flows inside functions and simple direct interprocedural flows through function return values and parameters.

Dependency closure is explicit opt-in through `--resolve-deps`. The resolver uses pip dry-run JSON reports for declared requirement strings only, prefers binary wheels, and records unresolved packages as warnings. The dependency scanner downloads resolved wheel/zip artifacts with limits and scans them through the static pipeline without recursive dependency resolution.

The graph builder turns dependencies, dependency edges, files, calls, findings, dependency risk paths, and suspicious flows into JSON, DOT, and Mermaid outputs.

Evaluation mode is a separate command that scans labeled dataset entries and computes metrics. It does not change scan behavior or scoring.
