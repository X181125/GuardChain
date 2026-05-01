# GuardChain Architecture

GuardChain analyzes packages without executing untrusted code.

```text
Package input
  -> Loader
  -> Metadata analyzer
  -> AST analyzer
  -> Taint analyzer
  -> Dependency analyzer
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

The AST analyzer resolves common import aliases, detects dangerous calls, records line/column data, and adds setup-time context. The taint analyzer tracks lightweight variable flows inside functions and simple direct interprocedural flows through function return values and parameters. The graph builder turns dependencies, files, calls, findings, and suspicious flows into JSON, DOT, and Mermaid outputs.

Evaluation mode is a separate command that scans labeled dataset entries and computes metrics. It does not change scan behavior or scoring.
