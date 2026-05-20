# Integrity Analysis

Integrity mode compares a distributed package directory or archive against an optional source repository directory.

```bash
python -m guardchain scan --path ./samples/integrity/dist_pkg --source ./samples/integrity/source_repo
```

Manual `--source` remains the recommended deterministic mode. GuardChain can also extract a repository URL hint from metadata and fetch it, but only when explicitly requested:

```bash
python -m guardchain scan --path ./dist_pkg --source-auto-fetch
```

Automatic source fetch currently supports conservative HTTPS GitHub/GitLab repository URLs, tries tags matching `v<version>` and `<version>`, and reports warnings instead of failing the scan if source retrieval is not possible.

GuardChain reports:

- `I001`: new Python file in the artifact.
- `I002`: Python file differs at AST level.
- `I003`: new suspicious binary or script file.
- `I004`: integrity violation combined with dangerous behavior.

Python AST comparison ignores formatting, comments, and docstring-only changes. For modified files, evidence includes changed function names, dangerous token presence, and any newly introduced dangerous tokens. If a new or modified file contains dangerous behavior markers, GuardChain emits a stronger correlated integrity finding.
