# Integrity Analysis

Integrity mode compares a distributed package directory or archive against an optional source repository directory.

```bash
python -m guardchain scan --path ./samples/integrity/dist_pkg --source ./samples/integrity/source_repo
```

GuardChain reports:

- `I001`: new Python file in the artifact.
- `I002`: Python file differs at AST level.
- `I003`: new suspicious binary or script file.
- `I004`: integrity violation combined with dangerous behavior.

Python AST comparison ignores formatting, comments, and docstring-only changes. If a new or modified file contains dangerous behavior markers, GuardChain emits a stronger correlated integrity finding.
