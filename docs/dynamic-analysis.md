# Dynamic Analysis

Dynamic analysis is disabled by default. Use it only when you explicitly want GuardChain to execute package code inside Docker:

```bash
python -m guardchain sandbox --path ./pkg
python -m guardchain analyze --path ./pkg --with-sandbox
```

The sandbox runner mounts the package read-only at `/package`, writes `strace` output to `/guardchain-output/trace.log`, and supports these modes:

- `setup-py-metadata`
- `setup-py-install`
- `pip-install-no-deps`

Build the reference sandbox image:

```bash
docker build -f docker/Dockerfile.sandbox -t guardchain-sandbox:latest .
```

Dynamic rules use `Y` prefixes:

- `Y001`: Runtime process execution.
- `Y002`: Runtime shell spawn.
- `Y003`: Runtime network connection attempt or network-capable tool execution.
- `Y004`: Runtime sensitive file access.
- `Y005`: Runtime suspicious file write.
- `Y006`: Runtime persistence-like file access.
- `Y007`: Runtime package manager invocation.
- `Y008`: Runtime binary or script drop.
- `Y009`: Runtime attempt blocked by sandbox policy or sandbox timeout.

The trace parser focuses on file, process, and network syscalls. Results are evidence for review, not proof that all runtime behavior was observed.
