# GuardChain Safety

GuardChain never executes untrusted package code.

- It does not run `setup.py`.
- It does not import scanned packages.
- It does not execute package entrypoints.
- It does not run pyproject build hooks.
- It does not send network traffic for behavior checks.

This guarantee applies to `guardchain scan` and the static phase of `guardchain analyze`.

Dynamic analysis is explicit opt-in:

```bash
python -m guardchain sandbox --path ./pkg
python -m guardchain analyze --path ./pkg --with-sandbox
```

Dynamic mode runs target code only inside the configured Docker sandbox. The default sandbox configuration uses no network, a read-only root filesystem, dropped Linux capabilities, non-root user, memory/CPU/PID limits, no host home mount, and a timeout. Build the reference image with:

```bash
docker build -f docker/Dockerfile.sandbox -t guardchain-sandbox:latest .
```

Demo samples are non-destructive and use `example.invalid` for simulated network destinations. Do not run unknown packages directly outside an isolated sandbox.
