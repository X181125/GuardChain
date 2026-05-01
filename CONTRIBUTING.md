# Contributing

GuardChain is intentionally standard-library first. Please keep new features static-only and avoid executing target package code.

Before submitting changes, run:

```bash
python -m unittest discover
python -m guardchain scan --path ./samples/benign_pkg
python -m guardchain scan --path ./samples/malicious_like_pkg
```

Rules should include clear evidence, line numbers when possible, and false-positive notes in `docs/rules.md`.
