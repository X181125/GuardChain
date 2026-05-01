# Security Policy

GuardChain treats scanned packages as untrusted input.

Security guarantees for the scanner:

- It does not import target packages.
- It does not run `setup.py`.
- It does not run pyproject build hooks.
- It does not execute package entrypoints.
- It does not execute strings extracted from target code.
- It does not connect to URLs discovered in target code.

Please report security issues privately to the project maintainers. Include a minimal reproducer when possible.
