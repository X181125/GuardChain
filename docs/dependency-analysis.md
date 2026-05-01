# Dependency Analysis

GuardChain parses dependency declarations from `requirements.txt`, `pyproject.toml`, `setup.cfg`, `setup.py` keyword arguments, `METADATA`, and `PKG-INFO`.

It uses `packaging.requirements.Requirement` when possible to parse names, extras, markers, direct URLs, and version specifiers. A fallback parser handles VCS and local-path requirements.

Detected dependency risks include:

- Direct URL dependencies.
- VCS dependencies.
- Local path dependencies.
- Unpinned dependencies.
- Typosquatting against `guardchain/data/popular_packages.txt`.
- Imported but not declared dependencies.
- Declared but not imported dependencies.
- Local educational suspicious dependency list matches.

The local suspicious package list is demo data, not a complete malware intelligence feed.
