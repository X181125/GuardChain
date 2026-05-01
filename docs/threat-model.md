# Threat Model

GuardChain targets Python package supply-chain threats, including:

- Malicious package uploads.
- Typosquatting and dependency confusion.
- Install-time malware in `setup.py`.
- Obfuscated payloads.
- Credential access and exfiltration patterns.
- Download-and-execute behavior.
- Distributed artifacts that differ from source repositories.

GuardChain assumes scanned packages are untrusted. It never imports, installs, or executes target package code.

Out of scope for v1:

- Runtime-only behavior that is invisible statically.
- Native binary reverse engineering.
- Full dependency resolution like `pip`.
- Complete malware intelligence coverage.
- Antivirus-style definitive verdicts.
