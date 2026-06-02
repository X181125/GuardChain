# GuardChain Python Malware Scanner

GuardChain is a HERCULE-inspired educational prototype, not a full reimplementation of HERCULE. It is a static, graph-based, and optionally sandbox-assisted CLI for detecting suspicious Python packages in a software supply chain setting, designed for coursework, demos, and evidence-driven security research.

GuardChain intentionally keeps the implementation lightweight: Python AST traversal instead of CodeQL, lightweight taint tracking instead of a full CFG/data-flow database, optional dependency closure instead of ecosystem-scale analysis, and an optional Docker/strace sandbox as an extension.

The scanner never imports or executes the target package. It reads files, parses Python ASTs, extracts metadata and dependencies, and produces an explainable risk score.

## Architecture

- `loader.py`: accepts directories, `.tar.gz`, `.tgz`, `.tar`, `.whl`, and `.zip` files, then lists package files.
- `metadata_analyzer.py`: checks package metadata and suspicious `setup.py` text.
- `ast_analyzer.py`: detects behavior patterns using Python AST traversal.
- `taint_analyzer.py`: tracks simple source-to-sink flows inside functions.
- `dependency_analyzer.py`: extracts dependency names and flags risky dependency patterns.
- `dependency_resolver.py`: opt-in online dependency closure resolution using pip dry-run reports.
- `dependency_scanner.py`: opt-in wheel/zip dependency artifact scanning through the static pipeline.
- `integrity_analyzer.py`: optionally compares distributed package files against a source tree.
- `graph_builder.py`: creates JSON, Graphviz DOT, and Mermaid behavior graphs.
- `dynamic/`: optional Docker sandbox, strace parser, and runtime behavior analyzer.
- `scoring.py`: clamps score to 0-100 and labels packages as `BENIGN`, `SUSPICIOUS`, or `MALICIOUS`.
- `report.py`: prints terminal output and writes JSON, Markdown, and SARIF reports.

## Project Structure

```text
GuardChain/
├── guardchain/                         # Main Python package for the CLI and analyzers.
│   ├── __init__.py                      # Package marker and version-facing import surface.
│   ├── __main__.py                      # Enables `python -m guardchain`.
│   ├── cli.py                           # CLI command definitions for scan, sandbox, analyze, evaluate, and rules.
│   ├── models.py                        # Shared dataclasses: Finding, ScanResult, PackageContext, graph and score models.
│   ├── scanner.py                       # Static scan orchestrator; wires loader, analyzers, scoring, and graph output together.
│   ├── loader.py                        # Safe package loader for directories and archives with traversal, size, and file-count limits.
│   ├── metadata_analyzer.py             # Extracts package metadata and flags suspicious metadata patterns.
│   ├── ast_analyzer.py                  # AST-based behavior detector for dangerous calls, imports, persistence, and exfil-like patterns.
│   ├── setup_analyzer.py                # Static install-time analyzer for risky `setup.py` behavior and custom command classes.
│   ├── taint_analyzer.py                # Lightweight source-to-sink taint analyzer with simple interprocedural propagation.
│   ├── dependency_analyzer.py           # Parses dependency declarations and detects URL, VCS, unpinned, suspicious, and typo-like deps.
│   ├── dependency_resolver.py           # Opt-in pip dry-run dependency closure resolver; disabled by default.
│   ├── dependency_scanner.py            # Downloads wheel/zip artifacts and scans dependency packages with strict limits.
│   ├── integrity_analyzer.py            # Compares a distributed package against a source tree using file and AST-level diffs.
│   ├── graph_builder.py                 # Builds evidence graphs and exports Graphviz DOT and Mermaid formats.
│   ├── scoring.py                       # Converts findings into deterministic 0-100 risk scores and BENIGN/SUSPICIOUS/MALICIOUS labels.
│   ├── report.py                        # Renders terminal, JSON, Markdown, SARIF, DOT, and Mermaid artifacts.
│   ├── evaluator.py                     # Dataset evaluation command for labeled samples and basic metrics.
│   ├── utils.py                         # Shared helper functions for safe reads, path normalization, previews, and similarity checks.
│   ├── dynamic/                         # Explicit opt-in runtime analysis; never used by default static scan.
│   │   ├── sandbox_config.py            # Docker sandbox hardening flags: no network, read-only rootfs, non-root, limits, timeout.
│   │   ├── execution_plan.py            # Maps sandbox modes to safe command plans wrapped with `strace`.
│   │   ├── docker_runner.py             # Runs Docker sandbox, collects trace output, and converts dynamic findings to ScanResult.
│   │   ├── strace_parser.py             # Parses file, process, and network syscall traces into DynamicEvent records.
│   │   └── dynamic_analyzer.py          # Converts runtime events into Y001-Y009 dynamic findings.
│   ├── rules/                           # Built-in rule metadata and validation inputs.
│   │   ├── behavior_rules.yaml          # Behavior rule definitions.
│   │   ├── taint_rules.yaml             # Taint-flow rule definitions.
│   │   ├── dependency_rules.yaml        # Dependency rule definitions.
│   │   ├── metadata_rules.yaml          # Metadata rule definitions.
│   │   ├── integrity_rules.yaml         # Integrity rule definitions.
│   │   ├── dynamic_rules.yaml           # Runtime sandbox rule definitions.
│   │   ├── suspicious_rules.json        # Compact rule registry used for built-in rule titles, severities, and scores.
│   │   └── rule_registry.py             # Loads and validates YAML/JSON rule metadata.
│   └── data/                            # Small local datasets used by analyzers.
│       ├── popular_packages.txt         # Popular package names for typosquatting similarity checks.
│       ├── malicious_packages.yaml      # Demo-only suspicious dependency blacklist.
│       ├── suspicious_domains.yaml      # Suspicious project URL/domain hints.
│       ├── suspicious_names.yaml        # Suspicious dependency/package name tokens.
│       ├── import_name_map.yaml         # Common distribution-to-import name mappings such as PyYAML -> yaml.
│       └── allowlist.yaml               # Reserved allowlist data for reducing noisy detections.
├── samples/                             # Safe demo packages used by tests and examples.
│   ├── benign_pkg/                      # Low-risk package expected to score BENIGN.
│   ├── suspicious_pkg/                  # Environment/socket patterns expected to score SUSPICIOUS.
│   ├── malicious_like_pkg/              # Harmless obfuscation/exfil-shaped sample expected to score MALICIOUS.
│   ├── setup_time_malicious_like_pkg/   # Static setup.py install-time behavior sample.
│   ├── exfiltration_like_pkg/           # Simulated environment-to-network flow using example.invalid.
│   ├── download_execute_like_pkg/       # Simulated download, write, and command-execution shape.
│   ├── typosquat_like_pkg/              # Package/dependency names close to popular packages.
│   ├── divide_and_hide/                 # Root package plus suspicious dependency payload demo.
│   └── integrity/                       # Source/dist comparison fixture.
├── tests/                               # Unit and integration tests for loader, analyzers, CLI, reports, scoring, and samples.
├── docs/                                # Extended documentation for architecture, rules, safety, reports, and analysis modes.
├── docker/                              # Docker assets for optional dynamic sandbox analysis.
│   └── Dockerfile.sandbox               # Reference image with Python and strace for `guardchain sandbox`.
├── schemas/                             # Machine-readable schemas for report validation.
├── reports/                             # Example/generated reports; safe to regenerate during demos.
├── rules/                               # Legacy/top-level rule fixture kept for compatibility with older examples.
├── pyproject.toml                       # Build metadata, package metadata, console script entrypoint, and optional dev extras.
├── requirements.txt                     # Runtime dependency list for local setup.
├── README.md                            # Main project overview and usage guide.
├── SECURITY.md                          # Security policy and reporting notes.
├── CONTRIBUTING.md                      # Contribution guidelines.
├── CODE_OF_CONDUCT.md                   # Community conduct guidelines.
└── LICENSE                              # Project license.
```

## Workflow

### Static scan workflow

`guardchain scan` is the default workflow and never executes target package code.

```text
User input path
  -> Safe loader
  -> PackageContext
  -> Metadata analysis
  -> AST behavior analysis
  -> setup.py static analysis
  -> Taint analysis
  -> Dependency analysis
  -> Optional dependency closure resolution and dependency artifact scanning
  -> Optional integrity analysis
  -> Behavior graph builder
  -> Scoring engine
  -> Terminal/JSON/Markdown/SARIF/DOT/Mermaid reports
```

1. Input is a directory or archive supplied through `--path`.
2. `loader.py` validates the target, safely extracts archives when needed, blocks path traversal, enforces `--max-files` and `--max-size-mb`, and builds a `PackageContext`.
3. `metadata_analyzer.py` reads `pyproject.toml`, `setup.cfg`, `setup.py`, `PKG-INFO`, `METADATA`, and dependency metadata without executing them.
4. `ast_analyzer.py` parses Python files into ASTs, resolves common import aliases, and emits behavior findings such as command execution, network calls, obfuscation, persistence-like paths, and exfiltration-shaped code.
5. `setup_analyzer.py` gives special static attention to `setup.py`, including top-level dangerous calls, custom install/build/develop classes, and `cmdclass` mappings.
6. `taint_analyzer.py` tracks simple variable flows from sensitive, network, file-secret, and obfuscation sources into dangerous sinks. It also handles direct function return and parameter wrapper flows.
7. `dependency_analyzer.py` extracts declared dependencies, compares them with inferred imports, applies common import-name mappings, and flags risky dependency declarations.
8. If `--resolve-deps` is passed, `dependency_resolver.py` asks pip for a dry-run JSON resolution report using declared requirement names/specifiers only. It uses `--only-binary=:all:` by default and reports warnings instead of failing the scan.
9. If dependency resolution succeeds, `dependency_scanner.py` downloads resolved wheel/zip artifacts with strict limits, scans them statically, and annotates dependency-origin findings with package, version, and chain context.
10. `integrity_analyzer.py` runs when `--source` is provided, or when `--source-auto-fetch` is explicitly enabled and a supported repository URL can be extracted; it compares distributed package files against the source tree and correlates suspicious new or modified files.
11. `graph_builder.py` creates an evidence graph linking packages, files, functions, imports, API calls, dependencies, findings, suspicious flows, and dependency risk paths.
12. `scoring.py` groups duplicate root causes, applies evidence-strength multipliers, caps the score at 100, and assigns `BENIGN`, `SUSPICIOUS`, or `MALICIOUS`.
13. `report.py` writes the selected artifacts and keeps the CLI exit code `0` for successful scans unless an explicit fail threshold is requested.

### Dynamic sandbox workflow

Dynamic analysis is separate and explicit. It only runs when the user chooses `guardchain sandbox` or `guardchain analyze --with-sandbox`.

```text
User opt-in
  -> Safe loader
  -> Docker sandbox command plan
  -> strace-monitored execution
  -> DynamicEvent parsing
  -> Y-rule findings
  -> Dynamic or combined report
```

1. The user builds the reference sandbox image with `docker build -f docker/Dockerfile.sandbox -t guardchain-sandbox:latest .`.
2. `sandbox_config.py` applies the default hardening profile: no network, read-only root filesystem, dropped capabilities, non-root user, resource limits, placeholder environment variables, and timeout.
3. `execution_plan.py` selects an explicit runtime mode such as `setup-py-metadata`, `setup-py-install`, or `pip-install-no-deps`.
4. `docker_runner.py` mounts the package read-only at `/package`, writes trace output to `/guardchain-output`, and runs the command under `strace`.
5. `strace_parser.py` converts trace lines into structured file, process, and network events.
6. `dynamic_analyzer.py` emits `Y001`-`Y009` findings for runtime process execution, shell spawn, network attempts, sensitive file access, suspicious writes, persistence-like access, package manager invocation, binary/script drops, and sandbox-blocked behavior.
7. `guardchain sandbox` reports only dynamic evidence. `guardchain analyze --with-sandbox` combines static and dynamic findings into one score and report.

## Install

Python 3.11+ is required. GuardChain prefers the standard library where practical and uses the lightweight runtime dependencies listed in `requirements.txt`.

```bash
cd GuardChain
python -m unittest discover
```

Optional editable install:

```bash
python -m pip install -e .
```

## Usage

Run from the project root:

```bash
python -m guardchain scan --path ./samples/benign_pkg
python -m guardchain scan --path ./samples/suspicious_pkg
python -m guardchain scan --path ./samples/malicious_like_pkg --json reports/result.json
python -m guardchain scan --path ./dist_pkg --source ./source_repo
python -m guardchain scan --path ./samples/malicious_like_pkg --markdown reports/report.md
python -m guardchain scan --path ./samples/malicious_like_pkg --sarif reports/guardchain.sarif
python -m guardchain scan --path ./samples/malicious_like_pkg --graph-dot reports/behavior_graph.dot
python -m guardchain scan --path ./samples/malicious_like_pkg --graph-mermaid reports/behavior_graph.mmd
python -m guardchain scan \
  --path ./samples/divide_and_hide/root_pkg \
  --resolve-deps \
  --dependency-no-index \
  --dependency-find-links ./samples/divide_and_hide/dist \
  --json reports/divide_and_hide.json \
  --markdown reports/divide_and_hide.md \
  --graph-mermaid reports/divide_and_hide.mmd
python -m guardchain scan --path ./dist_pkg --source-auto-fetch
python -m guardchain scan --path ./samples/malicious_like_pkg --max-files 5000 --max-size-mb 100
python -m guardchain scan --path ./samples/malicious_like_pkg --fail-on-malicious
python -m guardchain sandbox --path ./samples/setup_time_malicious_like_pkg --mode setup-py-install --json reports/dynamic.json --trace reports/trace.log
python -m guardchain analyze --path ./samples/setup_time_malicious_like_pkg --with-sandbox --json reports/combined.json
python -m guardchain evaluate --dataset ./samples --labels ./labels.csv --json reports/eval.json
python -m guardchain rules list
python -m guardchain rules validate
guardchain scan --path ./samples/malicious_like_pkg
```

For deterministic dependency-closure demos, use the local fixture wheel in `samples/divide_and_hide/dist` or a controlled package index. Resolver and download failures are reported as limitations instead of aborting the scan.

Dynamic sandbox mode requires Docker and a sandbox image with `strace`:

```bash
docker build -f docker/Dockerfile.sandbox -t guardchain-sandbox:latest .
```

Example output:

```text
Target: ./samples/malicious_like_pkg
Package: malicious_like_pkg
Label: MALICIOUS
Risk score: 100/100
Python files analyzed: 2
Dependencies: bot-package, requests

Findings:
[CRITICAL] B006 malicious_like_pkg/payload.py:7
Encoded or obfuscated content may be dynamically executed
```

## Rule List

Metadata:

- `M001`: Missing repository URL.
- `M002`: Very short description.
- `M003`: Package name similar to a popular package.
- `M004`: Suspicious executable logic in `setup.py`.

Behavior:

- `B001`: Dynamic code execution with `eval`, `exec`, or `compile`.
- `B002`: OS command execution through `os` or `subprocess`.
- `B003`: Network connection through `requests`, `urllib`, `http.client`, or `socket`.
- `B004`: Sensitive environment or credential access.
- `B005`: Obfuscation or encoded payload handling.
- `B006`: Obfuscated content may be dynamically executed.
- `B007`: Possible download-and-execute behavior.
- `B008`: Possible data exfiltration behavior.
- `B009`: Suspicious module import.
- `B010`: Persistence-like behavior.
- `B011`: Suspicious binary or script drop.
- `B012`: Remote command execution pattern.

Taint:

- `T001`: Sensitive source flows into network sink.
- `T002`: Network source flows into file write.
- `T003`: Network source flows into command execution.
- `T004`: Obfuscation source flows into dynamic execution.
- `T005`: Local file secret flows into network sink.
- `T006`: Network source flows into dynamic execution.
- `T007`: Sensitive source flows into command execution.

Setup-time:

- `S001`: Dangerous top-level `setup.py` behavior.
- `S002`: Custom install/build/develop command.
- `S003`: `setup.py` network access.
- `S004`: `setup.py` obfuscated dynamic execution.
- `S005`: `setup.py` modifies environment or files.

Dependency:

- `D001`: Known malicious/suspicious demo dependency.
- `D002`: Typosquatting dependency.
- `D003`: Direct URL dependency.
- `D004`: Unpinned dependency.
- `D005`: VCS dependency.
- `D006`: Local path dependency.
- `D007`: Imported but not declared dependency.
- `D008`: Declared but not imported dependency.
- `D009`: Suspicious dependency name pattern.

Dependency closure scanning is not part of the default offline scan. It is enabled only with `--resolve-deps`, uses pip dry-run resolution for declared requirements, prefers binary wheels, and records unresolved packages as warnings.

Integrity:

- `I001`: New Python file exists in package but not source repo.
- `I002`: Python file differs from source repo at AST level.
- `I003`: Suspicious new binary or script file.
- `I004`: Integrity violation combined with dangerous behavior.

Dynamic:

- `Y001`: Runtime process execution.
- `Y002`: Runtime shell spawn.
- `Y003`: Runtime network connection attempt or network-capable tool execution.
- `Y004`: Runtime sensitive file access.
- `Y005`: Runtime suspicious file write.
- `Y006`: Runtime persistence-like file access.
- `Y007`: Runtime package manager invocation.
- `Y008`: Runtime binary or script drop.
- `Y009`: Runtime attempt blocked by sandbox policy or sandbox timeout.

## Demo Samples

- `samples/benign_pkg`: simple arithmetic helper, expected `BENIGN`.
- `samples/suspicious_pkg`: local environment and socket patterns, expected `SUSPICIOUS`.
- `samples/malicious_like_pkg`: safe simulated obfuscation and exfiltration-shaped code, expected `MALICIOUS`.
- `samples/setup_time_malicious_like_pkg`: safe setup-time command pattern, expected `MALICIOUS`.
- `samples/exfiltration_like_pkg`: safe `os.environ` to `requests.post` flow, expected `MALICIOUS` or `SUSPICIOUS`.
- `samples/download_execute_like_pkg`: safe download-write-command shape, expected `MALICIOUS`.
- `samples/typosquat_like_pkg`: typo-like package/dependency names.
- `samples/divide_and_hide`: benign root package plus a separate suspicious dependency package.
- `samples/integrity`: source/dist comparison demo.

The malicious-like sample is deliberately harmless. It contains code patterns for static detection, but the scanner does not execute the sample package.

## Safety Notes

- The scanner does not run `setup.py`.
- The scanner does not import the scanned package.
- The scanner does not execute payloads.
- The default scanner does not send network requests.
- Dependency closure resolution is disabled by default and only runs with `--resolve-deps`.
- Dependency resolution never installs the target package path; it uses declared dependency requirement strings only.
- Dependency artifact scanning prefers binary wheels and skips unresolved packages instead of building sdists.
- Source repository fetching is disabled by default and only runs with `--source-auto-fetch`.
- Archive extraction blocks absolute paths and `../` traversal entries.
- Dynamic analysis is explicit opt-in through `sandbox` or `analyze --with-sandbox`.
- The default Docker sandbox uses no network, read-only root filesystem, dropped capabilities, non-root user, resource limits, and timeout.
- Demo payload strings are harmless and intended only for static detection.

## Limitations

- The tool is static-only and cannot detect every runtime behavior.
- Rule-based scoring can produce false positives and false negatives.
- Dependency closure is optional and bounded; it is not a full ecosystem-scale analysis.
- Dependency relationships depend on pip report metadata and may be partial.
- GuardChain uses Python AST and lightweight taint analysis rather than CodeQL or a full data-flow database.
- It is not a replacement for antivirus, sandboxing, or human review.
- Dynamic results depend on Docker, the sandbox image, and the runtime paths exercised during analysis.
- It does not analyze C/C++ extensions or binary payloads.

## Development

```bash
python -m pip install -r requirements.txt
python -m pip install -e .
python -m unittest discover
python -m guardchain scan --path ./samples/benign_pkg
```

GuardChain performs static evidence-based risk detection for suspicious or malicious Python package behavior. It does not prove that a package is safe or malicious in every runtime context.
