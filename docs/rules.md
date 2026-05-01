# GuardChain Rules

Each rule is a static signal for review, not a standalone verdict.

## Behavior

- `B001` Dynamic code execution: detects `eval`, `exec`, and `compile`. False positives: plugin systems and templating engines.
- `B002` System command execution: detects `os.system`, `os.popen`, and common `subprocess` calls. Higher risk in `setup.py`.
- `B003` Network communication: detects `requests`, `urllib`, `http.client`, and socket creation.
- `B004` Sensitive environment access: detects environment variables, host/user data, and credential-like path strings.
- `B005` Obfuscation or encoding: detects base64, marshal, zlib, codecs, and hex decoding.
- `B006` Obfuscated execution pattern: obfuscation and dynamic execution in the same file.
- `B007` Download and execute: network, file write, and execution behavior together.
- `B008` Possible exfiltration: sensitive access and network POST/request behavior together.
- `B009` Suspicious import: modules frequently seen in malware or automation abuse.
- `B010` Persistence-like behavior: startup, shell profile, systemd, or registry Run markers.
- `B011` Suspicious binary drop: writing executable/script extensions.
- `B012` Remote command execution pattern: network behavior and command/dynamic execution in the same function.

## Setup-Time

- `S001` Dangerous top-level setup.py behavior: command or dynamic execution at module scope.
- `S002` Custom install/build/develop command: `cmdclass` or setuptools command subclass.
- `S003` setup.py network access: network calls during install-time code.
- `S004` setup.py obfuscated dynamic execution: obfuscation and dynamic execution in setup.py.
- `S005` setup.py modifies environment or files: file writes or copy/move behavior in setup.py.

## Taint

- `T001` Sensitive source to network sink.
- `T002` Network source to file write.
- `T003` Network source to command execution.
- `T004` Obfuscation source to dynamic execution.
- `T005` Local secret file to network sink.
- `T006` Network source to dynamic execution.
- `T007` Sensitive source to command execution.

## Metadata

- `M001` Missing repository or homepage URL.
- `M002` Empty or very short description.
- `M003` Package name similar to a popular package.
- `M004` Suspicious executable logic in `setup.py`.
- `M005` Suspicious console script entrypoint.
- `M006` Unusual version pattern.
- `M007` Missing author or contact information.
- `M008` Suspicious project URL domain.

## Dependency

- `D001` Known suspicious demo dependency.
- `D002` Dependency name similar to a popular package.
- `D003` Direct URL dependency.
- `D004` Unpinned dependency.
- `D005` VCS dependency.
- `D006` Local path dependency.
- `D007` Imported module not declared as dependency.
- `D008` Declared dependency not imported by scanned Python files.
- `D009` Suspicious dependency name pattern.

## Integrity

- `I001` New Python file in distributed package.
- `I002` Modified Python file differs at AST level.
- `I003` New suspicious binary or script file.
- `I004` Integrity violation combined with dangerous behavior.

## Dynamic

- `Y001` Runtime process execution.
- `Y002` Runtime shell spawn.
- `Y003` Runtime network connection attempt or network-capable tool execution.
- `Y004` Runtime sensitive file access.
- `Y005` Runtime suspicious file write.
- `Y006` Runtime persistence-like file access.
- `Y007` Runtime package manager invocation.
- `Y008` Runtime binary or script drop.
- `Y009` Runtime attempt blocked by sandbox policy or sandbox timeout.
