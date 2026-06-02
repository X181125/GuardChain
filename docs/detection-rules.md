# GuardChain Detection Rules

This document summarizes the implemented static rules used by GuardChain for the coursework malware-behavior corpus. Examples are harmless source-text triggers only; GuardChain does not execute scanned package code during static analysis.

## Behavior Rules

| Rule | Title | Severity | Logic | Evidence |
| --- | --- | --- | --- | --- |
| B001 | Dynamic code execution | HIGH | Detects `eval`, `exec`, `compile`, `execfile`, `runpy`, `types.FunctionType`, and dynamic import forms after alias resolution. | Calls, line, function, argument preview |
| B002 | System command execution | HIGH/CRITICAL in setup.py | Detects `os.system`, `os.popen`, `subprocess.*`, `pty.spawn`, `commands.getoutput`, and `os.exec*`/`os.spawn*`, including aliases and `getattr`. | Calls, line, function, argument preview |
| B003 | Network communication | MEDIUM | Detects outbound APIs in `requests`, `urllib`, `http.client`, `socket`, `httpx`, `aiohttp`, `ftplib`, `smtplib`, `telnetlib`, `paramiko`, and websocket clients. | Calls and arguments |
| B004 | Sensitive environment access | HIGH | Detects `os.environ`, `os.getenv`, host/user identifiers, home-directory APIs, and secret-like path strings. | Calls or string markers |
| B005 | Obfuscation or encoding | MEDIUM | Detects base64, marshal, zlib, codecs, and hex decoding/encoding APIs. | Calls |
| B006 | Obfuscated execution pattern | CRITICAL | Correlates obfuscation with dynamic execution in the same file. | Correlated calls |
| B007 | Download and execute pattern | CRITICAL | Correlates network access, file write, and command/dynamic execution. | Correlated calls |
| B008 | Possible exfiltration pattern | CRITICAL | Correlates sensitive access with POST/PUT/request/send-style network sinks. | Sensitive and network calls |
| B009 | Suspicious import | LOW | Notes imports commonly seen in malware-like package behavior. | Import name |
| B010 | Persistence-like behavior | HIGH | Detects startup, shell profile, cron, systemd, and Run/RunOnce markers. | String marker |
| B011 | Suspicious binary drop | HIGH | Detects writes or path strings ending in executable/script/binary extensions. | Path or write call |
| B012 | Remote command execution pattern | CRITICAL | Detects network behavior in the same function as command/dynamic execution. | Function and pattern set |
| B013 | Import-time side effect | HIGH | Detects suspicious network, file, command, or dynamic behavior at module top level. | Top-level calls |
| B014 | Shell-enabled subprocess execution | CRITICAL | Detects `shell=True` on subprocess command execution APIs. | Subprocess call and arguments |

Safe trigger examples include `getattr(os, "system")("echo test")`, `subprocess.run("echo test", shell=True)`, and `base64.b64decode("..."); exec(payload)`.

## Taint Rules

| Rule | Title | Severity | Logic | Evidence |
| --- | --- | --- | --- | --- |
| T001 | Sensitive source flows into network sink | HIGH | Tracks environment, host/user, and home-directory data into network POST/PUT/request/send sinks. | Source, sink, variable, function, flow |
| T002 | Network source flows into file write | HIGH | Tracks network response data into `open(..., "w")`, `Path.write_*`, direct open writes, copy, and move sinks. | Source and file-write sink |
| T003 | Network source flows into command execution | CRITICAL | Tracks downloaded data into command execution APIs. | Source and command sink |
| T004 | Obfuscation source flows into dynamic execution | CRITICAL | Tracks decoded/decompressed data into `exec`, `eval`, or `compile`. | Source and dynamic sink |
| T005 | Local file secret flows into network sink | HIGH | Tracks reads from secret-like file paths into network sinks. | Secret path and network sink |
| T006 | Network source flows into dynamic execution | CRITICAL | Tracks network data into dynamic execution. | Source and dynamic sink |
| T007 | Sensitive source flows into command execution | HIGH | Tracks local sensitive data into command execution APIs. | Source and command sink |
| T008 | Sensitive source flows into suspicious file write | HIGH | Tracks sensitive/local-secret data into persistence-like or executable/script file writes. | Source, sink, variable, flow |

The taint analyzer supports assignments, annotated assignments, tuple/list unpacking, attributes such as `self.token`, simple containers, f-strings/concatenation, wrapper returns, and wrapper functions that pass parameters to sinks.

## Setup and Metadata Rules

| Rule | Title | Severity | Logic | Evidence |
| --- | --- | --- | --- | --- |
| S001 | Dangerous top-level setup.py behavior | CRITICAL | Detects command/dynamic execution at setup.py top level. | Call and arguments |
| S002 | Custom install/build/develop command | HIGH | Detects custom `cmdclass` hooks and classes extending install/build/develop/egg/sdist/wheel commands. | Class, base, cmdclass |
| S003 | setup.py network access | HIGH | Detects network calls in setup.py. | Call and arguments |
| S004 | setup.py obfuscated dynamic execution | CRITICAL | Correlates obfuscation with dynamic execution in setup.py. | Pattern list |
| S005 | setup.py modifies environment or files | MEDIUM | Detects setup.py file/environment write patterns. | Call and arguments |
| S006 | Custom setup command contains suspicious behavior | CRITICAL | Detects command or network behavior inside a custom command `run()` method. | Class, function, call |
| M010 | Custom build backend | MEDIUM | Detects custom/local `pyproject.toml` build backends or backend paths. | Build backend and backend path |

## Dependency Rules

| Rule | Title | Severity | Logic | Evidence |
| --- | --- | --- | --- | --- |
| D001 | Known suspicious demo dependency | CRITICAL | Matches the local educational suspicious dependency list. | Requirement text |
| D002 | Typosquatting dependency | HIGH | Finds dependency names similar to popular packages. | Requirement text and similar package |
| D003 | Direct URL dependency | MEDIUM | Detects PEP 508 direct URLs and raw HTTP(S) requirements. | Requirement text |
| D004 | Unpinned dependency | LOW | Detects index dependencies without exact pins. | Requirement text |
| D005 | VCS dependency | MEDIUM | Detects `git+`, `hg+`, `svn+`, and `bzr+` requirements. | Requirement text |
| D006 | Local path dependency | MEDIUM | Detects local path or `file:` requirements. | Requirement text |
| D007 | Imported but not declared dependency | LOW | Compares imports against declared third-party dependencies while excluding stdlib/local modules. | Import name |
| D008 | Declared but not imported dependency | LOW | Finds declared dependencies unused by scanned Python files. | Dependency name |
| D009 | Suspicious dependency name pattern | MEDIUM | Detects dependency names containing configured suspicious tokens. | Requirement text |
| D010 | Editable dependency | MEDIUM | Detects `-e` or `--editable` requirements. | Requirement text |

GuardChain parses dependencies from `requirements.txt`, `pyproject.toml`, `setup.cfg`, `setup.py`, `PKG-INFO`, and `METADATA`. Normal tests do not resolve dependencies over the network.

## Integrity Rules

| Rule | Title | Severity | Logic | Evidence |
| --- | --- | --- | --- | --- |
| I001 | New Python file in distributed package | MEDIUM/HIGH | Detects Python files present in a distribution but absent from the source tree; severity rises when suspicious behavior is present. | Imports, calls, top-level calls, dangerous tokens |
| I002 | Modified Python file | MEDIUM/HIGH | Compares AST summaries after stripping docstrings and comments. | Changed functions, added imports, added suspicious calls, top-level behavior |
| I003 | Suspicious new binary or script file | HIGH | Detects new executable/script/binary files in the distribution. | File path |
| I004 | Integrity violation combined with dangerous behavior | HIGH | Emitted when a new or modified file introduces suspicious behavior. | Integrity rule and added dangerous behavior |
| I005 | Missing Python file in distributed package | LOW | Detects Python files present in source but missing from the distribution. | File path |

Docstring-only and comment-only changes are intentionally ignored by integrity comparison.
