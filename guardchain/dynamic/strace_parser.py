from __future__ import annotations

import re
from pathlib import Path

from ..models import DynamicEvent

FILE_SYSCALLS = {"open", "openat", "creat", "read", "write", "rename", "unlink", "chmod", "chown", "mkdir"}
PROCESS_SYSCALLS = {"execve", "clone", "fork", "vfork"}
NETWORK_SYSCALLS = {"socket", "connect", "sendto", "recvfrom", "sendmsg", "recvmsg"}
SENSITIVE_PATH_MARKERS = {"/etc/passwd", "/etc/shadow", ".ssh", "id_rsa", ".aws/credentials", ".config/gcloud", ".kube/config"}
PERSISTENCE_MARKERS = {".bashrc", ".zshrc", ".profile", "systemd", "crontab", "startup"}

_LINE_RE = re.compile(r"^(?:(?P<pid>\d+)\s+)?(?P<timestamp>\d\d:\d\d:\d\d(?:\.\d+)?)\s+(?P<operation>[A-Za-z_][A-Za-z0-9_]*)\((?P<args>.*)\)\s+=\s+(?P<result>.*)$")
_QUOTED_RE = re.compile(r'"((?:\\.|[^"\\])*)"')
_INET_RE = re.compile(r'inet_addr\("([^"]+)"\)')
_PORT_RE = re.compile(r"htons\((\d+)\)")


def parse_strace_text(text: str) -> list[DynamicEvent]:
    events: list[DynamicEvent] = []
    for line in text.splitlines():
        event = parse_strace_line(line)
        if event:
            events.append(event)
    return events


def parse_strace_file(path: str | Path) -> list[DynamicEvent]:
    return parse_strace_text(Path(path).read_text(encoding="utf-8", errors="replace"))


def parse_strace_line(line: str) -> DynamicEvent | None:
    line = line.strip()
    match = _LINE_RE.match(line)
    if not match:
        return None
    operation = match.group("operation")
    if operation not in FILE_SYSCALLS | PROCESS_SYSCALLS | NETWORK_SYSCALLS:
        return None
    args = match.group("args")
    target = _target_for(operation, args)
    event_type = _event_type(operation)
    severity_hint = _severity_hint(event_type, operation, target, line)
    pid_text = match.group("pid")
    return DynamicEvent(
        event_type=event_type,
        operation=operation,
        target=target,
        process=_process_name(operation, target),
        pid=int(pid_text) if pid_text else None,
        timestamp=match.group("timestamp"),
        raw=line,
        severity_hint=severity_hint,
    )


def _event_type(operation: str) -> str:
    if operation in PROCESS_SYSCALLS:
        return "process"
    if operation in NETWORK_SYSCALLS:
        return "network"
    return "file"


def _target_for(operation: str, args: str) -> str:
    if operation == "connect":
        ip = _match_text(_INET_RE, args)
        port = _match_text(_PORT_RE, args)
        if ip and port:
            return f"{ip}:{port}"
        return ip or args[:120]
    quoted = _QUOTED_RE.findall(args)
    if operation == "openat" and len(quoted) >= 1:
        return quoted[0]
    if quoted:
        return quoted[0]
    return args[:120]


def _process_name(operation: str, target: str) -> str | None:
    if operation == "execve" and target:
        return Path(target).name
    return None


def _severity_hint(event_type: str, operation: str, target: str, raw: str) -> str | None:
    lowered = target.lower()
    raw_lowered = raw.lower()
    if "eacces" in raw_lowered or "eperm" in raw_lowered or "permission denied" in raw_lowered or "operation not permitted" in raw_lowered:
        return "sandbox_restriction"
    if event_type == "network" and operation == "connect":
        return "network_connect"
    if any(marker in lowered for marker in SENSITIVE_PATH_MARKERS):
        return "sensitive_file"
    if any(marker in lowered for marker in PERSISTENCE_MARKERS):
        return "persistence_path"
    if operation in {"open", "openat", "creat"} and any(flag in raw for flag in ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND")):
        return "file_write"
    return None


def _match_text(pattern: re.Pattern[str], value: str) -> str | None:
    match = pattern.search(value)
    return match.group(1) if match else None
