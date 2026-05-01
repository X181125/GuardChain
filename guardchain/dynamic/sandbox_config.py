from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class SandboxConfig:
    image: str = "guardchain-sandbox:latest"
    network: str = "none"
    timeout_seconds: int = 30
    memory_limit: str = "256m"
    cpus: str = "1"
    pids_limit: int = 128
    user: str = "1000:1000"
    read_only_rootfs: bool = True
    no_new_privileges: bool = True
    drop_capabilities: bool = True
    tmpfs: str = "/tmp:rw,noexec,nosuid,size=64m"
    environment: dict[str, str] = field(
        default_factory=lambda: {
            "GUARDCHAIN_SANDBOX": "1",
            "HOME": "/tmp/home",
            "USER": "sandbox",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
    )

    def security_args(self) -> list[str]:
        args = ["--network", self.network, "--memory", self.memory_limit, "--cpus", self.cpus, "--pids-limit", str(self.pids_limit), "--user", self.user]
        if self.read_only_rootfs:
            args.append("--read-only")
        if self.drop_capabilities:
            args.extend(["--cap-drop", "ALL"])
        if self.no_new_privileges:
            args.extend(["--security-opt", "no-new-privileges"])
        if self.tmpfs:
            args.extend(["--tmpfs", self.tmpfs])
        for key, value in self.environment.items():
            args.extend(["-e", f"{key}={value}"])
        return args

    def docker_args(self, package_dir: str | Path, trace_dir: str | Path) -> list[str]:
        package_path = Path(package_dir).resolve()
        output_path = Path(trace_dir).resolve()
        return [
            "run",
            "--rm",
            *self.security_args(),
            "-v",
            f"{package_path}:/package:ro",
            "-v",
            f"{output_path}:/guardchain-output:rw",
            "-w",
            "/package",
            self.image,
        ]
