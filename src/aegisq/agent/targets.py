"""Managed targets: the only place AegisQ writes server configuration or runs server commands."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from aegisq.agent.guardrails import MAX_CONFIG_BYTES
from aegisq.models import ManagedNginx, ServiceTarget
from aegisq.proc import CmdResult, run_sync
from aegisq.workspace import atomic_write


class TargetUnavailable(RuntimeError):
    pass


class NginxTarget:
    def __init__(self, service: ServiceTarget) -> None:
        if service.managed is None:
            raise TargetUnavailable(f"{service.name} is not managed by AegisQ (scan-only)")
        self.service = service
        self.m: ManagedNginx = service.managed
        self.path = Path(self.m.config_path)

    def _check_path(self) -> None:
        try:
            st = os.lstat(self.path)
        except FileNotFoundError:
            raise TargetUnavailable(f"config {self.path} does not exist") from None
        if stat.S_ISLNK(st.st_mode):
            raise TargetUnavailable(f"config {self.path} is a symlink; refusing to follow it")
        if not stat.S_ISREG(st.st_mode):
            raise TargetUnavailable(f"config {self.path} is not a regular file")
        if st.st_size > MAX_CONFIG_BYTES:
            raise TargetUnavailable(f"config {self.path} is larger than {MAX_CONFIG_BYTES} bytes")

    def read_config(self) -> str:
        self._check_path()
        return self.path.read_text(encoding="utf-8")

    def write_config(self, text: str) -> None:
        """Atomic replace that keeps the file mode. The config directory, not the file, must be
        bind-mounted into containers, or they keep seeing the old inode."""
        self._check_path()
        mode = stat.S_IMODE(os.stat(self.path).st_mode)
        atomic_write(self.path, text, mode=mode)

    def test(self) -> CmdResult:
        return run_sync(self.m.test_cmd, timeout=self.m.command_timeout)

    def reload(self) -> CmdResult:
        return run_sync(self.m.reload_cmd, timeout=self.m.command_timeout)

    def version(self) -> CmdResult | None:
        if not self.m.version_cmd:
            return None
        return run_sync(self.m.version_cmd, timeout=self.m.command_timeout)
