"""Safe subprocess execution: argv only (never a shell), hard timeouts, bounded output."""

from __future__ import annotations

import asyncio
import contextlib
import os
import signal
import subprocess
import sys
from dataclasses import dataclass
from typing import Any

MAX_OUTPUT = 1 << 20  # 1 MiB per stream


@dataclass
class CmdResult:
    argv: list[str]
    returncode: int | None  # None when the command timed out or could not start
    stdout: str
    stderr: str
    timed_out: bool = False
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out and self.error is None

    @property
    def output(self) -> str:
        parts = [p for p in (self.stdout.strip(), self.stderr.strip()) if p]
        if self.error:
            parts.append(self.error)
        return "\n".join(parts)


def _check_argv(argv: list[str]) -> None:
    if not argv or not all(isinstance(a, str) for a in argv):
        raise ValueError("argv must be a non-empty list of strings")
    if any("\x00" in a for a in argv):
        raise ValueError("NUL byte in argument")


async def run_async(argv: list[str], timeout: float, stdin_data: bytes | None = None) -> CmdResult:
    _check_argv(argv)
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.PIPE if stdin_data is not None else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            **_GROUP_KWARGS,  # own process group so a timeout kills children too
        )
    except (OSError, ValueError) as e:
        return CmdResult(argv, None, "", "", error=f"cannot run {argv[0]}: {e}")
    try:
        out, err = await asyncio.wait_for(proc.communicate(stdin_data), timeout)
    except asyncio.TimeoutError:
        _kill_group(proc.pid)
        with contextlib.suppress(Exception):
            await asyncio.wait_for(proc.wait(), 5)
        return CmdResult(argv, None, "", "", timed_out=True, error=f"timed out after {timeout:g}s")
    return CmdResult(argv, proc.returncode, _decode(out), _decode(err))


def run_sync(argv: list[str], timeout: float, stdin_data: bytes | None = None) -> CmdResult:
    _check_argv(argv)
    try:
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE if stdin_data is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            **_GROUP_KWARGS,
        )
    except (OSError, ValueError) as e:
        return CmdResult(argv, None, "", "", error=f"cannot run {argv[0]}: {e}")
    try:
        out, err = proc.communicate(stdin_data, timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_group(proc.pid)
        with contextlib.suppress(Exception):
            proc.communicate(timeout=5)
        return CmdResult(argv, None, "", "", timed_out=True, error=f"timed out after {timeout:g}s")
    return CmdResult(argv, proc.returncode, _decode(out), _decode(err))


# A new process group (POSIX session / Windows process group) lets a timeout kill grandchildren too.
_GROUP_KWARGS: dict[str, Any] = (
    {"creationflags": getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)}
    if sys.platform == "win32"
    else {"start_new_session": True}
)


def _kill_group(pid: int) -> None:
    if sys.platform == "win32":  # pragma: no cover - exercised by the Windows CI job
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)], capture_output=True, check=False)
        return
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(pid, signal.SIGKILL)


def _decode(b: bytes | None) -> str:
    if not b:
        return ""
    return b[:MAX_OUTPUT].decode("utf-8", "replace")
