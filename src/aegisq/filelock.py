"""Cross-process file locks that work on Linux, macOS and Windows.

The lock lives in its own file (``<name>.lock``), never on the data file: on
Windows, byte-range locks are mandatory and would block other processes from
even reading the locked data.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from types import TracebackType

if sys.platform != "win32":
    import fcntl


class LockHeld(RuntimeError):
    """A non-blocking lock attempt found the lock taken by someone else."""


class FileLock:
    def __init__(self, path: str | Path, *, blocking: bool = True, timeout: float = 60.0) -> None:
        self.path = Path(path)
        self.blocking = blocking
        self.timeout = timeout
        self._fd: int | None = None

    def acquire(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT | getattr(os, "O_BINARY", 0), 0o600)
        try:
            if sys.platform == "win32":  # pragma: no cover
                self._acquire_windows(fd)
            else:
                flags = fcntl.LOCK_EX | (0 if self.blocking else fcntl.LOCK_NB)
                try:
                    fcntl.flock(fd, flags)
                except BlockingIOError:
                    raise LockHeld(str(self.path)) from None
        except BaseException:
            os.close(fd)
            raise
        self._fd = fd

    def _acquire_windows(self, fd: int) -> None:  # pragma: no cover
        if sys.platform != "win32":  # narrows the platform for the type checker too
            raise RuntimeError("Windows-only code path")
        import msvcrt

        deadline = time.monotonic() + self.timeout
        while True:
            try:
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                return
            except OSError:
                if not self.blocking:
                    raise LockHeld(str(self.path)) from None
                if time.monotonic() >= deadline:
                    raise TimeoutError(f"could not lock {self.path} within {self.timeout:g}s") from None
                time.sleep(0.01)

    def release(self) -> None:
        fd, self._fd = self._fd, None
        if fd is None:
            return
        try:
            if sys.platform == "win32":  # pragma: no cover
                import msvcrt

                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    def __enter__(self) -> FileLock:
        self.acquire()
        return self

    def __exit__(
        self, exc_type: type[BaseException] | None, exc: BaseException | None, tb: TracebackType | None
    ) -> None:
        self.release()
