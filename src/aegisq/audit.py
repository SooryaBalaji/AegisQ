"""Append-only, hash-chained audit log (JSON Lines).

Every pipeline stage writes here, and the report and CBOM are built from it,
so there is one record of what happened. Each entry carries the hash of the
previous one; with ``AEGISQ_AUDIT_KEY`` set the chain uses HMAC-SHA256, so
an attacker who can edit the file still cannot forge a consistent chain.
Writers take an exclusive cross-platform file lock (``audit.jsonl.lock``) so
concurrent processes (CLI, dashboard, agent) never interleave or fork the chain.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import json
import os
import threading
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aegisq.filelock import FileLock

GENESIS = "0" * 64
_SECRET_KEYS = {"key", "api_key", "token", "secret", "password", "private_key"}


@dataclass
class VerifyResult:
    ok: bool
    entries: int
    error: str | None = None
    bad_seq: int | None = None
    keyed: bool = False


def _canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str).encode()


def _scrub(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: ("[redacted]" if k.lower() in _SECRET_KEYS else _scrub(v)) for k, v in obj.items()}
    if isinstance(obj, list | tuple):
        return [_scrub(v) for v in obj]
    return obj


class AuditLog:
    def __init__(self, path: str | Path, key: bytes | None = None) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        env_key = os.environ.get("AEGISQ_AUDIT_KEY")
        self.key = key if key is not None else (env_key.encode() if env_key else None)
        self._lock = threading.Lock()
        self._checkpoint: _Checkpoint | None = None
        self._lockfile = self.path.with_name(self.path.name + ".lock")

    def _digest(self, entry: dict[str, Any]) -> str:
        body = _canonical(entry)
        if self.key:
            return hmac.new(self.key, body, hashlib.sha256).hexdigest()
        return hashlib.sha256(body).hexdigest()

    def append(self, event: str, data: dict[str, Any] | None = None, actor: str = "aegisq") -> dict[str, Any]:
        if not event or len(event) > 100:
            raise ValueError("invalid audit event name")
        with self._lock, FileLock(self._lockfile):
            fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_APPEND | getattr(os, "O_BINARY", 0), 0o640)
            try:
                last = _read_last_line(fd)
                if last:
                    prev = json.loads(last)
                    seq, prev_hash = int(prev["seq"]) + 1, str(prev["hash"])
                else:
                    seq, prev_hash = 1, GENESIS
                entry: dict[str, Any] = {
                    "seq": seq,
                    "ts": dt.datetime.now(dt.timezone.utc).isoformat(timespec="microseconds"),
                    "event": event,
                    "actor": actor,
                    "data": _scrub(data or {}),
                    "prev": prev_hash,
                }
                entry["hash"] = self._digest(entry)
                os.write(fd, _canonical(entry) + b"\n")
                os.fsync(fd)
                return entry
            finally:
                os.close(fd)

    def entries(self) -> Iterator[dict[str, Any]]:
        if not self.path.exists():
            return
        with self.path.open("r", encoding="utf-8") as f:
            for raw in f:
                line = raw.strip()
                if line:
                    yield json.loads(line)

    def tail(self, n: int = 100, event_prefix: str | None = None) -> list[dict[str, Any]]:
        """The last n entries (optionally filtered), read backwards so cost tracks n, not the log size."""
        if n <= 0:
            out = [e for e in self.entries() if not event_prefix or str(e.get("event", "")).startswith(event_prefix)]
            return out
        if not self.path.exists():
            return []
        found: list[dict[str, Any]] = []
        with self.path.open("rb") as f:
            pos = f.seek(0, os.SEEK_END)
            rest = b""
            while pos > 0 and len(found) < n:
                step = min(_TAIL_CHUNK, pos)
                pos -= step
                f.seek(pos)
                chunk = f.read(step) + rest
                lines = chunk.split(b"\n")
                rest = lines.pop(0) if pos > 0 else b""  # possibly partial: complete it with the next chunk
                for line in reversed(lines):
                    if not line.strip():
                        continue
                    e = json.loads(line)
                    if not event_prefix or str(e.get("event", "")).startswith(event_prefix):
                        found.append(e)
                        if len(found) == n:
                            break
        found.reverse()
        return found

    def verify(self) -> VerifyResult:
        """Check the whole chain. Repeated calls only re-hash the bytes already verified (cheap) and
        check new entries in full; any change to an earlier byte falls back to a full verification."""
        keyed = bool(self.key)
        if not self.path.exists():
            return VerifyResult(True, 0, keyed=keyed)
        with FileLock(self._lockfile), self.path.open("rb") as f:  # never read a half-written entry
            cp = self._checkpoint
            start = _Checkpoint(0, hashlib.sha256(), 0, 0, GENESIS)
            if cp is not None and cp.key == self.key and _prefix_matches(f, cp):
                start = cp.resume()
            else:
                f.seek(0)
            result, checkpoint = self._verify_from(f, start)
        self._checkpoint = checkpoint if result.ok else None
        return result

    def _verify_from(self, f: Any, cp: _Checkpoint) -> tuple[VerifyResult, _Checkpoint]:
        keyed = bool(self.key)
        prev, count, lineno = cp.prev, cp.count, cp.lines
        prefix = cp.digest
        offset = cp.offset
        for raw in f:
            lineno += 1
            prefix.update(raw)
            offset += len(raw)
            if not raw.strip():
                continue
            try:
                entry = json.loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError):
                return VerifyResult(False, count, f"line {lineno}: not JSON", lineno, keyed), cp
            seq = entry.get("seq")
            if seq != count + 1:
                return VerifyResult(False, count, f"line {lineno}: sequence gap (seq={seq})", seq, keyed), cp
            if entry.get("prev") != prev:
                return VerifyResult(False, count, f"seq {seq}: broken chain link", seq, keyed), cp
            claimed = entry.pop("hash", None)
            if not isinstance(claimed, str) or not hmac.compare_digest(claimed, self._digest(entry)):
                return VerifyResult(False, count, f"seq {seq}: hash mismatch (entry altered)", seq, keyed), cp
            prev = claimed
            count += 1
        return VerifyResult(True, count, keyed=keyed), _Checkpoint(offset, prefix, count, lineno, prev, self.key)


_TAIL_CHUNK = 64 * 1024


@dataclass
class _Checkpoint:
    """State after verifying the first `offset` bytes of the log."""

    offset: int
    digest: Any  # running sha256 of those bytes
    count: int
    lines: int
    prev: str
    key: bytes | None = None

    def resume(self) -> _Checkpoint:
        return _Checkpoint(self.offset, self.digest.copy(), self.count, self.lines, self.prev, self.key)


def _prefix_matches(f: Any, cp: _Checkpoint) -> bool:
    """True if the first cp.offset bytes are unchanged; leaves f positioned at cp.offset."""
    size = f.seek(0, os.SEEK_END)
    if size < cp.offset:
        return False
    f.seek(0)
    h = hashlib.sha256()
    remaining = cp.offset
    while remaining:
        block = f.read(min(1 << 20, remaining))
        if not block:
            return False
        h.update(block)
        remaining -= len(block)
    return hmac.compare_digest(h.digest(), cp.digest.digest())


def _read_last_line(fd: int) -> bytes:
    size = os.lseek(fd, 0, os.SEEK_END)
    if size == 0:
        return b""
    chunk = 4096
    pos = size
    buf = b""
    while pos > 0:
        step = min(chunk, pos)
        pos -= step
        os.lseek(fd, pos, os.SEEK_SET)
        buf = os.read(fd, step) + buf
        stripped = buf.rstrip(b"\n")
        idx = stripped.rfind(b"\n")
        if idx >= 0:
            return stripped[idx + 1 :]
    return buf.rstrip(b"\n")
