"""On-disk workspace: audit log, approvals database, scan results, backups and artifacts."""

from __future__ import annotations

import contextlib
import json
import os
import sqlite3
import sys
import tempfile
import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aegisq.audit import AuditLog
from aegisq.models import ScanReport

RESERVED_APPROVERS = {"agent", "aegisq", "claude", "system", "auto"}


def atomic_write(path: Path, data: bytes | str, mode: int = 0o644) -> None:
    """Write via a temp file in the same directory and rename, so readers never see a partial file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    raw = data.encode() if isinstance(data, str) else data
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".tmp")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(raw)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        _replace(tmp, path)
    except BaseException:
        with _suppress():
            os.unlink(tmp)
        raise


def _replace(src: str, dst: Path) -> None:
    """os.replace, retried briefly: on Windows it fails while another process has dst open."""
    for attempt in range(50):
        try:
            os.replace(src, dst)
            return
        except PermissionError:
            if sys.platform != "win32" or attempt == 49:
                raise
            time.sleep(0.02)


def _suppress() -> contextlib.suppress:
    return contextlib.suppress(OSError)


@dataclass
class Approval:
    id: str
    service: str
    proposal_id: str
    diff: str
    diff_sha256: str
    summary: str
    status: str
    requested_by: str
    requested_at: float
    expires_at: float
    decided_by: str | None
    decided_at: float | None
    reason: str | None

    def to_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


class ApprovalStore:
    """Human approvals, persisted in SQLite so the dashboard, CLI and agent can be separate processes."""

    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self._local = threading.local()
        with self._conn() as c:
            c.execute(
                """CREATE TABLE IF NOT EXISTS approvals (
                    id TEXT PRIMARY KEY,
                    service TEXT NOT NULL,
                    proposal_id TEXT NOT NULL,
                    diff TEXT NOT NULL,
                    diff_sha256 TEXT NOT NULL,
                    summary TEXT NOT NULL,
                    status TEXT NOT NULL CHECK (status IN
                        ('pending','approved','rejected','expired','consumed','cancelled')),
                    requested_by TEXT NOT NULL,
                    requested_at REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    decided_by TEXT,
                    decided_at REAL,
                    reason TEXT
                )"""
            )
            c.execute("CREATE INDEX IF NOT EXISTS approvals_status ON approvals(status)")

    @contextmanager
    def _conn(self, write: bool = True) -> Any:
        """A transaction on this thread's connection. Writers take the lock up front (IMMEDIATE) so
        check-then-update is atomic; readers use a plain read transaction and never block each other."""
        conn = getattr(self._local, "conn", None)
        if conn is None:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(self.db_path, timeout=30, isolation_level=None, check_same_thread=False)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA busy_timeout=30000")
            conn.row_factory = sqlite3.Row
            self._local.conn = conn
        conn.execute("BEGIN IMMEDIATE" if write else "BEGIN")
        try:
            yield conn
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise

    def _expire(self, c: sqlite3.Connection) -> None:
        c.execute(
            "UPDATE approvals SET status='expired' WHERE status IN ('pending','approved') AND expires_at < ?",
            (time.time(),),
        )

    def create(
        self, service: str, proposal_id: str, diff: str, diff_sha256: str, summary: str, requested_by: str, ttl: float
    ) -> Approval:
        now = time.time()
        aid = uuid.uuid4().hex[:12]
        with self._conn() as c:
            # One open request per service: a new proposal supersedes an older pending one.
            c.execute(
                "UPDATE approvals SET status='cancelled', reason='superseded' WHERE service=? AND status='pending'",
                (service,),
            )
            c.execute(
                "INSERT INTO approvals (id, service, proposal_id, diff, diff_sha256, summary, status, requested_by,"
                " requested_at, expires_at) VALUES (?,?,?,?,?,?, 'pending', ?,?,?)",
                (aid, service, proposal_id, diff, diff_sha256, summary, requested_by, now, now + ttl),
            )
        got = self.get(aid)
        assert got is not None
        return got

    # Reads report expiry without writing it; writers persist it inside their own transaction.
    _EFFECTIVE = "CASE WHEN status IN ('pending','approved') AND expires_at < :now THEN 'expired' ELSE status END"
    _COLUMNS = (
        "id, service, proposal_id, diff, diff_sha256, summary, requested_by, requested_at, expires_at, "
        f"decided_by, decided_at, reason, {_EFFECTIVE} AS status"
    )

    def get(self, aid: str) -> Approval | None:
        with self._conn(write=False) as c:
            row = c.execute(
                f"SELECT {self._COLUMNS} FROM approvals WHERE id=:id",  # noqa: S608 - constant columns, bound values
                {"id": aid, "now": time.time()},
            ).fetchone()
        return Approval(**dict(row)) if row else None

    def list(self, status: str | None = None, limit: int = 200) -> list[Approval]:
        args: dict[str, Any] = {"now": time.time(), "limit": limit, "status": status}
        where = f"WHERE {self._EFFECTIVE} = :status" if status else ""
        with self._conn(write=False) as c:
            rows = c.execute(
                f"SELECT {self._COLUMNS} FROM approvals {where} ORDER BY requested_at DESC LIMIT :limit",  # noqa: S608
                args,
            ).fetchall()
        return [Approval(**dict(r)) for r in rows]

    def decide(self, aid: str, approve: bool, by: str, reason: str | None = None) -> Approval:
        by = (by or "").strip()
        if not by or by.lower() in RESERVED_APPROVERS:
            raise PermissionError("an approval must be decided by a named human")
        if len(by) > 100 or (reason and len(reason) > 2000):
            raise ValueError("approver or reason too long")
        with self._conn() as c:
            self._expire(c)
            cur = c.execute(
                "UPDATE approvals SET status=?, decided_by=?, decided_at=?, reason=? WHERE id=? AND status='pending'",
                ("approved" if approve else "rejected", by, time.time(), reason, aid),
            )
            if cur.rowcount != 1:
                row = c.execute("SELECT status FROM approvals WHERE id=?", (aid,)).fetchone()
                state = row["status"] if row else "missing"
                raise LookupError(f"approval {aid} is {state}, not pending")
        got = self.get(aid)
        assert got is not None
        return got

    def consume(self, aid: str, diff_sha256: str) -> bool:
        """Atomically spend an approval. It must be approved, unexpired, and bound to this exact diff."""
        with self._conn() as c:
            self._expire(c)
            cur = c.execute(
                "UPDATE approvals SET status='consumed' WHERE id=? AND status='approved' AND diff_sha256=?",
                (aid, diff_sha256),
            )
            return cur.rowcount == 1

    def cancel(self, aid: str, reason: str) -> None:
        with self._conn() as c:
            c.execute(
                "UPDATE approvals SET status='cancelled', reason=? WHERE id=? AND status='pending'", (reason, aid)
            )

    def wait(self, aid: str, timeout: float, poll: float = 0.5, stop: threading.Event | None = None) -> Approval:
        deadline = time.monotonic() + timeout
        while True:
            a = self.get(aid)
            if a is None:
                raise LookupError(f"approval {aid} not found")
            if a.status != "pending":
                return a
            if time.monotonic() >= deadline or (stop is not None and stop.is_set()):
                self.cancel(aid, "timed out waiting for a human decision")
                got = self.get(aid)
                assert got is not None
                return got
            time.sleep(poll)


class Workspace:
    def __init__(self, home: str | Path) -> None:
        self.home = Path(home).expanduser().resolve()
        for sub in ("scans", "backups", "reports", "entropy", "patches", "benchmarks", "realworld"):
            (self.home / sub).mkdir(parents=True, exist_ok=True)
        os.chmod(self.home, 0o750)  # noqa: S103 - owner+group only, deliberately not world-readable
        self.audit = AuditLog(self.home / "audit.jsonl")
        self.approvals = ApprovalStore(self.home / "state.db")
        self._scan_lock = threading.Lock()
        self._scan_cache: tuple[tuple[int, int, int], ScanReport] | None = None

    # ------------------------------------------------------------ scans
    def save_scan(self, report: ScanReport) -> Path:
        path = self.home / "scans" / f"{report.scan_id}.json"
        data = report.model_dump_json(indent=2)
        atomic_write(path, data)
        atomic_write(self.home / "scans" / "latest.json", data)
        return path

    def latest_scan(self) -> ScanReport | None:
        """The newest scan. Parsed once and cached until the file changes; treat the result as read-only."""
        p = self.home / "scans" / "latest.json"
        try:
            st = p.stat()
        except FileNotFoundError:
            return None
        key = (st.st_ino, st.st_mtime_ns, st.st_size)
        with self._scan_lock:
            if self._scan_cache is None or self._scan_cache[0] != key:
                self._scan_cache = (key, ScanReport.model_validate_json(p.read_bytes()))
            return self._scan_cache[1]

    def state_key(self) -> tuple[object, ...]:
        """Changes whenever the inputs to risk scoring (latest scan, learned facts) change."""
        parts: list[object] = []
        for rel in ("scans/latest.json", "facts.json"):
            try:
                st = (self.home / rel).stat()
                parts.append((st.st_ino, st.st_mtime_ns, st.st_size))
            except FileNotFoundError:
                parts.append(None)
        return tuple(parts)

    # -------------------------------------------------------- artifacts
    def save_json(self, rel: str, obj: Any) -> Path:
        path = self._safe(rel)
        atomic_write(path, json.dumps(obj, indent=2, default=str))
        return path

    def load_json(self, rel: str) -> Any | None:
        path = self._safe(rel)
        if not path.exists():
            return None
        return json.loads(path.read_text(encoding="utf-8"))

    def _safe(self, rel: str) -> Path:
        path = (self.home / rel).resolve()
        if self.home not in path.parents:
            raise ValueError(f"path escapes workspace: {rel}")
        return path
