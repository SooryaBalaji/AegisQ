"""Operations: scheduled scans and webhook alerts, stored in state.db and run by `aegisq serve`."""

from __future__ import annotations

import ipaddress
import json
import logging
import threading
import time
import urllib.error
import urllib.request
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from aegisq import __version__
from aegisq.agent.tools import apply_facts
from aegisq.config import AegisQConfig
from aegisq.risk import rank
from aegisq.workspace import Sqlite, Workspace

log = logging.getLogger(__name__)

EVENTS = ("exposure", "approval", "job_failed", "audit")
MIN_EVERY_MINUTES = 15
MAX_EVERY_MINUTES = 30 * 24 * 60


def check_webhook_url(url: str) -> str:
    """https anywhere; plain http only to this machine. No credentials in the URL."""
    url = (url or "").strip()
    if len(url) > 2000:
        raise ValueError("URL too long")
    parts = urlsplit(url)
    if parts.username or parts.password:
        raise ValueError("put credentials in the webhook path, not user:password@")
    host = parts.hostname or ""
    if parts.scheme == "https" and host:
        return url
    if parts.scheme == "http" and host:
        try:
            if ipaddress.ip_address(host).is_loopback:
                return url
        except ValueError:
            if host == "localhost":
                return url
    raise ValueError("webhook URLs must be https:// (http:// only to localhost)")


def mask(url: str) -> str:
    p = urlsplit(url)
    tail = p.path[-4:] if len(p.path) > 8 else ""
    return f"{p.scheme}://{p.hostname}{':' + str(p.port) if p.port else ''}/…{tail}"


class ScheduleStore(Sqlite):
    def __init__(self, db_path: Path) -> None:
        super().__init__(db_path)
        with self._conn() as c:
            c.execute(
                """CREATE TABLE IF NOT EXISTS schedules (
                    id TEXT PRIMARY KEY,
                    kind TEXT NOT NULL CHECK (kind IN ('scan')),
                    every_minutes INTEGER NOT NULL,
                    next_run REAL NOT NULL,
                    enabled INTEGER NOT NULL DEFAULT 1,
                    created_by TEXT,
                    created_at REAL NOT NULL,
                    last_run REAL,
                    last_job TEXT
                )"""
            )

    @staticmethod
    def _check(every_minutes: int) -> int:
        m = int(every_minutes)
        if not MIN_EVERY_MINUTES <= m <= MAX_EVERY_MINUTES:
            raise ValueError(f"interval must be between {MIN_EVERY_MINUTES} minutes and 30 days")
        return m

    def add(self, every_minutes: int, created_by: str | None, first_run: float | None = None) -> dict[str, Any]:
        m = self._check(every_minutes)
        sid = uuid.uuid4().hex[:10]
        now = time.time()
        with self._conn() as c:
            c.execute(
                "INSERT INTO schedules (id, kind, every_minutes, next_run, created_by, created_at)"
                " VALUES (?, 'scan', ?, ?, ?, ?)",
                (sid, m, first_run if first_run is not None else now + m * 60, created_by, now),
            )
        return self.get(sid)  # type: ignore[return-value]

    def get(self, sid: str) -> dict[str, Any] | None:
        with self._conn(write=False) as c:
            r = c.execute("SELECT * FROM schedules WHERE id=?", (sid,)).fetchone()
        return dict(r) if r else None

    def all(self) -> list[dict[str, Any]]:
        with self._conn(write=False) as c:
            return [dict(r) for r in c.execute("SELECT * FROM schedules ORDER BY created_at")]

    def update(self, sid: str, enabled: bool | None = None, every_minutes: int | None = None) -> dict[str, Any]:
        with self._conn() as c:
            row = c.execute("SELECT * FROM schedules WHERE id=?", (sid,)).fetchone()
            if row is None:
                raise LookupError("no such schedule")
            if every_minutes is not None:
                m = self._check(every_minutes)
                c.execute("UPDATE schedules SET every_minutes=?, next_run=? WHERE id=?", (m, time.time() + m * 60, sid))
            if enabled is not None:
                c.execute("UPDATE schedules SET enabled=? WHERE id=?", (int(enabled), sid))
        return self.get(sid)  # type: ignore[return-value]

    def remove(self, sid: str) -> None:
        with self._conn() as c:
            if c.execute("DELETE FROM schedules WHERE id=?", (sid,)).rowcount != 1:
                raise LookupError("no such schedule")

    def claim_due(self, now: float) -> list[dict[str, Any]]:
        """Atomically move every due schedule's next_run forward, so two servers never both fire it."""
        claimed = []
        with self._conn() as c:
            for r in c.execute("SELECT * FROM schedules WHERE enabled=1 AND next_run<=?", (now,)).fetchall():
                nxt = now + r["every_minutes"] * 60
                if c.execute(
                    "UPDATE schedules SET next_run=?, last_run=? WHERE id=? AND next_run=?",
                    (nxt, now, r["id"], r["next_run"]),
                ).rowcount:
                    claimed.append(dict(r))
        return claimed

    def record_job(self, sid: str, job_id: str) -> None:
        with self._conn() as c:
            c.execute("UPDATE schedules SET last_job=? WHERE id=?", (job_id, sid))


class AlertStore(Sqlite):
    def __init__(self, db_path: Path) -> None:
        super().__init__(db_path)
        with self._conn() as c:
            c.execute(
                """CREATE TABLE IF NOT EXISTS alerts (
                    id TEXT PRIMARY KEY,
                    url TEXT NOT NULL,
                    events TEXT NOT NULL,
                    created_by TEXT,
                    created_at REAL NOT NULL,
                    last_status TEXT,
                    last_sent_at REAL
                )"""
            )

    def add(self, url: str, events: list[str], created_by: str | None) -> dict[str, Any]:
        url = check_webhook_url(url)
        evs = sorted(set(events or EVENTS))
        if not evs or any(e not in EVENTS for e in evs):
            raise ValueError(f"events must be some of {', '.join(EVENTS)}")
        aid = uuid.uuid4().hex[:10]
        with self._conn() as c:
            c.execute(
                "INSERT INTO alerts (id, url, events, created_by, created_at) VALUES (?,?,?,?,?)",
                (aid, url, ",".join(evs), created_by, time.time()),
            )
        return self.public(self._row(aid))

    def _row(self, aid: str) -> dict[str, Any]:
        with self._conn(write=False) as c:
            r = c.execute("SELECT * FROM alerts WHERE id=?", (aid,)).fetchone()
        if r is None:
            raise LookupError("no such alert")
        return dict(r)

    @staticmethod
    def public(r: dict[str, Any]) -> dict[str, Any]:
        return {**{k: v for k, v in r.items() if k != "url"}, "url": mask(r["url"]), "events": r["events"].split(",")}

    def all(self, full: bool = False) -> list[dict[str, Any]]:
        with self._conn(write=False) as c:
            rows = [dict(r) for r in c.execute("SELECT * FROM alerts ORDER BY created_at")]
        return rows if full else [self.public(r) for r in rows]

    def remove(self, aid: str) -> None:
        with self._conn() as c:
            if c.execute("DELETE FROM alerts WHERE id=?", (aid,)).rowcount != 1:
                raise LookupError("no such alert")

    def record(self, aid: str, status: str) -> None:
        with self._conn() as c:
            c.execute("UPDATE alerts SET last_status=?, last_sent_at=? WHERE id=?", (status[:200], time.time(), aid))


class Ops:
    """Runs schedules, watches for things worth alerting on, and sends the alerts."""

    def __init__(
        self,
        ws: Workspace,
        cfg: AegisQConfig,
        start_scan: Callable[[str], str | None] | None = None,
        post: Callable[[str, bytes], int] | None = None,
    ) -> None:
        self.ws = ws
        self.cfg = cfg
        self.schedules = ScheduleStore(ws.home / "state.db")
        self.alerts = AlertStore(ws.home / "state.db")
        self.start_scan = start_scan
        self._post = post or _http_post
        self._seen_approvals: set[str] | None = None
        self._audit_alerted = False
        self._last_audit_check = 0.0
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    # ------------------------------------------------------------ alerts
    def send(self, event: str, text: str, data: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        body = json.dumps(
            {"text": text, "event": event, "data": data or {}, "source": f"AegisQ {__version__}"}, default=str
        ).encode("utf-8")
        results = []
        for a in self.alerts.all(full=True):
            if event not in a["events"].split(",") and event != "test":
                continue
            try:
                code = self._post(a["url"], body)
                status = f"HTTP {code}"
                ok = 200 <= code < 300
            except Exception as e:  # an unreachable webhook must never break a scan or a job
                status, ok = f"{type(e).__name__}: {e}"[:200], False
            self.alerts.record(a["id"], status)
            self.ws.audit.append(
                "alert.sent" if ok else "alert.failed",
                {"alert_id": a["id"], "event": event, "status": status},
                actor="aegisq",
            )
            results.append({"id": a["id"], "ok": ok, "status": status})
        return results

    # ----------------------------------------------------------- watchers
    def after_scan(self) -> None:
        """Compare the latest scan with the last one alerted on: regressions and newly exposed services."""
        report = self.ws.latest_scan()
        if report is None:
            return
        scans = apply_facts(report.results, self.ws)
        statuses = {s.service.name: s.status.value for s in scans}
        exposed = sorted(r.service for r in rank(scans, self.cfg.risk) if r.severity in ("critical", "high"))
        prev = self.ws.load_json("alerts/state.json")
        self.ws.save_json("alerts/state.json", {"statuses": statuses, "exposed": exposed, "scan_id": report.scan_id})
        if prev is None:
            return
        regressions = sorted(
            n for n, st in statuses.items() if prev["statuses"].get(n) == "pq_ready" and st != "pq_ready"
        )
        new_exposed = sorted(set(exposed) - set(prev.get("exposed", [])))
        if not regressions and not new_exposed:
            return
        parts = []
        if new_exposed:
            parts.append(f"{len(new_exposed)} newly at risk ({', '.join(new_exposed[:8])})")
        if regressions:
            parts.append(
                f"{len(regressions)} no longer post-quantum ready ("
                + ", ".join(f"{n} is now {statuses[n]}" for n in regressions[:8])
                + ")"
            )
        self.send(
            "exposure",
            "AegisQ: " + "; ".join(parts) + ".",
            {"scan_id": report.scan_id, "newly_exposed": new_exposed, "regressions": regressions},
        )

    def after_job(self, data: dict[str, Any], label: str | None = None) -> None:
        if data.get("status") == "succeeded" and data.get("kind") in ("scan", "migrate"):
            self.after_scan()
        elif data.get("status") == "failed":
            self.send(
                "job_failed",
                f"AegisQ: job {label or data.get('kind')} failed (exit {data.get('exit_code')}).",
                {"job": data.get("job"), "kind": data.get("kind")},
            )

    def watch_approvals(self) -> None:
        pending = self.ws.approvals.list("pending", limit=100)
        ids = {a.id for a in pending}
        if self._seen_approvals is None:
            self._seen_approvals = ids
            return
        for a in pending:
            if a.id not in self._seen_approvals:
                who = f" (started by {a.initiated_by}; someone else must approve)" if a.require_other else ""
                self.send(
                    "approval",
                    f"AegisQ: a change to {a.service} is waiting for approval: {a.summary}{who}.",
                    {"approval_id": a.id, "service": a.service},
                )
        self._seen_approvals = ids

    def watch_audit(self, now: float) -> None:
        if now - self._last_audit_check < 300:
            return
        self._last_audit_check = now
        res = self.ws.audit.verify()
        if not res.ok and not self._audit_alerted:
            self._audit_alerted = True
            self.send("audit", f"AegisQ: the audit log failed verification: {res.error}", {"entries": res.entries})
        elif res.ok:
            self._audit_alerted = False

    def run_schedules(self, now: float) -> None:
        for sch in self.schedules.claim_due(now):
            if self.start_scan is None:
                continue
            try:
                job_id = self.start_scan(sch["id"])
            except Exception as e:  # a running scan or a bad inventory must not stop the loop
                self.ws.audit.append("schedule.skipped", {"schedule": sch["id"], "reason": str(e)[:300]}, "scheduler")
                continue
            if job_id:
                self.schedules.record_job(sch["id"], job_id)

    def tick(self, now: float | None = None) -> None:
        now = time.time() if now is None else now
        for step in (lambda: self.run_schedules(now), self.watch_approvals, lambda: self.watch_audit(now)):
            try:
                step()
            except Exception:
                log.exception("ops tick step failed")

    # ------------------------------------------------------------ thread
    def start(self, interval: float = 15.0) -> None:
        if self._thread is not None:
            return

        def loop() -> None:
            while not self._stop.wait(interval):
                self.tick()

        self._thread = threading.Thread(target=loop, name="aegisq-ops", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()


def _http_post(url: str, body: bytes) -> int:
    req = urllib.request.Request(  # noqa: S310 - scheme checked by check_webhook_url
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "User-Agent": f"AegisQ/{__version__}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:  # noqa: S310
            return int(resp.status)
    except urllib.error.HTTPError as e:
        return int(e.code)
