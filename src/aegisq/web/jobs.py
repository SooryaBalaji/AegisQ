"""Background jobs started from the dashboard.

Each job runs the real ``aegisq`` CLI in its own process (argv lists only, never a shell), so the
dashboard does exactly what the terminal does: same code, same guardrails, same audit log. Output
is captured line by line for the live log view. Cancelling sends an interrupt first, so a migration
still runs its safety-net rollback, and force-kills the process group only if it does not exit.
"""

from __future__ import annotations

import os
import secrets
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from aegisq.proc import _GROUP_KWARGS, _kill_group

MAX_LINES = 4000  # per job; older lines are dropped (the audit log keeps the record)
MAX_HISTORY = 50
CANCEL_GRACE_S = 15.0


class JobConflict(RuntimeError):
    """A job of the same kind is already running."""


@dataclass
class Job:
    id: str
    kind: str
    label: str
    steps: list[list[str]]
    started_by: str
    status: str = "running"  # running | succeeded | failed | cancelled
    created: float = field(default_factory=time.time)
    finished: float | None = None
    exit_code: int | None = None
    lines: list[str] = field(default_factory=list)
    dropped: int = 0  # lines dropped from the front
    cancel_requested: bool = False
    proc: subprocess.Popen[str] | None = None

    def append(self, line: str) -> None:
        self.lines.append(line)
        if len(self.lines) > MAX_LINES:
            cut = len(self.lines) - MAX_LINES
            del self.lines[:cut]
            self.dropped += cut

    def summary(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "label": self.label,
            "started_by": self.started_by,
            "status": self.status,
            "created": self.created,
            "finished": self.finished,
            "exit_code": self.exit_code,
            "lines": self.dropped + len(self.lines),
            "last_line": self.lines[-1] if self.lines else "",
        }


class JobManager:
    def __init__(
        self,
        base_argv: list[str],
        env: dict[str, str],
        on_event: Callable[[str, dict[str, Any], str], object] | None = None,
    ) -> None:
        self.base_argv = base_argv
        self.env = env
        self.on_event = on_event or (lambda event, data, actor: None)
        self.jobs: dict[str, Job] = {}
        self.lock = threading.Lock()

    def start(self, kind: str, label: str, steps: list[list[str]], who: str) -> Job:
        with self.lock:
            if any(j.kind == kind and j.status == "running" for j in self.jobs.values()):
                raise JobConflict(f"a {kind} job is already running")
            job = Job(secrets.token_hex(6), kind, label, steps, who)
            self.jobs[job.id] = job
            finished = [j for j in self.jobs.values() if j.status != "running"]
            for old in sorted(finished, key=lambda j: j.created)[: max(0, len(self.jobs) - MAX_HISTORY)]:
                del self.jobs[old.id]
        self.on_event("job.started", {"job": job.id, "kind": kind, "label": label, "steps": steps}, who)
        threading.Thread(target=self._run, args=(job,), name=f"aegisq-job-{job.id}", daemon=True).start()
        return job

    def get(self, job_id: str) -> Job | None:
        with self.lock:
            return self.jobs.get(job_id)

    def list(self) -> list[dict[str, Any]]:
        with self.lock:
            jobs = sorted(self.jobs.values(), key=lambda j: j.created, reverse=True)
            return [j.summary() for j in jobs]

    def log(self, job: Job, since: int) -> dict[str, Any]:
        with self.lock:
            start = max(since - job.dropped, 0)
            return {**job.summary(), "since": job.dropped + start, "log": job.lines[start:]}

    def cancel(self, job: Job, who: str) -> None:
        with self.lock:
            if job.status != "running":
                return
            job.cancel_requested = True
            job.append(f"--- cancel requested by {who} ---")
            proc = job.proc
        if proc is not None and proc.poll() is None:
            _interrupt(proc)
            threading.Timer(CANCEL_GRACE_S, _force_kill, args=(proc,)).start()

    def _run(self, job: Job) -> None:
        code: int | None = 0
        try:
            for step in job.steps:
                if job.cancel_requested:
                    break
                with self.lock:
                    job.append("$ aegisq " + " ".join(step))
                proc = subprocess.Popen(
                    [*self.base_argv, *step],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    bufsize=1,
                    env=self.env,
                    **_GROUP_KWARGS,
                )
                with self.lock:
                    job.proc = proc
                assert proc.stdout is not None
                for line in proc.stdout:
                    with self.lock:
                        job.append(line.rstrip("\r\n"))
                code = proc.wait()
                if code != 0:
                    break
        except Exception as e:  # a job failing to start must not take the dashboard down
            with self.lock:
                job.append(f"error: {type(e).__name__}: {e}")
            code = None
        with self.lock:
            job.proc = None
            job.exit_code = code
            job.finished = time.time()
            job.status = "cancelled" if job.cancel_requested else "succeeded" if code == 0 else "failed"
            status = job.status
        self.on_event("job.finished", {"job": job.id, "kind": job.kind, "status": status, "exit_code": code}, "aegisq")


def _interrupt(proc: subprocess.Popen[str]) -> None:
    """Ctrl-C for the job's process group: the CLI turns it into KeyboardInterrupt and cleans up."""
    try:
        if sys.platform == "win32":  # pragma: no cover - exercised by the Windows CI job
            proc.send_signal(signal.CTRL_BREAK_EVENT)
        else:
            os.killpg(proc.pid, signal.SIGINT)
    except (ProcessLookupError, PermissionError, OSError):
        pass


def _force_kill(proc: subprocess.Popen[str]) -> None:
    if proc.poll() is None:
        _kill_group(proc.pid)
