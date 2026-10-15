"""Dashboard and REST API.

Security model: every /api route requires a bearer token. Tokens map to people and roles
(users created with `aegisq users add`, stored only as hashes, or AEGISQ_API_TOKENS); if
neither exists a one-time admin token is generated and printed. Each route checks the
role's permission (view, run, approve, admin). The approver identity is taken from the
token, never from the request body. Responses carry a strict CSP; the page loads no third-party code.
"""

from __future__ import annotations

import os
import re
import secrets
import sys
import threading
import time
import urllib.parse
from collections import defaultdict, deque
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from importlib import resources
from typing import Annotated, Any, Literal

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response
from pydantic import BaseModel, ConfigDict, Field

from aegisq import __version__
from aegisq.config import AegisQConfig, api_tokens
from aegisq.models import ServiceScan
from aegisq.risk import RESOURCE_ESTIMATE_NOTE, RESOURCE_ESTIMATES, rank
from aegisq.users import GRANTS, User, UserStore, can, env_users, token_hash
from aegisq.workspace import Workspace

CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
    "frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
)
_STATIC = {
    "app.js": "text/javascript; charset=utf-8",
    "app.css": "text/css; charset=utf-8",
    "ui.css": "text/css; charset=utf-8",
    "favicon.svg": "image/svg+xml",
}


class NewUser(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$")
    role: Literal["viewer", "operator", "approver", "admin"]


class RoleChange(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: Literal["viewer", "operator", "approver", "admin"]


class NewSchedule(BaseModel):
    model_config = ConfigDict(extra="forbid")
    every_minutes: int = Field(ge=15, le=43200)


class ScheduleChange(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool | None = None
    every_minutes: int | None = Field(default=None, ge=15, le=43200)


class NewAlert(BaseModel):
    model_config = ConfigDict(extra="forbid")
    url: str = Field(max_length=2000)
    events: list[Literal["exposure", "approval", "job_failed", "audit"]] = Field(default_factory=list, max_length=4)


class Decision(BaseModel):
    approve: bool
    reason: str | None = Field(default=None, max_length=2000)


# ------------------------------------------------------------ job requests ---
# Every field is an enum, a bounded number or a validated string: the dashboard can only start the
# CLI commands below, with these options, as argv lists.

_SERVICE_NAME = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"


class _Req(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ScanJob(_Req):
    kind: Literal["scan"]
    targets: str | None = Field(default=None, max_length=20000)  # one per line; None = the inventory


class MigrateJob(_Req):
    kind: Literal["migrate"]
    planner: Literal["auto", "local", "rules", "claude"] = "auto"
    services: list[Annotated[str, Field(pattern=_SERVICE_NAME)]] = Field(default_factory=list, max_length=200)


class BenchmarkJob(_Req):
    kind: Literal["benchmark"]
    url: str = Field(max_length=300)
    n: int = Field(default=200, ge=10, le=5000)
    method: Literal["auto", "native", "curl"] = "auto"


JobRequest = Annotated[ScanJob | MigrateJob | BenchmarkJob, Field(discriminator="kind")]


class _AuthLimiter:
    """Slow down token guessing: at most 20 failures per client per 5 minutes."""

    def __init__(self, limit: int = 20, window: float = 300) -> None:
        self.limit, self.window = limit, window
        self.fails: dict[str, deque[float]] = defaultdict(deque)
        self.lock = threading.Lock()

    def blocked(self, client: str) -> bool:
        with self.lock:
            q = self.fails[client]
            now = time.monotonic()
            while q and now - q[0] > self.window:
                q.popleft()
            return len(q) >= self.limit

    def fail(self, client: str) -> None:
        with self.lock:
            self.fails[client].append(time.monotonic())


def create_app(
    cfg: AegisQConfig,
    inventory: str | None = None,
    tokens: dict[str, str] | None = None,
    config_path: str | None = None,
    jobs_enabled: bool = True,
    background: bool = False,
) -> FastAPI:
    from aegisq.web.jobs import JobConflict, JobManager

    ws = Workspace(cfg.home_path)
    users = UserStore(ws.home / "state.db")
    toks = tokens if tokens is not None else api_tokens()
    if not toks and not users.list():
        generated = secrets.token_urlsafe(24)
        toks = {generated: "admin"}
        print(f"AegisQ dashboard token (this run only): {generated}", file=sys.stderr, flush=True)
    env = env_users(toks)
    limiter = _AuthLimiter()
    scan_state: dict[str, Any] = {"running": False, "last": None, "error": None}
    scan_lock = threading.Lock()

    from aegisq.ops import EVENTS, Ops

    def scheduled_scan(schedule_id: str) -> str | None:
        if not jobs_enabled or inventory is None:
            raise RuntimeError("scheduled scans need `aegisq serve --inventory FILE` without --read-only")
        return jobs.start("scan", "Scheduled scan", [["scan", inventory]], "scheduler").id

    ops = Ops(ws, cfg, start_scan=scheduled_scan)

    def on_job_event(event: str, data: dict[str, Any], actor: str) -> None:
        ws.audit.append(event, data, actor=actor)
        if event == "job.finished":
            ops.after_job(data)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        if background:
            ops.start()
        yield
        ops.stop()

    app = FastAPI(
        title="AegisQ", version=__version__, docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan
    )
    app.state.ops = ops

    base_argv = [sys.executable, "-m", "aegisq.cli", "--home", str(ws.home)]
    if config_path:
        base_argv += ["--config", os.path.abspath(config_path)]
    job_env = {**os.environ, "PYTHONUNBUFFERED": "1", "PYTHONIOENCODING": "utf-8", "NO_COLOR": "1"}
    jobs = JobManager(base_argv, job_env, on_event=on_job_event)

    @app.middleware("http")
    async def headers(request: Request, call_next: Any) -> Response:
        resp: Response = await call_next(request)
        resp.headers["Content-Security-Policy"] = CSP
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        if request.url.path.startswith("/api"):
            resp.headers["Cache-Control"] = "no-store"
        return resp

    def principal(request: Request) -> User:
        client = request.client.host if request.client else "unknown"
        if limiter.blocked(client):
            raise HTTPException(429, "too many failed authentication attempts")
        auth = request.headers.get("authorization", "")
        scheme, _, token = auth.partition(" ")
        if scheme.lower() == "bearer" and token and len(token) <= 512:
            u = env.get(token_hash(token)) or users.by_token(token)
            if u is not None:
                return u
        limiter.fail(client)
        raise HTTPException(401, "missing or invalid bearer token", headers={"WWW-Authenticate": "Bearer"})

    def identity(request: Request) -> str:
        return principal(request).name

    def requires(permission: str) -> Any:
        def dep(request: Request) -> str:
            u = principal(request)
            if not can(u.role, permission):
                raise HTTPException(403, f"your role ({u.role}) does not allow this")
            return u.name

        return dep

    can_run = requires("run")
    can_approve = requires("approve")
    is_admin = requires("admin")

    # -------------------------------------------------------------- pages
    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.get("/", response_class=HTMLResponse)
    def index() -> HTMLResponse:
        return HTMLResponse(_static_text("index.html"))

    @app.get("/favicon.ico", include_in_schema=False)
    def favicon() -> Response:  # browsers ask for this path even when the page names an SVG icon
        return Response(
            _static_text("favicon.svg"), media_type="image/svg+xml", headers={"Cache-Control": "public, max-age=86400"}
        )

    @app.get("/static/{name}")
    def static(name: str) -> Response:
        if name not in _STATIC:
            raise HTTPException(404)
        return Response(_static_text(name), media_type=_STATIC[name])

    # ---------------------------------------------------------------- API
    @app.get("/api/me")
    def me(u: User = Depends(principal)) -> dict[str, Any]:  # noqa: B008 - FastAPI dependency
        return {
            "identity": u.name,
            "role": u.role,
            "permissions": sorted(GRANTS[u.role]),
            "separation_of_duties": cfg.agent.separation_of_duties,
        }

    overview_cache: dict[tuple[object, ...], dict[str, Any]] = {}
    overview_lock = threading.Lock()

    @app.get("/api/overview")
    def overview(z: float | None = None, who: str = Depends(identity)) -> dict[str, Any]:
        if z is not None and not 0 <= z <= 100:
            raise HTTPException(422, "z must be between 0 and 100")
        # Every open dashboard polls this; recompute only when the scan, learned facts or Z change.
        key = (ws.state_key(), z)
        with overview_lock:
            cached = overview_cache.get(key)
        if cached is not None:
            return cached
        out = _overview(z)
        with overview_lock:
            if len(overview_cache) > 64:
                overview_cache.clear()
            overview_cache[key] = out
        return out

    def _overview(z: float | None) -> dict[str, Any]:
        from aegisq.agent.tools import apply_facts

        report = ws.latest_scan()
        out: dict[str, Any] = {
            "z_default": cfg.risk.z_years,
            "estimates": RESOURCE_ESTIMATES,
            "estimate_note": RESOURCE_ESTIMATE_NOTE,
            "scan": None,
            "services": [],
            "can_rescan": inventory is not None,
        }
        if report is None:
            return out
        scans = apply_facts(report.results, ws)
        ranking = {r.service: r for r in rank(scans, cfg.risk, z)}
        out["scan"] = {"id": report.scan_id, "finished": report.finished_at.isoformat(), "summary": report.summary()}
        for s in scans:
            r = ranking[s.service.name]
            out["services"].append(
                {
                    "name": s.service.name,
                    "endpoint": s.service.endpoint,
                    "protocol": s.service.protocol.value,
                    "status": s.status.value,
                    "data_category": s.service.data_category,
                    "managed": s.service.managed is not None,
                    "x": r.x_retention,
                    "y": r.y_migration,
                    "y_reason": r.y_reason,
                    "rank": r.rank,
                    "group": _display_group(s),
                    "findings": s.findings,
                    "errors": s.errors,
                }
            )
        out["services"].sort(key=lambda r: r["rank"])
        return out

    @app.get("/api/scan/latest")
    def scan_latest(who: str = Depends(identity)) -> Response:
        report = ws.latest_scan()
        if report is None:
            raise HTTPException(404, "no scan yet")
        return Response(report.model_dump_json(), media_type="application/json")

    @app.post("/api/scan", status_code=202)
    def scan_start(who: str = Depends(can_run)) -> dict[str, Any]:
        if inventory is None:
            raise HTTPException(409, "dashboard started without --inventory; rescans are disabled")
        with scan_lock:
            if scan_state["running"]:
                raise HTTPException(409, "a scan is already running")
            scan_state.update(running=True, error=None)
        threading.Thread(target=_run_scan, args=(who,), daemon=True).start()
        return {"started": True}

    def _run_scan(who: str) -> None:
        import asyncio

        from aegisq.inventory import load_inventory
        from aegisq.netutil import Scope
        from aegisq.scanner.engine import ScanOptions, scan_all

        try:
            assert inventory is not None
            targets = load_inventory(inventory)
            sc = cfg.scan
            opts = ScanOptions(
                timeout=sc.timeout,
                concurrency=sc.concurrency,
                legacy_protocols=sc.legacy_protocols,
                scope=Scope(sc.scope.allow, sc.scope.deny),
            )
            report = asyncio.run(scan_all(targets, opts))
            ws.save_scan(report)
            ws.audit.append(
                "scan.completed",
                {"scan_id": report.scan_id, "summary": report.summary(), "trigger": "dashboard"},
                actor=who,
            )
            scan_state["last"] = report.scan_id
        except Exception as e:
            scan_state["error"] = f"{type(e).__name__}: {e}"
        finally:
            scan_state["running"] = False

    @app.get("/api/scan/status")
    def scan_status(who: str = Depends(identity)) -> dict[str, Any]:
        return dict(scan_state)

    @app.get("/api/cbom")
    def get_cbom(who: str = Depends(identity)) -> JSONResponse:
        from aegisq.cbom import build_cbom, validate_cbom

        report = ws.latest_scan()  # always the latest scan: a saved cbom.json may predate a rescan
        if report is None:
            raise HTTPException(404, "no scan yet")
        bom = build_cbom(report)
        validate_cbom(bom)
        return JSONResponse(bom, headers={"Content-Disposition": 'attachment; filename="cbom.json"'})

    # ----------------------------------------------------------------- jobs
    def _inventory_targets() -> list[Any]:
        from aegisq.inventory import InventoryError, load_inventory

        if inventory is None:
            return []
        try:
            return load_inventory(inventory)
        except InventoryError:
            return []

    @app.get("/api/capabilities")
    def capabilities(who: str = Depends(identity)) -> dict[str, Any]:
        return _capabilities(cfg, _inventory_targets(), inventory is not None, jobs_enabled)

    @app.get("/api/jobs")
    def list_jobs(who: str = Depends(identity)) -> list[dict[str, Any]]:
        return jobs.list()

    @app.post("/api/jobs", status_code=202)
    def start_job(body: JobRequest, who: str = Depends(can_run)) -> dict[str, Any]:
        if not jobs_enabled:
            raise HTTPException(403, "this dashboard is read-only (started with --read-only)")
        label, steps = _job_steps(body, who)
        try:
            return jobs.start(body.kind, label, steps, who).summary()
        except JobConflict as e:
            raise HTTPException(409, str(e)) from None

    @app.get("/api/jobs/{job_id}")
    def job_log(job_id: str, since: int = 0, who: str = Depends(identity)) -> dict[str, Any]:
        job = jobs.get(job_id)
        if job is None:
            raise HTTPException(404, "no such job")
        return jobs.log(job, max(0, since))

    @app.post("/api/jobs/{job_id}/cancel")
    def cancel_job(job_id: str, who: str = Depends(can_run)) -> dict[str, Any]:
        job = jobs.get(job_id)
        if job is None:
            raise HTTPException(404, "no such job")
        jobs.cancel(job, who)
        return job.summary()

    def _job_steps(body: Any, who: str) -> tuple[str, list[list[str]]]:
        from aegisq.inventory import InventoryError, load_inventory

        if isinstance(body, ScanJob):
            if body.targets and body.targets.strip():
                lines = [ln for ln in body.targets.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
                if len(lines) > 500:
                    raise HTTPException(422, "at most 500 targets per scan")
                path = ws.home / "targets" / f"dashboard-{secrets.token_hex(4)}.txt"
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("\n".join(lines) + "\n", encoding="utf-8")
                try:
                    load_inventory(path)
                except InventoryError as e:
                    path.unlink(missing_ok=True)
                    raise HTTPException(422, f"targets: {e}") from None
                return f"Scan {len(lines)} server{'s' if len(lines) != 1 else ''}", [["scan", str(path)]]
            if inventory is None:
                raise HTTPException(409, "no inventory: enter servers to scan, or start with --inventory FILE")
            return "Scan the inventory", [["scan", inventory]]
        if isinstance(body, MigrateJob):
            if inventory is None:
                raise HTTPException(409, "migration needs an inventory with managed services: serve --inventory FILE")
            known = {t.name for t in _inventory_targets()}
            unknown = [s for s in body.services if s not in known]
            if unknown:
                raise HTTPException(422, f"unknown service(s): {', '.join(unknown)}")
            argv = ["migrate", inventory, "--planner", body.planner, "--initiator", who]
            for s in body.services:
                argv += ["--service", s]
            scope = ", ".join(body.services) if body.services else "all services"
            # Rescan afterwards so the ranking on the dashboard shows the result of the migration.
            return f"Migrate {scope} ({body.planner} planner)", [argv, ["scan", inventory]]
        if isinstance(body, BenchmarkJob):
            url = _https_url(body.url)
            return f"Benchmark {url}", [["benchmark", url, "-n", str(body.n), "--method", body.method]]
        raise HTTPException(422, "unknown job kind")  # pragma: no cover - the request model rejects it first

    @app.get("/api/approvals")
    def list_approvals(status: str | None = None, who: str = Depends(identity)) -> list[dict[str, Any]]:
        if status and status not in ("pending", "approved", "rejected", "expired", "consumed", "cancelled"):
            raise HTTPException(422, "bad status")
        return [a.to_dict() for a in ws.approvals.list(status, limit=100)]

    @app.post("/api/approvals/{approval_id}/decision")
    def decide(approval_id: str, body: Decision, who: str = Depends(can_approve)) -> dict[str, Any]:
        try:
            a = ws.approvals.decide(approval_id, body.approve, who, body.reason)
        except LookupError as e:
            raise HTTPException(409, str(e)) from None
        except PermissionError as e:
            raise HTTPException(403, str(e)) from None
        except ValueError as e:
            raise HTTPException(422, str(e)) from None
        ws.audit.append(
            "approval.decided",
            {"approval_id": a.id, "service": a.service, "status": a.status, "reason": body.reason, "via": "dashboard"},
            actor=who,
        )
        return a.to_dict()

    # ---------------------------------------------------------------- users
    def _all_admins_after(change: dict[str, str | None]) -> int:
        roles = {u.name: u.role for u in users.list()}
        for name, role in change.items():
            if role is None:
                roles.pop(name, None)
            else:
                roles[name] = role
        return sum(r == "admin" for r in roles.values()) + sum(u.role == "admin" for u in env.values())

    def _db_user(name: str) -> None:
        if any(u.name == name for u in env.values()):
            raise HTTPException(409, f"{name} is defined in AEGISQ_API_TOKENS; change it there")
        if not any(u.name == name for u in users.list()):
            raise HTTPException(404, "no such user")

    @app.get("/api/users")
    def list_users(who: str = Depends(is_admin)) -> list[dict[str, Any]]:
        seen = {u.name for u in env.values()}
        return [u.to_dict() for u in env.values()] + [u.to_dict() for u in users.list() if u.name not in seen]

    @app.post("/api/users", status_code=201)
    def add_user(body: NewUser, who: str = Depends(is_admin)) -> dict[str, Any]:
        if any(u.name == body.name for u in env.values()):
            raise HTTPException(409, f"{body.name} is defined in AEGISQ_API_TOKENS")
        try:
            token = users.add(body.name, body.role, created_by=who)
        except ValueError as e:
            raise HTTPException(409 if "exists" in str(e) else 422, str(e)) from None
        ws.audit.append("user.created", {"name": body.name, "role": body.role, "via": "dashboard"}, actor=who)
        return {"name": body.name, "role": body.role, "token": token}

    @app.patch("/api/users/{name}")
    def set_role(name: str, body: RoleChange, who: str = Depends(is_admin)) -> dict[str, Any]:
        _db_user(name)
        if body.role != "admin" and _all_admins_after({name: body.role}) == 0:
            raise HTTPException(409, "at least one admin must remain")
        users.set_role(name, body.role)
        ws.audit.append("user.role_changed", {"name": name, "role": body.role, "via": "dashboard"}, actor=who)
        return {"name": name, "role": body.role}

    @app.post("/api/users/{name}/token")
    def rotate_token(name: str, who: str = Depends(is_admin)) -> dict[str, Any]:
        _db_user(name)
        token = users.rotate(name)
        ws.audit.append("user.token_rotated", {"name": name, "via": "dashboard"}, actor=who)
        return {"name": name, "token": token}

    @app.delete("/api/users/{name}")
    def remove_user(name: str, who: str = Depends(is_admin)) -> dict[str, Any]:
        _db_user(name)
        if _all_admins_after({name: None}) == 0:
            raise HTTPException(409, "at least one admin must remain")
        users.remove(name)
        ws.audit.append("user.removed", {"name": name, "via": "dashboard"}, actor=who)
        return {"removed": name}

    # ------------------------------------------------------- schedules
    @app.get("/api/schedules")
    def list_schedules(who: str = Depends(identity)) -> list[dict[str, Any]]:
        return ops.schedules.all()

    @app.post("/api/schedules", status_code=201)
    def add_schedule(body: NewSchedule, who: str = Depends(is_admin)) -> dict[str, Any]:
        if inventory is None or not jobs_enabled:
            raise HTTPException(409, "scheduled scans need `aegisq serve --inventory FILE` without --read-only")
        try:
            sch = ops.schedules.add(body.every_minutes, who)
        except ValueError as e:
            raise HTTPException(422, str(e)) from None
        ws.audit.append("schedule.created", {"schedule": sch["id"], "every_minutes": sch["every_minutes"]}, actor=who)
        return sch

    @app.patch("/api/schedules/{sid}")
    def change_schedule(sid: str, body: ScheduleChange, who: str = Depends(is_admin)) -> dict[str, Any]:
        try:
            sch = ops.schedules.update(sid, enabled=body.enabled, every_minutes=body.every_minutes)
        except LookupError:
            raise HTTPException(404, "no such schedule") from None
        except ValueError as e:
            raise HTTPException(422, str(e)) from None
        ws.audit.append("schedule.changed", {"schedule": sid, **body.model_dump(exclude_none=True)}, actor=who)
        return sch

    @app.delete("/api/schedules/{sid}")
    def remove_schedule(sid: str, who: str = Depends(is_admin)) -> dict[str, Any]:
        try:
            ops.schedules.remove(sid)
        except LookupError:
            raise HTTPException(404, "no such schedule") from None
        ws.audit.append("schedule.removed", {"schedule": sid}, actor=who)
        return {"removed": sid}

    # ---------------------------------------------------------- alerts
    @app.get("/api/alerts")
    def list_alerts(who: str = Depends(is_admin)) -> dict[str, Any]:
        return {"events": list(EVENTS), "alerts": ops.alerts.all()}

    @app.post("/api/alerts", status_code=201)
    def add_alert(body: NewAlert, who: str = Depends(is_admin)) -> dict[str, Any]:
        try:
            a = ops.alerts.add(body.url, list(body.events), who)
        except ValueError as e:
            raise HTTPException(422, str(e)) from None
        ws.audit.append("alert.created", {"alert_id": a["id"], "events": a["events"]}, actor=who)
        return a

    @app.delete("/api/alerts/{aid}")
    def remove_alert(aid: str, who: str = Depends(is_admin)) -> dict[str, Any]:
        try:
            ops.alerts.remove(aid)
        except LookupError:
            raise HTTPException(404, "no such alert") from None
        ws.audit.append("alert.removed", {"alert_id": aid}, actor=who)
        return {"removed": aid}

    @app.post("/api/alerts/test")
    def test_alerts(who: str = Depends(is_admin)) -> list[dict[str, Any]]:
        return ops.send("test", f"AegisQ: test alert from {who}. Alerts are working.", {"by": who})

    @app.get("/api/audit")
    def audit_tail(limit: int = 200, event: str | None = None, who: str = Depends(identity)) -> list[dict[str, Any]]:
        return ws.audit.tail(max(1, min(limit, 2000)), event)

    @app.get("/api/audit/verify")
    def audit_verify(who: str = Depends(identity)) -> dict[str, Any]:
        r = ws.audit.verify()
        return {"ok": r.ok, "entries": r.entries, "error": r.error, "keyed": r.keyed}

    def _artifact(rel: str) -> Any:
        data = ws.load_json(rel)
        if data is None:
            raise HTTPException(404, "not available yet")
        return data

    @app.get("/api/benchmark")
    def benchmark(who: str = Depends(identity)) -> Any:
        return _artifact("benchmarks/latest.json")

    @app.get("/api/report.{fmt}")
    def report(fmt: str, z: float | None = None, who: str = Depends(identity)) -> Response:
        from aegisq.report import collect, render

        if fmt not in ("md", "html"):
            raise HTTPException(404)
        text = render(collect(ws, cfg, z), fmt)
        if fmt == "html":
            return HTMLResponse(text, headers={"Content-Disposition": 'attachment; filename="aegisq-report.html"'})
        return PlainTextResponse(text, headers={"Content-Disposition": 'attachment; filename="aegisq-report.md"'})

    app.state.workspace = ws
    return app


def _https_url(raw: str) -> str:
    """Normalise a benchmark URL: https only, a valid host, an optional port, no credentials."""
    from aegisq.netutil import validate_host, validate_port

    u = urllib.parse.urlsplit(raw.strip())
    if u.scheme != "https" or not u.hostname or u.username or u.password:
        raise HTTPException(422, "benchmark URL must look like https://host[:port]/")
    try:
        host = validate_host(u.hostname)
        port = validate_port(u.port) if u.port else 443
    except ValueError as e:
        raise HTTPException(422, f"benchmark URL: {e}") from None
    path = u.path if re.fullmatch(r"[A-Za-z0-9/._~%-]*", u.path or "") else "/"
    h = f"[{host}]" if ":" in host else host
    return f"https://{h}:{port}{path or '/'}"


def _capabilities(cfg: AegisQConfig, targets: list[Any], has_inventory: bool, jobs_enabled: bool) -> dict[str, Any]:
    """What the dashboard can start here, with the reason when something is unavailable."""
    from importlib.util import find_spec

    from aegisq.agent.runner import resolve_local_endpoint

    def item(ok: bool, detail: str) -> dict[str, Any]:
        return {"ok": ok, "detail": detail}

    try:
        ep = resolve_local_endpoint(cfg.agent)
        configured = bool(ep.api_key or os.environ.get("AEGISQ_LLM_BASE_URL") or cfg.agent.local_base_url)
        local = item(configured, ep.label if configured else "set GEMINI_API_KEY (Gemma 4) or AEGISQ_LLM_BASE_URL")
    except RuntimeError as e:
        local = item(False, str(e))
    has_anthropic = bool(os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN"))
    if find_spec("anthropic") is None:
        claude = item(False, "pip install 'aegisq[agent]'")
    else:
        claude = item(has_anthropic, cfg.agent.model if has_anthropic else "set ANTHROPIC_API_KEY")
    return {
        "jobs": jobs_enabled,
        "inventory": has_inventory,
        "services": [
            {"name": t.name, "endpoint": t.endpoint, "protocol": t.protocol.value, "managed": t.managed is not None}
            for t in targets
        ],
        "planners": {"rules": item(True, "deterministic, no AI"), "local": local, "claude": claude},
        "schedules": has_inventory and jobs_enabled,
    }


def _display_group(s: ServiceScan) -> str | None:
    """The key exchange a client actually gets: the PQ group if ready, else what a modern offer negotiates."""
    if s.tls:
        if s.tls.pq_ready:
            return s.tls.pq_group
        return s.tls.modern_probe.group if s.tls.modern_probe else None
    if s.ssh:
        return s.ssh.negotiated_kex or (s.ssh.kex_algorithms[0] if s.ssh.kex_algorithms else None)
    return None


def _static_text(name: str) -> str:
    return (resources.files("aegisq") / "web" / "static" / name).read_text(encoding="utf-8")
