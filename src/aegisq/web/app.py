"""Dashboard and REST API.

Security model: people sign in with a user name and password (scrypt hashes in state.db). A sign-in
sets an HttpOnly, SameSite=Strict session cookie; the server keeps only its hash. Every /api route
except sign-in requires a session, and every state-changing request must also carry the
``X-AegisQ: 1`` header, which a cross-site page cannot add without a CORS preflight that this server
never grants. Each route checks the role's permission (view, run, approve, admin); the approver
identity comes from the session, never from the request body. With no users yet, the first admin can
be created from this computer only, or with `aegisq users add`. Responses carry a strict CSP; the
page loads no third-party code.
"""

from __future__ import annotations

import ipaddress
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
from aegisq.config import AegisQConfig
from aegisq.models import ServiceScan
from aegisq.risk import RESOURCE_ESTIMATE_NOTE, RESOURCE_ESTIMATES, rank
from aegisq.users import GRANTS, MAX_PASSWORD, SESSION_MAX_S, User, UserStore, can
from aegisq.workspace import Workspace

CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; "
    "frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
)
_STATIC = {
    "app.js": "text/javascript; charset=utf-8",
    "boot.js": "text/javascript; charset=utf-8",
    "ui.css": "text/css; charset=utf-8",
    "favicon.svg": "image/svg+xml",
    "plex-sans-400.woff2": "font/woff2",
    "plex-sans-500.woff2": "font/woff2",
    "plex-sans-600.woff2": "font/woff2",
    "OFL-plex-sans.txt": "text/plain; charset=utf-8",
}


class NewUser(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$")
    role: Literal["viewer", "operator", "approver", "admin"]
    password: str = Field(max_length=MAX_PASSWORD)


class Credentials(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(max_length=64)
    password: str = Field(max_length=MAX_PASSWORD)


class NewPassword(BaseModel):
    model_config = ConfigDict(extra="forbid")
    password: str = Field(max_length=MAX_PASSWORD)
    current: str | None = Field(default=None, max_length=MAX_PASSWORD)


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
    planner: Literal["auto", "gemma", "rules"] = "auto"
    services: list[Annotated[str, Field(pattern=_SERVICE_NAME)]] = Field(default_factory=list, max_length=200)


class BenchmarkJob(_Req):
    kind: Literal["benchmark"]
    url: str = Field(max_length=300)
    n: int = Field(default=200, ge=10, le=5000)
    method: Literal["auto", "native", "curl"] = "auto"


JobRequest = Annotated[ScanJob | MigrateJob | BenchmarkJob, Field(discriminator="kind")]


class ClaimSource(_Req):
    text: str | None = Field(default=None, max_length=64_000)
    image: str | None = Field(default=None, max_length=7_000_000)  # base64, at most 5 MB decoded


class ClaimPick(_Req):
    endpoints: list[int] = Field(min_length=1, max_length=50)


_SERVICE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


class BriefRequest(_Req):
    service: str = Field(pattern=_SERVICE_RE.pattern)
    template: bool = False


SESSION_COOKIE = "aegisq_session"
CSRF_HEADER = "x-aegisq"
_UNSAFE = {"POST", "PUT", "PATCH", "DELETE"}


class _AuthLimiter:
    """Slow down password guessing: at most 20 failures per key (client or user name) per 5 minutes."""

    def __init__(self, limit: int = 20, window: float = 300) -> None:
        self.limit, self.window = limit, window
        self.fails: dict[str, deque[float]] = defaultdict(deque)
        self.lock = threading.Lock()

    def _trim(self, key: str, now: float) -> deque[float]:
        q = self.fails[key]
        while q and now - q[0] > self.window:
            q.popleft()
        return q

    def acquire(self, keys: tuple[str, ...]) -> bool:
        """Count this attempt against every key before the password is checked, atomically, so parallel
        guesses cannot slip past the limit. False when any key is already at the limit."""
        with self.lock:
            now = time.monotonic()
            if any(len(self._trim(k, now)) >= self.limit for k in keys):
                return False
            for k in keys:
                self.fails[k].append(now)
            return True

    def forgive(self, keys: tuple[str, ...]) -> None:
        """The attempt succeeded: it does not count as a failure."""
        with self.lock:
            for k in keys:
                if self.fails[k]:
                    self.fails[k].pop()


def _is_loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host == "localhost"


def _initial_admin(users: UserStore, ws: Workspace) -> None:
    """Containers and scripted installs: AEGISQ_ADMIN_USER / AEGISQ_ADMIN_PASSWORD create the first admin once."""
    if os.environ.get("AEGISQ_API_TOKENS"):
        print(
            "AEGISQ_API_TOKENS is no longer used: people sign in with a user name and password. "
            "Create users with `aegisq users add NAME --role ROLE`.",
            file=sys.stderr,
            flush=True,
        )
    name, password = os.environ.get("AEGISQ_ADMIN_USER"), os.environ.get("AEGISQ_ADMIN_PASSWORD")
    if name and password and users.get(name) is None:
        users.add(name, "admin", password, created_by="environment")
        ws.audit.append("user.created", {"name": name, "role": "admin", "via": "AEGISQ_ADMIN_USER"}, actor="system")
    elif users.count() == 0:
        print(
            "AegisQ has no users yet. Open the dashboard on this computer to create the first admin, "
            "or run `aegisq users add NAME --role admin`.",
            file=sys.stderr,
            flush=True,
        )


def create_app(
    cfg: AegisQConfig,
    inventory: str | None = None,
    config_path: str | None = None,
    jobs_enabled: bool = True,
    background: bool = False,
) -> FastAPI:
    from aegisq.web.jobs import JobConflict, JobManager

    ws = Workspace(cfg.home_path)
    users = UserStore(ws.home / "state.db")
    _initial_admin(users, ws)
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

    @app.middleware("http")
    async def csrf(request: Request, call_next: Any) -> Response:
        unsafe = request.method in _UNSAFE and request.url.path.startswith("/api")
        if unsafe and request.headers.get(CSRF_HEADER) != "1":
            return JSONResponse({"detail": "missing X-AegisQ header"}, status_code=403)
        resp: Response = await call_next(request)
        return resp

    def principal(request: Request) -> User:
        sid = request.cookies.get(SESSION_COOKIE, "")
        u = users.session_user(sid) if sid else None
        if u is None:
            raise HTTPException(401, "sign in to continue")
        return u

    def _client(request: Request) -> str:
        return request.client.host if request.client else "unknown"

    def _local_only(request: Request) -> bool:
        """The request comes from this computer and not through a proxy."""
        forwarded = any(h in request.headers for h in ("x-forwarded-for", "forwarded", "x-real-ip"))
        return _is_loopback(_client(request)) and not forwarded

    def _sign_in(request: Request, user: User) -> JSONResponse:
        sid = users.start_session(user.name)
        resp = JSONResponse(_me(user))
        resp.set_cookie(
            SESSION_COOKIE,
            sid,
            max_age=SESSION_MAX_S,
            httponly=True,
            samesite="strict",
            secure=request.url.scheme == "https",
            path="/",
        )
        return resp

    def _me(u: User) -> dict[str, Any]:
        return {
            "identity": u.name,
            "role": u.role,
            "permissions": sorted(GRANTS[u.role]),
            "separation_of_duties": cfg.agent.separation_of_duties,
        }

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
        cache = "public, max-age=31536000, immutable" if name.endswith(".woff2") else "no-cache"
        return Response(_static_bytes(name), media_type=_STATIC[name], headers={"Cache-Control": cache})

    # ---------------------------------------------------------------- API
    @app.get("/api/me")
    def me(u: User = Depends(principal)) -> dict[str, Any]:  # noqa: B008 - FastAPI dependency
        return _me(u)

    @app.get("/api/setup")
    def setup_status(request: Request) -> dict[str, Any]:
        needed = users.count() == 0
        return {"needed": needed, "allowed": needed and _local_only(request)}

    @app.post("/api/setup")
    def setup(body: Credentials, request: Request) -> JSONResponse:
        if users.count():
            raise HTTPException(409, "AegisQ already has users: sign in instead")
        if not _local_only(request):
            raise HTTPException(
                403, "create the first admin on the computer running AegisQ, or with `aegisq users add`"
            )
        try:
            u = users.add(body.name, "admin", body.password, created_by="setup")
        except ValueError as e:
            raise HTTPException(422, str(e)) from None
        ws.audit.append("user.created", {"name": u.name, "role": "admin", "via": "first-run setup"}, actor=u.name)
        return _sign_in(request, u)

    @app.post("/api/login")
    def login(body: Credentials, request: Request) -> JSONResponse:
        keys = (f"client:{_client(request)}", f"user:{body.name.lower()}")
        if not limiter.acquire(keys):
            raise HTTPException(429, "too many failed sign-ins: wait a few minutes and try again")
        u = users.verify(body.name, body.password)
        if u is None:
            ws.audit.append("user.sign_in_failed", {"name": body.name[:64], "client": _client(request)})
            raise HTTPException(401, "wrong user name or password")
        limiter.forgive(keys)
        ws.audit.append("user.signed_in", {"client": _client(request)}, actor=u.name)
        return _sign_in(request, u)

    @app.post("/api/logout")
    def logout(request: Request) -> JSONResponse:
        sid = request.cookies.get(SESSION_COOKIE, "")
        if sid:
            users.end_session(sid)
        resp = JSONResponse({"signed_out": True})
        resp.delete_cookie(SESSION_COOKIE, path="/")
        return resp

    @app.post("/api/me/password")
    def change_password(body: NewPassword, request: Request, u: User = Depends(principal)) -> dict[str, Any]:  # noqa: B008
        if body.current is None or users.verify(u.name, body.current) is None:
            raise HTTPException(403, "your current password is not right")
        try:
            users.set_password(u.name, body.password, keep_session=request.cookies.get(SESSION_COOKIE))
        except ValueError as e:
            raise HTTPException(422, str(e)) from None
        ws.audit.append("user.password_changed", {"name": u.name, "via": "dashboard"}, actor=u.name)
        return {"changed": True}

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
                    "margin": r.margin,
                    "severity": r.severity,
                    "at_risk": r.at_risk,
                    "breaks_even_z": r.breaks_even_z,
                    "kind": s.service.managed.kind if s.service.managed else None,
                    "platform": s.service.platform,
                    "starttls": s.service.starttls,
                    "owner": s.service.owner,
                    "advice": None if s.service.managed or s.pq_ready else _advice(s),
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

    claim_lock = threading.Lock()

    # --------------------------------------------------------------- briefs
    @app.get("/api/brief/{service}")
    def get_brief(service: str, who: str = Depends(identity)) -> dict[str, Any]:
        if not _SERVICE_RE.match(service):
            raise HTTPException(404, "no brief for this server yet")
        data = ws.load_json(f"briefs/{service}.json")
        if not data:
            raise HTTPException(404, "no brief for this server yet")
        return dict(data)

    @app.post("/api/brief")
    def new_brief(body: BriefRequest, who: str = Depends(can_run)) -> dict[str, Any]:
        from aegisq.agent import brief
        from aegisq.agent.claims import gemma_client
        from aegisq.agent.tools import apply_facts

        if not jobs_enabled:
            raise HTTPException(403, "this dashboard is read-only (started with --read-only)")
        report = ws.latest_scan()
        scan = (
            next((s for s in apply_facts(report.results, ws) if s.service.name == body.service), None)
            if report
            else None
        )
        if scan is None:
            raise HTTPException(404, f"no server named {body.service!r} in the latest scan")
        post = model = None
        if not body.template:
            from aegisq.agent.runner import gemma_status

            ok, why = gemma_status(cfg.agent)
            if not ok:
                raise HTTPException(409, f"Gemma 4 is not set up: {why}")
            try:
                post, ep = gemma_client(cfg.agent)
                model = ep.model
            except RuntimeError as e:
                raise HTTPException(409, f"Gemma 4 is not set up: {e}") from None
        if not claim_lock.acquire(blocking=False):
            raise HTTPException(409, "Gemma 4 is busy with another request")
        try:
            b = brief.write(ws, scan, cfg.risk, post, model, who=who)
        finally:
            claim_lock.release()
        return b.to_dict()

    # --------------------------------------------------------------- claims

    @app.get("/api/claims")
    def list_claims(who: str = Depends(identity)) -> list[dict[str, Any]]:
        from aegisq.agent import claims as cl

        out = []
        for p in sorted((ws.home / "claims").glob("chk-*.json"), reverse=True):
            if p.stem.endswith("-scan"):
                continue
            ext = cl.load(ws, p.stem)
            if ext is None:
                continue
            out.append(
                {
                    "id": ext.id,
                    "created_at": ext.created_at,
                    "created_by": ext.created_by,
                    "source": ext.source,
                    "endpoints": len(ext.endpoints),
                    "summary": cl.summarize(ext.checks) if ext.checks else None,
                }
            )
            if len(out) >= 20:
                break
        return out

    @app.get("/api/claims/{cid}")
    def get_claim(cid: str, who: str = Depends(identity)) -> dict[str, Any]:
        from aegisq.agent import claims as cl

        ext = cl.load(ws, cid)
        if ext is None:
            raise HTTPException(404, "no such check")
        return ext.model_dump(mode="json")

    @app.post("/api/claims")
    def new_claim(body: ClaimSource, who: str = Depends(can_run)) -> dict[str, Any]:
        import base64
        import binascii

        from aegisq.agent import claims as cl

        if not jobs_enabled:
            raise HTTPException(403, "this dashboard is read-only (started with --read-only)")
        image = None
        if body.image:
            try:
                image = base64.b64decode(body.image.split(",", 1)[-1], validate=True)
            except (binascii.Error, ValueError):
                raise HTTPException(422, "image is not valid base64") from None
        try:
            post, ep = cl.gemma_client(cfg.agent)
        except RuntimeError as e:
            raise HTTPException(409, f"Gemma 4 is not set up: {e}") from None
        if not claim_lock.acquire(blocking=False):
            raise HTTPException(409, "another check is running")
        try:
            ext = cl.extract(post, ep.model, text=body.text, image=image, who=who)
        except cl.ClaimError as e:
            raise HTTPException(422, str(e)) from None
        except RuntimeError as e:
            raise HTTPException(502, f"the model endpoint failed: {e}") from None
        finally:
            claim_lock.release()
        cl.record_extraction(ws, ext)
        return ext.model_dump(mode="json")

    @app.post("/api/claims/{cid}/verify")
    def verify_claim(cid: str, body: ClaimPick, who: str = Depends(can_run)) -> dict[str, Any]:
        from aegisq.agent import claims as cl
        from aegisq.netutil import Scope
        from aegisq.scanner.engine import ScanOptions

        if not jobs_enabled:
            raise HTTPException(403, "this dashboard is read-only (started with --read-only)")
        ext = cl.load(ws, cid)
        if ext is None:
            raise HTTPException(404, "no such check")
        sc = cfg.scan
        opts = ScanOptions(
            timeout=sc.timeout,
            concurrency=sc.concurrency,
            legacy_protocols=False,
            scope=Scope(sc.scope.allow, sc.scope.deny),
        )
        if not claim_lock.acquire(blocking=False):
            raise HTTPException(409, "another check is running")
        try:
            cl.verify(ws, ext, body.endpoints, opts, who)
        except cl.ClaimError as e:
            raise HTTPException(422, str(e)) from None
        finally:
            claim_lock.release()
        return ext.model_dump(mode="json")

    @app.get("/api/claims/{cid}/cbom")
    def claim_cbom(cid: str, who: str = Depends(identity)) -> JSONResponse:
        from aegisq.agent import claims as cl
        from aegisq.cbom import build_cbom, validate_cbom

        ext = cl.load(ws, cid)
        report = cl.scan_report(ws, ext) if ext else None
        if report is None:
            raise HTTPException(404, "this check has no scan yet")
        bom = build_cbom(report)
        validate_cbom(bom)
        return JSONResponse(bom, headers={"Content-Disposition": f'attachment; filename="cbom-{cid}.json"'})

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
        roles = {u.name: u.role for u in users.all()}
        for name, role in change.items():
            if role is None:
                roles.pop(name, None)
            else:
                roles[name] = role
        return sum(r == "admin" for r in roles.values())

    def _db_user(name: str) -> None:
        if users.get(name) is None:
            raise HTTPException(404, "no such user")

    @app.get("/api/users")
    def list_users(who: str = Depends(is_admin)) -> list[dict[str, Any]]:
        return [u.to_dict() for u in users.all()]

    @app.post("/api/users", status_code=201)
    def add_user(body: NewUser, who: str = Depends(is_admin)) -> dict[str, Any]:
        try:
            u = users.add(body.name, body.role, body.password, created_by=who)
        except ValueError as e:
            raise HTTPException(409 if "exists" in str(e) else 422, str(e)) from None
        ws.audit.append("user.created", {"name": body.name, "role": body.role, "via": "dashboard"}, actor=who)
        return u.to_dict()

    @app.patch("/api/users/{name}")
    def set_role(name: str, body: RoleChange, who: str = Depends(is_admin)) -> dict[str, Any]:
        _db_user(name)
        if body.role != "admin" and _all_admins_after({name: body.role}) == 0:
            raise HTTPException(409, "at least one admin must remain")
        users.set_role(name, body.role)
        ws.audit.append("user.role_changed", {"name": name, "role": body.role, "via": "dashboard"}, actor=who)
        return {"name": name, "role": body.role}

    @app.post("/api/users/{name}/password")
    def reset_password(name: str, body: NewPassword, who: str = Depends(is_admin)) -> dict[str, Any]:
        _db_user(name)
        try:
            users.set_password(name, body.password)
        except ValueError as e:
            raise HTTPException(422, str(e)) from None
        ws.audit.append("user.password_reset", {"name": name, "via": "dashboard"}, actor=who)
        return {"name": name, "reset": True}

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
    from aegisq.agent.runner import gemma_status

    def item(ok: bool, detail: str) -> dict[str, Any]:
        return {"ok": ok, "detail": detail}

    gemma = item(*gemma_status(cfg.agent))
    return {
        "jobs": jobs_enabled,
        "inventory": has_inventory,
        "services": [
            {"name": t.name, "endpoint": t.endpoint, "protocol": t.protocol.value, "managed": t.managed is not None}
            for t in targets
        ],
        "planners": {"rules": item(True, "deterministic, no AI"), "gemma": gemma},
        "schedules": has_inventory and jobs_enabled,
    }


def _advice(s: ServiceScan) -> str:
    from aegisq.agent.advice import advice_for

    return advice_for(s.service.platform, s.service.protocol.value).removeprefix("not managed by AegisQ: ")


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


def _static_bytes(name: str) -> bytes:
    return (resources.files("aegisq") / "web" / "static" / name).read_bytes()
