"""The hosted site: anyone can create an account, and every account is private.

Each account gets its own workspace (scans, claim checks, briefs, audit log) under ``tenants/<name>``. Nobody,
including the site operator, can open another account's workspace: the front app only signs people in, and
every other API request is answered by the signed-in person's own app.

Scanning is limited to domains the account has proved it controls, with a DNS TXT record, and never reaches
private, loopback or link-local addresses, so the site cannot be used to probe other people's servers or the
host's own network.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import json
import re
import secrets
import threading
import time
import urllib.parse
import urllib.request
from collections.abc import Callable
from http.cookies import SimpleCookie
from pathlib import Path
from typing import Any

import yaml
from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field

from aegisq.config import AegisQConfig
from aegisq.users import NAME_RE, User, UserStore
from aegisq.workspace import Workspace, atomic_write

TXT_PREFIX = "aegisq-verify="
DOH_URL = "https://cloudflare-dns.com/dns-query"
MAX_DOMAINS = 20
ACTIONS_PER_HOUR = 60
NO_DOMAINS = "no-verified-domain.invalid"
PRIVATE = [
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "::/128",
    "::1/128",
    "::ffff:0:0/96",
    "64:ff9b::/96",
    "fc00::/7",
    "fe80::/10",
    "ff00::/8",
]
FRONT = ("/api/login", "/api/logout", "/api/me", "/api/setup", "/api/signup", "/api/users")
COUNTED = (("POST", "/api/jobs"), ("POST", "/api/claims"), ("POST", "/api/brief"), ("POST", "/api/domains"))
_DOMAIN_RE = re.compile(r"^(?=.{4,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def normalize_domain(raw: str) -> str:
    d = raw.strip().lower()
    if "://" in d:
        d = urllib.parse.urlsplit(d).hostname or ""
    d = d.split("/")[0].rstrip(".")
    try:
        ipaddress.ip_address(d.strip("[]"))
    except ValueError:
        pass
    else:
        raise ValueError("enter a domain name, not an IP address")
    if not _DOMAIN_RE.match(d):
        raise ValueError(f"{raw.strip()[:80]!r} is not a domain name")
    return d


def lookup_txt(name: str, timeout: float = 5.0) -> list[str]:
    """TXT records for ``name`` through DNS over HTTPS (works on hosts without a usable local resolver)."""
    url = f"{DOH_URL}?{urllib.parse.urlencode({'name': name, 'type': 'TXT'})}"
    req = urllib.request.Request(url, headers={"Accept": "application/dns-json"})  # noqa: S310 - fixed https URL
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 - fixed https URL
        data = json.load(r)
    out = []
    for a in data.get("Answer") or []:
        if a.get("type") == 16:
            out.append("".join(re.findall(r'"((?:[^"\\]|\\.)*)"', str(a.get("data", "")))) or str(a.get("data", "")))
    return out


class Domains:
    def __init__(self, home: Path) -> None:
        self.path = home / "domains.json"
        self.lock = threading.Lock()

    def all(self) -> dict[str, dict[str, Any]]:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}
        return data if isinstance(data, dict) else {}

    def _save(self, data: dict[str, dict[str, Any]]) -> None:
        atomic_write(self.path, json.dumps(data, indent=2))

    def add(self, domain: str) -> dict[str, Any]:
        with self.lock:
            data = self.all()
            if domain not in data:
                if len(data) >= MAX_DOMAINS:
                    raise ValueError(f"at most {MAX_DOMAINS} domains per account")
                data[domain] = {"token": secrets.token_urlsafe(18), "added_at": _now(), "verified_at": None}
                self._save(data)
            return data[domain]

    def remove(self, domain: str) -> bool:
        with self.lock:
            data = self.all()
            if data.pop(domain, None) is None:
                return False
            self._save(data)
            return True

    def mark_verified(self, domain: str) -> None:
        with self.lock:
            data = self.all()
            if domain in data:
                data[domain]["verified_at"] = _now()
                self._save(data)

    def verified(self) -> list[str]:
        return sorted(d for d, v in self.all().items() if v.get("verified_at"))


def record_name(domain: str) -> str:
    return f"_aegisq.{domain}"


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def apply_scope(cfg: AegisQConfig, domains: Domains) -> None:
    cfg.scan.scope.allow = ["." + d for d in domains.verified()] or [NO_DOMAINS]
    cfg.scan.scope.deny = list(PRIVATE)


def write_config(cfg: AegisQConfig, path: Path) -> None:
    atomic_write(path, yaml.safe_dump(cfg.model_dump(mode="json"), sort_keys=False))


class DomainIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    domain: str = Field(max_length=300)


def domain_routes(cfg: AegisQConfig, config_file: Path, lookup: Callable[[str], list[str]]) -> Any:
    def extend(app: FastAPI, ws: Workspace, _cfg: AegisQConfig) -> None:
        domains = Domains(ws.home)

        def who(request: Request) -> str:
            u = request.scope.get("aegisq.user")
            if not isinstance(u, User):
                raise HTTPException(401, "sign in to continue")
            return u.name

        def view(d: str, v: dict[str, Any]) -> dict[str, Any]:
            return {
                "domain": d,
                "verified": bool(v.get("verified_at")),
                "verified_at": v.get("verified_at"),
                "record": record_name(d),
                "value": TXT_PREFIX + str(v.get("token")),
            }

        def refresh() -> None:
            apply_scope(cfg, domains)
            write_config(cfg, config_file)

        @app.get("/api/domains")
        def list_domains(request: Request) -> list[dict[str, Any]]:
            who(request)
            return [view(d, v) for d, v in sorted(domains.all().items())]

        @app.post("/api/domains", status_code=201)
        def add_domain(body: DomainIn, request: Request) -> dict[str, Any]:
            name = who(request)
            try:
                d = normalize_domain(body.domain)
                v = domains.add(d)
            except ValueError as e:
                raise HTTPException(422, str(e)) from None
            ws.audit.append("domain.added", {"domain": d}, actor=name)
            return view(d, v)

        @app.post("/api/domains/{domain}/verify")
        def verify_domain(domain: str, request: Request) -> dict[str, Any]:
            name = who(request)
            v = domains.all().get(domain)
            if v is None:
                raise HTTPException(404, "add the domain first")
            expected = TXT_PREFIX + str(v["token"])
            try:
                found = lookup(record_name(domain))
            except (OSError, ValueError) as e:
                raise HTTPException(502, f"could not look up DNS: {e}") from None
            if expected not in found:
                ws.audit.append("domain.verify_failed", {"domain": domain, "found": found[:5]}, actor=name)
                raise HTTPException(
                    409,
                    f"no TXT record {expected} at {record_name(domain)} yet; DNS changes can take a few minutes",
                )
            domains.mark_verified(domain)
            refresh()
            ws.audit.append("domain.verified", {"domain": domain}, actor=name)
            return view(domain, domains.all()[domain])

        @app.delete("/api/domains/{domain}")
        def remove_domain(domain: str, request: Request) -> dict[str, Any]:
            name = who(request)
            if not domains.remove(domain):
                raise HTTPException(404, "no such domain")
            refresh()
            ws.audit.append("domain.removed", {"domain": domain}, actor=name)
            return {"removed": domain}

    return extend


class HostedApp:
    """ASGI app: the front signs people in; every other API call goes to that person's own app."""

    def __init__(self, cfg: AegisQConfig, background: bool = False, lookup: Callable[[str], list[str]] = lookup_txt):
        from aegisq.web.app import create_app

        self.cfg = cfg
        self.root = cfg.home_path
        self.lookup = lookup
        self.front = create_app(cfg, jobs_enabled=False, background=background, mode="front")
        self.users = UserStore(self.root / "state.db")
        self.tenants: dict[str, Any] = {}
        self.lock = threading.Lock()
        self.actions: dict[str, list[float]] = {}

    def tenant(self, name: str) -> Any:
        from aegisq.web.app import create_app

        with self.lock:
            app = self.tenants.get(name)
            if app is not None:
                return app
            if not NAME_RE.match(name):
                raise ValueError("bad account name")
            home = (self.root / "tenants" / name).resolve()
            home.mkdir(parents=True, exist_ok=True)
            tcfg = self.cfg.model_copy(deep=True)
            tcfg.home = str(home)
            tcfg.agent.separation_of_duties = False
            config_file = home / "aegisq.yaml"
            apply_scope(tcfg, Domains(home))
            write_config(tcfg, config_file)
            app = create_app(
                tcfg,
                config_path=str(config_file),
                jobs_enabled=True,
                background=False,
                mode="tenant",
                extend=domain_routes(tcfg, config_file, self.lookup),
            )
            self.tenants[name] = app
            return app

    def _user(self, scope: dict[str, Any]) -> User | None:
        from aegisq.web.app import SESSION_COOKIE

        raw = b"; ".join(v for k, v in scope.get("headers", []) if k == b"cookie").decode("latin-1")
        jar: SimpleCookie = SimpleCookie()
        try:
            jar.load(raw)
        except Exception:  # a malformed Cookie header is the same as none
            return None
        sid = jar[SESSION_COOKIE].value if SESSION_COOKIE in jar else ""
        return self.users.session_user(sid) if sid else None

    def _over_limit(self, name: str, method: str, path: str) -> bool:
        if not any(method == m and path.startswith(p) for m, p in COUNTED):
            return False
        now = time.time()
        with self.lock:
            recent = [t for t in self.actions.get(name, []) if now - t < 3600]
            if len(recent) >= ACTIONS_PER_HOUR:
                self.actions[name] = recent
                return True
            recent.append(now)
            self.actions[name] = recent
            return False

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        path = scope.get("path", "")
        if scope["type"] != "http" or not path.startswith("/api/") or path.startswith(FRONT):
            await self.front(scope, receive, send)
            return
        user = self._user(scope)
        if user is None:
            await _json(send, 401, {"detail": "sign in to continue"})
            return
        if self._over_limit(user.name, scope.get("method", "GET"), path):
            await _json(send, 429, {"detail": f"at most {ACTIONS_PER_HOUR} scans, checks and briefs per hour"})
            return
        app = self.tenant(user.name)
        await app({**scope, "aegisq.user": User(user.name, "operator")}, receive, send)


async def _json(send: Any, status: int, body: dict[str, Any]) -> None:
    data = json.dumps(body).encode()
    headers = [(b"content-type", b"application/json"), (b"content-length", str(len(data)).encode())]
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": data})
