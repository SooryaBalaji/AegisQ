from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent))

from aegisq.config import AegisQConfig
from aegisq.workspace import Workspace
from fakes import FAKE_NGINX

# Tests must not see the developer's real keys: never read a .env, and drop model/IBM credentials
# so nothing can reach a paid or rate-limited API (tests that need them set fakes explicitly).
os.environ["AEGISQ_ENV_FILE"] = str(Path(__file__).parent / "no-such-dir" / ".env")
for _var in (
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "AEGISQ_LLM_BASE_URL",
    "AEGISQ_LLM_MODEL",
    "AEGISQ_LLM_API_KEY",
    "AEGISQ_LLM_API",
    "AEGISQ_LLM_FALLBACK_MODELS",
    "AEGISQ_AUDIT_KEY",
):
    os.environ.pop(_var, None)

NGINX_CONF = """events {}
http {
  server {
    listen 443 ssl;
    ssl_certificate     /etc/certs/server.crt;
    ssl_certificate_key /etc/certs/server.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ecdh_curve X25519:prime256v1;  # set by platform team
    location / { return 200; }
  }
}
"""


@pytest.fixture
def home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    h = tmp_path / "aegisq-home"
    monkeypatch.setenv("AEGISQ_HOME", str(h))
    monkeypatch.delenv("AEGISQ_AUDIT_KEY", raising=False)
    for var in ("AEGISQ_API_TOKENS", "AEGISQ_ADMIN_USER", "AEGISQ_ADMIN_PASSWORD"):
        monkeypatch.delenv(var, raising=False)
    return h


@pytest.fixture
def cfg(home: Path) -> AegisQConfig:
    c = AegisQConfig()
    c.agent.verify_attempts = 1
    c.agent.verify_interval_s = 0
    c.agent.approval_timeout_s = 5
    return c


@pytest.fixture
def ws(cfg: AegisQConfig) -> Workspace:
    return Workspace(cfg.home_path)


@pytest.fixture
def fake_nginx(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, object]:
    """A managed 'server': config file + fake nginx binary. Returns paths and an argv prefix."""
    d = tmp_path / "server"
    d.mkdir()
    conf = d / "site.conf"
    conf.write_text(NGINX_CONF)
    state = d / "running.conf"
    state.write_text(NGINX_CONF)
    exe = d / "nginx"
    exe.write_text(FAKE_NGINX)
    exe.chmod(exe.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("FAKE_NGINX_CONF", str(conf))
    monkeypatch.setenv("FAKE_NGINX_STATE", str(state))
    monkeypatch.setenv("FAKE_OPENSSL", "3.5.0")
    return {"conf": conf, "state": state, "argv": [sys.executable, str(exe)], "dir": d}


PASSWORD = "correct horse battery"


def add_user(cfg: AegisQConfig, name: str, role: str = "admin", password: str = PASSWORD) -> None:
    from aegisq.users import UserStore

    UserStore(Workspace(cfg.home_path).home / "state.db").add(name, role, password, created_by="test")


def browser(app, client: tuple[str, int] = ("127.0.0.1", 50000)):
    """A TestClient that behaves like the dashboard: sends X-AegisQ and keeps the session cookie."""
    from fastapi.testclient import TestClient

    return TestClient(app, headers={"X-AegisQ": "1"}, client=client)


def signed_in(app, name: str, password: str = PASSWORD):
    c = browser(app)
    r = c.post("/api/login", json={"name": name, "password": password})
    assert r.status_code == 200, r.text
    return c
