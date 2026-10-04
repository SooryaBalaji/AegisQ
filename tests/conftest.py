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
    "ANTHROPIC_API_KEY",
    "ANTHROPIC_AUTH_TOKEN",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "AEGISQ_LLM_BASE_URL",
    "AEGISQ_LLM_MODEL",
    "AEGISQ_LLM_API_KEY",
    "QISKIT_IBM_TOKEN",
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
    monkeypatch.delenv("AEGISQ_API_TOKENS", raising=False)
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


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    try:
        import qiskit  # noqa: F401
        import qiskit_aer  # noqa: F401

        have_quantum = True
    except ImportError:
        have_quantum = False
    skip_q = pytest.mark.skip(reason="qiskit / qiskit-aer not installed")
    for item in items:
        if "quantum" in item.keywords and not have_quantum:
            item.add_marker(skip_q)
