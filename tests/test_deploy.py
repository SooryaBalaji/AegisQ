from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml
from click.testing import CliRunner

ROOT = Path(__file__).resolve().parents[1]


def test_serve_reads_port_and_proxy_setting(cfg, ws, monkeypatch: pytest.MonkeyPatch) -> None:
    import uvicorn

    from aegisq.cli import main

    seen: dict[str, Any] = {}
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: seen.update(kw))
    monkeypatch.setenv("PORT", "10000")
    monkeypatch.setenv("AEGISQ_BEHIND_PROXY", "1")
    res = CliRunner().invoke(main, ["--home", str(ws.home), "serve", "--host", "0.0.0.0"])
    assert res.exit_code == 0, res.output
    assert seen["port"] == 10000 and seen["host"] == "0.0.0.0"
    assert seen["proxy_headers"] is True and seen["forwarded_allow_ips"] == "*"


def test_serve_does_not_trust_proxy_headers_by_default(cfg, ws, monkeypatch: pytest.MonkeyPatch) -> None:
    import uvicorn

    from aegisq.cli import main

    seen: dict[str, Any] = {}
    monkeypatch.setattr(uvicorn, "run", lambda app, **kw: seen.update(kw))
    monkeypatch.delenv("PORT", raising=False)
    monkeypatch.delenv("AEGISQ_BEHIND_PROXY", raising=False)
    assert CliRunner().invoke(main, ["--home", str(ws.home), "serve"]).exit_code == 0
    assert seen["port"] == 8000 and seen["proxy_headers"] is False


def test_render_blueprint() -> None:
    bp = yaml.safe_load((ROOT / "render.yaml").read_text())
    svc = bp["services"][0]
    assert svc["runtime"] == "docker" and svc["healthCheckPath"] == "/healthz"
    assert (ROOT / svc["dockerfilePath"]).is_file()
    assert svc["disk"]["mountPath"] == "/var/lib/aegisq/workspace"
    keys = {e["key"] for e in svc["envVars"]}
    assert {"AEGISQ_ADMIN_USER", "AEGISQ_ADMIN_PASSWORD", "GEMINI_API_KEY", "AEGISQ_AUDIT_KEY"} <= keys
    start = (ROOT / "deploy" / "render-start.sh").read_bytes()
    assert b"\r\n" not in start and start.startswith(b"#!/bin/sh")
