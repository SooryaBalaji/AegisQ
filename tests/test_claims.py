"""Gemma proposes, the scanner proves: extraction is grounded, every claim is checked with a real handshake."""

from __future__ import annotations

import base64
import json
from typing import Any

import pytest
from click.testing import CliRunner

from aegisq.agent import claims as cl
from aegisq.agent.gemma_check import SAMPLE, run_checks, solid_png
from aegisq.agent.runner import LocalEndpoint
from aegisq.scanner.engine import ScanOptions
from conftest import add_user, signed_in
from fakes import tls_server

CONF = """server {
  server_name shop.example.com;
  listen 443 ssl;
  ssl_ecdh_curve X25519MLKEM768:X25519;
}
"""


def reply(obj: Any) -> dict[str, Any]:
    text = obj if isinstance(obj, str) else json.dumps(obj)
    return {"choices": [{"message": {"role": "assistant", "content": text}, "finish_reason": "stop"}]}


class Model:
    def __init__(self, *turns: Any) -> None:
        self.turns, self.bodies = list(turns), []

    def __call__(self, body: dict[str, Any]) -> dict[str, Any]:
        self.bodies.append(body)
        t = self.turns[len(self.bodies) - 1]
        return t(body) if callable(t) else t


def endpoint(host: str, port: int | None = 443, **kw: Any) -> dict[str, Any]:
    return {"host": host, "port": port, "protocol": "tls", **kw}


def test_extraction_is_grounded_in_the_shared_text() -> None:
    model = Model(
        reply(
            {
                "endpoints": [
                    endpoint(
                        "shop.example.com",
                        platform="nginx",
                        groups=["X25519MLKEM768", "X25519"],
                        evidence="ssl_ecdh_curve   X25519MLKEM768:X25519;",
                    ),
                    endpoint("made-up.example.com", pq_claimed=True, evidence="pq on everywhere"),
                    endpoint("shop.example.com", evidence="duplicate"),
                    endpoint("bad host!", evidence="x"),
                    endpoint("mail.example.com", None, starttls="smtp", platform="sendmail"),
                ],
                "notes": "two servers",
            }
        )
    )
    ext = cl.extract(model, "gemma-4-31b-it", text=CONF)
    assert [c.label for c in ext.endpoints] == [
        "shop.example.com:443",
        "made-up.example.com:443",
        "mail.example.com:25 (smtp)",
    ]
    shop, made_up, mail = ext.endpoints
    assert shop.grounded is True and shop.pq_expected is True and shop.platform == "nginx"
    assert made_up.grounded is False  # the quote is not in the input: shown to the person as unsupported
    assert mail.platform is None and mail.pq_expected is None  # unknown platform names are dropped
    assert len(ext.dropped) == 1 and "bad host" in ext.dropped[0]
    sent = model.bodies[0]
    assert sent["model"] == "gemma-4-31b-it" and sent["messages"][0]["role"] == "system"
    assert CONF in sent["messages"][1]["content"][1]["text"]


def test_extraction_retries_once_on_bad_json() -> None:
    model = Model(reply("Sure! Here you go."), reply("```json\n" + json.dumps({"endpoints": []}) + "\n```"))
    assert cl.extract(model, "m", text="nothing here").endpoints == []
    assert "JSON" in model.bodies[1]["messages"][-1]["content"]
    with pytest.raises(cl.ClaimError):
        cl.extract(Model(reply("no"), reply("still no")), "m", text="x")


def test_image_is_sent_as_a_data_url_and_type_is_sniffed() -> None:
    png = solid_png()
    model = Model(reply({"endpoints": [endpoint("lb.example.net", pq_claimed=False, evidence="TLS 1.2 policy")]}))
    ext = cl.extract(model, "m", image=png)
    assert ext.source == "image" and ext.endpoints[0].grounded is None
    part = model.bodies[0]["messages"][1]["content"][-1]
    assert part["type"] == "image_url" and part["image_url"]["url"].startswith("data:image/png;base64,")
    with pytest.raises(cl.ClaimError, match="PNG, JPEG or WebP"):
        cl.extract(model, "m", image=b"<svg/>")
    with pytest.raises(cl.ClaimError):
        cl.extract(model, "m")


def _ext(*eps: dict[str, Any]) -> cl.Extraction:
    return cl.extract(Model(reply({"endpoints": list(eps)})), "m", text="x")


def test_the_scanner_decides_every_verdict(ws) -> None:
    opts = ScanOptions(timeout=2, legacy_protocols=False, fetch_certificate=False)
    with tls_server("pq") as pq, tls_server("classical") as classical:
        ext = _ext(
            endpoint("127.0.0.1", pq.port, pq_claimed=True),
            endpoint(
                "127.0.0.1",
                classical.port,
                pq_claimed=True,
                platform="haproxy",
                library="OpenSSL",
                library_version="3.5.0",
            ),
            endpoint(
                "127.0.0.1", classical.port + 0, groups=["X25519"], starttls=None, protocol="tls", host_note="dup"
            ),
            endpoint("127.0.0.1", 1, groups=["X25519MLKEM768"]),
        )
        checks = cl.verify(ws, ext, [0, 1, 2], opts, "alice")
    by = {c["index"]: c for c in checks}
    assert by[0]["verdict"] == "confirmed" and "X25519MLKEM768" in by[0]["observed"]
    assert by[1]["verdict"] == "contradicted" and "ssl-default-bind-curves" in by[1]["fix"]
    assert "cannot see versions" in by[1]["unverified"]
    assert by[2]["verdict"] == "unverifiable"  # the duplicate endpoint was merged, so index 2 is port 1
    assert cl.summarize(checks) == {"confirmed": 1, "contradicted": 1, "unverifiable": 1}
    again = cl.load(ws, ext.id)
    assert again is not None and again.checks == checks and cl.scan_report(ws, again) is not None
    events = [e["event"] for e in ws.audit.tail(10)]
    assert "claims.verified" in events
    with pytest.raises(cl.ClaimError):
        cl.verify(ws, ext, [], opts, "alice")
    with pytest.raises(cl.ClaimError):
        cl.targets_for(ext, [9])


def test_scope_still_applies(ws) -> None:
    from aegisq.netutil import Scope

    ext = _ext(endpoint("127.0.0.1", 9, pq_claimed=True))
    checks = cl.verify(ws, ext, [0], ScanOptions(timeout=1, scope=Scope(deny=["127.0.0.0/8"])), "alice")
    assert checks[0]["verdict"] == "unverifiable" and "scan scope" in checks[0]["observed"]


def test_load_rejects_odd_ids(ws) -> None:
    assert cl.load(ws, "../../state") is None and cl.load(ws, "chk-1") is None


def _fake_gemma(monkeypatch: pytest.MonkeyPatch, model: Any) -> None:
    monkeypatch.setattr(cl, "gemma_client", lambda *a, **k: (model, LocalEndpoint("http://127.0.0.1:1/v1", "m", None)))


def test_dashboard_flow(cfg, ws, monkeypatch: pytest.MonkeyPatch) -> None:
    from aegisq.web.app import create_app

    add_user(cfg, "alice")
    add_user(cfg, "vic", role="viewer")
    app = create_app(cfg)
    with tls_server("classical") as srv:
        _fake_gemma(
            monkeypatch,
            Model(reply({"endpoints": [endpoint("127.0.0.1", srv.port, pq_claimed=True, evidence="ML-KEM enabled")]})),
        )
        c = signed_in(app, "alice")
        assert signed_in(app, "vic").post("/api/claims", json={"text": "x"}).status_code == 403
        r = c.post(
            "/api/claims", json={"text": "ML-KEM enabled on 127.0.0.1", "image": base64.b64encode(solid_png()).decode()}
        )
        assert r.status_code == 200, r.text
        ext = r.json()
        assert ext["source"] == "text+image" and ext["endpoints"][0]["grounded"] is True
        assert c.get(f"/api/claims/{ext['id']}/cbom").status_code == 404
        v = c.post(f"/api/claims/{ext['id']}/verify", json={"endpoints": [0]})
        assert v.status_code == 200, v.text
        assert v.json()["checks"][0]["verdict"] == "contradicted"
    assert c.get("/api/claims").json()[0]["summary"]["contradicted"] == 1
    bom = c.get(f"/api/claims/{ext['id']}/cbom")
    assert bom.status_code == 200 and bom.json()["specVersion"] == "1.6"
    assert c.post("/api/claims", json={"image": "not base64!"}).status_code == 422
    assert c.get("/api/claims/chk-20990101000000-abcdef").status_code == 404


def test_dashboard_without_gemma(cfg, monkeypatch: pytest.MonkeyPatch) -> None:
    from aegisq.web.app import create_app

    def nope(*a: Any, **k: Any) -> Any:
        raise RuntimeError("the Gemini API needs GEMINI_API_KEY")

    monkeypatch.setattr(cl, "gemma_client", nope)
    add_user(cfg, "alice")
    r = signed_in(create_app(cfg), "alice").post("/api/claims", json={"text": "x"})
    assert r.status_code == 409 and "GEMINI_API_KEY" in r.json()["detail"]


def test_cli_claims_check(cfg, ws, tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    from aegisq.cli import main

    f = tmp_path / "main.cf"
    with tls_server("pq") as srv:
        f.write_text(f"# relay at 127.0.0.1:{srv.port}\n{SAMPLE}")
        _fake_gemma(
            monkeypatch,
            Model(
                reply(
                    {
                        "endpoints": [
                            endpoint(
                                "127.0.0.1", srv.port, groups=["X25519MLKEM768"], evidence="X25519MLKEM768, X25519"
                            )
                        ]
                    }
                )
            ),
        )
        res = CliRunner().invoke(main, ["--home", str(ws.home), "claims", "check", "--text", str(f), "--yes"])
    assert res.exit_code == 0, res.output
    assert "CONFIRMED" in res.output and "aegisq cbom --scan" in res.output


def test_gemma_check_passes_and_fails_honestly() -> None:
    def good(body: dict[str, Any]) -> dict[str, Any]:
        if body.get("tools"):
            call = {"id": "1", "type": "function", "function": {"name": "list_services", "arguments": "{}"}}
            return {"choices": [{"message": {"role": "assistant", "content": "", "tool_calls": [call]}}]}
        parts = body["messages"][-1]["content"]
        if isinstance(parts, list) and parts[-1]["type"] == "image_url" and "color" in parts[0]["text"]:
            return reply("Red")
        return reply(
            {
                "endpoints": [
                    endpoint(
                        "mail.example.com",
                        25,
                        starttls="smtp",
                        evidence="tls_eecdh_auto_curves = X25519MLKEM768, X25519, prime256v1",
                        groups=["X25519MLKEM768"],
                    )
                ]
            }
        )

    assert all(r["ok"] for r in run_checks(good, "m"))
    bad = run_checks(lambda body: reply("I can't do that."), "m")
    assert [r["ok"] for r in bad] == [False, False, False]
    assert "list_services" in bad[0]["detail"] and "red" in bad[1]["detail"]


def test_pq_names() -> None:
    assert cl.is_pq_name("X25519MLKEM768") and cl.is_pq_name("mlkem768x25519-sha256")
    assert cl.is_pq_name("ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09") and cl.is_pq_name("x25519_mlkem768")
    assert not cl.is_pq_name("X25519") and not cl.is_pq_name("prime256v1")


def test_cli_yes_skips_hosts_not_in_the_text(cfg, ws, tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    from aegisq.cli import main

    f = tmp_path / "main.cf"
    f.write_text(SAMPLE)
    _fake_gemma(
        monkeypatch,
        Model(reply({"endpoints": [endpoint("invented.example.net", 25, starttls="smtp", evidence="X25519MLKEM768")]})),
    )
    res = CliRunner().invoke(main, ["--home", str(ws.home), "claims", "check", "--text", str(f), "--yes"])
    assert res.exit_code == 0, res.output
    assert "not scanning invented.example.net:25 (smtp): not found in your text" in res.output
    assert "CONFIRMED" not in res.output and "CONTRADICTED" not in res.output
