from __future__ import annotations

import datetime as dt
import json
from typing import Any

import pytest
from click.testing import CliRunner

from aegisq.agent import brief
from aegisq.agent.advice import advice_for
from aegisq.models import ScanReport, ServiceScan, ServiceTarget, Status
from conftest import add_user, signed_in


def _scan(ws) -> ServiceScan:
    svc = ServiceTarget(
        name="billing",
        host="billing.example.com",
        port=443,
        data_category="financial",
        owner="payments-team",
        platform="apache",
        stack={"openssl": "3.0.13"},
    )
    s = ServiceScan(service=svc, status=Status.CLASSICAL)
    now = dt.datetime.now(dt.timezone.utc)
    ws.save_scan(ScanReport(scan_id="s1", started_at=now, finished_at=now, tool_version="t", backend="n", results=[s]))
    ws.audit.append("patch.test_failed", {"service": "billing", "reason": "unknown group X25519MLKEM768"})
    return s


def model(*sentences: str) -> Any:
    def post(body: dict[str, Any]) -> dict[str, Any]:
        post.body = body  # type: ignore[attr-defined]
        return {"choices": [{"message": {"content": json.dumps({"sentences": list(sentences)})}}]}

    return post


def test_check_sentence_rules() -> None:
    facts = ["Its openssl is 3.0.13.", "Risk is high: 7 years of secrecy plus 2 years to migrate."]
    assert brief.check_sentence("The server runs OpenSSL 3.0.13 [F1].", facts) == (
        "The server runs OpenSSL 3.0.13.",
        ["F1"],
    )
    assert brief.check_sentence("It is urgent.", facts) == "no citation"
    assert brief.check_sentence("It runs OpenSSL 3.4 [F1].", facts) == "'3.4' is not in the cited facts"
    assert brief.check_sentence("It runs OpenSSL 3 [F1].", facts) == "'3' is not in the cited facts"
    assert brief.check_sentence("Secrets last 7 years [F9].", facts) == "cites a fact that does not exist"
    assert "not in the cited facts" in brief.check_sentence("Run `apachectl -k graceful` now [F1].", facts)
    assert brief.check_sentence("Secrets last 7 years [F1].", facts) == "'7' is not in the cited facts"
    assert brief.check_sentence("Secrets last 7 years, migration takes 2 [F1, F2].", facts)[1] == ["F1", "F2"]


def test_brief_keeps_cited_sentences_and_removes_the_rest(ws, cfg) -> None:
    s = _scan(ws)
    post = model(
        "billing.example.com only uses classical key exchange [F1].",
        "It handles financial data owned by payments-team [F2].",
        "Its OpenSSL 3.0.13 cannot use post-quantum groups [F4].",
        "Upgrade to OpenSSL 3.4 to fix it [F4].",
        "This is very urgent.",
        "Run `sudo apt install openssl` [F4].",
    )
    b = brief.write(ws, s, cfg.risk, post, "gemma-4-31b-it", who="alice")
    assert [x["text"] for x in b.sentences] == [
        "billing.example.com only uses classical key exchange.",
        "It handles financial data owned by payments-team.",
        "Its OpenSSL 3.0.13 cannot use post-quantum groups.",
    ]
    assert {r["reason"] for r in b.removed} == {
        "'3.4' is not in the cited facts",
        "no citation",
        "'`sudo apt install openssl`' is not in the cited facts",
    }
    assert b.fix == advice_for("apache", "tls").removeprefix("not managed by AegisQ: ")
    assert any("config test" in f and "X25519MLKEM768" in f for f in b.facts)
    sent = post.body["messages"][1]["content"]  # type: ignore[attr-defined]
    assert "F1: billing is billing.example.com:443" in sent
    md = b.markdown()
    assert "## Fix (vendor documentation, not written by AI)" in md and "Removed by the fact check" in md
    ev = [e for e in ws.audit.entries() if e["event"] == "brief.generated"][-1]["data"]
    assert ev["kept"] == 3 and ev["removed"] == 3 and ev["written_by"] == "gemma-4-31b-it"
    assert ws.load_json("briefs/billing.json")["service"] == "billing"


def test_brief_falls_back_to_the_template(ws, cfg) -> None:
    s = _scan(ws)

    def broken(body: dict[str, Any]) -> dict[str, Any]:
        raise RuntimeError("HTTP 503")

    b = brief.write(ws, s, cfg.risk, broken, "gemma-4-31b-it")
    assert b.written_by.startswith("template (gemma-4-31b-it failed") and not b.removed
    assert len(b.sentences) == min(len(b.facts), brief.MAX_SENTENCES)
    assert brief.write(ws, s, cfg.risk).written_by == "template (no model)"


def test_cli_and_api(ws, cfg, tmp_path) -> None:
    from aegisq.cli import main
    from aegisq.web.app import create_app

    _scan(ws)
    out = tmp_path / "b.md"
    res = CliRunner().invoke(main, ["--home", str(ws.home), "brief", "billing", "--template", "-o", str(out)])
    assert res.exit_code == 0, res.output
    assert "# Post-quantum brief: billing" in out.read_text()
    assert CliRunner().invoke(main, ["--home", str(ws.home), "brief", "nope", "--template"]).exit_code != 0

    add_user(cfg, "alice", "operator")
    c = signed_in(create_app(cfg), "alice")
    r = c.post("/api/brief", json={"service": "billing", "template": True})
    assert r.status_code == 200, r.text
    assert r.json()["written_by"] == "template (no model)"
    assert c.get("/api/brief/billing").json()["service"] == "billing"
    assert c.get("/api/brief/..%2Fusers").status_code == 404
    assert c.post("/api/brief", json={"service": "missing", "template": True}).status_code == 404
    assert c.post("/api/brief", json={"service": "billing"}).status_code == 409


@pytest.mark.parametrize("role", ["viewer"])
def test_viewers_cannot_spend_model_calls(ws, cfg, role: str) -> None:
    from aegisq.web.app import create_app

    _scan(ws)
    add_user(cfg, "vic", role)
    c = signed_in(create_app(cfg), "vic")
    assert c.post("/api/brief", json={"service": "billing", "template": True}).status_code == 403


def test_blocked_managed_server_gets_upgrade_advice(ws, cfg) -> None:
    from aegisq.models import ManagedNginx

    svc = ServiceTarget(
        name="app-legacy",
        host="127.0.0.1",
        port=8444,
        managed=ManagedNginx(config_path="/tmp/site.conf"),
        stack={"openssl": "3.0.13"},
    )
    b = brief.write(ws, ServiceScan(service=svc, status=Status.CLASSICAL), cfg.risk)
    assert b.fix.startswith("Upgrade first: set 'ssl_ecdh_curve") and "OpenSSL 3.5 or later" in b.fix
    assert "Its TLS library is OpenSSL 3.0.13." in b.facts
