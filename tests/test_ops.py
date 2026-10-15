import datetime as dt
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from fastapi.testclient import TestClient

from aegisq.models import ScanReport, ServiceScan, ServiceTarget, Status
from aegisq.ops import Ops, ScheduleStore, check_webhook_url, mask
from aegisq.web.app import create_app

ADMIN, VIEWER = "root-token-0123456789", "viewer-token-0123456789"


def hdr(t: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {t}"}


@pytest.fixture
def webhook():
    """A real HTTP endpoint that records what AegisQ posts to it."""
    got: list[dict] = []
    state = {"code": 200}

    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            n = int(self.headers["Content-Length"])
            got.append({"path": self.path, "body": json.loads(self.rfile.read(n)), "ua": self.headers["User-Agent"]})
            self.send_response(state["code"])
            self.end_headers()

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield {"url": f"http://127.0.0.1:{srv.server_port}/hooks/T000/B000/secretpart", "got": got, "state": state}
    srv.shutdown()


def scan(ws, statuses: dict[str, Status], sid: str) -> None:
    now = dt.datetime.now(dt.timezone.utc)
    results = [
        ServiceScan(service=ServiceTarget(name=n, host="127.0.0.1", port=443 + i, data_category="health"), status=s)
        for i, (n, s) in enumerate(statuses.items())
    ]
    ws.save_scan(
        ScanReport(scan_id=sid, started_at=now, finished_at=now, tool_version="t", backend="n", results=results)
    )


def test_webhook_url_rules() -> None:
    assert check_webhook_url("https://hooks.slack.com/services/x") == "https://hooks.slack.com/services/x"
    assert check_webhook_url("http://127.0.0.1:9000/h") and check_webhook_url("http://localhost/h")
    for bad in ("http://example.com/h", "ftp://example.com", "https://u:p@example.com/h", "javascript:alert(1)", ""):
        with pytest.raises(ValueError):
            check_webhook_url(bad)
    assert mask("https://hooks.slack.com/services/T0/B0/abcdefgh1234") == "https://hooks.slack.com/…1234"


def test_schedules_fire_once_per_interval(ws) -> None:
    store = ScheduleStore(ws.home / "state.db")
    with pytest.raises(ValueError):
        store.add(5, "root")
    s = store.add(60, "root", first_run=1000.0)
    assert store.claim_due(999.0) == []
    assert [x["id"] for x in store.claim_due(1000.0)] == [s["id"]]
    assert store.claim_due(1000.0) == []  # already claimed: a second server does not fire it again
    assert store.get(s["id"])["next_run"] == 1000.0 + 3600
    store.update(s["id"], enabled=False)
    assert store.claim_due(10_000.0) == []
    store.update(s["id"], enabled=True)
    assert len(store.claim_due(10_000_000_000.0)) == 1


def test_run_schedules_starts_scans_and_survives_errors(ws, cfg) -> None:
    started: list[str] = []
    ops = Ops(ws, cfg, start_scan=lambda sid: started.append(sid) or "job1")
    s = ops.schedules.add(15, "root", first_run=0.0)
    ops.tick(now=100.0)
    assert started == [s["id"]] and ops.schedules.get(s["id"])["last_job"] == "job1"

    def boom(sid: str) -> str:
        raise RuntimeError("a scan job is already running")

    ops.start_scan = boom
    ops.tick(now=100.0 + 15 * 60)
    skipped = [e for e in ws.audit.entries() if e["event"] == "schedule.skipped"]
    assert skipped and "already running" in skipped[0]["data"]["reason"]


def test_alerts_reach_a_real_webhook(ws, cfg, webhook) -> None:
    ops = Ops(ws, cfg)
    a = ops.alerts.add(webhook["url"], ["exposure", "job_failed"], "root")
    assert a["url"].endswith("…part") and "secretpart" not in json.dumps(a)
    res = ops.send("test", "hello")
    assert res[0]["ok"] and webhook["got"][0]["body"]["text"] == "hello"
    assert webhook["got"][0]["path"] == "/hooks/T000/B000/secretpart" and webhook["got"][0]["ua"].startswith("AegisQ/")
    ops.send("approval", "not subscribed")
    assert len(webhook["got"]) == 1
    webhook["state"]["code"] = 500
    assert ops.send("job_failed", "x")[0]["ok"] is False
    assert ops.alerts.all()[0]["last_status"] == "HTTP 500"
    ops.alerts.add("http://127.0.0.1:9/nothing-listens", ["job_failed"], "root")
    out = ops.send("job_failed", "y")
    assert [r["ok"] for r in out] == [False, False]
    events = [e["event"] for e in ws.audit.entries()]
    assert events.count("alert.sent") == 1 and events.count("alert.failed") == 3
    assert all("secretpart" not in json.dumps(e) for e in ws.audit.entries())


def test_exposure_alert_on_regression(ws, cfg, webhook) -> None:
    ops = Ops(ws, cfg)
    ops.alerts.add(webhook["url"], ["exposure"], "root")
    scan(ws, {"web": Status.PQ_READY, "crm": Status.CLASSICAL}, "s1")
    ops.after_scan()
    assert webhook["got"] == []  # first scan only sets the baseline
    scan(ws, {"web": Status.PQ_READY, "crm": Status.CLASSICAL}, "s2")
    ops.after_scan()
    assert webhook["got"] == []  # nothing changed
    scan(ws, {"web": Status.CLASSICAL, "crm": Status.CLASSICAL}, "s3")
    ops.after_scan()
    body = webhook["got"][0]["body"]
    assert body["event"] == "exposure" and body["data"]["regressions"] == ["web"]
    assert "web is now classical" in body["text"] and "web" in body["data"]["newly_exposed"]


def test_approval_and_job_alerts(ws, cfg, webhook) -> None:
    ops = Ops(ws, cfg)
    ops.alerts.add(webhook["url"], [], "root")
    ops.watch_approvals()
    ws.approvals.create("bastion", "p", "d", "h" * 64, "- a; + b", "agent", 60, initiated_by="olga", require_other=True)
    ops.watch_approvals()
    ops.watch_approvals()
    texts = [g["body"]["text"] for g in webhook["got"]]
    assert len(texts) == 1 and "bastion" in texts[0] and "someone else must approve" in texts[0]
    ops.after_job({"job": "j", "kind": "scan", "status": "failed", "exit_code": 1})
    assert webhook["got"][-1]["body"]["event"] == "job_failed"


def test_audit_tamper_alert(ws, cfg, webhook) -> None:
    ops = Ops(ws, cfg)
    ops.alerts.add(webhook["url"], ["audit"], "root")
    ws.audit.append("x", {"n": 1})
    ws.audit.append("y", {"n": 2})
    log = ws.home / "audit.jsonl"
    log.write_text(log.read_text().replace('"n":1', '"n":9').replace('"n": 1', '"n": 9'))
    ops.watch_audit(now=1000.0)
    ops.watch_audit(now=2000.0)
    assert [g["body"]["event"] for g in webhook["got"]] == ["audit"]


def test_schedule_and_alert_api(cfg, ws, tmp_path, webhook) -> None:
    tokens = {ADMIN: "root", VIEWER: "vic:viewer"}
    bare = TestClient(create_app(cfg, tokens=tokens))
    assert bare.post("/api/schedules", json={"every_minutes": 60}, headers=hdr(ADMIN)).status_code == 409
    inv = tmp_path / "inv.yaml"
    inv.write_text("services: [{name: a, host: 127.0.0.1, port: 9}]\n")
    c = TestClient(create_app(cfg, inventory=str(inv), tokens=tokens))
    assert c.get("/api/capabilities", headers=hdr(ADMIN)).json()["schedules"] is True
    assert c.post("/api/schedules", json={"every_minutes": 60}, headers=hdr(VIEWER)).status_code == 403
    assert c.post("/api/schedules", json={"every_minutes": 1}, headers=hdr(ADMIN)).status_code == 422
    s = c.post("/api/schedules", json={"every_minutes": 360}, headers=hdr(ADMIN)).json()
    assert [x["id"] for x in c.get("/api/schedules", headers=hdr(VIEWER)).json()] == [s["id"]]
    assert c.patch(f"/api/schedules/{s['id']}", json={"enabled": False}, headers=hdr(ADMIN)).json()["enabled"] == 0
    assert c.delete(f"/api/schedules/{s['id']}", headers=hdr(ADMIN)).status_code == 200
    assert c.get("/api/alerts", headers=hdr(VIEWER)).status_code == 403
    assert c.post("/api/alerts", json={"url": "http://evil.example/h"}, headers=hdr(ADMIN)).status_code == 422
    assert (
        c.post("/api/alerts", json={"url": webhook["url"], "events": ["bogus"]}, headers=hdr(ADMIN)).status_code == 422
    )
    a = c.post("/api/alerts", json={"url": webhook["url"]}, headers=hdr(ADMIN)).json()
    assert sorted(a["events"]) == ["approval", "audit", "exposure", "job_failed"]
    assert c.post("/api/alerts/test", headers=hdr(ADMIN)).json()[0]["ok"] is True
    assert "test alert from root" in webhook["got"][0]["body"]["text"]
    assert c.delete(f"/api/alerts/{a['id']}", headers=hdr(ADMIN)).status_code == 200
    assert c.get("/api/alerts", headers=hdr(ADMIN)).json()["alerts"] == []
