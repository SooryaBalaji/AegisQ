import datetime as dt

import pytest
from fastapi.testclient import TestClient

from aegisq.models import ScanReport, ServiceScan, ServiceTarget, Status
from aegisq.web.app import create_app

TOK_A, TOK_B = "alice-token-0123456789", "bob-token-0123456789ab"


@pytest.fixture
def client(cfg, ws):
    now = dt.datetime.now(dt.timezone.utc)
    ws.save_scan(
        ScanReport(
            scan_id="s",
            started_at=now,
            finished_at=now,
            tool_version="t",
            backend="n",
            results=[
                ServiceScan(
                    service=ServiceTarget(name="a", host="127.0.0.1", port=443, data_category="health"),
                    status=Status.CLASSICAL,
                ),
                ServiceScan(service=ServiceTarget(name="b", host="127.0.0.1", port=444), status=Status.PQ_READY),
            ],
        )
    )
    app = create_app(cfg, tokens={TOK_A: "alice", TOK_B: "bob"})
    return TestClient(app)


def auth(t: str = TOK_A) -> dict[str, str]:
    return {"Authorization": f"Bearer {t}"}


def test_auth_required_everywhere(client) -> None:
    for path in ("/api/me", "/api/overview", "/api/approvals", "/api/audit", "/api/cbom", "/api/scan/latest"):
        assert client.get(path).status_code == 401
        assert client.get(path, headers={"Authorization": "Bearer wrong-token-xxxxxxxx"}).status_code == 401
        assert client.get(path, headers={"Authorization": f"Basic {TOK_A}"}).status_code == 401
    assert client.get("/healthz").json()["status"] == "ok"
    assert client.get("/api/me", headers=auth()).json() == {"identity": "alice"}


def test_security_headers_and_static(client) -> None:
    r = client.get("/")
    assert r.status_code == 200 and "AegisQ" in r.text
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    assert r.headers["x-content-type-options"] == "nosniff" and r.headers["x-frame-options"] == "DENY"
    assert client.get("/static/app.js").headers["content-type"].startswith("text/javascript")
    for path in ("/static/favicon.svg", "/favicon.ico"):
        icon = client.get(path)
        assert icon.status_code == 200 and icon.headers["content-type"] == "image/svg+xml" and "<svg" in icon.text
    assert 'href="/static/favicon.svg"' in r.text
    for font in ("fredoka.woff2", "nunito.woff2"):
        f = client.get(f"/static/{font}")
        assert f.status_code == 200 and f.headers["content-type"] == "font/woff2" and f.content[:4] == b"wOF2"
    assert client.get("/static/OFL-nunito.txt").status_code == 404  # licence ships in the package, not served
    assert client.get("/static/../app.py").status_code == 404
    assert client.get("/static/secret.txt").status_code == 404
    assert client.get("/api/me", headers=auth()).headers["cache-control"] == "no-store"


def test_overview_and_cbom(client) -> None:
    ov = client.get("/api/overview", headers=auth()).json()
    assert ov["scan"]["summary"]["total"] == 2
    assert [s["name"] for s in ov["services"]] == ["a", "b"] and ov["services"][0]["x"] == 25
    assert client.get("/api/overview?z=500", headers=auth()).status_code == 422
    bom = client.get("/api/cbom", headers=auth()).json()
    assert bom["specVersion"] == "1.6"
    assert client.get("/api/entropy", headers=auth()).status_code == 404
    assert client.post("/api/scan", headers=auth()).status_code == 409  # no inventory configured


def test_approval_decision_uses_token_identity(client, ws) -> None:
    a = ws.approvals.create("a", "p", "diff", "h" * 64, "s", "agent", 60)
    r = client.post(
        f"/api/approvals/{a.id}/decision",
        headers=auth(TOK_B),
        json={"approve": True, "reason": "ok", "decided_by": "mallory"},
    )
    assert r.status_code == 200 and r.json()["decided_by"] == "bob"
    again = client.post(f"/api/approvals/{a.id}/decision", headers=auth(), json={"approve": False})
    assert again.status_code == 409
    assert client.post("/api/approvals/x/decision", headers=auth(), json={"approve": "maybe"}).status_code == 422
    assert (
        client.post(
            "/api/approvals/x/decision", headers=auth(), json={"approve": True, "reason": "r" * 3000}
        ).status_code
        == 422
    )
    audit = client.get("/api/audit?event=approval", headers=auth()).json()
    assert audit[-1]["actor"] == "bob" and audit[-1]["data"]["via"] == "dashboard"
    assert client.get("/api/audit/verify", headers=auth()).json()["ok"]
    assert client.get("/api/approvals?status=bogus", headers=auth()).status_code == 422


def test_report_endpoint_escapes(client, ws) -> None:
    ws.audit.append(
        "approval.outcome",
        {
            "service": "a",
            "status": "rejected",
            "decided_by": "<script>x</script>",
            "reason": "<img src=x onerror=alert(1)>",
        },
    )
    html = client.get("/api/report.html", headers=auth()).text
    assert "<script>x</script>" not in html and "&lt;script&gt;" in html
    assert "<img src=x" not in html
    assert client.get("/api/report.md", headers=auth()).status_code == 200
    assert client.get("/api/report.pdf", headers=auth()).status_code == 404


def test_bruteforce_is_throttled(client) -> None:
    codes = [client.get("/api/me", headers={"Authorization": f"Bearer guess-{i:020d}"}).status_code for i in range(25)]
    assert codes[:20] == [401] * 20 and codes[-1] == 429
    assert client.get("/api/me", headers=auth()).status_code == 429  # still throttled for this client


def test_generated_token_when_none_configured(cfg, ws, capsys) -> None:
    create_app(cfg, tokens={})
    assert "dashboard token" in capsys.readouterr().err


# ---------------------------------------------------------------- jobs ---

import sys  # noqa: E402
import time  # noqa: E402

from aegisq.web.jobs import JobConflict, JobManager  # noqa: E402
from fakes import tls_server  # noqa: E402


def wait_job(client: TestClient, job_id: str, timeout: float = 60) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        d = client.get(f"/api/jobs/{job_id}", headers=auth()).json()
        if d["status"] != "running":
            return d
        time.sleep(0.2)
    raise AssertionError(f"job {job_id} still running")


def test_capabilities(client) -> None:
    caps = client.get("/api/capabilities", headers=auth()).json()
    assert caps["jobs"] is True and caps["inventory"] is False and caps["services"] == []
    assert caps["planners"]["rules"]["ok"] is True
    assert caps["planners"]["local"]["ok"] is False and "GEMINI_API_KEY" in caps["planners"]["local"]["detail"]
    assert caps["ibm"]["ok"] is False
    assert client.get("/api/capabilities").status_code == 401


def test_job_requests_are_validated(client) -> None:
    def post(body: dict) -> int:
        return client.post("/api/jobs", json=body, headers=auth()).status_code

    assert client.post("/api/jobs", json={"kind": "scan", "targets": "x"}).status_code == 401
    assert post({"kind": "shell", "cmd": "rm -rf /"}) == 422
    assert post({"kind": "scan", "targets": "a.example", "extra": 1}) == 422
    assert post({"kind": "scan"}) == 409  # no inventory and no targets
    assert post({"kind": "scan", "targets": "-oProxyCommand=evil"}) == 422
    assert post({"kind": "scan", "targets": "host.example:99999"}) == 422
    assert post({"kind": "scan", "targets": "\n".join(f"h{i}.example" for i in range(501))}) == 422
    assert post({"kind": "migrate", "planner": "rules"}) == 409  # needs an inventory
    assert post({"kind": "migrate", "planner": "gpt"}) == 422
    assert post({"kind": "entropy", "source": "dwave"}) == 422
    assert post({"kind": "shor", "backend": "ibm_fez; rm"}) == 422
    for url in ("http://a.example/", "https://user:pw@a.example/", "https://-x/", "ftp://a.example", "https://"):
        assert post({"kind": "benchmark", "url": url}) == 422, url
    assert post({"kind": "benchmark", "url": "https://a.example/", "n": 1}) == 422
    assert client.get("/api/jobs", headers=auth()).json() == []


def test_scan_job_runs_the_cli_and_updates_results(client, ws) -> None:
    with tls_server("pq") as pq:
        r = client.post(
            "/api/jobs", json={"kind": "scan", "targets": f"# comment\n127.0.0.1:{pq.port}\n"}, headers=auth()
        )
        assert r.status_code == 202, r.text
        job = r.json()
        assert job["label"] == "Scan 1 server" and job["started_by"] == "alice" and job["status"] == "running"
        done = wait_job(client, job["id"])
    assert done["status"] == "succeeded" and done["exit_code"] == 0, done
    text = "\n".join(done["log"])
    assert text.startswith("$ aegisq scan ") and "PQ READY" in text
    assert ws.latest_scan().results[0].status == Status.PQ_READY
    # incremental log polling
    tail = client.get(f"/api/jobs/{job['id']}?since={done['lines'] - 1}", headers=auth()).json()
    assert tail["log"] == done["log"][-1:]
    listed = client.get("/api/jobs", headers=auth()).json()
    assert any(j["id"] == job["id"] and j["status"] == "succeeded" for j in listed)
    events = [(e["event"], e["actor"]) for e in ws.audit.entries()]
    assert ("job.started", "alice") in events and ("job.finished", "aegisq") in events
    assert any(e == "scan.completed" for e, _ in events)
    assert client.get("/api/jobs/nope", headers=auth()).status_code == 404


def test_read_only_dashboard(cfg) -> None:
    c = TestClient(create_app(cfg, tokens={TOK_A: "alice"}, jobs_enabled=False))
    assert c.get("/api/capabilities", headers=auth()).json()["jobs"] is False
    assert c.post("/api/jobs", json={"kind": "scan", "targets": "a.example"}, headers=auth()).status_code == 403


def test_job_manager_cancel_and_conflict() -> None:
    events: list[tuple[str, dict]] = []
    code = "import time\nprint('started', flush=True)\ntry:\n    time.sleep(60)\nexcept KeyboardInterrupt:\n    print('cleaned up', flush=True)\n    raise SystemExit(130)\n"
    jm = JobManager([sys.executable, "-c", code], dict(__import__("os").environ), lambda e, d, a: events.append((e, d)))
    job = jm.start("demo", "Long job", [[]], "alice")
    with pytest.raises(JobConflict):
        jm.start("demo", "Again", [[]], "bob")
    deadline = time.monotonic() + 20
    while "started" not in job.lines and time.monotonic() < deadline:
        time.sleep(0.05)
    jm.cancel(job, "alice")
    while job.status == "running" and time.monotonic() < deadline:
        time.sleep(0.05)
    assert job.status == "cancelled"
    assert "--- cancel requested by alice ---" in job.lines
    if sys.platform != "win32":
        assert "cleaned up" in job.lines  # interrupted gracefully, not killed
    assert [e for e, _ in events] == ["job.started", "job.finished"]
    assert events[-1][1]["status"] == "cancelled"
    # a failing step stops the job and is reported
    jm2 = JobManager([sys.executable, "-c"], dict(__import__("os").environ))
    bad = jm2.start("x", "Fails", [["raise SystemExit(3)"], ["print('never')"]], "bob")
    while bad.status == "running":
        time.sleep(0.05)
    assert bad.status == "failed" and bad.exit_code == 3 and "never" not in bad.lines
