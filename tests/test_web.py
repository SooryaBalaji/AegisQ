import datetime as dt

import pytest
from fastapi.testclient import TestClient

from aegisq.models import ScanReport, ServiceScan, ServiceTarget, Status
from aegisq.web.app import create_app
from conftest import PASSWORD, add_user, browser, signed_in


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
    add_user(cfg, "alice")
    add_user(cfg, "bob", "approver")
    app = create_app(cfg)
    c = signed_in(app, "alice")
    return c


@pytest.fixture
def bob(client):
    return signed_in(client.app, "bob")


@pytest.fixture
def anon(client):
    return browser(client.app)


def test_auth_required_everywhere(client, anon) -> None:
    for path in ("/api/me", "/api/overview", "/api/approvals", "/api/audit", "/api/cbom", "/api/scan/latest"):
        assert anon.get(path).status_code == 401
        assert anon.get(path, headers={"Authorization": "Bearer anything"}).status_code == 401
    forged = browser(client.app)
    forged.cookies.set("aegisq_session", "forged-session-id")
    assert forged.get("/api/me").status_code == 401
    assert anon.get("/healthz").json()["status"] == "ok"
    me = client.get("/api/me").json()
    assert me["identity"] == "alice" and me["role"] == "admin" and "approve" in me["permissions"]


def test_sign_in_sets_a_strict_http_only_cookie(client, anon, ws) -> None:
    r = anon.post("/api/login", json={"name": "alice", "password": PASSWORD})
    cookie = r.headers["set-cookie"]
    assert r.status_code == 200 and "HttpOnly" in cookie and "SameSite=strict" in cookie and "Path=/" in cookie
    sid = r.cookies["aegisq_session"]
    assert sid.encode() not in (ws.home / "state.db").read_bytes()  # only its hash is stored
    assert anon.post("/api/login", json={"name": "alice", "password": "wrong password!"}).status_code == 401
    assert anon.post("/api/login", json={"name": "nobody", "password": PASSWORD}).status_code == 401
    events = [e["event"] for e in ws.audit.entries()]
    assert events.count("user.signed_in") == 2 and events.count("user.sign_in_failed") == 2
    assert anon.post("/api/logout").status_code == 200
    assert anon.get("/api/me").status_code == 401
    assert client.get("/api/me").status_code == 200  # other sessions are untouched


def test_state_changes_need_the_dashboard_header(client) -> None:
    a = client.post("/api/logout", headers={"X-AegisQ": ""})
    assert a.status_code == 403 and "X-AegisQ" in a.json()["detail"]
    plain = browser(client.app)
    plain.headers.pop("X-AegisQ")
    assert plain.post("/api/login", json={"name": "alice", "password": PASSWORD}).status_code == 403
    assert client.get("/api/me").status_code == 200


def test_password_change_and_reset(client, bob, anon) -> None:
    short = client.post("/api/me/password", json={"current": PASSWORD, "password": "short"})
    assert short.status_code == 422
    assert client.post("/api/me/password", json={"current": "nope", "password": "a much longer one"}).status_code == 403
    assert (
        client.post("/api/me/password", json={"current": PASSWORD, "password": "a much longer one"}).status_code == 200
    )
    assert client.get("/api/me").status_code == 200  # the session that changed it stays signed in
    assert anon.post("/api/login", json={"name": "alice", "password": PASSWORD}).status_code == 401
    assert anon.post("/api/login", json={"name": "alice", "password": "a much longer one"}).status_code == 200
    assert client.post("/api/users/bob/password", json={"password": "bob's new password"}).status_code == 200
    assert bob.get("/api/me").status_code == 401  # a reset signs the user out everywhere
    assert bob.post("/api/users/alice/password", json={"password": "x" * 20}).status_code == 401


def test_first_admin_setup_only_from_this_computer(cfg) -> None:
    app = create_app(cfg)
    remote = browser(app, client=("203.0.113.9", 4000))
    assert remote.get("/api/setup").json() == {"needed": True, "allowed": False}
    assert remote.post("/api/setup", json={"name": "eve", "password": PASSWORD}).status_code == 403
    local = browser(app)
    proxied = local.post(
        "/api/setup", json={"name": "eve", "password": PASSWORD}, headers={"X-Forwarded-For": "1.2.3.4"}
    )
    assert proxied.status_code == 403
    assert local.get("/api/setup").json() == {"needed": True, "allowed": True}
    assert local.post("/api/setup", json={"name": "root", "password": "short"}).status_code == 422
    r = local.post("/api/setup", json={"name": "root", "password": PASSWORD})
    assert r.status_code == 200 and r.json()["role"] == "admin"
    assert local.get("/api/me").json()["identity"] == "root"
    assert local.get("/api/setup").json() == {"needed": False, "allowed": False}
    assert browser(app).post("/api/setup", json={"name": "x", "password": PASSWORD}).status_code == 409


def test_initial_admin_from_environment(cfg, monkeypatch, capsys) -> None:
    create_app(cfg)
    assert "no users yet" in capsys.readouterr().err
    monkeypatch.setenv("AEGISQ_ADMIN_USER", "ops")
    monkeypatch.setenv("AEGISQ_ADMIN_PASSWORD", PASSWORD)
    monkeypatch.setenv("AEGISQ_API_TOKENS", "old:token-0123456789abcdef")
    app = create_app(cfg)
    assert "no longer used" in capsys.readouterr().err
    assert signed_in(app, "ops").get("/api/me").json()["role"] == "admin"
    create_app(cfg)  # a restart does not reset or duplicate the account


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
    assert client.get("/static/ui.css").headers["content-type"].startswith("text/css")
    assert 'href="/static/ui.css"' in r.text and 'src="/static/boot.js"' in r.text
    font = client.get("/static/plex-sans-400.woff2")
    assert font.headers["content-type"] == "font/woff2" and font.content[:4] == b"wOF2"
    assert "immutable" in font.headers["cache-control"]
    assert client.get("/static/app.css").status_code == 404
    assert client.get("/static/fredoka.woff2").status_code == 404
    assert client.get("/static/../app.py").status_code == 404
    assert client.get("/static/secret.txt").status_code == 404
    assert client.get("/api/me").headers["cache-control"] == "no-store"


def test_overview_and_cbom(client) -> None:
    ov = client.get("/api/overview").json()
    assert ov["scan"]["summary"]["total"] == 2
    assert [s["name"] for s in ov["services"]] == ["a", "b"] and ov["services"][0]["x"] == 25
    assert client.get("/api/overview?z=500").status_code == 422
    bom = client.get("/api/cbom").json()
    assert bom["specVersion"] == "1.6"
    assert client.get("/api/entropy").status_code == 404  # removed endpoint
    assert client.post("/api/scan").status_code == 409  # no inventory configured


def test_approval_decision_uses_session_identity(client, bob, ws) -> None:
    a = ws.approvals.create("a", "p", "diff", "h" * 64, "s", "agent", 60)
    r = bob.post(
        f"/api/approvals/{a.id}/decision",
        json={"approve": True, "reason": "ok", "decided_by": "mallory"},
    )
    assert r.status_code == 200 and r.json()["decided_by"] == "bob"
    again = client.post(f"/api/approvals/{a.id}/decision", json={"approve": False})
    assert again.status_code == 409
    assert client.post("/api/approvals/x/decision", json={"approve": "maybe"}).status_code == 422
    assert client.post("/api/approvals/x/decision", json={"approve": True, "reason": "r" * 3000}).status_code == 422
    audit = client.get("/api/audit?event=approval").json()
    assert audit[-1]["actor"] == "bob" and audit[-1]["data"]["via"] == "dashboard"
    assert client.get("/api/audit/verify").json()["ok"]
    assert client.get("/api/approvals?status=bogus").status_code == 422


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
    html = client.get("/api/report.html").text
    assert "<script>x</script>" not in html and "&lt;script&gt;" in html
    assert "<img src=x" not in html
    assert client.get("/api/report.md").status_code == 200
    assert client.get("/api/report.pdf").status_code == 404


def test_password_guessing_is_throttled(client, anon) -> None:
    codes = [
        anon.post("/api/login", json={"name": "alice", "password": f"guess-{i:012d}"}).status_code for i in range(22)
    ]
    assert codes[:20] == [401] * 20 and codes[-1] == 429
    assert anon.post("/api/login", json={"name": "alice", "password": PASSWORD}).status_code == 429
    other = browser(client.app, client=("127.0.0.2", 1))
    assert other.post("/api/login", json={"name": "alice", "password": PASSWORD}).status_code == 429  # per name too
    assert other.post("/api/login", json={"name": "bob", "password": PASSWORD}).status_code == 200


def test_parallel_guesses_cannot_pass_the_limit(client) -> None:
    from concurrent.futures import ThreadPoolExecutor

    def guess(i: int) -> int:
        c = browser(client.app, client=("127.0.0.9", 1))
        return c.post("/api/login", json={"name": "bob", "password": f"parallel-guess-{i:04d}"}).status_code

    with ThreadPoolExecutor(16) as pool:
        codes = list(pool.map(guess, range(40)))
    assert codes.count(401) == 20 and codes.count(429) == 20


# ---------------------------------------------------------------- jobs ---

import sys  # noqa: E402
import time  # noqa: E402

from aegisq.web.jobs import JobConflict, JobManager  # noqa: E402
from fakes import tls_server  # noqa: E402


def wait_job(client: TestClient, job_id: str, timeout: float = 60) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        d = client.get(f"/api/jobs/{job_id}").json()
        if d["status"] != "running":
            return d
        time.sleep(0.2)
    raise AssertionError(f"job {job_id} still running")


def test_capabilities(client) -> None:
    caps = client.get("/api/capabilities").json()
    assert caps["jobs"] is True and caps["inventory"] is False and caps["services"] == []
    assert caps["planners"]["rules"]["ok"] is True
    assert caps["planners"]["gemma"]["ok"] is False and "GEMINI_API_KEY" in caps["planners"]["gemma"]["detail"]
    assert set(caps["planners"]) == {"rules", "gemma"}
    assert "ibm" not in caps and "quantum" not in caps
    assert browser(client.app).get("/api/capabilities").status_code == 401


def test_job_requests_are_validated(client) -> None:
    def post(body: dict) -> int:
        return client.post("/api/jobs", json=body).status_code

    assert browser(client.app).post("/api/jobs", json={"kind": "scan", "targets": "x"}).status_code == 401
    assert post({"kind": "shell", "cmd": "rm -rf /"}) == 422
    assert post({"kind": "scan", "targets": "a.example", "extra": 1}) == 422
    assert post({"kind": "scan"}) == 409  # no inventory and no targets
    assert post({"kind": "scan", "targets": "-oProxyCommand=evil"}) == 422
    assert post({"kind": "scan", "targets": "host.example:99999"}) == 422
    assert post({"kind": "scan", "targets": "\n".join(f"h{i}.example" for i in range(501))}) == 422
    assert post({"kind": "migrate", "planner": "rules"}) == 409  # needs an inventory
    assert post({"kind": "migrate", "planner": "gpt"}) == 422
    assert post({"kind": "entropy", "source": "simulated"}) == 422  # removed job kinds
    assert post({"kind": "shor", "backend": "aer"}) == 422
    assert post({"kind": "realworld"}) == 422
    for url in ("http://a.example/", "https://user:pw@a.example/", "https://-x/", "ftp://a.example", "https://"):
        assert post({"kind": "benchmark", "url": url}) == 422, url
    assert post({"kind": "benchmark", "url": "https://a.example/", "n": 1}) == 422
    assert client.get("/api/jobs").json() == []


def test_scan_job_runs_the_cli_and_updates_results(client, ws) -> None:
    with tls_server("pq") as pq:
        r = client.post("/api/jobs", json={"kind": "scan", "targets": f"# comment\n127.0.0.1:{pq.port}\n"})
        assert r.status_code == 202, r.text
        job = r.json()
        assert job["label"] == "Scan 1 server" and job["started_by"] == "alice" and job["status"] == "running"
        done = wait_job(client, job["id"])
    assert done["status"] == "succeeded" and done["exit_code"] == 0, done
    text = "\n".join(done["log"])
    assert text.startswith("$ aegisq scan ") and "PQ READY" in text
    assert ws.latest_scan().results[0].status == Status.PQ_READY
    # incremental log polling
    tail = client.get(f"/api/jobs/{job['id']}?since={done['lines'] - 1}").json()
    assert tail["log"] == done["log"][-1:]
    listed = client.get("/api/jobs").json()
    assert any(j["id"] == job["id"] and j["status"] == "succeeded" for j in listed)
    events = [(e["event"], e["actor"]) for e in ws.audit.entries()]
    assert ("job.started", "alice") in events and ("job.finished", "aegisq") in events
    assert any(e == "scan.completed" for e, _ in events)
    assert client.get("/api/jobs/nope").status_code == 404


def test_read_only_dashboard(cfg) -> None:
    add_user(cfg, "alice")
    c = signed_in(create_app(cfg, jobs_enabled=False), "alice")
    assert c.get("/api/capabilities").json()["jobs"] is False
    assert c.post("/api/jobs", json={"kind": "scan", "targets": "a.example"}).status_code == 403


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
