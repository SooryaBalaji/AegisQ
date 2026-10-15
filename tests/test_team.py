import os

import pytest
from click.testing import CliRunner
from fastapi.testclient import TestClient

from aegisq.cli import main
from aegisq.config import api_tokens
from aegisq.users import UserStore, can, env_users
from aegisq.web.app import create_app

ADMIN, VIEWER, OPERATOR, APPROVER = (
    "root-token-0123456789",
    "viewer-token-0123456789",
    "operator-token-0123456789",
    "approver-token-0123456789",
)


def hdr(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture
def team(cfg, ws):
    tokens = {ADMIN: "root", VIEWER: "vic:viewer", OPERATOR: "olga:operator", APPROVER: "abe:approver"}
    return TestClient(create_app(cfg, tokens=tokens))


def test_role_permissions() -> None:
    assert can("admin", "admin") and can("admin", "approve") and can("admin", "run")
    assert can("operator", "run") and not can("operator", "approve")
    assert can("approver", "approve") and not can("approver", "run")
    assert can("viewer", "view") and not can("viewer", "run") and not can("nobody", "view")


def test_api_tokens_roles(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AEGISQ_API_TOKENS", "alice:a-token-0123456789ab,bob:b-token-0123456789ab:approver")
    toks = api_tokens()
    assert toks == {"a-token-0123456789ab": "alice", "b-token-0123456789ab": "bob:approver"}
    assert {u.name: u.role for u in env_users(toks).values()} == {"alice": "admin", "bob": "approver"}
    monkeypatch.setenv("AEGISQ_API_TOKENS", "bob:b-token-0123456789ab:root")
    with pytest.raises(ValueError, match="role"):
        api_tokens()


def test_user_store_keeps_only_hashes(ws) -> None:
    store = UserStore(ws.home / "state.db")
    token = store.add("carol", "approver", created_by="root")
    assert store.by_token(token).role == "approver" and store.by_token("nope-token-0123456789") is None
    assert token.encode() not in (ws.home / "state.db").read_bytes()
    with pytest.raises(ValueError, match="exists"):
        store.add("carol", "viewer")
    with pytest.raises(ValueError, match="reserved"):
        store.add("agent", "admin")
    new = store.rotate("carol")
    assert store.by_token(token) is None and store.by_token(new).name == "carol"
    store.set_role("carol", "viewer")
    assert store.by_token(new).role == "viewer"
    store.remove("carol")
    assert store.by_token(new) is None


def test_routes_check_roles(team, ws) -> None:
    roles = {t: team.get("/api/me", headers=hdr(t)).json()["role"] for t in (ADMIN, VIEWER, OPERATOR, APPROVER)}
    assert roles == {ADMIN: "admin", VIEWER: "viewer", OPERATOR: "operator", APPROVER: "approver"}
    for t in (ADMIN, VIEWER, OPERATOR, APPROVER):
        assert team.get("/api/overview", headers=hdr(t)).status_code == 200
    job = {"kind": "scan", "targets": "a.example"}
    assert team.post("/api/jobs", json=job, headers=hdr(VIEWER)).status_code == 403
    assert team.post("/api/jobs", json=job, headers=hdr(APPROVER)).status_code == 403
    assert team.post("/api/scan", headers=hdr(VIEWER)).status_code == 403
    a = ws.approvals.create("svc", "p", "diff", "h" * 64, "s", "agent", 60)
    assert team.post(f"/api/approvals/{a.id}/decision", json={"approve": True}, headers=hdr(VIEWER)).status_code == 403
    assert (
        team.post(f"/api/approvals/{a.id}/decision", json={"approve": True}, headers=hdr(OPERATOR)).status_code == 403
    )
    r = team.post(f"/api/approvals/{a.id}/decision", json={"approve": True}, headers=hdr(APPROVER))
    assert r.status_code == 200 and r.json()["decided_by"] == "abe"
    for t in (VIEWER, OPERATOR, APPROVER):
        assert team.get("/api/users", headers=hdr(t)).status_code == 403


def test_admin_manages_users(team) -> None:
    r = team.post("/api/users", json={"name": "dana", "role": "operator"}, headers=hdr(ADMIN))
    assert r.status_code == 201
    token = r.json()["token"]
    assert team.get("/api/me", headers=hdr(token)).json() == {
        "identity": "dana",
        "role": "operator",
        "permissions": ["run", "view"],
        "separation_of_duties": True,
    }
    names = {u["name"]: (u["role"], u["source"]) for u in team.get("/api/users", headers=hdr(ADMIN)).json()}
    assert names["dana"] == ("operator", "database") and names["root"] == ("admin", "environment")
    assert team.post("/api/users", json={"name": "dana", "role": "viewer"}, headers=hdr(ADMIN)).status_code == 409
    assert team.post("/api/users", json={"name": "x;rm", "role": "viewer"}, headers=hdr(ADMIN)).status_code == 422
    assert team.post("/api/users", json={"name": "eve", "role": "god"}, headers=hdr(ADMIN)).status_code == 422
    assert team.patch("/api/users/root", json={"role": "viewer"}, headers=hdr(ADMIN)).status_code == 409
    assert team.patch("/api/users/dana", json={"role": "approver"}, headers=hdr(ADMIN)).status_code == 200
    assert team.get("/api/me", headers=hdr(token)).json()["role"] == "approver"
    new = team.post("/api/users/dana/token", headers=hdr(ADMIN)).json()["token"]
    assert team.get("/api/me", headers=hdr(token)).status_code == 401
    assert team.get("/api/me", headers=hdr(new)).status_code == 200
    assert team.delete("/api/users/dana", headers=hdr(ADMIN)).status_code == 200
    assert team.get("/api/me", headers=hdr(new)).status_code == 401
    events = [e["event"] for e in team.get("/api/audit?event=user.", headers=hdr(ADMIN)).json()]
    assert events == ["user.created", "user.role_changed", "user.token_rotated", "user.removed"]


def test_last_admin_cannot_be_removed(cfg, ws) -> None:
    store = UserStore(ws.home / "state.db")
    store.add("only", "admin")
    token = store.rotate("only")
    client = TestClient(create_app(cfg, tokens={}))
    assert client.get("/api/me", headers=hdr(token)).json()["role"] == "admin"
    assert client.delete("/api/users/only", headers=hdr(token)).status_code == 409
    assert client.patch("/api/users/only", json={"role": "viewer"}, headers=hdr(token)).status_code == 409


def test_separation_of_duties(team, ws) -> None:
    a = ws.approvals.create("svc", "p", "diff", "h" * 64, "s", "agent", 60, initiated_by="abe", require_other=True)
    r = team.post(f"/api/approvals/{a.id}/decision", json={"approve": True}, headers=hdr(APPROVER))
    assert r.status_code == 403 and "another approver" in r.json()["detail"]
    assert ws.approvals.get(a.id).status == "pending"
    r = team.post(f"/api/approvals/{a.id}/decision", json={"approve": True}, headers=hdr(ADMIN))
    assert r.status_code == 200 and r.json()["decided_by"] == "root" and r.json()["initiated_by"] == "abe"
    b = ws.approvals.create("svc", "p2", "diff", "h" * 64, "s", "agent", 60, initiated_by="abe", require_other=True)
    assert (
        team.post(f"/api/approvals/{b.id}/decision", json={"approve": False}, headers=hdr(APPROVER)).status_code == 200
    )
    c = ws.approvals.create("svc", "p3", "diff", "h" * 64, "s", "agent", 60, initiated_by="abe", require_other=False)
    assert ws.approvals.decide(c.id, True, "abe").status == "approved"


def test_migrate_job_records_the_initiator(cfg, ws, tmp_path, monkeypatch) -> None:
    inv = tmp_path / "inv.yaml"
    inv.write_text("services: [{name: a, host: 127.0.0.1, port: 9}]\n")
    client = TestClient(create_app(cfg, inventory=str(inv), tokens={OPERATOR: "olga:operator"}))
    started = []
    monkeypatch.setattr(
        "aegisq.web.jobs.JobManager.start",
        lambda self, kind, label, steps, who: started.append((steps, who)) or _Fake(),
    )
    r = client.post("/api/jobs", json={"kind": "migrate", "planner": "rules"}, headers=hdr(OPERATOR))
    assert r.status_code == 202
    steps, who = started[0]
    assert who == "olga" and steps[0][steps[0].index("--initiator") + 1] == "olga"


class _Fake:
    def summary(self) -> dict[str, str]:
        return {"id": "x"}


@pytest.fixture
def runner(home):
    r = CliRunner()
    return lambda *args: r.invoke(main, ["--home", str(home), *args], catch_exceptions=False)


def test_cli_users(runner) -> None:
    r = runner("users", "add", "frank", "--role", "approver")
    assert r.exit_code == 0 and "shown only once" in r.output
    token = r.output.strip().splitlines()[-1]
    assert len(token) >= 24 and "frank" in runner("users", "list").output
    assert runner("users", "role", "frank", "viewer").exit_code == 0
    assert runner("users", "add", "frank", "--role", "viewer").exit_code == 1
    assert runner("users", "remove", "frank").exit_code == 0
    assert runner("users", "remove", "frank").exit_code == 1
    assert os.environ.get("AEGISQ_API_TOKENS") is None


def test_toolbox_records_the_initiator(ws, cfg, fake_nginx) -> None:
    from aegisq.agent.tools import Toolbox
    from test_agent import make_report

    tb = Toolbox(ws, cfg, make_report(fake_nginx), verify_timeout=1, initiator="olga", approval_waiter=lambda a: a)
    prop = tb.propose_patch("web", ssl_ecdh_curve="X25519MLKEM768:X25519")
    tb.request_approval(prop["proposal_id"])
    a = ws.approvals.list()[0]
    assert (a.initiated_by, a.require_other) == ("olga", 1)
    with pytest.raises(PermissionError):
        ws.approvals.decide(a.id, True, "olga")
