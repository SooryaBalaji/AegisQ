import time

import pytest
from click.testing import CliRunner

from aegisq.cli import main
from aegisq.users import UserStore, can, check_password, hash_password
from aegisq.web.app import create_app
from conftest import PASSWORD, add_user, signed_in

ROLES = {"root": "admin", "vic": "viewer", "olga": "operator", "abe": "approver"}


@pytest.fixture
def team(cfg, ws):
    for name, role in ROLES.items():
        add_user(cfg, name, role)
    app = create_app(cfg)
    return {name: signed_in(app, name) for name in ROLES}


def test_role_permissions() -> None:
    assert can("admin", "admin") and can("admin", "approve") and can("admin", "run")
    assert can("operator", "run") and not can("operator", "approve")
    assert can("approver", "approve") and not can("approver", "run")
    assert can("viewer", "view") and not can("viewer", "run") and not can("nobody", "view")


def test_passwords_are_only_stored_as_scrypt_hashes(ws) -> None:
    store = UserStore(ws.home / "state.db")
    store.add("carol", "approver", "carol's long password", created_by="root")
    assert b"carol's long password" not in (ws.home / "state.db").read_bytes()
    assert store.verify("carol", "carol's long password").role == "approver"
    assert store.verify("carol", "wrong") is None and store.verify("nobody", "carol's long password") is None
    h = hash_password("x" * 12)
    assert h.startswith("scrypt$") and check_password("x" * 12, h) and not check_password("y" * 12, h)
    assert not check_password("x", "garbage")
    with pytest.raises(ValueError, match="exists"):
        store.add("carol", "viewer", PASSWORD)
    with pytest.raises(ValueError, match="reserved"):
        store.add("agent", "admin", PASSWORD)
    with pytest.raises(ValueError, match="12 characters"):
        store.add("dave", "admin", "short")
    with pytest.raises(ValueError, match="user name"):
        store.add("dave-the-admin", "admin", "Dave-The-Admin")
    sid = store.start_session("carol")
    assert store.session_user(sid).name == "carol"
    store.set_role("carol", "viewer")
    assert store.session_user(sid).role == "viewer"  # role changes apply to live sessions
    assert store.session_user(sid, now=time.time() + 13 * 3600) is None  # idle sessions expire
    sid = store.start_session("carol")
    store.remove("carol")
    assert store.session_user(sid) is None


def test_old_token_users_keep_their_roles(ws) -> None:
    import sqlite3

    db = ws.home / "state.db"
    db.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(db)
    con.execute(
        "CREATE TABLE users (name TEXT PRIMARY KEY, role TEXT NOT NULL, token_sha256 TEXT NOT NULL UNIQUE, "
        "created_at REAL NOT NULL, created_by TEXT)"
    )
    con.execute("INSERT INTO users VALUES ('priya','approver','abc',1.0,'root')")
    con.commit()
    con.close()
    store = UserStore(db)
    u = store.get("priya")
    assert u.role == "approver" and not u.has_password
    assert store.verify("priya", "") is None
    store.set_password("priya", PASSWORD)
    assert store.verify("priya", PASSWORD).name == "priya"


def test_routes_check_roles(team, ws) -> None:
    assert {n: c.get("/api/me").json()["role"] for n, c in team.items()} == ROLES
    for c in team.values():
        assert c.get("/api/overview").status_code == 200
    job = {"kind": "scan", "targets": "a.example"}
    assert team["vic"].post("/api/jobs", json=job).status_code == 403
    assert team["abe"].post("/api/jobs", json=job).status_code == 403
    assert team["vic"].post("/api/scan").status_code == 403
    a = ws.approvals.create("svc", "p", "diff", "h" * 64, "s", "agent", 60)
    assert team["vic"].post(f"/api/approvals/{a.id}/decision", json={"approve": True}).status_code == 403
    assert team["olga"].post(f"/api/approvals/{a.id}/decision", json={"approve": True}).status_code == 403
    r = team["abe"].post(f"/api/approvals/{a.id}/decision", json={"approve": True})
    assert r.status_code == 200 and r.json()["decided_by"] == "abe"
    for n in ("vic", "olga", "abe"):
        assert team[n].get("/api/users").status_code == 403
        assert team[n].post("/api/users/root/password", json={"password": "x" * 20}).status_code == 403


def test_admin_manages_users(team, cfg) -> None:
    root = team["root"]
    r = root.post("/api/users", json={"name": "dana", "role": "operator", "password": PASSWORD})
    assert r.status_code == 201 and "password" not in r.text.lower().replace("has_password", "")
    dana = signed_in(root.app, "dana")
    assert dana.get("/api/me").json() == {
        "identity": "dana",
        "role": "operator",
        "permissions": ["run", "view"],
        "separation_of_duties": True,
    }
    names = {u["name"]: u["role"] for u in root.get("/api/users").json()}
    assert names["dana"] == "operator" and names["root"] == "admin"
    assert root.post("/api/users", json={"name": "dana", "role": "viewer", "password": PASSWORD}).status_code == 409
    assert root.post("/api/users", json={"name": "x;rm", "role": "viewer", "password": PASSWORD}).status_code == 422
    assert root.post("/api/users", json={"name": "eve", "role": "god", "password": PASSWORD}).status_code == 422
    assert root.post("/api/users", json={"name": "eve", "role": "viewer", "password": "short"}).status_code == 422
    assert root.patch("/api/users/dana", json={"role": "approver"}).status_code == 200
    assert dana.get("/api/me").json()["role"] == "approver"
    assert root.post("/api/users/dana/password", json={"password": "dana's new password"}).status_code == 200
    assert dana.get("/api/me").status_code == 401
    assert root.delete("/api/users/dana").status_code == 200
    events = [e["event"] for e in root.get("/api/audit?event=user.").json()]
    assert [e for e in events if e not in ("user.signed_in",)] == [
        "user.created",
        "user.role_changed",
        "user.password_reset",
        "user.removed",
    ]


def test_last_admin_cannot_be_removed(cfg, ws) -> None:
    add_user(cfg, "only")
    client = signed_in(create_app(cfg), "only")
    assert client.delete("/api/users/only").status_code == 409
    assert client.patch("/api/users/only", json={"role": "viewer"}).status_code == 409


def test_separation_of_duties(team, ws) -> None:
    a = ws.approvals.create("svc", "p", "diff", "h" * 64, "s", "agent", 60, initiated_by="abe", require_other=True)
    r = team["abe"].post(f"/api/approvals/{a.id}/decision", json={"approve": True})
    assert r.status_code == 403 and "another approver" in r.json()["detail"]
    assert ws.approvals.get(a.id).status == "pending"
    r = team["root"].post(f"/api/approvals/{a.id}/decision", json={"approve": True})
    assert r.status_code == 200 and r.json()["decided_by"] == "root" and r.json()["initiated_by"] == "abe"
    b = ws.approvals.create("svc", "p2", "diff", "h" * 64, "s", "agent", 60, initiated_by="abe", require_other=True)
    assert team["abe"].post(f"/api/approvals/{b.id}/decision", json={"approve": False}).status_code == 200
    c = ws.approvals.create("svc", "p3", "diff", "h" * 64, "s", "agent", 60, initiated_by="abe", require_other=False)
    assert ws.approvals.decide(c.id, True, "abe").status == "approved"


def test_migrate_job_records_the_initiator(cfg, ws, tmp_path, monkeypatch) -> None:
    inv = tmp_path / "inv.yaml"
    inv.write_text("services: [{name: a, host: 127.0.0.1, port: 9}]\n")
    add_user(cfg, "olga", "operator")
    client = signed_in(create_app(cfg, inventory=str(inv)), "olga")
    started = []
    monkeypatch.setattr(
        "aegisq.web.jobs.JobManager.start",
        lambda self, kind, label, steps, who: started.append((steps, who)) or _Fake(),
    )
    r = client.post("/api/jobs", json={"kind": "migrate", "planner": "rules"})
    assert r.status_code == 202
    steps, who = started[0]
    assert who == "olga" and steps[0][steps[0].index("--initiator") + 1] == "olga"


class _Fake:
    def summary(self) -> dict[str, str]:
        return {"id": "x"}


@pytest.fixture
def runner_in(home):
    r = CliRunner()
    return lambda stdin, *args: r.invoke(main, ["--home", str(home), *args], input=stdin, catch_exceptions=False)


def test_cli_users(home, runner_in) -> None:
    r = runner_in("frank's password\nfrank's password\n", "users", "add", "frank", "--role", "approver")
    assert r.exit_code == 0 and "can now sign in" in r.output and "frank's password" not in r.output
    store = UserStore(home / "state.db")
    assert store.verify("frank", "frank's password").role == "approver"
    assert runner_in("", "users", "add", "gus", "--role", "admin", "--password-stdin").exit_code == 1  # too short
    assert (
        runner_in("gus's long password\n", "users", "add", "gus", "--role", "admin", "--password-stdin").exit_code == 0
    )
    assert "frank" in runner_in("", "users", "list").output
    assert runner_in("", "users", "role", "frank", "viewer").exit_code == 0
    assert runner_in("another password\n", "users", "password", "frank", "--password-stdin").exit_code == 0
    assert store.verify("frank", "another password") is not None
    assert runner_in("", "users", "remove", "frank").exit_code == 0
    assert runner_in("", "users", "remove", "frank").exit_code == 1
    assert runner_in("", "users", "remove", "gus").exit_code == 1  # the last admin stays
    assert runner_in("", "users", "role", "gus", "viewer").exit_code == 1


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
