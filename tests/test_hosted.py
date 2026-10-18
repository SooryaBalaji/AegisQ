from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest
import yaml
from click.testing import CliRunner
from fastapi.testclient import TestClient

from aegisq.web import hosted
from aegisq.web.hosted import HostedApp, normalize_domain

PW = "correct horse battery staple"


class DNS:
    def __init__(self) -> None:
        self.records: dict[str, list[str]] = {}

    def __call__(self, name: str) -> list[str]:
        return self.records.get(name, [])


@pytest.fixture
def site(cfg) -> tuple[HostedApp, DNS]:
    dns = DNS()
    return HostedApp(cfg, lookup=dns), dns


def client(app: Any) -> TestClient:
    return TestClient(app, headers={"X-AegisQ": "1"}, client=("203.0.113.7", 50000))


def account(app: Any, name: str, password: str = PW) -> TestClient:
    c = client(app)
    r = c.post("/api/signup", json={"name": name, "password": password})
    assert r.status_code == 200, r.text
    return c


def test_anyone_can_create_a_private_account(site) -> None:
    app, _ = site
    anon = client(app)
    assert anon.get("/api/setup").json() == {"needed": False, "allowed": False, "signup": True}
    assert anon.get("/api/overview").status_code == 401
    alice = account(app, "alice")
    me = alice.get("/api/me").json()
    assert me["identity"] == "alice" and me["hosted"] is True and "admin" not in me["permissions"]
    assert client(app).post("/api/signup", json={"name": "alice", "password": PW}).status_code == 409
    assert client(app).post("/api/signup", json={"name": "bob", "password": "short"}).status_code == 422
    assert client(app).post("/api/setup", json={"name": "eve", "password": PW}).status_code == 403
    assert alice.get("/api/capabilities").json()["hosted"] is True


def test_accounts_cannot_see_each_other(site) -> None:
    app, _ = site
    alice, bob = account(app, "alice"), account(app, "bob")
    assert alice.post("/api/domains", json={"domain": "https://Alice.Example.com/path"}).status_code == 201
    assert [d["domain"] for d in alice.get("/api/domains").json()] == ["alice.example.com"]
    assert bob.get("/api/domains").json() == []
    alice_events = {e["event"] for e in alice.get("/api/audit").json()}
    bob_events = {e["event"] for e in bob.get("/api/audit").json()}
    assert "domain.added" in alice_events and "domain.added" not in bob_events
    assert Path(app.root / "tenants" / "alice" / "domains.json").is_file()
    assert not Path(app.root / "tenants" / "bob" / "domains.json").exists()


def test_domain_must_be_proved_with_a_txt_record(site) -> None:
    app, dns = site
    alice = account(app, "alice")
    d = alice.post("/api/domains", json={"domain": "example.com"}).json()
    assert d["record"] == "_aegisq.example.com" and d["value"].startswith("aegisq-verify=") and not d["verified"]
    assert alice.post("/api/domains/example.com/verify").status_code == 409
    dns.records["_aegisq.example.com"] = ["something else", d["value"]]
    r = alice.post("/api/domains/example.com/verify")
    assert r.status_code == 200 and r.json()["verified"] is True
    conf = yaml.safe_load((app.root / "tenants" / "alice" / "aegisq.yaml").read_text())
    assert conf["scan"]["scope"]["allow"] == [".example.com"] and "10.0.0.0/8" in conf["scan"]["scope"]["deny"]
    assert alice.delete("/api/domains/example.com").status_code == 200
    conf = yaml.safe_load((app.root / "tenants" / "alice" / "aegisq.yaml").read_text())
    assert conf["scan"]["scope"]["allow"] == [hosted.NO_DOMAINS]


@pytest.mark.parametrize("bad", ["127.0.0.1", "[::1]", "localhost", "com", "-bad-.example", "a..b.com", ""])
def test_bad_domains_are_refused(bad: str) -> None:
    with pytest.raises(ValueError):
        normalize_domain(bad)


def test_tenant_scope_blocks_unverified_and_private_targets(site, tmp_path: Path) -> None:
    from aegisq.cli import main
    from aegisq.netutil import Scope, TargetError

    app, dns = site
    alice = account(app, "alice")
    v = alice.post("/api/domains", json={"domain": "example.com"}).json()
    conf_path = app.root / "tenants" / "alice" / "aegisq.yaml"
    sc = yaml.safe_load(conf_path.read_text())["scan"]["scope"]
    with pytest.raises(TargetError, match="outside"):
        Scope(sc["allow"], sc["deny"]).check("www.example.com", ["93.184.216.34"])
    dns.records["_aegisq.example.com"] = [v["value"]]
    alice.post("/api/domains/example.com/verify")
    sc = yaml.safe_load(conf_path.read_text())["scan"]["scope"]
    scope = Scope(sc["allow"], sc["deny"])
    scope.check("www.example.com", ["93.184.216.34"])
    scope.check("example.com", ["93.184.216.34"])
    for host, ip in (("example.org", "93.184.216.34"), ("www.example.com", "10.0.0.5"), ("example.com", "::1")):
        with pytest.raises(TargetError):
            scope.check(host, [ip])
    targets = tmp_path / "t.txt"
    targets.write_text("127.0.0.1:443\n")
    res = CliRunner().invoke(main, ["--config", str(conf_path), "--home", str(tmp_path / "h"), "scan", str(targets)])
    assert "refused by scope" in res.output, res.output
    os.environ.pop("AEGISQ_HOME", None)


def test_hosted_accounts_cannot_fix_benchmark_or_manage_others(site) -> None:
    app, _ = site
    alice = account(app, "alice")
    assert alice.post("/api/jobs", json={"kind": "migrate", "planner": "rules"}).status_code == 403
    assert alice.post("/api/jobs", json={"kind": "benchmark", "url": "https://example.com/"}).status_code == 403
    assert alice.post("/api/alerts", json={"url": "https://10.0.0.1/x", "events": ["approval"]}).status_code == 403
    assert alice.get("/api/users").status_code == 403


def test_site_operator_can_only_list_and_remove(cfg, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AEGISQ_ADMIN_USER", "op")
    monkeypatch.setenv("AEGISQ_ADMIN_PASSWORD", PW)
    app = HostedApp(cfg, lookup=DNS())
    alice = account(app, "alice")
    alice.post("/api/domains", json={"domain": "secret.example.com"})
    op = client(app)
    assert op.post("/api/login", json={"name": "op", "password": PW}).status_code == 200
    assert {u["name"] for u in op.get("/api/users").json()} == {"op", "alice"}
    assert op.post("/api/users/alice/password", json={"password": "a new long password"}).status_code == 403
    assert op.patch("/api/users/alice", json={"role": "admin"}).status_code == 403
    assert op.post("/api/users", json={"name": "x", "role": "admin", "password": PW}).status_code == 403
    assert op.get("/api/domains").json() == []
    assert op.delete("/api/users/alice").status_code == 200
    assert alice.get("/api/overview").status_code == 401


def test_sign_ups_and_actions_are_rate_limited(site, monkeypatch: pytest.MonkeyPatch) -> None:
    app, _ = site
    for i in range(5):
        account(app, f"user{i}")
    assert client(app).post("/api/signup", json={"name": "user9", "password": PW}).status_code == 429
    monkeypatch.setattr(hosted, "ACTIONS_PER_HOUR", 2)
    c = TestClient(app, headers={"X-AegisQ": "1"}, client=("198.51.100.1", 1))
    assert c.post("/api/signup", json={"name": "zed", "password": PW}).status_code == 200
    codes = [c.post("/api/domains", json={"domain": f"d{i}.example.com"}).status_code for i in range(3)]
    assert codes == [201, 201, 429]


def test_csrf_header_is_still_required(site) -> None:
    app, _ = site
    alice = account(app, "alice")
    r = TestClient(app, cookies=alice.cookies).post("/api/domains", json={"domain": "example.com"})
    assert r.status_code == 403
