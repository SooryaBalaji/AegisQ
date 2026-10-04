import datetime as dt
import json
import os
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from aegisq.agent import tools as tools_mod
from aegisq.agent.health import HealthResult
from aegisq.agent.runner import ClaudePlanner, RulesPlanner, desired_groups, dispatch, tool_specs
from aegisq.agent.tools import Toolbox, ToolError
from aegisq.config import AegisQConfig
from aegisq.models import ManagedNginx, Protocol, ScanReport, ServiceScan, ServiceTarget, Status
from aegisq.workspace import Workspace


@pytest.fixture
def verify_stub(monkeypatch: pytest.MonkeyPatch, fake_nginx: dict[str, Any]) -> dict[str, bool]:
    """Verification reflects the *running* config of the fake server."""
    flags = {"health": True}

    async def pq_check(service: ServiceTarget, timeout: float = 5.0) -> tuple[bool, str]:
        running = Path(fake_nginx["state"]).read_text()
        ok = "X25519MLKEM768" in running
        return ok, "negotiated X25519MLKEM768" if ok else "server alert: handshake_failure"

    async def http_health(service: ServiceTarget, timeout: float = 5.0) -> HealthResult:
        return HealthResult(
            flags["health"], 200 if flags["health"] else None, "HTTP 200" if flags["health"] else "down"
        )

    monkeypatch.setattr(tools_mod, "pq_check", pq_check)
    monkeypatch.setattr(tools_mod, "http_health", http_health)
    return flags


def make_report(fake_nginx: dict[str, Any], status: Status = Status.CLASSICAL) -> ScanReport:
    argv = fake_nginx["argv"]
    managed = ManagedNginx(
        config_path=str(fake_nginx["conf"]),
        test_cmd=[*argv, "-t"],
        reload_cmd=[*argv, "-s", "reload"],
        version_cmd=[*argv, "-V"],
    )
    now = dt.datetime.now(dt.timezone.utc)
    results = [
        ServiceScan(
            service=ServiceTarget(name="web", host="127.0.0.1", port=8443, data_category="health", managed=managed),
            status=status,
        ),
        ServiceScan(service=ServiceTarget(name="scanonly", host="127.0.0.1", port=9443), status=Status.CLASSICAL),
        ServiceScan(
            service=ServiceTarget(name="ssh", host="127.0.0.1", port=22, protocol=Protocol.SSH), status=Status.CLASSICAL
        ),
    ]
    return ScanReport(scan_id="x", started_at=now, finished_at=now, tool_version="t", backend="n", results=results)


def approver(ws: Workspace, decision: bool = True, who: str = "alice"):
    """A human approving from 'the dashboard': records the decision in the store."""

    def wait(a):
        return ws.approvals.decide(a.id, decision, who, "test")

    return wait


def toolbox(ws: Workspace, cfg: AegisQConfig, fake_nginx: dict[str, Any], **kw: Any) -> Toolbox:
    return Toolbox(ws, cfg, make_report(fake_nginx), verify_timeout=1, **kw)


def events(ws: Workspace) -> list[str]:
    return [e["event"] for e in ws.audit.entries()]


# --------------------------------------------------------------- happy path ---


def test_rules_planner_migrates_and_verifies(ws, cfg, fake_nginx, verify_stub) -> None:
    tb = toolbox(ws, cfg, fake_nginx, approval_waiter=approver(ws))
    summary = RulesPlanner().run(tb)
    assert summary.outcomes["web"] == "fixed"
    assert summary.outcomes["scanonly"] == "skipped" and summary.outcomes["ssh"] == "skipped"
    conf = Path(fake_nginx["conf"]).read_text()
    assert "ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;  # set by platform team" in conf
    assert Path(fake_nginx["state"]).read_text() == conf  # reloaded
    ev = events(ws)
    for e in (
        "patch.proposed",
        "approval.requested",
        "approval.outcome",
        "patch.applied",
        "service.verified",
        "report.generated",
        "agent.finished",
    ):
        assert e in ev
    assert ws.audit.verify().ok
    assert (ws.home / "reports" / "migration-report.html").exists()
    assert any("SSH is scan-only" in n for n in summary.notes["ssh"])
    a = ws.approvals.list()[0]
    assert a.status == "consumed" and a.decided_by == "alice"


def test_rejection_leaves_server_untouched(ws, cfg, fake_nginx, verify_stub) -> None:
    before = Path(fake_nginx["conf"]).read_text()
    tb = toolbox(ws, cfg, fake_nginx, approval_waiter=approver(ws, decision=False))
    summary = RulesPlanner().run(tb)
    assert summary.outcomes["web"] == "rejected"
    assert Path(fake_nginx["conf"]).read_text() == before
    assert "patch.applying" not in events(ws)


# ------------------------------------------------------------ the planned failure ---


def test_old_openssl_fails_test_restores_and_diagnoses(ws, cfg, fake_nginx, verify_stub, monkeypatch) -> None:
    monkeypatch.setenv("FAKE_OPENSSL", "3.0.11")
    before = Path(fake_nginx["conf"]).read_text()
    tb = toolbox(ws, cfg, fake_nginx, approval_waiter=approver(ws))
    summary = RulesPlanner().run(tb)
    assert summary.outcomes["web"] == "failed"
    assert Path(fake_nginx["conf"]).read_text() == before  # restored
    failed = next(e for e in ws.audit.entries() if e["event"] == "patch.test_failed")
    diag = failed["data"]["diagnosis"]
    assert diag["category"] == "tls_library_too_old" and diag["openssl_version"] == "3.0.11"
    assert failed["data"]["restored_config_test_ok"] is True
    assert "OpenSSL 3.0.11" in summary.notes["web"][0]
    assert ws.load_json("facts.json") == {"web": {"openssl": "3.0.11"}}
    # the risk model now knows this is an old stack
    listing = tb.list_services()["services"]
    assert next(r for r in listing if r["service"] == "web")["margin"] == 25 + 1.5 - 10


def test_reload_failure_restores(ws, cfg, fake_nginx, verify_stub, monkeypatch) -> None:
    monkeypatch.setenv("FAKE_RELOAD_FAIL", "1")
    before = Path(fake_nginx["conf"]).read_text()
    tb = toolbox(ws, cfg, fake_nginx, approval_waiter=approver(ws))
    prop = tb.propose_patch("web", ssl_ecdh_curve="X25519MLKEM768:X25519")
    tb.request_approval(prop["proposal_id"])
    out = tb.apply_patch(prop["proposal_id"])
    assert out["applied"] is False and out["stage"] == "reload"
    assert Path(fake_nginx["conf"]).read_text() == before


def test_verify_failure_rolls_back(ws, cfg, fake_nginx, verify_stub) -> None:
    verify_stub["health"] = False
    before = Path(fake_nginx["conf"]).read_text()
    tb = toolbox(ws, cfg, fake_nginx, approval_waiter=approver(ws))
    summary = RulesPlanner().run(tb)
    assert summary.outcomes["web"] == "rolled_back"
    assert Path(fake_nginx["conf"]).read_text() == before
    assert Path(fake_nginx["state"]).read_text() == before


# ---------------------------------------------------------------- refusals ---


def test_apply_refusals(ws, cfg, fake_nginx, verify_stub) -> None:
    tb = toolbox(ws, cfg, fake_nginx, approval_waiter=approver(ws))
    prop = tb.propose_patch("web", ssl_ecdh_curve="X25519MLKEM768:X25519")
    pid = prop["proposal_id"]
    with pytest.raises(ToolError, match="request_approval first"):
        tb.apply_patch(pid)
    decision = tb.request_approval(pid)
    assert decision["status"] == "approved"
    # the approval gets spent elsewhere (replay): apply must refuse
    assert ws.approvals.consume(decision["approval_id"], tb.proposals[pid].diff_sha256)
    with pytest.raises(ToolError, match="no valid human approval"):
        tb.apply_patch(pid)
    assert "patch.applying" not in events(ws)
    with pytest.raises(ToolError, match="unknown proposal"):
        tb.apply_patch("nope")


def test_undecided_approval_blocks(ws, cfg, fake_nginx, verify_stub) -> None:
    tb = toolbox(ws, cfg, fake_nginx, approval_waiter=lambda a: a)  # nobody decides
    pid = tb.propose_patch("web", ssl_ecdh_curve="X25519MLKEM768:X25519")["proposal_id"]
    assert tb.request_approval(pid)["status"] == "pending"
    with pytest.raises(ToolError, match="no usable approval"):
        tb.apply_patch(pid)


def test_approval_bound_to_diff_and_single_use(ws, cfg, fake_nginx, verify_stub) -> None:
    tb = toolbox(ws, cfg, fake_nginx, approval_waiter=approver(ws))
    p1 = tb.propose_patch("web", ssl_ecdh_curve="X25519MLKEM768:X25519")
    tb.request_approval(p1["proposal_id"])
    # tamper with the stored proposal after approval: apply must refuse
    tb.proposals[p1["proposal_id"]].diff = tb.proposals[p1["proposal_id"]].diff.replace(":X25519;", ":secp384r1;")
    with pytest.raises(ToolError):
        tb.apply_patch(p1["proposal_id"])


def test_drift_refused(ws, cfg, fake_nginx, verify_stub) -> None:
    tb = toolbox(ws, cfg, fake_nginx, approval_waiter=approver(ws))
    p = tb.propose_patch("web", ssl_ecdh_curve="X25519MLKEM768:X25519")
    tb.request_approval(p["proposal_id"])
    conf = Path(fake_nginx["conf"])
    conf.write_text(conf.read_text().replace("return 200", "return 204"))
    with pytest.raises(ToolError, match="changed since the proposal"):
        tb.apply_patch(p["proposal_id"])


def test_unmanaged_unknown_and_symlink(ws, cfg, fake_nginx, verify_stub, tmp_path) -> None:
    tb = toolbox(ws, cfg, fake_nginx)
    with pytest.raises(ToolError, match="scan-only"):
        tb.read_config("scanonly")
    with pytest.raises(ToolError, match="unknown service"):
        tb.read_config("../../etc/passwd")
    real = Path(fake_nginx["conf"])
    link = tmp_path / "link.conf"
    try:
        link.symlink_to(real)
    except OSError:
        pytest.skip("creating symlinks needs extra privileges on this OS")
    rep = make_report(fake_nginx)
    rep.results[0].service.managed.config_path = str(link)  # type: ignore[union-attr]
    tb2 = Toolbox(ws, cfg, rep)
    with pytest.raises(ToolError, match="symlink"):
        tb2.read_config("web")


def test_guardrail_refusal_is_audited(ws, cfg, fake_nginx, verify_stub) -> None:
    tb = toolbox(ws, cfg, fake_nginx)
    with pytest.raises(ToolError, match="guardrail"):
        tb.propose_patch("web", diff="@@ -1 +1 @@\n-events {}\n+events { worker_connections 1; }\n")
    with pytest.raises(ToolError, match="guardrail"):
        tb.propose_patch("web", ssl_ecdh_curve="X25519")
    assert events(ws).count("patch.rejected_by_guardrail") == 2


def test_one_change_in_flight_and_safety_net(ws, cfg, fake_nginx, verify_stub) -> None:
    rep = make_report(fake_nginx)
    second = rep.results[0].service.model_copy(update={"name": "web2"})
    rep.results.append(ServiceScan(service=second, status=Status.CLASSICAL))
    tb = Toolbox(ws, cfg, rep, approval_waiter=approver(ws))
    p = tb.propose_patch("web", ssl_ecdh_curve="X25519MLKEM768:X25519")
    tb.request_approval(p["proposal_id"])
    assert tb.apply_patch(p["proposal_id"])["applied"]
    # web2 shares the same file in this test; propose against the now-patched content
    p2 = tb.propose_patch("web2", ssl_ecdh_curve="X25519MLKEM768:secp384r1")
    tb.request_approval(p2["proposal_id"])
    with pytest.raises(ToolError, match="unverified"):
        tb.apply_patch(p2["proposal_id"])
    before_apply = "ssl_ecdh_curve X25519:prime256v1;"
    rolled = tb.finalize()
    assert rolled == ["web"]
    assert before_apply in Path(fake_nginx["conf"]).read_text()
    assert "agent.safety_rollback" in events(ws)


def test_rollback_without_backup(ws, cfg, fake_nginx, verify_stub) -> None:
    tb = toolbox(ws, cfg, fake_nginx)
    assert tb.rollback("web")["rolled_back"] is False


def test_patch_branch_recorded(ws, cfg, fake_nginx, verify_stub) -> None:
    tb = toolbox(ws, cfg, fake_nginx)
    p = tb.propose_patch("web", ssl_ecdh_curve="X25519MLKEM768:X25519")
    if p["branch"] is None:
        pytest.skip("git not installed")
    from aegisq.proc import run_sync

    repo = ws.home / "patches" / "repo.git"
    show = run_sync(["git", "--git-dir", str(repo), "diff", f"{p['branch']}~1", p["branch"], "--", "site.conf"], 10)
    assert "+    ssl_ecdh_curve X25519MLKEM768:X25519;" in show.stdout


# ------------------------------------------------------------- dispatcher ---


def test_dispatch_validates_inputs(ws, cfg, fake_nginx) -> None:
    tb = toolbox(ws, cfg, fake_nginx)
    out, err = dispatch(tb, "rm_rf", {})
    assert err and "unknown tool" in out
    out, err = dispatch(tb, "read_config", {"service": "web", "path": "/etc/shadow"})
    assert err and "invalid input" in out
    out, err = dispatch(tb, "read_config", "not a dict")
    assert err
    out, err = dispatch(tb, "list_services", {})
    assert not err and json.loads(out)["services"][0]["service"] == "web"
    names = {t["name"] for t in tool_specs()}
    assert names == {
        "list_services",
        "read_config",
        "propose_patch",
        "request_approval",
        "apply_patch",
        "verify",
        "rollback",
        "write_report",
    }
    for t in tool_specs():
        assert t["input_schema"]["additionalProperties"] is False


def test_desired_groups() -> None:
    allowed = AegisQConfig().agent.allowed_groups
    assert desired_groups(["X25519:prime256v1"], allowed) == "X25519MLKEM768:X25519:prime256v1"
    assert desired_groups(["prime256v1"], allowed) == "X25519MLKEM768:X25519:prime256v1"
    assert desired_groups([], allowed) == "X25519MLKEM768:X25519"
    assert desired_groups(["X25519MLKEM768:X25519"], allowed) == "X25519MLKEM768:X25519"


# ------------------------------------------------------- Claude planner ---


class ScriptedClaude:
    """Plays back a fixed sequence of assistant turns and records what AegisQ sent."""

    def __init__(self, turns: list[list[dict[str, Any]]]) -> None:
        self.turns = turns
        self.requests: list[dict[str, Any]] = []
        self.messages = self

    def create(self, **kw: Any) -> Any:
        self.requests.append({**kw, "messages": list(kw["messages"])})
        blocks = self.turns[len(self.requests) - 1]
        content = [SimpleNamespace(**b) for b in blocks]
        stop = "tool_use" if any(b["type"] == "tool_use" for b in blocks) else "end_turn"
        if blocks and blocks[0].get("type") == "refusal":
            return SimpleNamespace(content=[], stop_reason="refusal", stop_details={"category": "cyber"})
        return SimpleNamespace(content=content, stop_reason=stop)


def tu(i: int, name: str, **inp: Any) -> dict[str, Any]:
    return {"type": "tool_use", "id": f"t{i}", "name": name, "input": inp}


def last_results(client: ScriptedClaude, n: int) -> list[dict[str, Any]]:
    msgs = client.requests[n]["messages"]
    return msgs[-1]["content"]


def test_claude_planner_cannot_bypass_guardrails(ws, cfg, fake_nginx, verify_stub) -> None:
    turns = [
        [tu(1, "list_services")],
        [tu(2, "read_config", service="web")],
        # a misbehaving model: rewrite other directives, then try to apply without approval
        [
            tu(
                3,
                "propose_patch",
                service="web",
                diff="@@ -8 +8 @@\n-    ssl_ecdh_curve X25519:prime256v1;  # set by "
                "platform team\n+    ssl_ecdh_curve X25519MLKEM768:X25519; include /etc/passwd;\n",
            )
        ],
        [tu(4, "apply_patch", proposal_id="whatever")],
        [tu(5, "propose_patch", service="web", ssl_ecdh_curve="X25519MLKEM768:X25519", rationale="hybrid first")],
        [{"type": "text", "text": "waiting"}, tu(6, "request_approval", proposal_id="__PID__")],
        [tu(7, "apply_patch", proposal_id="__PID__")],
        [tu(8, "verify", service="web")],
        [tu(9, "write_report")],
        [{"type": "text", "text": "web: fixed."}],
    ]
    client = ScriptedClaude(turns)
    orig_create = client.create

    def create(**kw: Any) -> Any:
        # substitute the real proposal id the toolbox returned
        for msg in kw["messages"]:
            if msg["role"] == "user" and isinstance(msg["content"], list):
                for r in msg["content"]:
                    if r.get("tool_use_id") == "t5" and not r["is_error"]:
                        pid = json.loads(r["content"])["proposal_id"]
                        for turn in client.turns:
                            for b in turn:
                                if b.get("input", {}).get("proposal_id") == "__PID__":
                                    b["input"]["proposal_id"] = pid
        return orig_create(**kw)

    client.create = create  # type: ignore[method-assign]
    planner = ClaudePlanner(model="claude-opus-5-5", client=client)
    tb = toolbox(ws, cfg, fake_nginx, approval_waiter=approver(ws))
    summary = planner.run(tb)

    r3 = last_results(client, 3)[0]
    assert r3["is_error"] and "guardrail" in r3["content"]
    r4 = last_results(client, 4)[0]
    assert r4["is_error"] and "unknown proposal" in r4["content"]
    assert summary.outcomes["web"] == "fixed"
    assert summary.final_message == "web: fixed."
    req = client.requests[0]
    assert req["model"] == "claude-opus-5-5" and req["thinking"] == {"type": "adaptive"}
    assert req["extra_body"] == {"fallbacks": "default"}
    assert "X25519MLKEM768:X25519" in Path(fake_nginx["conf"]).read_text()
    assert "include" not in Path(fake_nginx["conf"]).read_text()
    assert events(ws).count("agent.tool_call") == 9


def test_claude_planner_scope_refusal_and_safety_net(ws, cfg, fake_nginx, verify_stub) -> None:
    turns = [
        [tu(1, "read_config", service="scanonly")],
        [tu(2, "propose_patch", service="web", ssl_ecdh_curve="X25519MLKEM768:X25519")],
        [{"type": "refusal"}],
    ]
    client = ScriptedClaude(turns)
    planner = ClaudePlanner(model="m", client=client)
    tb = toolbox(ws, cfg, fake_nginx, approval_waiter=approver(ws))
    summary = planner.run(tb, only=["web"])
    r1 = last_results(client, 1)[0]
    assert r1["is_error"] and "outside the scope" in r1["content"]
    assert "declined" in summary.final_message
    assert "agent.refusal" in events(ws)


def test_claude_planner_turn_limit(ws, cfg, fake_nginx, verify_stub) -> None:
    client = ScriptedClaude([[tu(i, "list_services")] for i in range(5)])
    summary = ClaudePlanner(model="m", max_turns=3, client=client).run(toolbox(ws, cfg, fake_nginx))
    assert "Stopped after 3 turns" in summary.final_message


def test_concurrent_lock(ws, cfg, fake_nginx, verify_stub) -> None:
    tb = toolbox(ws, cfg, fake_nginx)
    started, release = threading.Event(), threading.Event()

    def hold() -> None:
        with tb._lock("web"):
            started.set()
            release.wait(5)

    t = threading.Thread(target=hold)
    t.start()
    started.wait(5)
    try:
        with pytest.raises(ToolError, match="locked"), tb._lock("web"):
            pass
    finally:
        release.set()
        t.join()
    assert os.path.exists(ws.home / "locks" / "web.lock")


def test_stopped_run_withdraws_pending_approval(ws, cfg, fake_nginx, verify_stub) -> None:
    """Ctrl-C / dashboard Cancel while waiting for a human: the request must not stay approvable."""

    def interrupted(a):
        raise KeyboardInterrupt

    tb = toolbox(ws, cfg, fake_nginx, approval_waiter=interrupted)
    pid = tb.propose_patch("web", ssl_ecdh_curve="X25519MLKEM768:X25519")["proposal_id"]
    with pytest.raises(KeyboardInterrupt):
        tb.request_approval(pid)
    assert ws.approvals.list("pending") == []
    assert ws.approvals.list("cancelled")[0].service == "web"
    assert "approval.cancelled" in events(ws)
