import threading
import time

import pytest

from aegisq.workspace import Workspace


def mk(ws: Workspace, service: str = "app", sha: str = "a" * 64, ttl: float = 60):
    return ws.approvals.create(service, "prop1", "diff", sha, "summary", "agent", ttl)


def test_lifecycle_and_binding(ws: Workspace) -> None:
    a = mk(ws)
    assert a.status == "pending"
    assert not ws.approvals.consume(a.id, a.diff_sha256)  # not approved yet
    ws.approvals.decide(a.id, True, "alice", "ok")
    assert not ws.approvals.consume(a.id, "b" * 64)  # bound to the exact diff
    assert ws.approvals.consume(a.id, a.diff_sha256)
    assert not ws.approvals.consume(a.id, a.diff_sha256)  # single use
    assert ws.approvals.get(a.id).status == "consumed"


def test_only_named_humans_decide_and_only_once(ws: Workspace) -> None:
    a = mk(ws)
    for who in ("", "agent", "Claude", "aegisq", "  "):
        with pytest.raises(PermissionError):
            ws.approvals.decide(a.id, True, who)
    ws.approvals.decide(a.id, False, "bob", "no")
    with pytest.raises(LookupError):
        ws.approvals.decide(a.id, True, "alice")
    with pytest.raises(LookupError):
        ws.approvals.decide("missing", True, "alice")


def test_expiry_and_supersede(ws: Workspace) -> None:
    a = mk(ws, ttl=0.01)
    time.sleep(0.05)
    assert ws.approvals.get(a.id).status == "expired"
    with pytest.raises(LookupError):
        ws.approvals.decide(a.id, True, "alice")
    b = mk(ws, service="svc")
    c = mk(ws, service="svc")
    assert ws.approvals.get(b.id).status == "cancelled" and ws.approvals.get(c.id).status == "pending"
    approved_then_expired = mk(ws, service="z", ttl=0.2)
    ws.approvals.decide(approved_then_expired.id, True, "alice")
    time.sleep(0.3)
    assert not ws.approvals.consume(approved_then_expired.id, approved_then_expired.diff_sha256)


def test_wait_returns_decision_or_times_out(ws: Workspace) -> None:
    a = mk(ws)
    threading.Timer(0.2, lambda: ws.approvals.decide(a.id, True, "alice")).start()
    assert ws.approvals.wait(a.id, timeout=5, poll=0.05).status == "approved"
    b = mk(ws, service="other")
    assert ws.approvals.wait(b.id, timeout=0.2, poll=0.05).status == "cancelled"


def test_workspace_paths_are_confined(ws: Workspace) -> None:
    with pytest.raises(ValueError):
        ws.save_json("../escape.json", {})
    ws.save_json("entropy/x.json", {"a": 1})
    assert ws.load_json("entropy/x.json") == {"a": 1}
    assert ws.load_json("entropy/missing.json") is None
