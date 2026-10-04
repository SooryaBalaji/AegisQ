"""End-to-end tests against the real Docker demo fleet (nginx/OpenSSL 3.5, nginx/OpenSSL 3.0, OpenSSH 10).

Run with: make demo-up && pytest -m integration
"""

import asyncio
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from aegisq.agent.runner import RulesPlanner
from aegisq.agent.tools import Toolbox
from aegisq.inventory import load_inventory
from aegisq.models import Status
from aegisq.scanner.engine import ScanOptions, scan_all

pytestmark = pytest.mark.integration
DEMO = Path(__file__).resolve().parent.parent / "demo"
CONTAINERS = ["aegisq-app-modern", "aegisq-app-legacy", "aegisq-app-tls12", "aegisq-app-ready", "aegisq-app-plain"]


def _running() -> bool:
    if not shutil.which("docker"):
        return False
    out = subprocess.run(
        ["docker", "ps", "--format", "{{.Names}}"], capture_output=True, text=True, timeout=20, check=False
    )
    names = set(out.stdout.split())
    return out.returncode == 0 and set(CONTAINERS) <= names


@pytest.fixture
def fleet():
    if not _running():
        pytest.skip("demo fleet not running (make demo-up)")

    def reset() -> None:
        subprocess.run([sys.executable, str(DEMO / "setup.py"), "--configs-only"], check=True, capture_output=True)
        for c in CONTAINERS:
            subprocess.run(["docker", "exec", c, "nginx", "-s", "reload"], check=True, capture_output=True)

    reset()
    # fleet.docker.yaml addresses servers by container name (when the tests themselves run in Docker)
    yield load_inventory(DEMO / os.environ.get("AEGISQ_FLEET", "fleet.yaml"))
    reset()


def scan(targets):
    rep = asyncio.run(scan_all(targets, ScanOptions(timeout=5)))
    return rep, {r.service.name: r.status for r in rep.results}


def test_fleet_scan(fleet) -> None:
    _, st = scan(fleet)
    assert st == {
        "app-modern": Status.CLASSICAL,
        "app-legacy": Status.CLASSICAL,
        "app-tls12": Status.TLS12_ONLY,
        "app-ready": Status.PQ_READY,
        "app-plain": Status.PLAINTEXT,
        "ssh-pq": Status.PQ_READY,
        "ssh-legacy": Status.CLASSICAL,
    }


def test_full_migration_with_planned_failure(fleet, ws, cfg) -> None:
    report, _ = scan(fleet)
    cfg.agent.verify_attempts = 5
    cfg.agent.verify_interval_s = 0.5
    tb = Toolbox(ws, cfg, report, approval_waiter=lambda a: ws.approvals.decide(a.id, True, "integration-test"))
    summary = RulesPlanner().run(tb)
    assert summary.outcomes["app-modern"] == "fixed"
    assert summary.outcomes["app-tls12"] == "fixed"
    assert summary.outcomes["app-legacy"] == "failed"
    assert "OpenSSL 3.0" in summary.notes["app-legacy"][0]
    legacy = (DEMO / "fleet/app-legacy/conf.d/site.conf").read_text()
    assert "ssl_ecdh_curve X25519:prime256v1;" in legacy  # restored
    _, st = scan(fleet)
    assert st["app-modern"] == st["app-tls12"] == Status.PQ_READY
    assert st["app-legacy"] == Status.CLASSICAL  # still serving, untouched
    assert ws.audit.verify().ok
