import json
import os
from pathlib import Path

import pytest
from click.testing import CliRunner

from aegisq.cli import main
from fakes import ssh_server, tls_server


@pytest.fixture
def runner(home: Path):
    r = CliRunner()

    def invoke(*args: str, **kw):
        return r.invoke(main, ["--home", str(home), *args], catch_exceptions=False, **kw)

    return invoke


@pytest.fixture
def inventory(tmp_path: Path):
    with tls_server("pq") as pq, tls_server("classical") as cl, ssh_server("classical") as ssh:
        inv = tmp_path / "inv.yaml"
        inv.write_text(
            f"""
defaults: {{host: 127.0.0.1, sni: fake.test}}
services:
  - {{name: ready, port: {pq.port}, data_category: marketing}}
  - {{name: exposed, port: {cl.port}, data_category: health}}
  - {{name: shell, port: {ssh.port}, protocol: ssh, data_category: internal}}
"""
        )
        yield inv


def test_scan_cbom_risk_report(runner, inventory, tmp_path) -> None:
    r = runner("scan", str(inventory), "--timeout", "2")
    assert r.exit_code == 0, r.output
    assert "PQ READY" in r.output and "CLASSICAL" in r.output
    r = runner("scan", str(inventory), "--json", "--no-legacy")
    assert json.loads(r.output)["results"][0]["status"] == "pq_ready"
    out = tmp_path / "cbom.json"
    r = runner("cbom", "--out", str(out))
    assert r.exit_code == 0 and "valid CycloneDX 1.6" in r.output
    assert runner("cbom-validate", str(out)).exit_code == 0
    r = runner("risk", "--z", "5", "--sweep", "0,10,30")
    assert "exposed" in r.output and "critical" in r.output
    ranking = json.loads(runner("risk", "--json").output)
    assert ranking[0]["service"] == "exposed"
    r = runner("report")
    assert r.exit_code == 0 and "migration-report.html" in r.output
    assert runner("audit", "verify").exit_code == 0
    assert "scan.completed" in runner("audit", "tail", "-n", "50").output


def test_fail_on_gates_ci(runner, inventory) -> None:
    assert runner("scan", str(inventory), "--fail-on", "classical").exit_code == 2
    assert runner("scan", str(inventory), "--fail-on", "at-risk").exit_code == 2
    assert runner("scan", str(inventory), "--fail-on", "none").exit_code == 0


def test_invalid_cbom_file_exit_code(runner, tmp_path) -> None:
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [{"type": "nope"}]}))
    assert runner("cbom-validate", str(bad)).exit_code == 2


def test_tampered_audit_exit_code(runner, inventory, home) -> None:
    runner("scan", str(inventory))
    log = home / "audit.jsonl"
    lines = log.read_text().splitlines()
    lines[0] = lines[0].replace("scan.started", "scan.forged")
    log.write_text("\n".join(lines) + "\n")
    r = runner("audit", "verify")
    assert r.exit_code == 2


def test_approvals_cli(runner, home) -> None:
    from aegisq.workspace import Workspace

    ws = Workspace(home)
    a = ws.approvals.create("svc", "p", "--- a\n+++ b\n", "h" * 64, "change", "agent", 60)
    assert a.id in runner("approvals", "list", "--status", "pending").output
    assert "+++ b" in runner("approvals", "show", a.id).output
    assert runner("approve", a.id, "--by", "agent").exit_code == 1  # must be a named human
    r = runner("approve", a.id, "--by", "alice", "--reason", "CHG-1")
    assert r.exit_code == 0 and "approved by alice" in r.output
    assert runner("reject", a.id, "--by", "bob", "--reason", "late").exit_code == 1


def test_errors_are_clean(runner, tmp_path) -> None:
    bad = tmp_path / "inv.yaml"
    bad.write_text("services: [{name: x, host: '$(id)', port: 1}]")
    r = runner("scan", str(bad))
    assert r.exit_code == 1 and "host" in r.output
    assert runner("risk").exit_code == 1  # no scan yet
    assert runner("entropy", "analyze").exit_code == 1


def test_doctor(runner) -> None:
    r = runner("doctor")
    assert r.exit_code == 0 and "native TLS/SSH probes" in r.output and "CycloneDX 1.6 schema" in r.output


def test_migrate_terminal_needs_tty(runner, inventory) -> None:
    r = runner("migrate", str(inventory), "--approve-in", "terminal", "--planner", "rules")
    assert r.exit_code == 1 and "interactive terminal" in r.output
    assert runner("migrate", str(inventory), "--service", "ghost").exit_code == 1


def test_env_file_loading(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Native `aegisq` reads the same demo/.env that Docker Compose uses; real environment values win."""
    from aegisq.config import load_env_file

    monkeypatch.setattr(os, "environ", os.environ.copy())  # load_env_file writes os.environ directly
    for k in ("AQ_T_PLAIN", "AQ_T_QUOTED", "AQ_T_SINGLE", "AQ_T_EXPORT", "AQ_T_EMPTY", "AQ_T_SET", "AQ_T_COMMENT"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("AQ_T_SET", "from-shell")
    monkeypatch.delenv("AEGISQ_ENV_FILE", raising=False)
    monkeypatch.chdir(tmp_path)
    assert load_env_file() is None
    (tmp_path / "demo").mkdir()
    (tmp_path / "demo" / ".env").write_text(
        "﻿# keys\nAQ_T_PLAIN=abc\nAQ_T_QUOTED=\"with space\"\nAQ_T_SINGLE='x=y'\n"
        "export AQ_T_EXPORT=1\nAQ_T_EMPTY=\nAQ_T_SET=from-file\n#AQ_T_COMMENT=no\nnot a line\n",
        encoding="utf-8",
    )
    path, n = load_env_file()  # type: ignore[misc]
    assert path == Path("demo") / ".env" and n == 4
    assert os.environ["AQ_T_PLAIN"] == "abc" and os.environ["AQ_T_QUOTED"] == "with space"
    assert os.environ["AQ_T_SINGLE"] == "x=y" and os.environ["AQ_T_EXPORT"] == "1"
    assert os.environ["AQ_T_SET"] == "from-shell"
    assert "AQ_T_EMPTY" not in os.environ and "AQ_T_COMMENT" not in os.environ
    (tmp_path / ".env").write_text("AQ_T_PLAIN=root-wins\n", encoding="utf-8")
    monkeypatch.delenv("AQ_T_PLAIN")
    assert load_env_file()[0] == Path(".env") and os.environ["AQ_T_PLAIN"] == "root-wins"  # type: ignore[index]


def test_doctor_reads_env_file(runner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(os, "environ", os.environ.copy())  # the CLI loads the file into os.environ
    env = tmp_path / "my.env"
    env.write_text("GEMINI_API_KEY=test-key\nAEGISQ_API_TOKENS=me:0123456789abcdefgh\n", encoding="utf-8")
    monkeypatch.setenv("AEGISQ_ENV_FILE", str(env))
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("AEGISQ_API_TOKENS", raising=False)
    r = runner("doctor")
    assert r.exit_code == 0
    assert f"{env} (2 variables loaded)" in r.output
    assert "gemma-4-31b-it @ generativelanguage.googleapis.com" in r.output
    assert "1 configured" in r.output
    assert "\nno  " not in r.output  # optional tools are never shown as failures
