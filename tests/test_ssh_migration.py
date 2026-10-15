import asyncio
import os
import shutil
import socket
import subprocess
import time
from pathlib import Path
from typing import Any

import pytest

from aegisq.agent import guardrails as gr
from aegisq.agent.diagnose import diagnose_sshd, openssh_version_from
from aegisq.agent.runner import RulesPlanner, desired_ssh_kex
from aegisq.agent.tools import Toolbox
from aegisq.config import AegisQConfig, AgentConfig
from aegisq.models import ManagedSSHD, Protocol, ServiceTarget, Status
from aegisq.scanner.engine import ScanOptions, scan_all
from aegisq.workspace import Workspace

POLICY = gr.Policy(allowed_groups=AgentConfig().allowed_groups, allowed_ssh_kex=AgentConfig().allowed_ssh_kex)
CONF = """# sshd test config
Port 22
KexAlgorithms curve25519-sha256,ecdh-sha2-nistp256
PasswordAuthentication no

Match User backup
    X11Forwarding no
"""
GOOD = "sntrup761x25519-sha512@openssh.com,curve25519-sha256"


def patch(kex: str, conf: str = CONF) -> gr.ValidatedPatch:
    return gr.validate_patch(conf, gr.make_sshd_patch(conf, "sshd_config", kex), POLICY, gr.SSHD)


# ------------------------------------------------------------- guardrails ---


def test_sshd_patch_rewrites_only_the_global_kex_line() -> None:
    vp = patch(GOOD)
    assert vp.changes == [
        "- KexAlgorithms curve25519-sha256,ecdh-sha2-nistp256",
        f"+ KexAlgorithms {GOOD}",
    ]
    assert "Match User backup\n    X11Forwarding no" in vp.new_text
    assert gr.current_directives(vp.new_text, gr.SSHD) == {"KexAlgorithms": [GOOD]}


def test_sshd_patch_inserts_before_the_first_directive() -> None:
    conf = "# comment\n\nInclude /etc/ssh/sshd_config.d/*.conf\nPort 22\n"
    vp = patch(GOOD, conf)
    assert vp.new_text.split("\n")[2] == f"KexAlgorithms {GOOD}"
    assert patch(GOOD, "# only comments\n").new_text == f"# only comments\nKexAlgorithms {GOOD}\n"


@pytest.mark.parametrize(
    ("kex", "reason"),
    [
        ("curve25519-sha256", "post-quantum hybrid"),
        ("curve25519-sha256,mlkem768x25519-sha256", "must come first"),
        ("mlkem768x25519-sha256", "classical fallback"),
        ("mlkem768x25519-sha256,diffie-hellman-group1-sha1", "weak key exchange"),
        ("mlkem768x25519-sha256,mlkem768x25519-sha256,curve25519-sha256", "listed twice"),
        ("mlkem768x25519-sha256,made-up-kex,curve25519-sha256", "not in the allowed list"),
    ],
)
def test_sshd_policy_rejections(kex: str, reason: str) -> None:
    with pytest.raises(gr.PatchRejected, match=reason):
        patch(kex)


def test_sshd_rejects_modifiers_and_other_directives() -> None:
    diff = gr.make_sshd_patch(CONF, "sshd_config", GOOD).replace(GOOD, "+" + GOOD)
    with pytest.raises(gr.PatchRejected, match="explicit list"):
        gr.validate_patch(CONF, diff, POLICY, gr.SSHD)
    smuggled = (
        "--- a/sshd_config\n+++ b/sshd_config\n@@ -2,2 +2,3 @@\n Port 22\n"
        f"-KexAlgorithms curve25519-sha256,ecdh-sha2-nistp256\n+KexAlgorithms {GOOD}\n+PermitRootLogin yes\n"
    )
    with pytest.raises(gr.PatchRejected, match="change outside KexAlgorithms refused"):
        gr.validate_patch(CONF, smuggled, POLICY, gr.SSHD)
    nginx_line = (
        "--- a/sshd_config\n+++ b/sshd_config\n@@ -3,1 +3,1 @@\n"
        "-KexAlgorithms curve25519-sha256,ecdh-sha2-nistp256\n+ssl_ecdh_curve X25519MLKEM768:X25519;\n"
    )
    with pytest.raises(gr.PatchRejected):
        gr.validate_patch(CONF, nginx_line, POLICY, gr.SSHD)


def test_sshd_rejects_kex_inside_match_block() -> None:
    diff = (
        "--- a/sshd_config\n+++ b/sshd_config\n@@ -6,2 +6,3 @@\n Match User backup\n"
        f"     X11Forwarding no\n+    KexAlgorithms {GOOD}\n"
    )
    with pytest.raises(gr.PatchRejected, match="Match block"):
        gr.validate_patch(CONF, diff, POLICY, gr.SSHD)


def test_sshd_patch_refuses_unparseable_existing_line() -> None:
    with pytest.raises(gr.PatchRejected, match="cannot safely rewrite"):
        gr.make_sshd_patch('KexAlgorithms "curve25519-sha256"\n', "sshd_config", GOOD)
    with pytest.raises(gr.PatchRejected, match="comma-separated"):
        gr.make_sshd_patch(CONF, "sshd_config", "x;rm -rf /")


# ------------------------------------------------------- planning helpers ---


def test_desired_ssh_kex_follows_the_openssh_version() -> None:
    allowed = AgentConfig().allowed_ssh_kex
    existing = ["curve25519-sha256,diffie-hellman-group1-sha1,ecdh-sha2-nistp256"]
    assert desired_ssh_kex(existing, "10.0", allowed) == (
        "mlkem768x25519-sha256,sntrup761x25519-sha512@openssh.com,curve25519-sha256,ecdh-sha2-nistp256"
    )
    assert desired_ssh_kex(existing, "9.6", allowed) == (
        "sntrup761x25519-sha512@openssh.com,curve25519-sha256,ecdh-sha2-nistp256"
    )
    assert desired_ssh_kex(existing, "8.4", allowed) is None
    assert desired_ssh_kex([], "9.6", allowed).startswith("sntrup761x25519-sha512@openssh.com,curve25519-sha256,")
    assert desired_ssh_kex(["+sntrup761x25519-sha512@openssh.com"], "9.6", allowed).endswith("group14-sha256")


def test_diagnose_sshd() -> None:
    out = "/etc/ssh/sshd_config line 3: Bad SSH2 KexAlgorithms 'mlkem768x25519-sha256'."
    d = diagnose_sshd(out, "OpenSSH_9.6p1 Ubuntu-3ubuntu13, OpenSSL 3.0.13")
    assert d.category == "ssh_too_old" and "9.6" in d.root_cause and "sntrup761" in d.recommendation
    assert diagnose_sshd("line 9: Bad configuration option: Foo", "").category == "syntax"
    assert openssh_version_from("SSH-2.0-OpenSSH_10.2") == (10, 2)


def test_managed_kind_follows_protocol() -> None:
    t = ServiceTarget.model_validate(
        {"name": "s", "host": "127.0.0.1", "protocol": "ssh", "port": 22, "managed": {"config_path": "/x"}}
    )
    assert isinstance(t.managed, ManagedSSHD) and t.managed.test_cmd == ["sshd", "-t", "-f", "/x"]
    with pytest.raises(ValueError, match="does not match protocol"):
        ServiceTarget.model_validate(
            {"name": "s", "host": "127.0.0.1", "port": 443, "managed": {"kind": "sshd", "config_path": "/x"}}
        )


# --------------------------------------------------- end to end, real sshd ---

SSHD_BIN = next((p for p in (shutil.which("sshd"), "/usr/sbin/sshd") if p and os.path.exists(p)), None)


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@pytest.fixture
def real_sshd(tmp_path: Path):
    if SSHD_BIN is None or shutil.which("ssh-keygen") is None:
        pytest.skip("OpenSSH server not installed")
    key = tmp_path / "hostkey"
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(key)], check=True)
    port = _free_port()
    conf = tmp_path / "sshd_config"
    conf.write_text(
        f"# AegisQ test server\nPort {port}\nListenAddress 127.0.0.1\nHostKey {key}\n"
        f"PidFile {tmp_path / 'sshd.pid'}\nKexAlgorithms curve25519-sha256,ecdh-sha2-nistp256\n"
        "PasswordAuthentication no\nUsePAM no\n"
    )
    proc = subprocess.Popen([SSHD_BIN, "-D", "-e", "-f", str(conf)], stderr=subprocess.PIPE, text=True)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            pytest.skip(f"sshd could not start here: {proc.stderr.read()[:300] if proc.stderr else ''}")
        try:
            socket.create_connection(("127.0.0.1", port), 0.2).close()
            break
        except OSError:
            time.sleep(0.1)
    managed = ManagedSSHD(
        config_path=str(conf),
        test_cmd=[SSHD_BIN, "-t", "-f", str(conf)],
        reload_cmd=["kill", "-HUP", str(proc.pid)],
        version_cmd=[SSHD_BIN, "-V"],
    )
    target = ServiceTarget(name="bastion", host="127.0.0.1", port=port, protocol=Protocol.SSH, managed=managed)
    yield {"conf": conf, "target": target, "proc": proc}
    proc.terminate()
    proc.wait(5)


def _scan(target: ServiceTarget):
    return asyncio.run(scan_all([target], ScanOptions(timeout=3)))


def _patient(cfg: AegisQConfig) -> AegisQConfig:
    """sshd stops listening for a moment while it restarts on SIGHUP: verify like production does."""
    return cfg.model_copy(
        update={"agent": cfg.agent.model_copy(update={"verify_attempts": 10, "verify_interval_s": 0.3})}
    )


def _openssh_version() -> tuple[int, int] | None:
    out = subprocess.run([SSHD_BIN, "-V"], capture_output=True, text=True, check=False) if SSHD_BIN else None
    return openssh_version_from((out.stdout + out.stderr) if out else "")


def test_rules_planner_fixes_a_real_sshd(real_sshd: dict[str, Any], cfg: AegisQConfig) -> None:
    if (_openssh_version() or (0, 0)) < (8, 5):
        pytest.skip("needs OpenSSH 8.5+")
    cfg = _patient(cfg)
    ws = Workspace(cfg.home_path)
    report = _scan(real_sshd["target"])
    assert report.results[0].status == Status.CLASSICAL
    tb = Toolbox(ws, cfg, report, verify_timeout=3, approval_waiter=lambda a: ws.approvals.decide(a.id, True, "alice"))
    summary = RulesPlanner().run(tb)
    assert summary.outcomes == {"bastion": "fixed"}, summary.notes
    text = real_sshd["conf"].read_text()
    assert "KexAlgorithms " in text and ",curve25519-sha256,ecdh-sha2-nistp256\n" in text
    assert "PasswordAuthentication no" in text and "UsePAM no" in text
    assert _scan(real_sshd["target"]).results[0].status == Status.PQ_READY
    ev = [e["event"] for e in ws.audit.entries()]
    for e in ("patch.proposed", "approval.requested", "patch.applied", "service.verified"):
        assert e in ev
    assert ws.audit.verify().ok


def test_unsupported_kex_is_restored_and_diagnosed(real_sshd: dict[str, Any], cfg: AegisQConfig) -> None:
    if (_openssh_version() or (99, 0)) >= (9, 9):
        pytest.skip("this OpenSSH supports mlkem768x25519-sha256")
    ws = Workspace(cfg.home_path)
    before = real_sshd["conf"].read_text()
    tb = Toolbox(
        ws,
        cfg,
        _scan(real_sshd["target"]),
        verify_timeout=3,
        approval_waiter=lambda a: ws.approvals.decide(a.id, True, "bob"),
    )
    prop = tb.propose_patch("bastion", kex_algorithms="mlkem768x25519-sha256,curve25519-sha256")
    assert tb.request_approval(prop["proposal_id"])["status"] == "approved"
    out = tb.apply_patch(prop["proposal_id"])
    assert out["applied"] is False and out["stage"] == "config_test" and out["restored_previous_config"]
    assert out["diagnosis"]["category"] == "ssh_too_old"
    assert real_sshd["conf"].read_text() == before
    assert _scan(real_sshd["target"]).results[0].status == Status.CLASSICAL
