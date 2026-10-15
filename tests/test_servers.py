import asyncio
import datetime as dt
import re
import stat
import sys
from pathlib import Path

import pytest
from pydantic import ValidationError

from aegisq.agent import diagnose as dg
from aegisq.agent import guardrails as gr
from aegisq.agent import tlslib
from aegisq.agent import tools as tools_mod
from aegisq.agent.advice import advice_for
from aegisq.agent.health import HealthResult
from aegisq.agent.runner import RulesPlanner, desired_groups
from aegisq.agent.tools import Toolbox
from aegisq.config import AgentConfig
from aegisq.models import ManagedServer, ScanReport, ServiceScan, ServiceTarget, Status
from aegisq.scanner import engine, tls_probe
from fakes import FakeTLSServer

POLICY = gr.Policy(AgentConfig().allowed_groups)

APACHE = """<VirtualHost *:443>
    ServerName shop.example
    SSLEngine on
    SSLCertificateFile /etc/ssl/shop.crt
    SSLCertificateKeyFile /etc/ssl/shop.key
</VirtualHost>
"""
HAPROXY = """global
    log stdout format raw local0
    ssl-default-bind-curves X25519:P-256

defaults
    mode http

frontend web
    bind :443 ssl crt /etc/haproxy/site.pem
"""
CADDY = """shop.example {
\ttls /etc/ssl/a.pem /etc/ssl/a.key {
\t\tcurves x25519 secp256r1
\t}
\trespond "ok"
}
"""
POSTFIX = """myhostname = mail.example
smtpd_tls_security_level = may
tls_eecdh_auto_curves = X25519, prime256v1, secp384r1
"""
DOVECOT = """ssl = yes
ssl_cert = </etc/ssl/mail.pem
ssl_key = </etc/ssl/mail.key
"""


def patched(kind: str, conf: str, groups: list[str]) -> str:
    diff = gr.make_groups_patch(conf, "f.conf", kind, groups)
    return gr.validate_patch(conf, diff, POLICY, gr.DIALECTS[kind]).new_text


def changed(old: str, new: str) -> list[str]:
    o, n = set(old.split("\n")), new.split("\n")
    return [line for line in n if line not in o]


def test_apache_inserts_after_each_key_and_rewrites() -> None:
    new = patched("apache", APACHE, ["X25519MLKEM768", "X25519", "prime256v1"])
    assert changed(APACHE, new) == ["    SSLOpenSSLConfCmd Groups X25519MLKEM768:X25519:prime256v1"]
    assert new.index("SSLOpenSSLConfCmd") > new.index("SSLCertificateKeyFile")
    again = patched("apache", new, ["X25519MLKEM768", "X25519"])
    assert changed(new, again) == ["    SSLOpenSSLConfCmd Groups X25519MLKEM768:X25519"]
    with pytest.raises(gr.PatchRejected, match="does not look like a TLS virtual host"):
        gr.make_groups_patch("<VirtualHost *:80>\n</VirtualHost>\n", "f", "apache", ["X25519MLKEM768", "X25519"])


def test_haproxy_global_only() -> None:
    new = patched("haproxy", HAPROXY, ["X25519MLKEM768", "X25519", "P-256"])
    assert changed(HAPROXY, new) == ["    ssl-default-bind-curves X25519MLKEM768:X25519:P-256"]
    bare = HAPROXY.replace("    ssl-default-bind-curves X25519:P-256\n", "")
    ins = patched("haproxy", bare, ["X25519MLKEM768", "X25519"])
    assert ins.split("\n")[1] == "    ssl-default-bind-curves X25519MLKEM768:X25519"
    with pytest.raises(gr.PatchRejected, match="bind line sets its own curves"):
        gr.make_groups_patch(
            HAPROXY + "    bind :8443 ssl crt x.pem curves X25519\n", "f", "haproxy", ["X25519MLKEM768"]
        )
    hostile = HAPROXY + "    ssl-default-bind-curves X25519MLKEM768:X25519\n"
    with pytest.raises(gr.PatchRejected, match="only allowed in the global section"):
        gr.validate_patch(HAPROXY, gr._unified(HAPROXY, hostile, "f"), POLICY, gr.HAPROXY)


def test_caddy_uses_its_own_names_and_never_adds_a_line() -> None:
    new = patched("caddy", CADDY, ["X25519MLKEM768", "X25519", "prime256v1"])
    assert changed(CADDY, new) == ["\t\tcurves x25519mlkem768 x25519 secp256r1"]
    with pytest.raises(gr.PatchRejected, match="upgrade Caddy"):
        gr.make_groups_patch(CADDY.replace("\t\tcurves x25519 secp256r1\n", ""), "f", "caddy", ["X25519MLKEM768"])
    with pytest.raises(gr.PatchRejected, match="Caddy does not support"):
        gr.make_groups_patch(CADDY, "f", "caddy", ["X25519MLKEM768", "X448"])
    assert (
        desired_groups(["x25519 secp256r1 x448"], POLICY.allowed_groups, "caddy") == "X25519MLKEM768:x25519:secp256r1"
    )


def test_postfix_rewrites_appends_and_refuses_continuations() -> None:
    new = patched("postfix", POSTFIX, ["X25519MLKEM768", "X25519", "prime256v1", "secp384r1"])
    assert changed(POSTFIX, new) == ["tls_eecdh_auto_curves = X25519MLKEM768, X25519, prime256v1, secp384r1"]
    bare = "myhostname = mail.example\n"
    assert patched("postfix", bare, ["X25519MLKEM768", "X25519"]).endswith(
        "tls_eecdh_auto_curves = X25519MLKEM768, X25519\n"
    )
    cont = "tls_eecdh_auto_curves = X25519\n    prime256v1\n"
    with pytest.raises(gr.PatchRejected, match="continues onto the next line"):
        patched("postfix", cont, ["X25519MLKEM768", "X25519"])
    with pytest.raises(gr.PatchRejected, match="cannot safely rewrite"):
        gr.make_groups_patch("tls_eecdh_auto_curves = $default_curves\n", "f", "postfix", ["X25519MLKEM768"])


def test_dovecot_appends_and_rewrites() -> None:
    new = patched("dovecot", DOVECOT, ["X25519MLKEM768", "X25519"])
    assert changed(DOVECOT, new) == ["ssl_curve_list = X25519MLKEM768:X25519"]
    again = patched("dovecot", new, ["X25519MLKEM768", "X25519", "prime256v1"])
    assert changed(new, again) == ["ssl_curve_list = X25519MLKEM768:X25519:prime256v1"]


@pytest.mark.parametrize(
    ("kind", "conf", "extra"),
    [
        ("apache", APACHE, "    SSLProtocol all"),
        ("haproxy", HAPROXY, "    tune.ssl.default-dh-param 1024"),
        ("caddy", CADDY, "\treverse_proxy evil.example"),
        ("postfix", POSTFIX, "smtpd_tls_security_level = none"),
        ("dovecot", DOVECOT, "ssl = no"),
    ],
)
def test_only_group_lines_can_change(kind: str, conf: str, extra: str) -> None:
    good = patched(kind, conf, ["X25519MLKEM768", "X25519"])
    with pytest.raises(gr.PatchRejected, match="refused"):
        gr.validate_patch(conf, gr._unified(conf, good + extra + "\n", "f"), POLICY, gr.DIALECTS[kind])
    downgrade = gr.make_groups_patch(good, "f", kind, ["X25519", "prime256v1"] if kind != "caddy" else ["X25519"])
    with pytest.raises(gr.PatchRejected, match="post-quantum"):
        gr.validate_patch(good, downgrade, POLICY, gr.DIALECTS[kind])


def test_managed_server_defaults_and_rules() -> None:
    s = ServiceTarget(
        name="m", host="127.0.0.1", port=25, starttls="smtp", managed={"kind": "postfix", "config_path": "/x"}
    )
    assert isinstance(s.managed, ManagedServer) and s.managed.test_cmd == ["postfix", "check"]
    h = ServiceTarget(name="h", host="127.0.0.1", port=443, managed={"kind": "haproxy", "config_path": "/h.cfg"})
    assert h.managed and h.managed.test_cmd == ["haproxy", "-c", "-f", "/h.cfg"]
    with pytest.raises(ValidationError):
        ServiceTarget(
            name="x", host="127.0.0.1", port=22, protocol="ssh", managed={"kind": "apache", "config_path": "/a"}
        )
    with pytest.raises(ValidationError):
        ServiceTarget(name="x", host="127.0.0.1", port=22, protocol="ssh", starttls="smtp")
    with pytest.raises(ValidationError):
        ServiceTarget(
            name="x",
            host="127.0.0.1",
            port=25,
            managed={"kind": "postfix", "config_path": "/m", "health_url": "http://a/"},
        )
    with pytest.raises(ValidationError):
        ServiceTarget(name="x", host="127.0.0.1", port=443, platform="iis")


def test_diagnosis_from_real_server_output() -> None:
    haproxy = (
        "[ALERT]    (23289) : config : Proxy 'web': unable to set SSL curves list to 'X25519MLKEM768:X25519:P-256' "
        "for bind '127.0.0.1:9443' at [/opt/haproxy.cfg:12].\n[ALERT] : config : Fatal errors found in configuration."
    )
    d = dg.diagnose(haproxy, "Built with OpenSSL version : OpenSSL 3.0.13 30 Jan 2024", server="haproxy")
    assert d.category == "tls_library_too_old" and "HAProxy uses OpenSSL 3.0.13" in d.root_cause
    assert "AWS-LC" in d.recommendation
    assert dg.server_too_old("postfix", "3.8.6") is not None
    assert dg.server_too_old("postfix", "3.10.6") is None and dg.server_too_old("postfix", "") is None


def test_tls_library_check_uses_the_real_library() -> None:
    assert tlslib.locate("apache", explicit="/no/such/libssl.so.3") is None
    found = next(
        (
            c
            for c in (
                "/lib/x86_64-linux-gnu/libssl.so.3",
                "/usr/lib/x86_64-linux-gnu/libssl.so.3",
                "/usr/lib64/libssl.so.3",
            )
            if Path(c).exists()
        ),
        None,
    )
    if found is None:
        pytest.skip("no system libssl.so.3")
    classical = tlslib.check("apache", ["X25519", "prime256v1"], found)
    assert classical.supported is True and classical.version and "OpenSSL" in classical.version
    pq = tlslib.check("apache", ["X25519MLKEM768", "X25519"], found)
    m = re.search(r"(\d+)\.(\d+)", pq.version or "")
    assert m and pq.supported == ((int(m.group(1)), int(m.group(2))) >= (3, 5))
    assert tlslib.check("apache", ["X25519", "nope"], found).supported is False


def test_advice_per_platform() -> None:
    assert "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09" in advice_for("aws-elb", "tls")
    assert "--post-quantum-key-exchange ENABLED" in advice_for("gcp-lb", "tls")
    assert "ECC Curve Order" in advice_for("windows", "tls")
    assert "managed block (kind haproxy)" in advice_for("haproxy", "tls")
    assert "managed block (kind sshd)" in advice_for(None, "ssh")
    assert "set 'platform'" in advice_for(None, "tls")


# ----------------------------------------------------------------- STARTTLS ---


class FakeMailServer(FakeTLSServer):
    """A FakeTLSServer behind an SMTP, IMAP or POP3 STARTTLS dialogue."""

    def __init__(self, mode: str, proto: str, offer: bool = True) -> None:
        super().__init__(mode)
        self.proto, self.offer = proto, offer

    async def _respond(self, reader, writer) -> None:
        if self.proto == "smtp":
            writer.write(b"220 mail.test ESMTP\r\n")
            await reader.readline()
            ext = b"250-mail.test\r\n250-PIPELINING\r\n" + (b"250 STARTTLS\r\n" if self.offer else b"250 8BITMIME\r\n")
            writer.write(ext)
            line = await reader.readline()
            if not line.upper().startswith(b"STARTTLS"):
                return
            writer.write(b"220 2.0.0 Ready to start TLS\r\n")
        elif self.proto == "imap":
            writer.write(b"* OK [CAPABILITY IMAP4rev1 STARTTLS] ready\r\n")
            tag = (await reader.readline()).split()[0]
            writer.write(tag + b" OK Begin TLS negotiation now\r\n")
        else:
            writer.write(b"+OK POP3 ready\r\n")
            await reader.readline()
            writer.write(b"+OK Begin TLS negotiation\r\n")
        await writer.drain()
        await super()._respond(reader, writer)


@pytest.mark.parametrize("proto", ["smtp", "imap", "pop3"])
@pytest.mark.parametrize(("mode", "status"), [("pq", Status.PQ_READY), ("classical", Status.CLASSICAL)])
def test_starttls_scan(proto: str, mode: str, status: Status) -> None:
    with FakeMailServer(mode, proto) as srv:
        t = ServiceTarget(name="m", host="127.0.0.1", port=srv.port, starttls=proto)
        res = asyncio.run(engine.scan_service(t, engine.ScanOptions(timeout=2, fetch_certificate=False)))
    assert res.status == status, res.errors
    assert srv.hellos  # the ClientHello arrived after the STARTTLS dialogue


def test_starttls_not_offered_is_an_error_not_plaintext() -> None:
    with FakeMailServer("pq", "smtp", offer=False) as srv:
        t = ServiceTarget(name="m", host="127.0.0.1", port=srv.port, starttls="smtp")
        res = asyncio.run(engine.scan_service(t, engine.ScanOptions(timeout=2)))
    assert res.status == Status.ERROR and "does not offer STARTTLS" in res.errors[0]
    assert tls_probe.STARTTLS.get() is None  # the setting never leaks out of a scan


# ------------------------------------------------------------- agent runs ---

FAKE_SERVER = r"""#!/usr/bin/env python3
import os, pathlib, sys
conf, state = pathlib.Path(os.environ["FAKE_CONF"]), pathlib.Path(os.environ["FAKE_STATE"])
cmd = sys.argv[1]
if cmd == "version":
    print(os.environ.get("FAKE_VERSION", "1.0")); sys.exit(0)
if cmd == "test":
    sys.exit(0)
if cmd == "reload":
    state.write_text(conf.read_text()); sys.exit(0)
sys.exit(2)
"""


@pytest.fixture
def fake_server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    exe = tmp_path / "srv"
    exe.write_text(FAKE_SERVER)
    exe.chmod(exe.stat().st_mode | stat.S_IXUSR)
    state = tmp_path / "running.conf"
    monkeypatch.setenv("FAKE_STATE", str(state))
    flags = {"health": True}

    async def pq_check(service, timeout=5.0):
        ok = "mlkem768" in state.read_text().lower() if state.exists() else False
        return ok, "negotiated X25519MLKEM768" if ok else "server alert: handshake_failure"

    async def health(service, timeout=5.0):
        return HealthResult(flags["health"], None, "ok" if flags["health"] else "down")

    monkeypatch.setattr(tools_mod, "pq_check", pq_check)
    monkeypatch.setattr(tools_mod, "http_health", health)
    monkeypatch.setattr(tools_mod, "tls_health", health)

    def make(kind: str, conf_text: str, **extra):
        conf = tmp_path / f"{kind}.conf"
        conf.write_text(conf_text)
        state.write_text(conf_text)
        monkeypatch.setenv("FAKE_CONF", str(conf))
        argv = [sys.executable, str(exe)]
        managed = {
            "kind": kind,
            "config_path": str(conf),
            "test_cmd": [*argv, "test"],
            "reload_cmd": [*argv, "reload"],
            "version_cmd": [*argv, "version"],
            **extra,
        }
        svc = ServiceTarget(name="svc", host="127.0.0.1", port=443, managed=managed)
        now = dt.datetime.now(dt.timezone.utc)
        rep = ScanReport(
            scan_id="x",
            started_at=now,
            finished_at=now,
            tool_version="t",
            backend="n",
            results=[ServiceScan(service=svc, status=Status.CLASSICAL)],
        )
        return conf, rep

    return make


def run_rules(ws, cfg, rep, decision=True):
    tb = Toolbox(ws, cfg, rep, verify_timeout=1, approval_waiter=lambda a: ws.approvals.decide(a.id, decision, "priya"))
    return RulesPlanner().run(tb)


@pytest.mark.parametrize(
    ("kind", "conf", "expect"),
    [
        ("haproxy", HAPROXY, "ssl-default-bind-curves X25519MLKEM768:X25519:P-256"),
        ("caddy", CADDY, "curves x25519mlkem768 x25519 secp256r1"),
        ("dovecot", DOVECOT, "ssl_curve_list = X25519MLKEM768:X25519"),
    ],
)
def test_rules_planner_fixes_each_server(ws, cfg, fake_server, monkeypatch, kind, conf, expect) -> None:
    monkeypatch.setattr(tlslib, "check", lambda *a, **k: tlslib.LibraryCheck(True, "/lib", "OpenSSL 3.5.4", "ok"))
    path, rep = fake_server(kind, conf)
    summary = run_rules(ws, cfg, rep)
    assert summary.outcomes["svc"] == "fixed", summary.notes
    assert expect in path.read_text()


def test_old_tls_library_refused_before_anything_changes(ws, cfg, fake_server, monkeypatch) -> None:
    monkeypatch.setattr(
        tlslib, "check", lambda *a, **k: tlslib.LibraryCheck(False, "/lib/libssl.so.3", "OpenSSL 3.0.13", "rejects")
    )
    path, rep = fake_server("apache", APACHE)
    summary = run_rules(ws, cfg, rep)
    assert summary.outcomes["svc"] == "failed" and path.read_text() == APACHE
    assert "Apache uses OpenSSL 3.0.13" in " ".join(summary.notes["svc"])
    assert ws.approvals.list() == []  # nobody was asked to approve a change that cannot work


def test_old_postfix_refused_before_anything_changes(ws, cfg, fake_server, monkeypatch) -> None:
    monkeypatch.setenv("FAKE_VERSION", "3.8.6")
    path, rep = fake_server("postfix", POSTFIX)
    summary = run_rules(ws, cfg, rep)
    assert summary.outcomes["svc"] == "failed" and path.read_text() == POSTFIX
    assert "Postfix 3.10 or later" in " ".join(summary.notes["svc"])


def test_mail_server_verify_uses_classical_handshake(ws, cfg, fake_server, monkeypatch) -> None:
    monkeypatch.setenv("FAKE_VERSION", "3.10.6")
    monkeypatch.setattr(tlslib, "check", lambda *a, **k: tlslib.LibraryCheck(True, "/lib", "OpenSSL 3.5.4", "ok"))
    calls: list[str] = []

    async def health(service, timeout=5.0):
        calls.append("tls")
        return HealthResult(False, None, "a classical-only client failed")

    monkeypatch.setattr(tools_mod, "tls_health", health)
    path, rep = fake_server("postfix", POSTFIX)
    summary = run_rules(ws, cfg, rep)
    assert calls and summary.outcomes["svc"] == "rolled_back" and path.read_text() == POSTFIX
