import asyncio
import datetime as dt

import pytest

from aegisq.models import Protocol, ServiceTarget, Status
from aegisq.netutil import Scope
from aegisq.scanner import tls_probe as p
from aegisq.scanner.engine import ScanOptions, scan_all, scan_service
from fakes import make_cert_der, tls_server


def target(port: int, name: str = "svc", **kw) -> ServiceTarget:
    return ServiceTarget(name=name, host="127.0.0.1", port=port, sni="fake.test", **kw)


def run(coro):
    return asyncio.run(coro)


def test_pq_probe_accepts_hybrid() -> None:
    with tls_server("pq") as srv:
        out = run(p.probe_pq("127.0.0.1", srv.port, "fake.test", 3))
    assert out.outcome == "accepted"
    assert out.group == "X25519MLKEM768"
    assert out.server_key_share_bytes == 1120 and out.client_key_share_bytes == 1216
    assert srv.hellos[0].groups == [0x11EC] and srv.hellos[0].sni == "fake.test"


@pytest.mark.parametrize(
    ("mode", "outcome", "detail"),
    [
        ("classical", "rejected", "handshake_failure"),
        ("tls12", "rejected", "protocol_version"),
        ("http", "not_tls", "plaintext HTTP"),
        ("garbage", "not_tls", "non-TLS"),
        ("close", "rejected", "closed"),
        ("hrr", "rejected", "HelloRetryRequest"),
        ("badgroup", "error", "un-offered group"),
    ],
)
def test_pq_probe_negative_outcomes(mode: str, outcome: str, detail: str) -> None:
    with tls_server(mode) as srv:
        out = run(p.probe_pq("127.0.0.1", srv.port, "fake.test", 3))
    assert out.outcome == outcome, out
    assert detail in (out.detail or "")


def test_fragmented_server_hello_is_reassembled() -> None:
    with tls_server("fragment") as srv:
        out = run(p.probe_pq("127.0.0.1", srv.port, None, 3))
    assert out.outcome == "accepted" and out.group == "X25519MLKEM768"


def test_hang_times_out_quickly() -> None:
    with tls_server("hang") as srv:
        out = run(p.probe_pq("127.0.0.1", srv.port, None, 0.5))
    assert out.outcome == "error" and "within" in (out.detail or "")


def test_unreachable() -> None:
    out = run(p.probe_pq("127.0.0.1", 1, None, 1))
    assert out.outcome == "unreachable"


def test_tls12_probe_reads_curve_and_certificate() -> None:
    with tls_server("tls12") as srv:
        r = run(p.probe_tls12("127.0.0.1", srv.port, "fake.test", 3))
    assert r.outcome.outcome == "accepted" and r.key_exchange == "ECDHE x25519"
    assert len(r.certificates) == 1
    info = p.parse_certificate(r.certificates[0])
    assert info.key_type == "EC" and info.curve == "secp256r1" and info.self_signed


def test_parse_certificate_expiry() -> None:
    der = make_cert_der(days=10)
    info = p.parse_certificate(der, now=dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=20))
    assert info.expired and info.days_to_expiry < 0


@pytest.mark.parametrize(
    ("mode", "status"),
    [
        ("pq", Status.PQ_READY),
        ("classical", Status.CLASSICAL),
        ("tls12", Status.TLS12_ONLY),
        ("tls10", Status.LEGACY_TLS),
        ("http", Status.PLAINTEXT),
        ("garbage", Status.ERROR),
    ],
)
def test_engine_status(mode: str, status: Status) -> None:
    with tls_server(mode) as srv:
        res = run(scan_service(target(srv.port), ScanOptions(timeout=2)))
    assert res.status == status, res.errors
    assert res.findings is not None
    if status == Status.PLAINTEXT:
        assert res.tls and res.tls.http_server == "fakehttp/1.0"
    if status == Status.TLS12_ONLY:
        assert res.tls and res.tls.certificate is not None  # recovered from the plaintext TLS 1.2 flight
        assert any("TLS 1.3 unsupported" in f for f in res.findings)
    if status == Status.CLASSICAL:
        assert res.tls and res.tls.modern_probe and res.tls.modern_probe.group == "x25519"


def test_engine_unreachable_and_scope() -> None:
    res = run(scan_service(target(1), ScanOptions(timeout=1)))
    assert res.status == Status.UNREACHABLE
    res = run(scan_service(target(443), ScanOptions(scope=Scope(deny=["127.0.0.0/8"]))))
    assert res.status == Status.ERROR and "scope" in res.errors[0]


def test_scan_all_isolates_failures_and_checks_names() -> None:
    with tls_server("pq") as a, tls_server("classical") as b:
        targets = [target(a.port, "a"), target(b.port, "b"), target(1, "c")]
        seen = []
        rep = run(scan_all(targets, ScanOptions(timeout=1, concurrency=2), progress=seen.append))
    assert [r.status for r in rep.results] == [Status.PQ_READY, Status.CLASSICAL, Status.UNREACHABLE]
    assert len(seen) == 3 and rep.summary()["total"] == 3
    with pytest.raises(ValueError):
        run(scan_all([target(1, "x"), target(2, "x")]))


def test_pq_only_mode_sends_one_handshake() -> None:
    with tls_server("classical") as srv:
        res = run(scan_service(target(srv.port), ScanOptions(timeout=2, pq_only=True)))
    assert res.status == Status.CLASSICAL and len(srv.hellos) == 1


def test_options_validation() -> None:
    for bad in (ScanOptions(timeout=0), ScanOptions(concurrency=0), ScanOptions(tls_backend="nope")):
        with pytest.raises(ValueError):
            bad.validate()


def test_ssh_target_on_http_port_is_plaintext() -> None:
    with tls_server("http") as srv:
        t = ServiceTarget(name="s", host="127.0.0.1", port=srv.port, protocol=Protocol.SSH)
        res = run(scan_service(t, ScanOptions(timeout=2)))
    assert res.status == Status.PLAINTEXT
