import asyncio
import sys
import threading
import time
import zipfile
from pathlib import Path

import pytest

from aegisq import tranco
from aegisq.agent.diagnose import diagnose, openssl_version_from
from aegisq.benchmark import _stats, bench_native
from aegisq.models import ServiceScan, ServiceTarget, Status
from aegisq.proc import run_async, run_sync
from fakes import tls_server


def test_proc_timeout_and_missing_binary() -> None:
    py = sys.executable
    r = run_sync([py, "-c", "import time; time.sleep(5)"], timeout=0.5)
    assert r.timed_out and not r.ok
    assert run_sync(["/nonexistent/bin"], timeout=1).error
    assert run_sync([py, "-c", "print('hi'); raise SystemExit(3)"], timeout=10).returncode == 3
    # a child that spawns its own child: the timeout must kill the whole group, and quickly
    grandchild = "import subprocess, sys, time; subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)']); time.sleep(30)"
    t0 = time.monotonic()
    r = asyncio.run(run_async([py, "-c", grandchild], timeout=0.5))
    assert r.timed_out and time.monotonic() - t0 < 10
    with pytest.raises(ValueError):
        run_sync([], timeout=1)
    with pytest.raises(ValueError):
        run_sync(["echo", "a\x00b"], timeout=1)


def test_diagnose() -> None:
    d = diagnose(
        'nginx: [emerg] SSL_CTX_set1_curves_list("X25519MLKEM768:X25519") failed',
        "built with OpenSSL 3.0.9 30 May 2023 (running with OpenSSL 3.0.11 19 Sep 2023)",
    )
    assert d.category == "tls_library_too_old" and d.openssl_version == "3.0.11"
    assert "3.5" in d.root_cause and "Upgrade" in d.recommendation
    assert diagnose('unknown directive "foo"').category == "syntax"
    assert diagnose("open() failed (13: Permission denied)").category == "permission"
    assert diagnose("???").category == "unknown"
    assert openssl_version_from("built with OpenSSL 3.5.5 27 Jan 2026") == (3, 5, 5)


def test_benchmark_native() -> None:
    with tls_server("pq") as srv:
        r = asyncio.run(bench_native("127.0.0.1", srv.port, None, "X25519MLKEM768", 20))
        c = asyncio.run(bench_native("127.0.0.1", srv.port, None, "x25519", 5))
    assert r["failures"] == 0 and r["p50_ms"] is not None and r["server_key_share_bytes"] == 1120
    assert c["client_key_share_bytes"] == 32
    assert _stats([])["p50_ms"] is None


def test_tranco_load_and_sample(tmp_path: Path) -> None:
    rows = "\n".join(f"{i},site{i}.example" for i in range(1, 2001))
    csv_path = tmp_path / "list.csv"
    csv_path.write_text("rank,domain\n" + rows)
    zpath = tmp_path / "list.zip"
    with zipfile.ZipFile(zpath, "w") as z:
        z.writestr("top-1m.csv", rows)
    assert tranco.load_list(csv_path) == tranco.load_list(zpath)
    head, tail = tranco.sample(tranco.load_list(csv_path), top=10, tail=20, lo=1000, hi=2000, seed=1)
    assert [r for r, _ in head] == list(range(1, 11))
    assert all(1000 <= r <= 2000 for r, _ in tail) and len(tail) == 20
    assert tail == tranco.sample(tranco.load_list(csv_path), 10, 20, 1000, 2000, seed=1)[1]  # reproducible
    (tmp_path / "empty.csv").write_text("nothing here")
    with pytest.raises(ValueError):
        tranco.load_list(tmp_path / "empty.csv")


def test_tranco_group_stats() -> None:
    t = ServiceTarget(name="x", host="a.example", port=443)
    res = [ServiceScan(service=t, status=s) for s in (Status.PQ_READY, Status.CLASSICAL, Status.UNREACHABLE)]
    g = tranco._group_stats("Top", res)
    assert (g["sites"], g["reachable"], g["pq_ready"], g["pq_pct"], g["failed_to_connect"]) == (3, 2, 1, 50.0, 1)


def test_realworld_refuses_private_space(tmp_path: Path) -> None:
    p = tmp_path / "l.csv"
    p.write_text("1,localhost\n2,bad..name\n")
    summary, results = tranco.run_realworld(p, top=2, tail=0, timeout=1)
    assert [r.status for r in results] == [Status.ERROR]  # localhost -> 127.0.0.1 is denied; bad name skipped
    assert "scope" in results[0].errors[0]
    assert summary["groups"][0]["reachable"] == 0


def test_openssl_backend_output_parsing(monkeypatch) -> None:
    """Outputs captured from OpenSSL 3.5.5 s_client against the demo fleet."""
    from aegisq.proc import CmdResult
    from aegisq.scanner import external

    samples = {
        "accepted": "CONNECTED(00000003)\nNegotiated TLS1.3 group: X25519MLKEM768\nProtocol: TLSv1.3\n",
        "rejected": "error:0A000410:SSL routines:ssl3_read_bytes:ssl/tls alert handshake failure:../ssl/record/"
        "rec_layer_s3.c:918:SSL alert number 40\nCONNECTED(00000003)\nNegotiated TLS1.3 group: <NULL>\n",
        "not_tls": "Connecting to 127.0.0.1\nerror:0A0000C6:SSL routines:tls_get_more_records:packet length too long\n"
        "error:0A000139:SSL routines::record layer failure\nCONNECTED(00000003)\n",
        "unreachable": "connect:errno=111\n",
    }
    monkeypatch.setattr(external, "require_openssl_mlkem", lambda b="openssl": "openssl")
    for expected, text in samples.items():

        async def fake(argv, timeout, stdin_data=None, _t=text):
            return CmdResult(argv, 1, "", _t)

        monkeypatch.setattr(external, "run_async", fake)
        out = asyncio.run(external.openssl_pq_probe("127.0.0.1", 443, "a.example", 5))
        assert out.outcome == expected, (expected, out)
    assert asyncio.run(external.openssl_pq_probe("127.0.0.1", 443, None, 5)).outcome == "unreachable"
    with pytest.raises(Exception):
        asyncio.run(external.openssl_pq_probe("-oops", 443, None, 5))


def test_filelock_is_exclusive_across_handles(tmp_path: Path) -> None:
    from aegisq.filelock import FileLock, LockHeld

    path = tmp_path / "x.lock"
    with FileLock(path):
        with pytest.raises(LockHeld):
            FileLock(path, blocking=False).acquire()
    with FileLock(path, blocking=False):  # free again once released
        pass
    released = threading.Event()

    def holder() -> None:
        with FileLock(path):
            time.sleep(0.3)
        released.set()

    t = threading.Thread(target=holder)
    t.start()
    time.sleep(0.05)
    with FileLock(path):  # blocking acquire waits for the holder
        assert released.is_set()
    t.join()
