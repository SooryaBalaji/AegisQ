"""Handshake cost of the migration: measured, never assumed.

``curl`` mode (the design's method) times full TLS handshakes,
time_appconnect - time_connect, with a curl built on OpenSSL 3.5+.
``native`` mode works with any local OpenSSL: it times ClientHello ->
ServerHello, which includes the server's key generation / encapsulation but
not certificate verification. Both report p50 and p99, and the byte sizes are
taken from the probe itself.
"""

from __future__ import annotations

import asyncio
import re
import shutil
import time
from typing import Any
from urllib.parse import urlsplit

import numpy as np

from aegisq.crypto_registry import X25519, X25519MLKEM768, group_by_name
from aegisq.netutil import resolve, validate_host
from aegisq.proc import run_sync
from aegisq.scanner import tls_probe
from aegisq.scanner import tls_wire as w

CAVEAT = (
    "Measured against the target as configured; on localhost there is no network delay, so these numbers are "
    "computation cost only. Real-world latency also depends on round trips and packet loss."
)
TYPICAL_MSS = 1460  # TCP payload in a 1,500-byte Ethernet packet


def curl_supports_mlkem(curl: str = "curl") -> bool:
    exe = shutil.which(curl)
    if not exe:
        return False
    out = run_sync([exe, "-V"], timeout=10).stdout
    m = re.search(r"OpenSSL/(\d+)\.(\d+)", out)
    return bool(m and (int(m.group(1)), int(m.group(2))) >= (3, 5))


def _stats(samples: list[float]) -> dict[str, float | None]:
    if not samples:
        return {"p50_ms": None, "p99_ms": None, "mean_ms": None}
    a = np.array(samples) * 1000
    return {
        "p50_ms": round(float(np.percentile(a, 50)), 3),
        "p99_ms": round(float(np.percentile(a, 99)), 3),
        "mean_ms": round(float(a.mean()), 3),
    }


def bench_curl(url: str, group: str, n: int, curl: str = "curl", timeout: float = 10.0) -> dict[str, Any]:
    exe = shutil.which(curl) or curl
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname:
        raise ValueError("benchmark URL must be https://host[:port]/")
    validate_host(parts.hostname)
    if not re.fullmatch(r"[A-Za-z0-9_]+", group):
        raise ValueError("bad group name")
    check = run_sync([exe, "-kv", "-o", "/dev/null", "--curves", group, url], timeout=timeout)
    negotiated = None
    m = re.search(r"SSL connection using (\S+) / (\S+) / (\S+)", check.output)
    if m:
        negotiated = m.group(3)
    samples: list[float] = []
    failures = 0
    fmt = "%{time_connect} %{time_appconnect}\n"
    for _ in range(n):
        res = run_sync([exe, "-ks", "-o", "/dev/null", "--curves", group, "-w", fmt, url], timeout=timeout)
        try:
            tc, ta = (float(x) for x in res.stdout.split())
            if not res.ok or ta <= 0:
                raise ValueError
            samples.append(ta - tc)
        except ValueError:
            failures += 1
    return {
        "label": f"{group} (full handshake, curl)",
        "group": group,
        "negotiated": negotiated,
        "n": n,
        "failures": failures,
        **_stats(samples),
    }


async def bench_native(
    host: str, port: int, sni: str | None, group: str, n: int, timeout: float = 5.0
) -> dict[str, Any]:
    info = group_by_name(group)
    if info is None:
        raise ValueError(f"unknown group {group}")
    ip = (await resolve(host, port, timeout))[0]
    samples: list[float] = []
    failures = 0
    hello_bytes = share_c = share_s = None
    for _ in range(n):
        built = w.build_client_hello(
            w.ClientHelloSpec(sni, (0x0304,), (0x1301, 0x1302, 0x1303), (info.code,), (info.code,))
        )
        t0 = time.perf_counter()
        ex = await tls_probe.exchange(ip, port, built.record, timeout)
        dt_s = time.perf_counter() - t0
        sh = ex.server_hello
        if ex.kind == "server_hello" and sh and sh.key_share_group == info.code and not sh.hello_retry:
            samples.append(dt_s)
            hello_bytes, share_c, share_s = len(built.record), built.key_share_bytes, sh.key_share_len
        else:
            failures += 1
    return {
        "label": f"{info.name} (to ServerHello, native)",
        "group": info.name,
        "negotiated": info.name if samples else None,
        "n": n,
        "failures": failures,
        "client_hello_bytes": hello_bytes,
        "client_key_share_bytes": share_c,
        "server_key_share_bytes": share_s,
        **_stats(samples),
    }


def _annotate(r: dict[str, Any]) -> dict[str, Any]:
    if r["n"] and r["failures"] == r["n"]:
        r["note"] = f"every handshake failed: the server does not accept {r['group']}"
    return r


def run_benchmark(url: str, n: int = 1000, method: str = "auto", curl: str = "curl") -> dict[str, Any]:
    parts = urlsplit(url)
    host = parts.hostname or ""
    port = parts.port or 443
    if method == "auto":
        method = "curl" if curl_supports_mlkem(curl) else "native"
    groups = [X25519MLKEM768.name, "X25519" if method == "curl" else X25519.name]
    results = []
    for g in groups:
        if method == "curl":
            results.append(_annotate(bench_curl(url, g, n, curl)))
        else:
            results.append(_annotate(asyncio.run(bench_native(host, port, host, g, n))))
    # Wire sizes always come from a native probe, so they are measured too.
    sizes = [asyncio.run(bench_native(host, port, host, g, 3)) for g in (X25519MLKEM768.name, X25519.name)]
    pq, classic = sizes
    size_info: dict[str, Any] = {
        "client_key_share": {"pq": pq["client_key_share_bytes"], "classical": classic["client_key_share_bytes"]},
        "server_key_share": {"pq": pq["server_key_share_bytes"], "classical": classic["server_key_share_bytes"]},
        "client_hello": {"pq": pq["client_hello_bytes"], "classical": classic["client_hello_bytes"]},
    }
    if pq["client_key_share_bytes"] and classic["client_key_share_bytes"]:
        extra = (pq["client_key_share_bytes"] - classic["client_key_share_bytes"]) + (
            (pq["server_key_share_bytes"] or 0) - (classic["server_key_share_bytes"] or 0)
        )
        size_info["extra_bytes_per_handshake"] = extra
    ch = pq["client_hello_bytes"] or 0
    size_info["packet_split"] = f"PQ ClientHello is {ch} bytes; " + (
        "larger than one TCP segment (MSS 1460), so it is split across two segments - this has broken some "
        "older middleboxes."
        if ch > TYPICAL_MSS
        else "AegisQ's minimal hello fits one segment, but browser hellos with GREASE and more extensions exceed "
        "1,460 bytes and are split across two TCP segments - this has broken some older middleboxes."
    )
    return {
        "url": url,
        "method": method,
        "results": results,
        "sizes": size_info,
        "caveat": CAVEAT,
        "measured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
