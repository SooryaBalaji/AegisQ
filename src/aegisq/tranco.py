"""Real-world adoption gap: top Tranco sites versus the long tail.

Method: take the top N and a seeded random N from ranks 100,000-1,000,000,
run only the TLS post-quantum probe on port 443 (one handshake per site,
exactly what a browser does), and report the share ready in each group, how
many failed to connect, and the total time. Read-only by construction.
"""

from __future__ import annotations

import asyncio
import csv
import io
import random
import time
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

from aegisq.models import ServiceScan, ServiceTarget, Status
from aegisq.netutil import Scope, TargetError, validate_host
from aegisq.scanner.engine import ScanOptions, scan_all

TRANCO_URL = "https://tranco-list.eu/top-1m.csv.zip"
# Never let a public-internet scan wander into private address space via DNS.
PRIVATE_RANGES = [
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
]


def download(dest: Path, url: str = TRANCO_URL, timeout: float = 60) -> Path:
    req = urllib.request.Request(url, headers={"User-Agent": "aegisq-research-scan"})  # noqa: S310
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 - fixed https URL
        data = resp.read(64 * 1024 * 1024)
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(data)
    return dest


def load_list(path: Path) -> list[tuple[int, str]]:
    raw = path.read_bytes()
    if raw[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            name = next(n for n in z.namelist() if n.endswith(".csv"))
            raw = z.read(name)
    rows: list[tuple[int, str]] = []
    for rec in csv.reader(io.StringIO(raw.decode("utf-8", "replace"))):
        if len(rec) < 2 or not rec[0].strip().isdigit():
            continue
        rows.append((int(rec[0]), rec[1].strip()))
    if not rows:
        raise ValueError(f"{path} contains no rank,domain rows")
    return rows


def sample(
    rows: list[tuple[int, str]],
    top: int = 500,
    tail: int = 500,
    lo: int = 100_000,
    hi: int = 1_000_000,
    seed: int = 2026,
) -> tuple[list[tuple[int, str]], list[tuple[int, str]]]:
    rows = sorted(rows)
    head = rows[:top]
    pool = [r for r in rows if lo <= r[0] <= hi]
    rng = random.Random(seed)
    tail_rows = sorted(rng.sample(pool, min(tail, len(pool))))
    return head, tail_rows


def _targets(rows: list[tuple[int, str]], group: str) -> list[ServiceTarget]:
    out = []
    for rank, domain in rows:
        try:
            host = validate_host(domain)
        except TargetError:
            continue
        out.append(ServiceTarget(name=f"{group}-{rank}", host=host, port=443, sni=host, tags=[group]))
    return out


def _group_stats(label: str, results: list[ServiceScan]) -> dict[str, Any]:
    reachable = [r for r in results if r.status.scanned]
    ready = [r for r in reachable if r.status == Status.PQ_READY]
    return {
        "label": label,
        "sites": len(results),
        "reachable": len(reachable),
        "failed_to_connect": len(results) - len(reachable),
        "pq_ready": len(ready),
        "pq_pct": round(100 * len(ready) / len(reachable), 1) if reachable else 0.0,
        "groups_seen": sorted({r.tls.pq_group for r in ready if r.tls and r.tls.pq_group}),
    }


def run_realworld(
    list_path: Path,
    top: int = 500,
    tail: int = 500,
    seed: int = 2026,
    timeout: float = 5.0,
    concurrency: int = 50,
    list_id: str = "unknown",
) -> tuple[dict[str, Any], list[ServiceScan]]:
    rows = load_list(list_path)
    head, tail_rows = sample(rows, top, tail, seed=seed)
    targets = _targets(head, "top") + _targets(tail_rows, "tail")
    opts = ScanOptions(
        timeout=timeout,
        concurrency=concurrency,
        pq_only=True,
        fetch_certificate=False,
        legacy_protocols=False,
        scope=Scope(deny=PRIVATE_RANGES),
    )
    t0 = time.perf_counter()
    report = asyncio.run(scan_all(targets, opts))
    duration = round(time.perf_counter() - t0, 1)
    top_res = [r for r in report.results if "top" in r.service.tags]
    tail_res = [r for r in report.results if "tail" in r.service.tags]
    summary = {
        "list_id": list_id,
        "list_file": list_path.name,
        "seed": seed,
        "method": "one TLS 1.3 handshake per site offering only X25519MLKEM768 on port 443",
        "groups": [_group_stats(f"Top {top}", top_res), _group_stats(f"Random {tail} from ranks 100k-1M", tail_res)],
        "duration_s": duration,
        "scan_id": report.scan_id,
    }
    return summary, report.results
