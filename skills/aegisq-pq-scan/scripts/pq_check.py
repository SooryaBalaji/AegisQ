#!/usr/bin/env python3
"""Scan servers for post-quantum key exchange with AegisQ and print one JSON summary.

Usage: pq_check.py TARGET... [--cbom FILE]
TARGET is host, host:port, "host:port ssh", or "host:port smtp|imap|pop3" (pass the protocol as the next argument).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

MAIL = {"smtp", "imap", "pop3"}


def parse(args: list[str]) -> tuple[list[dict[str, object]], str | None]:
    targets: list[dict[str, object]] = []
    cbom = None
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--cbom":
            if i + 1 >= len(args):
                sys.exit("error: --cbom needs a file name")
            cbom, i = args[i + 1], i + 2
            continue
        if a in ("ssh", "tls", *MAIL):
            if not targets:
                sys.exit(f"error: {a!r} must follow a host")
            targets[-1]["kind"] = a
            i += 1
            continue
        host, _, port = a.rpartition(":") if a.count(":") == 1 else (a, "", "")
        targets.append({"host": host or a, "port": int(port) if port.isdigit() else None, "kind": "tls"})
        i += 1
    if not targets:
        sys.exit(__doc__)
    return targets, cbom


def inventory(targets: list[dict[str, object]]) -> dict[str, object]:
    services = []
    for t in targets:
        kind = str(t["kind"])
        svc: dict[str, object] = {"host": t["host"], "protocol": "ssh" if kind == "ssh" else "tls"}
        default = {"ssh": 22, "smtp": 25, "imap": 143, "pop3": 110}.get(kind, 443)
        svc["port"] = t["port"] or default
        if kind in MAIL:
            svc["starttls"] = kind
        services.append(svc)
    return {"services": services}


def run_aegisq(home: str, *argv: str) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "NO_COLOR": "1"}
    return subprocess.run(
        [sys.executable, "-m", "aegisq.cli", "--home", home, *argv],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )


def main() -> None:
    try:
        import aegisq  # noqa: F401
    except ImportError:
        sys.exit('error: aegisq is not installed: pip install "git+https://github.com/SooryaBalaji/AegisQ"')
    targets, cbom = parse(sys.argv[1:])
    with tempfile.TemporaryDirectory(prefix="aegisq-skill-") as home:
        inv = Path(home) / "targets.json"
        inv.write_text(json.dumps(inventory(targets)))
        scan = run_aegisq(home, "scan", str(inv), "--json")
        if scan.returncode != 0:
            sys.exit(f"error: scan failed: {scan.stderr.strip()[-500:]}")
        report = json.loads(scan.stdout)
        risk = run_aegisq(home, "risk", "--json")
        ranked = json.loads(risk.stdout or "[]") if risk.returncode == 0 else []
        ranks = {r["service"]: (n, r) for n, r in enumerate(ranked, 1)}
        from aegisq.agent.advice import advice_for

        out = []
        for r in report["results"]:
            svc, tls, ssh = r["service"], r.get("tls") or {}, r.get("ssh") or {}
            kx = tls.get("pq_group") if tls.get("pq_ready") else (tls.get("modern_probe") or {}).get("group")
            if ssh:
                kx = ssh.get("negotiated_kex") or ", ".join((ssh.get("kex_algorithms") or [])[:3])
            row: dict[str, object] = {
                "server": f"{svc['host']}:{svc['port']}" + (f" ({svc['starttls']})" if svc.get("starttls") else ""),
                "status": r["status"],
                "key_exchange": kx,
                "risk_rank": ranks.get(svc["name"], (None, None))[0],
            }
            if r["status"] in ("unreachable", "error"):
                row["error"] = (r.get("errors") or [""])[0][:200]
            elif r["status"] != "pq_ready":
                row["fix"] = advice_for(svc.get("platform"), svc["protocol"]).removeprefix("not managed by AegisQ: ")
            out.append(row)
        result: dict[str, object] = {
            "summary": {
                "servers": len(out),
                "pq_ready": sum(1 for o in out if o["status"] == "pq_ready"),
                "reached": sum(1 for o in out if o["status"] not in ("unreachable", "error")),
            },
            "servers": sorted(out, key=lambda o: (o["risk_rank"] is None, o["risk_rank"] or 0)),
        }
        if cbom:
            res = run_aegisq(home, "cbom", "--out", str(Path(cbom).resolve()))
            ok = res.returncode == 0
            result["cbom"] = str(Path(cbom).resolve()) if ok else f"failed: {res.stderr.strip()[-300:]}"
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
