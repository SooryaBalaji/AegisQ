#!/usr/bin/env python3
"""Build a realistic AegisQ workspace for load testing, and verify it afterwards.

    seed.py seed   --home DIR --services 2000 --audit 20000 --approvals 200 --out loadtest/out
    seed.py verify --home DIR --out loadtest/out

`seed` writes a synthetic scan (mixed statuses), a long audit log and pending
approvals, and saves the approval IDs for k6. `verify` checks what the load
test must not have broken: every approval decided exactly once, one audit
entry per decision, and an intact hash chain.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import random
import sys
from pathlib import Path

from aegisq.agent.guardrails import sha256_text
from aegisq.models import (
    ProbeOutcome,
    Protocol,
    ScanReport,
    ServiceScan,
    ServiceTarget,
    SSHDetails,
    Status,
    TLSDetails,
)
from aegisq.workspace import Workspace

CATEGORIES = ["health", "payments", "pii", "internal", "marketing", "public", "legal"]
STATUSES = [
    (Status.PQ_READY, 0.25),
    (Status.CLASSICAL, 0.45),
    (Status.TLS12_ONLY, 0.12),
    (Status.LEGACY_TLS, 0.03),
    (Status.PLAINTEXT, 0.05),
    (Status.UNREACHABLE, 0.08),
    (Status.ERROR, 0.02),
]


def synthetic_scan(n: int, rng: random.Random) -> ScanReport:
    now = dt.datetime.now(dt.timezone.utc)
    results = []
    statuses, weights = zip(*STATUSES, strict=True)
    for i in range(n):
        status = rng.choices(statuses, weights)[0]
        ssh = i % 10 == 0
        svc = ServiceTarget(
            name=f"svc-{i:05d}",
            host=f"10.{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255}",
            port=22 if ssh else 443,
            protocol=Protocol.SSH if ssh else Protocol.TLS,
            data_category=rng.choice(CATEGORIES),
        )
        if ssh:
            pq = status == Status.PQ_READY
            det = SSHDetails(
                pq_ready=pq,
                negotiated_kex="mlkem768x25519-sha256" if pq else None,
                kex_algorithms=["mlkem768x25519-sha256", "curve25519-sha256"] if pq else ["curve25519-sha256"],
            )
            results.append(ServiceScan(service=svc, status=status if status.scanned else status, ssh=det))
            continue
        tls = TLSDetails(
            pq_ready=status == Status.PQ_READY,
            pq_group="X25519MLKEM768" if status == Status.PQ_READY else None,
            modern_probe=ProbeOutcome(outcome="accepted", version="TLSv1.3", group="x25519")
            if status in (Status.PQ_READY, Status.CLASSICAL)
            else None,
        )
        findings = [] if status == Status.PQ_READY else ["Key exchange is classical-only."]
        results.append(ServiceScan(service=svc, status=status, tls=tls, findings=findings))
    return ScanReport(
        scan_id="loadtest", started_at=now, finished_at=now, tool_version="loadtest", backend="synthetic",
        results=results,
    )  # fmt: skip


def seed(args: argparse.Namespace) -> None:
    rng = random.Random(args.seed)
    home = Path(args.home)
    if home.exists() and any(home.iterdir()):
        sys.exit(f"{home} is not empty; use a fresh directory")
    ws = Workspace(home)
    ws.save_scan(synthetic_scan(args.services, rng))
    for i in range(args.audit):
        ws.audit.append("service.scanned", {"service": f"svc-{i % args.services:05d}", "status": "classical"})
    ids = []
    for i in range(args.approvals):
        diff = f"--- a/site.conf\n+++ b/site.conf\n@@ -1 +1 @@\n-    ssl_ecdh_curve X25519;\n+    ssl_ecdh_curve X25519MLKEM768:X25519; # {i}\n"
        a = ws.approvals.create(f"svc-{i:05d}", f"p{i}", diff, sha256_text(diff), "load test", "agent", 7200)
        ids.append(a.id)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "approvals.json").write_text(json.dumps(ids))
    (out / "seed.json").write_text(json.dumps(vars(args)))
    print(f"seeded {home}: {args.services} services, {args.audit} audit entries, {args.approvals} approvals")


def verify(args: argparse.Namespace) -> None:
    ws = Workspace(Path(args.home))
    ids = json.loads((Path(args.out) / "approvals.json").read_text())
    problems = []
    decided = {}
    for aid in ids:
        a = ws.approvals.get(aid)
        if a is None or a.status not in ("approved", "rejected"):
            problems.append(f"approval {aid} is {a.status if a else 'missing'}, expected decided")
        else:
            decided[aid] = a.decided_by
    events = [e for e in ws.audit.entries() if e["event"] == "approval.decided"]
    per_id: dict[str, int] = {}
    for e in events:
        per_id[e["data"]["approval_id"]] = per_id.get(e["data"]["approval_id"], 0) + 1
    doubles = {k: v for k, v in per_id.items() if v != 1}
    if doubles:
        problems.append(f"{len(doubles)} approvals recorded more than once in the audit log: {list(doubles)[:5]}")
    for aid in ids:
        if aid in decided and per_id.get(aid) != 1:
            problems.append(f"approval {aid} has {per_id.get(aid, 0)} audit entries, expected 1")
            break
    for e in events:
        if e["actor"] != decided.get(e["data"]["approval_id"], e["actor"]):
            problems.append(f"audit actor {e['actor']} differs from the stored decider for {e['data']['approval_id']}")
            break
    res = ws.audit.verify()
    if not res.ok:
        problems.append(f"audit chain broken: {res.error}")
    print(f"approvals decided: {len(decided)}/{len(ids)}; audit decision entries: {len(events)}; "
          f"audit chain: {'intact' if res.ok else 'BROKEN'} ({res.entries} entries)")  # fmt: skip
    if problems:
        for p in problems[:20]:
            print(f"FAIL: {p}")
        sys.exit(1)
    print("OK: every approval decided exactly once; audit chain intact")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("seed")
    s.add_argument("--home", required=True)
    s.add_argument("--out", default="loadtest/out")
    s.add_argument("--services", type=int, default=2000)
    s.add_argument("--audit", type=int, default=20000)
    s.add_argument("--approvals", type=int, default=200)
    s.add_argument("--seed", type=int, default=2026)
    v = sub.add_parser("verify")
    v.add_argument("--home", required=True)
    v.add_argument("--out", default="loadtest/out")
    args = ap.parse_args()
    seed(args) if args.cmd == "seed" else verify(args)


if __name__ == "__main__":
    main()
