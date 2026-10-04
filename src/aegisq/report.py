"""Migration report, built from the audit log and the latest scan (Markdown and self-contained HTML)."""

from __future__ import annotations

import datetime as dt
from collections import defaultdict
from pathlib import Path
from typing import Any

from jinja2 import Environment, PackageLoader, select_autoescape

from aegisq import __version__
from aegisq.config import AegisQConfig
from aegisq.risk import RESOURCE_ESTIMATE_NOTE, RESOURCE_ESTIMATES, rank
from aegisq.workspace import Workspace, atomic_write

MIGRATION_EVENTS = (
    "patch.proposed",
    "patch.rejected_by_guardrail",
    "approval.outcome",
    "patch.applied",
    "patch.test_failed",
    "patch.reload_failed",
    "patch.refused_drift",
    "patch.refused_no_approval",
    "service.verified",
    "service.verify_failed",
    "patch.rolled_back",
    "agent.safety_rollback",
)


def collect(ws: Workspace, cfg: AegisQConfig, z: float | None = None) -> dict[str, Any]:
    from aegisq.agent.tools import apply_facts

    verify = ws.audit.verify()
    report = ws.latest_scan()
    data: dict[str, Any] = {
        "generated_at": dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "version": __version__,
        "audit": {"ok": verify.ok, "entries": verify.entries, "error": verify.error, "keyed": verify.keyed},
        "z": cfg.risk.z_years if z is None else z,
        "scan": None,
        "ranking": [],
        "findings": {},
        "timeline": {},
        "outcomes": {},
        "estimates": RESOURCE_ESTIMATES,
        "estimate_note": RESOURCE_ESTIMATE_NOTE,
        "realworld": ws.load_json("realworld/latest.json"),
        "entropy": ws.load_json("entropy/latest-analysis.json"),
        "benchmark": ws.load_json("benchmarks/latest.json"),
        "cbom": ws.load_json("cbom-summary.json"),
    }
    if report:
        summary = report.summary()
        scanned = summary["total"] - summary["unreachable"] - summary["error"]
        scans = apply_facts(report.results, ws)
        ranking = rank(scans, cfg.risk, data["z"])
        data["scan"] = {
            "id": report.scan_id,
            "finished": report.finished_at.strftime("%Y-%m-%d %H:%M UTC"),
            "summary": summary,
            "scanned": scanned,
            "ready_pct": round(100 * summary["pq_ready"] / scanned, 1) if scanned else 0.0,
            "at_risk": sum(1 for r in ranking if r.at_risk),
        }
        data["ranking"] = [r.to_dict() for r in ranking]
        data["findings"] = {r.service.name: r.findings for r in report.results if r.findings}

    timeline: dict[str, list[dict[str, Any]]] = defaultdict(list)
    outcomes: dict[str, str] = {}
    for e in ws.audit.entries():
        if e["event"] not in MIGRATION_EVENTS:
            continue
        d = e.get("data", {})
        svc = d.get("service") or ", ".join(d.get("services", [])) or "-"
        timeline[svc].append(
            {
                "ts": e["ts"][:19].replace("T", " "),
                "event": e["event"],
                "actor": e["actor"],
                "text": _describe(e["event"], d),
            }
        )
        outcome = {
            "service.verified": "fixed",
            "patch.test_failed": "failed (rolled back)",
            "patch.reload_failed": "failed (rolled back)",
            "patch.rolled_back": "rolled back",
        }.get(e["event"])
        if e["event"] == "approval.outcome" and d.get("status") != "approved":
            outcome = f"not applied ({d.get('status')})"
        if outcome:
            outcomes[svc] = outcome
    data["timeline"] = dict(timeline)
    data["outcomes"] = outcomes
    return data


def _describe(event: str, d: dict[str, Any]) -> str:
    if event == "patch.proposed":
        return (
            "Proposed: "
            + " ".join(f"`{c}`" for c in d.get("changes", []))
            + (f" (branch {d['branch']})" if d.get("branch") else "")
        )
    if event == "approval.outcome":
        who = f" by {d['decided_by']}" if d.get("decided_by") else ""
        why = f": {d['reason']}" if d.get("reason") else ""
        return f"Approval {d.get('status')}{who}{why}"
    if event == "patch.applied":
        return "Applied; config test passed; reloaded"
    if event == "patch.test_failed":
        diag = d.get("diagnosis") or {}
        return (
            f"Config test FAILED, previous config restored. Root cause: {diag.get('root_cause')} "
            f"Recommendation: {diag.get('recommendation')}"
        )
    if event == "patch.reload_failed":
        return "Reload failed, previous config restored"
    if event == "service.verified":
        return f"Verified: {d.get('pq_detail')}; health {d.get('health_detail')}"
    if event == "service.verify_failed":
        return f"Verification failed: PQ={d.get('pq_detail')}; health={d.get('health_detail')}"
    if event == "patch.rolled_back":
        return f"Rolled back to {d.get('backup')} ({d.get('reason')})"
    if event == "patch.rejected_by_guardrail":
        return f"Guardrail refused patch: {d.get('reason')}"
    if event == "patch.refused_drift":
        return "Refused: live config changed since proposal"
    if event == "patch.refused_no_approval":
        return f"Refused: no valid approval ({d.get('approval_status')})"
    if event == "agent.safety_rollback":
        return "Safety net rolled back unverified changes"
    return event


def _env() -> Environment:
    return Environment(
        loader=PackageLoader("aegisq", "templates"),
        autoescape=select_autoescape(enabled_extensions=("html",), default_for_string=False),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def render(data: dict[str, Any], fmt: str) -> str:
    name = {"md": "report.md.j2", "html": "report.html"}[fmt]
    return _env().get_template(name).render(**data)


def generate_report(ws: Workspace, cfg: AegisQConfig, z: float | None = None) -> list[Path]:
    data = collect(ws, cfg, z)
    paths = []
    for fmt in ("md", "html"):
        p = ws.home / "reports" / f"migration-report.{fmt}"
        atomic_write(p, render(data, fmt))
        paths.append(p)
    ws.audit.append("report.generated", {"files": [p.name for p in paths], "audit_ok": data["audit"]["ok"]})
    return paths
