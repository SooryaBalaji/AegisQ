"""Owner brief: Gemma 4 writes the ticket for the team that owns a server, and code checks every sentence.

AegisQ collects numbered facts about one server (scan result, risk, findings, what the fixer did, claim-check
verdicts, the vendor-documented fix). Gemma turns them into a short brief in plain language for the owning
team. A sentence is kept only if it cites at least one fact and every technical token in it (versions, numbers,
algorithm and group names, hosts, ports, anything in backticks) appears in the facts it cites. Everything else
is removed and listed. The fix itself is never written by the model: it is the ``advice.py`` text, verbatim.
"""

from __future__ import annotations

import datetime as dt
import json
import re
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from typing import Any

from aegisq.agent.advice import advice_for
from aegisq.config import RiskConfig
from aegisq.models import ServiceScan
from aegisq.risk import score_service
from aegisq.workspace import Workspace

Post = Callable[[dict[str, Any]], dict[str, Any]]

MAX_SENTENCES = 8
_CITE_RE = re.compile(r"\[(F\d+(?:\s*,\s*F\d+)*)\]")
_TOKEN_RE = re.compile(
    r"`[^`]+`"
    r"|\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b"
    r"|\b[A-Za-z][\w-]*\d[\w.-]*\b"
    r"|\b\d+(?:\.\d+)*\b",
    re.I,
)
_STATUS = {
    "pq_ready": "post-quantum ready",
    "classical": "classical key exchange only (not post-quantum)",
    "tls12_only": "TLS 1.2 only, so it cannot use post-quantum key exchange",
    "legacy_tls": "still accepts legacy TLS",
    "plaintext": "unencrypted",
    "unreachable": "unreachable during the scan",
    "error": "scan error",
}
_EVENTS = {
    "patch.test_failed": "AegisQ's change failed the server's config test and the old config was restored",
    "patch.reload_failed": "the server failed to reload with AegisQ's change and the old config was restored",
    "patch.rolled_back": "AegisQ rolled back its change",
    "patch.refused_server_version": "AegisQ refused to change it because the server version is too old",
    "patch.rejected_by_guardrail": "a guardrail refused a proposed change",
    "service.verify_failed": "a change was applied but the outside check did not see post-quantum key exchange",
    "service.verified": "AegisQ's change was verified from outside",
    "tls_library.checked": "the TLS library was checked before approval",
}

PROMPT = """You write a short brief for the team that owns one server. They are busy and not crypto experts.
You get numbered facts F1, F2, ... Use only those facts. Every sentence must end with the facts it relies on,
like [F2] or [F1, F4]. Copy versions, numbers, algorithm names, hosts and ports exactly as the facts write them.
Do not write commands, configuration lines or fix steps: the fix is attached separately, word for word.
Say what is wrong, why it matters for their data, how urgent it is, and what already happened.
Reply with only JSON: {"sentences": ["...", "..."]} with at most 8 sentences."""


@dataclass
class Brief:
    service: str
    written_by: str
    created_at: str
    facts: list[str]
    sentences: list[dict[str, Any]] = field(default_factory=list)
    removed: list[dict[str, str]] = field(default_factory=list)
    fix: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def markdown(self) -> str:
        lines = [f"# Post-quantum brief: {self.service}", ""]
        lines += [f"{s['text']} [{', '.join(s['cites'])}]" for s in self.sentences]
        lines += ["", "## Fix (vendor documentation, not written by AI)", "", self.fix or "No change needed.", ""]
        lines += ["## Facts", ""] + [f"- F{i}: {f}" for i, f in enumerate(self.facts, 1)]
        if self.removed:
            lines += ["", "## Removed by the fact check", ""]
            lines += [f"- {r['text']} ({r['reason']})" for r in self.removed]
        lines += [
            "",
            f"_Written by {self.written_by} on {self.created_at[:10]}. Every sentence cites the facts above._",
        ]
        return "\n".join(lines) + "\n"


def collect_facts(ws: Workspace, scan: ServiceScan, risk: RiskConfig) -> tuple[list[str], str]:
    svc = scan.service
    r = score_service(scan, risk)
    status = _STATUS.get(scan.status.value, scan.status.value)
    facts = [f"{svc.name} is {svc.endpoint} ({svc.protocol.value}); scan result: {status}."]
    if scan.tls and scan.tls.pq_ready:
        facts.append(f"It negotiated {scan.tls.pq_group}.")
    elif scan.tls and scan.tls.modern_probe and scan.tls.modern_probe.group:
        facts.append(f"A modern client gets {scan.tls.modern_probe.version} with {scan.tls.modern_probe.group}.")
    if scan.ssh:
        facts.append(f"It offers SSH key exchange {', '.join(scan.ssh.kex_algorithms[:4]) or 'none'}.")
    facts.append(
        f"It handles {svc.data_category} data"
        + (f" and is owned by {svc.owner}" if svc.owner else "")
        + f"; that data must stay secret for {r.x_retention:g} years."
    )
    if scan.status.scanned and not scan.pq_ready:
        facts.append(
            f"Risk is {r.severity}: {r.x_retention:g} years of secrecy plus {r.y_migration:g} years to migrate, "
            f"against a quantum estimate of {r.z_quantum:g} years ({r.y_reason})."
        )
    for k, v in sorted(svc.stack.items()):
        facts.append(
            f"Its TLS library is OpenSSL {v}."
            if k == "openssl"
            else f"Upgrade blocker: {v}."
            if k == "blocker"
            else f"Its {k} is {v}."
        )
    facts += [f"Finding: {f}" for f in scan.findings[:5]]
    for e in ws.audit.entries():
        d = e.get("data") or {}
        if d.get("service") == svc.name and e["event"] in _EVENTS:
            extra = d.get("detail") or d.get("reason") or (d.get("diagnosis") or {}).get("root_cause") or ""
            facts.append(f"{e['ts'][:10]}: {_EVENTS[e['event']]}" + (f": {str(extra)[:160]}" if extra else "."))
    for p in sorted((ws.home / "claims").glob("chk-*.json")):
        data = ws.load_json(f"claims/{p.name}") or {}
        for c in data.get("checks") or []:
            if str(c.get("endpoint", "")).split(":")[0].strip("[]") == svc.host:
                facts.append(
                    f"A shared document claimed: {c['claim']}. The handshake showed: {c['observed']} ({c['verdict']})."
                )
    facts = list(dict.fromkeys(facts))[:20]
    if scan.pq_ready:
        fix = ""
    elif svc.managed and "upgrade first" in r.y_reason:
        fix = "Upgrade first: " + advice_for(
            "openssh" if svc.managed.kind == "sshd" else svc.managed.kind, svc.protocol.value
        ).removeprefix("not managed by AegisQ: ")
        fix = fix.split(" Or add a managed block")[0]
    elif svc.managed:
        fix = "AegisQ manages this server: run Scan and fix, review the proposed one-line change and approve it."
    else:
        fix = advice_for(svc.platform, svc.protocol.value).removeprefix("not managed by AegisQ: ")
    return facts, fix


def check_sentence(text: str, facts: list[str]) -> tuple[str, list[str]] | str:
    """(clean text, cites) if the sentence is supported, else the reason it was removed."""
    m = _CITE_RE.findall(text)
    if not m:
        return "no citation"
    cites = sorted({c.strip() for group in m for c in group.split(",")}, key=lambda c: int(c[1:]))
    if any(not 1 <= int(c[1:]) <= len(facts) for c in cites):
        return "cites a fact that does not exist"
    body = _CITE_RE.sub("", text).strip()
    body = re.sub(r"\s+([.,;:!?])", r"\1", body)
    if not body:
        return "empty"
    source = " ".join(facts[int(c[1:]) - 1] for c in cites).lower()
    for tok in _TOKEN_RE.findall(body):
        t = tok.strip("`").lower().rstrip(".")
        if not t:
            continue
        found = re.search(rf"(?<![\d.]){re.escape(t)}(?!\d|\.\d)", source) if t[0].isdigit() else t in source
        if not found:
            return f"{tok!r} is not in the cited facts"
    return body, cites


def _template(facts: list[str]) -> list[str]:
    return [f"{f} [F{i}]" for i, f in enumerate(facts[:MAX_SENTENCES], 1)]


def _ask(post: Post, model: str, svc: str, facts: list[str]) -> tuple[list[str], str]:
    listing = "\n".join(f"F{i}: {f}" for i, f in enumerate(facts, 1))
    resp = post(
        {
            "model": model,
            "messages": [
                {"role": "system", "content": PROMPT},
                {"role": "user", "content": f"Server: {svc}\n\n{listing}"},
            ],
            "temperature": 0,
        }
    )
    content = resp["choices"][0]["message"].get("content") or ""
    if isinstance(content, list):
        content = "".join(p.get("text", "") for p in content if isinstance(p, dict))
    text = re.sub(r"<thought>.*?</thought>", "", str(content), flags=re.S)
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end < start:
        raise ValueError("the model did not reply with JSON")
    data = json.loads(text[start : end + 1])
    sentences = data.get("sentences") if isinstance(data, dict) else None
    if not isinstance(sentences, list):
        raise ValueError("the model's JSON has no 'sentences' list")
    return [str(s) for s in sentences[: MAX_SENTENCES * 2]], str(resp.get("model") or model)


def write(
    ws: Workspace,
    scan: ServiceScan,
    risk: RiskConfig,
    post: Post | None = None,
    model: str | None = None,
    who: str = "cli",
) -> Brief:
    facts, fix = collect_facts(ws, scan, risk)
    written_by = "template (no model)"
    raw = _template(facts)
    error = None
    if post is not None and model:
        try:
            raw, written_by = _ask(post, model, scan.service.name, facts)
        except (RuntimeError, ValueError, KeyError, IndexError, TypeError) as e:
            error = str(e)[:200]
            written_by = f"template ({model} failed: {error})"
    b = Brief(scan.service.name, written_by, dt.datetime.now(dt.timezone.utc).isoformat(), facts, fix=fix)
    for s in raw:
        res = check_sentence(s, facts)
        if isinstance(res, str):
            text = re.sub(r"\s+([.,;:!?])", r"\1", _CITE_RE.sub("", s)).strip()
            b.removed.append({"text": text[:300], "reason": res})
        elif len(b.sentences) < MAX_SENTENCES:
            b.sentences.append({"text": res[0], "cites": res[1]})
    ws.save_json(f"briefs/{scan.service.name}.json", b.to_dict())
    ws.audit.append(
        "brief.generated",
        {
            "service": scan.service.name,
            "written_by": written_by,
            "kept": len(b.sentences),
            "removed": len(b.removed),
            "error": error,
        },
        actor=who,
    )
    return b
