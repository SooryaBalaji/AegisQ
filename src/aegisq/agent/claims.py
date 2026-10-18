"""Gemma proposes, the scanner proves.

A person shares what they have: a pasted config, command output, or a screenshot of a vendor console.
Gemma 4 reads it (text or image) and lists the endpoints it mentions and what it claims about their
key exchange. None of that is trusted:

* a claim from text must quote the text it came from, and the quote is checked against the input;
* nothing is scanned until a person picks the endpoints;
* every picked endpoint gets a real post-quantum handshake, and each claim is marked confirmed,
  contradicted or unverifiable from what the server actually did;
* fix advice comes only from ``advice.py`` (vendor documentation), never from the model.
"""

from __future__ import annotations

import base64
import datetime as dt
import json
import re
import secrets
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

from aegisq.agent.advice import advice_for
from aegisq.crypto_registry import group_by_name, ssh_kex_is_pq
from aegisq.models import PLATFORMS, Protocol, ScanReport, ServiceScan, ServiceTarget
from aegisq.netutil import TargetError, validate_host

if TYPE_CHECKING:
    from aegisq.agent.runner import LocalEndpoint
    from aegisq.config import AgentConfig
    from aegisq.scanner.engine import ScanOptions
    from aegisq.workspace import Workspace

MAX_TEXT = 64_000
MAX_IMAGE = 5 * 1024 * 1024
MAX_ENDPOINTS = 50
STARTTLS_PORTS = {"smtp": 25, "imap": 143, "pop3": 110}
_IMAGE_MAGIC = (
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"RIFF", "image/webp"),
)
_THOUGHT_RE = re.compile(r"<thought>.*?</thought>", re.S)
_PQ_HINT = re.compile(r"mlkem|ml-kem|kyber|sntrup|-pq-|post-?quantum", re.I)

PROMPT = """You read configuration files, command output and screenshots of server or cloud consoles, and list
every network endpoint they describe together with what they say about its key exchange.

Reply with ONE JSON object and nothing else, in exactly this shape:
{"endpoints": [{"host": "mail.example.com", "port": 25, "protocol": "tls", "starttls": "smtp",
  "platform": "postfix", "pq_claimed": true, "groups": ["X25519MLKEM768", "X25519"],
  "library": "OpenSSL", "library_version": "3.5.1", "evidence": "tls_eecdh_auto_curves = X25519MLKEM768, X25519"}],
 "notes": "one short sentence"}

Rules:
- host: a DNS name or IP address exactly as written. Never invent a host; skip endpoints with no host.
- port: a number, or null if not shown.
- protocol: "tls" or "ssh". starttls: "smtp", "imap", "pop3" or null.
- platform: one of nginx, apache, haproxy, caddy, postfix, dovecot, openssh, lighttpd, envoy, windows, aws-elb,
  gcp-lb, or null.
- pq_claimed: true if the source says post-quantum / ML-KEM / hybrid key exchange is enabled, false if it shows
  only classical groups, null if it does not say.
- groups: key-exchange groups or SSH KexAlgorithms exactly as written, in order. [] if none.
- library and library_version: only if written in the source, else null.
- evidence: copy the exact line or words from the source that support the claim (at most 200 characters).
- If nothing relevant is shown, return {"endpoints": [], "notes": "..."}."""

Verdict = Literal["confirmed", "contradicted", "unverifiable"]


class ClaimError(ValueError):
    pass


class Claim(BaseModel):
    model_config = ConfigDict(extra="ignore")

    host: str
    port: int | None = None
    protocol: Literal["tls", "ssh"] = "tls"
    starttls: Literal["smtp", "imap", "pop3"] | None = None
    platform: str | None = None
    pq_claimed: bool | None = None
    groups: list[str] = Field(default_factory=list, max_length=40)
    library: str | None = Field(default=None, max_length=80)
    library_version: str | None = Field(default=None, max_length=40)
    evidence: str = Field(default="", max_length=400)
    grounded: bool | None = None  # host and evidence found in the shared text; None for images

    @field_validator("host")
    @classmethod
    def _host(cls, v: str) -> str:
        return validate_host(v.strip().strip("[]"))

    @field_validator("port")
    @classmethod
    def _port(cls, v: int | None) -> int | None:
        return v if v is None or 1 <= v <= 65535 else None

    @field_validator("platform")
    @classmethod
    def _platform(cls, v: str | None) -> str | None:
        v = (v or "").strip().lower()
        return v if v in PLATFORMS else None

    @field_validator("groups")
    @classmethod
    def _groups(cls, v: list[str]) -> list[str]:
        return [str(g).strip()[:80] for g in v if str(g).strip()]

    @property
    def effective_port(self) -> int:
        if self.port:
            return self.port
        if self.starttls:
            return STARTTLS_PORTS[self.starttls]
        return 22 if self.protocol == "ssh" else 443

    @property
    def pq_expected(self) -> bool | None:
        """What the source says about post-quantum key exchange: stated, or implied by the listed groups."""
        if self.pq_claimed is not None:
            return self.pq_claimed
        if self.groups:
            return any(is_pq_name(g) for g in self.groups)
        return None

    @property
    def label(self) -> str:
        h = f"[{self.host}]" if ":" in self.host else self.host
        return f"{h}:{self.effective_port}" + (f" ({self.starttls})" if self.starttls else "")


class Extraction(BaseModel):
    id: str
    created_at: dt.datetime
    created_by: str
    source: Literal["text", "image", "text+image"]
    model: str
    endpoints: list[Claim]
    dropped: list[str] = Field(default_factory=list)
    notes: str = ""
    checks: list[dict[str, Any]] | None = None
    scan_file: str | None = None


def is_pq_name(name: str) -> bool:
    g = group_by_name(name)
    if g is not None:
        return g.pq
    return ssh_kex_is_pq(name.strip().lower()) or bool(_PQ_HINT.search(name))


def sniff_image(data: bytes) -> str:
    """The image type from its first bytes; the browser's or client's claim is not trusted."""
    for magic, mime in _IMAGE_MAGIC:
        if data.startswith(magic) and (mime != "image/webp" or data[8:12] == b"WEBP"):
            return mime
    raise ClaimError("the image must be a PNG, JPEG or WebP file")


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip().lower()


def _json_object(text: str) -> Any:
    text = _THOUGHT_RE.sub("", text).strip()
    text = re.sub(r"^```(?:json)?\s*|\s*```$", "", text, flags=re.I)
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end <= start:
        raise ClaimError("the model did not return a JSON object")
    try:
        return json.loads(text[start : end + 1])
    except json.JSONDecodeError as e:
        raise ClaimError(f"the model returned invalid JSON: {e}") from None


def _parse(raw: Any, text: str | None) -> tuple[list[Claim], list[str], str]:
    if not isinstance(raw, dict) or not isinstance(raw.get("endpoints"), list):
        raise ClaimError("the model's JSON has no 'endpoints' list")
    claims: list[Claim] = []
    dropped: list[str] = []
    seen: set[tuple[str, int, str | None]] = set()
    source = _norm(text) if text else None
    for item in raw["endpoints"][: MAX_ENDPOINTS * 2]:
        if not isinstance(item, dict):
            continue
        try:
            c = Claim.model_validate(item)
        except (ValidationError, TargetError, ValueError) as e:
            dropped.append(f"{str(item.get('host', '?'))[:80]}: {str(e).splitlines()[0][:120]}")
            continue
        key = (c.host.lower(), c.effective_port, c.starttls)
        if key in seen:
            continue
        seen.add(key)
        if source is not None:
            ev = _norm(c.evidence)
            c.grounded = bool(ev) and ev in source and _norm(c.host) in source
        claims.append(c)
        if len(claims) >= MAX_ENDPOINTS:
            break
    notes = str(raw.get("notes") or "")[:300]
    return claims, dropped, notes


def build_messages(text: str | None, image: bytes | None) -> list[dict[str, Any]]:
    parts: list[dict[str, Any]] = [
        {"type": "text", "text": "List the endpoints and key-exchange claims in what follows."}
    ]
    if text:
        parts.append({"type": "text", "text": f"--- shared text ---\n{text}\n--- end ---"})
    if image:
        url = f"data:{sniff_image(image)};base64,{base64.b64encode(image).decode()}"
        parts.append({"type": "image_url", "image_url": {"url": url}})
    return [{"role": "system", "content": PROMPT}, {"role": "user", "content": parts}]


def extract(
    post: Callable[[dict[str, Any]], dict[str, Any]],
    model: str,
    text: str | None = None,
    image: bytes | None = None,
    who: str = "cli",
) -> Extraction:
    """Ask Gemma for the claims in ``text`` and/or ``image``. One retry if the reply is not valid JSON."""
    text = (text or "").strip() or None
    if not text and not image:
        raise ClaimError("share some text or an image")
    if text and len(text) > MAX_TEXT:
        raise ClaimError(f"text is longer than {MAX_TEXT} characters")
    if image and len(image) > MAX_IMAGE:
        raise ClaimError("image is larger than 5 MB")
    messages = build_messages(text, image)
    last: ClaimError | None = None
    for _attempt in range(2):
        resp = post({"model": model, "messages": messages, "temperature": 0})
        used = str(resp.get("model") or model) if isinstance(resp, dict) else model
        try:
            content = resp["choices"][0]["message"].get("content") or ""
        except (KeyError, IndexError, TypeError, AttributeError):
            raise ClaimError("the model endpoint returned an unexpected response") from None
        if isinstance(content, list):  # some servers return content parts
            content = "".join(p.get("text", "") for p in content if isinstance(p, dict))
        try:
            claims, dropped, notes = _parse(_json_object(str(content)), text)
            break
        except ClaimError as e:
            last = e
            messages = [
                *messages,
                {"role": "assistant", "content": str(content)[:4000]},
                {"role": "user", "content": f"{e}. Reply with only the JSON object in the shape described."},
            ]
    else:
        assert last is not None
        raise last
    source: Literal["text", "image", "text+image"] = "text+image" if text and image else "text" if text else "image"
    return Extraction(
        id=f"chk-{dt.datetime.now(dt.timezone.utc):%Y%m%d%H%M%S}-{secrets.token_hex(3)}",
        created_at=dt.datetime.now(dt.timezone.utc),
        created_by=who,
        source=source,
        model=used,
        endpoints=claims,
        dropped=dropped,
        notes=notes,
    )


def targets_for(ext: Extraction, picked: list[int]) -> list[ServiceTarget]:
    from aegisq.inventory import _auto_name

    out: list[ServiceTarget] = []
    for i in sorted(set(picked)):
        if not 0 <= i < len(ext.endpoints):
            raise ClaimError(f"no endpoint number {i}")
        c = ext.endpoints[i]
        out.append(
            ServiceTarget(
                name=f"{_auto_name(c.host, c.effective_port)[:58]}-{i}",
                host=c.host,
                port=c.effective_port,
                protocol=Protocol(c.protocol),
                starttls=c.starttls if c.protocol == "tls" else None,
                platform=c.platform,  # type: ignore[arg-type]
                tags=["claim-check", ext.id],
            )
        )
    return out


def _observed(r: ServiceScan) -> str:
    if r.tls:
        if r.tls.pq_ready:
            return f"negotiated {r.tls.pq_group}"
        m = r.tls.modern_probe
        if m and m.group:
            return f"{m.version} with {m.group} only"
    if r.ssh:
        if r.ssh.pq_ready:
            return f"agreed {r.ssh.negotiated_kex}"
        return f"offers {', '.join(r.ssh.kex_algorithms[:3]) or 'no known key exchange'}"
    return r.status.value.replace("_", " ")


def judge(ext: Extraction, picked: list[int], report: ScanReport) -> list[dict[str, Any]]:
    """Compare each picked claim with its scan. Deterministic: no model involved."""
    by_index = {int(r.service.name.rsplit("-", 1)[1]): r for r in report.results}
    out: list[dict[str, Any]] = []
    for i in sorted(set(picked)):
        c, r = ext.endpoints[i], by_index.get(i)
        row: dict[str, Any] = {
            "index": i,
            "endpoint": c.label,
            "protocol": c.protocol,
            "claim": claim_text(c),
            "evidence": c.evidence,
            "grounded": c.grounded,
        }
        if r is None or not r.status.scanned:
            why = _why(r.errors[0] if r and r.errors else "")
            row.update(
                status=r.status.value if r else "error",
                observed=why,
                verdict="unverifiable",
                reason="The server could not be reached, so the claim cannot be checked.",
            )
        else:
            expected = c.pq_expected
            actual = r.pq_ready
            if expected is None:
                verdict: Verdict = "unverifiable"
                reason = "The source makes no post-quantum claim; see what the server does."
            elif expected == actual:
                verdict, reason = "confirmed", "The handshake matches the claim."
            else:
                verdict = "contradicted"
                reason = (
                    "The source says post-quantum, but the server only completes a classical key exchange."
                    if expected
                    else "The source shows classical groups only, but the server completes a post-quantum exchange."
                )
            row.update(status=r.status.value, observed=_observed(r), verdict=verdict, reason=reason)
            if not actual:
                row["fix"] = advice_for(c.platform, c.protocol).removeprefix("not managed by AegisQ: ")
        if c.library_version:
            row["unverified"] = f"{c.library or 'Library'} {c.library_version}: an outside scan cannot see versions"
        out.append(row)
    return out


def _why(err: str) -> str:
    low = err.lower()
    for needle, text in (
        ("refused by scope", "Not scanned: outside the allowed scan scope"),
        ("refused", "No answer: connection refused"),
        ("timed out", "No answer: timed out"),
        ("timeout", "No answer: timed out"),
        ("dns", "No answer: the name does not resolve"),
    ):
        if needle in low:
            return text
    return f"No answer: {err[:140]}" if err else "No answer"


def claim_text(c: Claim) -> str:
    if c.pq_claimed is True:
        base = "Post-quantum key exchange enabled"
    elif c.pq_claimed is False:
        base = "Classical key exchange only"
    elif c.groups:
        base = ("Post-quantum" if c.pq_expected else "Classical") + " groups listed"
    else:
        base = "No key-exchange claim"
    return base + (f" ({', '.join(c.groups[:4])})" if c.groups else "")


def summarize(checks: list[dict[str, Any]]) -> dict[str, int]:
    out = {"confirmed": 0, "contradicted": 0, "unverifiable": 0}
    for row in checks:
        out[row["verdict"]] += 1
    return out


# ------------------------------------------------------------ workflow ---

_ID_RE = re.compile(r"^chk-\d{14}-[0-9a-f]{6}$")


def gemma_client(
    cfg: AgentConfig, retries: int = 2, timeout: float = 120.0
) -> tuple[Callable[[dict[str, Any]], dict[str, Any]], LocalEndpoint]:
    """The same Gemma 4 endpoint the planner uses (Gemini API or local Ollama). RuntimeError if unset."""
    from aegisq.agent.runner import GemmaPlanner, resolve_local_endpoint

    ep = resolve_local_endpoint(cfg)
    return GemmaPlanner(ep, retries=retries, timeout=timeout)._http_post, ep


def save(ws: Workspace, ext: Extraction) -> None:
    ws.save_json(f"claims/{ext.id}.json", ext.model_dump(mode="json"))


def load(ws: Workspace, cid: str) -> Extraction | None:
    if not _ID_RE.match(cid):
        return None
    data = ws.load_json(f"claims/{cid}.json")
    return Extraction.model_validate(data) if data else None


def record_extraction(ws: Workspace, ext: Extraction) -> None:
    save(ws, ext)
    ws.audit.append(
        "claims.extracted",
        {
            "id": ext.id,
            "source": ext.source,
            "model": ext.model,
            "endpoints": [c.label for c in ext.endpoints],
            "ungrounded": [c.label for c in ext.endpoints if c.grounded is False],
            "dropped": len(ext.dropped),
        },
        actor=ext.created_by,
    )


def verify(ws: Workspace, ext: Extraction, picked: list[int], opts: ScanOptions, who: str) -> list[dict[str, Any]]:
    """Scan the endpoints a person picked and judge every claim against the handshake."""
    import asyncio

    from aegisq.scanner.engine import scan_all

    if not picked:
        raise ClaimError("pick at least one endpoint to check")
    targets = targets_for(ext, picked)
    report = asyncio.run(scan_all(targets, opts))
    scan_rel = f"claims/{ext.id}-scan.json"
    ws.save_json(scan_rel, json.loads(report.model_dump_json()))
    checks = judge(ext, picked, report)
    ext.checks, ext.scan_file = checks, scan_rel
    save(ws, ext)
    ws.audit.append(
        "claims.verified",
        {
            "id": ext.id,
            "scan_id": report.scan_id,
            "summary": summarize(checks),
            "contradicted": [c["endpoint"] for c in checks if c["verdict"] == "contradicted"],
        },
        actor=who,
    )
    return checks


def scan_report(ws: Workspace, ext: Extraction) -> ScanReport | None:
    if not ext.scan_file:
        return None
    data = ws.load_json(ext.scan_file)
    return ScanReport.model_validate(data) if data else None
