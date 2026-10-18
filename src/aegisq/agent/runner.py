"""Agent drivers. Both call the same Toolbox, so the guardrails are identical:

* ``GemmaPlanner`` - Gemma 4 chooses the next tool call, through Google's Gemini API or a Gemma 4
  running on your own machine (Ollama, LM Studio, llama.cpp or vLLM).
* ``RulesPlanner`` - a deterministic driver for air-gapped sites, CI and fallback.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from aegisq.agent import guardrails as gr
from aegisq.agent import native
from aegisq.agent.advice import advice_for
from aegisq.agent.tools import Toolbox, ToolError
from aegisq.config import AgentConfig
from aegisq.crypto_registry import SSH_WEAK_KEX, group_by_name, ssh_kex_is_pq

log = logging.getLogger(__name__)

# ------------------------------------------------------------ tool inputs ---


class _In(BaseModel):
    model_config = ConfigDict(extra="forbid")


class NoInput(_In):
    pass


class ServiceInput(_In):
    service: str = Field(max_length=64)


class ProposeInput(_In):
    service: str = Field(max_length=64)
    ssl_ecdh_curve: str | None = Field(default=None, max_length=200)
    ssl_protocols: str | None = Field(default=None, max_length=100)
    kex_algorithms: str | None = Field(default=None, max_length=1000)
    groups: str | None = Field(default=None, max_length=200)
    diff: str | None = Field(default=None, max_length=65536)
    rationale: str = Field(default="", max_length=2000)


class ProposalInput(_In):
    proposal_id: str = Field(max_length=32)


class RollbackInput(_In):
    service: str = Field(max_length=64)
    reason: str = Field(default="requested by agent", max_length=500)


TOOL_INPUTS: dict[str, type[_In]] = {
    "list_services": NoInput,
    "read_config": ServiceInput,
    "propose_patch": ProposeInput,
    "request_approval": ProposalInput,
    "apply_patch": ProposalInput,
    "verify": ServiceInput,
    "rollback": RollbackInput,
    "write_report": NoInput,
}

TOOL_DESCRIPTIONS = {
    "list_services": "List every scanned service in risk-priority order (highest Mosca margin first), with its "
    "status, whether AegisQ manages its config, and what happened to it in this run.",
    "read_config": "Return a managed service's config (read-only): its kind (nginx, apache, haproxy, caddy, postfix, "
    "dovecot or sshd), sha256, the current key-exchange directives, the current TLS groups (apache, haproxy, caddy, "
    "postfix, dovecot) or KexAlgorithms and openssh_version (sshd).",
    "propose_patch": "Record a minimal config change for a managed service and store it on a git branch. For nginx "
    "give ssl_ecdh_curve / ssl_protocols; for apache, haproxy, caddy, postfix and dovecot give groups (a list such as "
    "'X25519MLKEM768:X25519:prime256v1'; AegisQ writes it in that server's syntax); for sshd give kex_algorithms; or "
    "give a unified diff. Code rejects any change outside the key-exchange directives, values outside the allowlist, "
    "a list without a PQ hybrid first, a list without a classical fallback, weak SSH key exchanges, any TLS protocol "
    "other than TLSv1.2/TLSv1.3, and (apache, postfix, dovecot) a list the server's own TLS library cannot load. "
    "Returns proposal_id and the diff.",
    "request_approval": "Show the proposal's diff to a human on the dashboard and block until they approve or "
    "reject it (or it times out). Returns the decision.",
    "apply_patch": "Apply an approved proposal: back up the config, write the patch, run the server's config test "
    "(for example nginx -t, haproxy -c or sshd -t), and reload. If the test or reload fails the old config is "
    "restored automatically and a "
    "diagnosis is returned. Refused without a recorded human approval for this exact diff.",
    "verify": "Re-run the post-quantum probe plus a health check (HTTP for web servers; a classical-only TLS "
    "handshake for mail servers; a fresh SSH handshake for sshd). "
    "The service is marked fixed only if both pass.",
    "rollback": "Restore the last known-good config for a service and reload. Always available.",
    "write_report": "Build the migration report from the audit log (read-only).",
}


def tool_specs() -> list[dict[str, Any]]:
    specs = []
    for name, model in TOOL_INPUTS.items():
        schema = model.model_json_schema()
        schema.pop("title", None)
        for prop in schema.get("properties", {}).values():
            prop.pop("title", None)
        schema.setdefault("properties", {})
        schema["additionalProperties"] = False
        specs.append({"name": name, "description": TOOL_DESCRIPTIONS[name], "input_schema": schema})
    return specs


def dispatch(tb: Toolbox, name: str, raw_input: Any) -> tuple[str, bool]:
    """Validate input and run one tool. Returns (JSON result, is_error)."""
    model = TOOL_INPUTS.get(name)
    if model is None:
        return json.dumps({"error": f"unknown tool {name!r}"}), True
    try:
        args = model.model_validate(raw_input if isinstance(raw_input, dict) else {})
    except ValidationError as e:
        return json.dumps({"error": "invalid input", "details": e.errors(include_url=False)}, default=str), True
    fn: Callable[..., dict[str, Any]] = getattr(tb, name)
    try:
        result = fn(**args.model_dump(exclude_none=True))
    except ToolError as e:
        return json.dumps({"error": str(e)}), True
    except Exception as e:  # a tool crash is reported to the agent, never silently swallowed
        log.exception("tool %s crashed", name)
        tb.ws.audit.append("agent.tool_crashed", {"tool": name, "error": f"{type(e).__name__}: {e}"})
        return json.dumps({"error": f"internal error in {name}: {type(e).__name__}"}), True
    return json.dumps(result, default=str), False


def run_tool_call(tb: Toolbox, only: list[str] | None, name: str, raw_input: Any) -> tuple[str, bool]:
    """One model-requested tool call: scope check, dispatch, audit. Shared by every AI planner."""
    if only and isinstance(raw_input, dict) and raw_input.get("service") not in (None, *only):
        out, err = json.dumps({"error": "service is outside the scope of this run"}), True
    else:
        out, err = dispatch(tb, name, raw_input)
    tb.ws.audit.append(
        "agent.tool_call",
        {"tool": name, "input": raw_input, "is_error": err, "result": out[:4000]},
        actor="agent",
    )
    return out, err


@dataclass
class RunSummary:
    planner: str
    outcomes: dict[str, str] = field(default_factory=dict)
    notes: dict[str, list[str]] = field(default_factory=dict)
    safety_rollbacks: list[str] = field(default_factory=list)
    final_message: str = ""
    tool_calls: int = 0


def _summarize(tb: Toolbox, planner: str, final: str, calls: int, rolled: list[str]) -> RunSummary:
    return RunSummary(
        planner=planner,
        outcomes={k: v.outcome for k, v in tb.state.items() if v.outcome},
        notes={k: v.notes for k, v in tb.state.items() if v.notes},
        safety_rollbacks=rolled,
        final_message=final,
        tool_calls=calls,
    )


# ---------------------------------------------------------- rules planner ---


DEFAULT_SSH_CLASSICAL = (
    "curve25519-sha256",
    "curve25519-sha256@libssh.org",
    "ecdh-sha2-nistp256",
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp521",
    "diffie-hellman-group-exchange-sha256",
    "diffie-hellman-group16-sha512",
    "diffie-hellman-group18-sha512",
    "diffie-hellman-group14-sha256",
)


def desired_ssh_kex(existing: list[str], openssh_version: str | None, allowed: list[str]) -> str | None:
    """The strongest PQ hybrid this OpenSSH supports first, then the classical methods already configured."""
    try:
        v = tuple(int(x) for x in openssh_version.split(".")[:2]) if openssh_version else None
    except ValueError:
        v = None
    pq = []
    if v is None or v >= (9, 9):
        pq.append("mlkem768x25519-sha256")
    if v is None or v >= (8, 5):
        pq.append("sntrup761x25519-sha512@openssh.com")
    pq = [k for k in pq if k in allowed]
    if not pq:
        return None
    classical: list[str] = []
    for value in existing:
        if value[:1] in ("+", "-", "^"):
            continue
        for k in value.split(","):
            if k and not ssh_kex_is_pq(k) and k in allowed and k not in SSH_WEAK_KEX and k not in classical:
                classical.append(k)
    if not classical:
        classical = [k for k in DEFAULT_SSH_CLASSICAL if k in allowed]
    return ",".join(pq + classical)


def desired_groups(existing: list[str], allowed: list[str], kind: str = "nginx") -> str:
    """X25519MLKEM768 first, then the classical groups already configured (X25519 guaranteed)."""
    allowed_l = {a.lower() for a in allowed}
    out = ["X25519MLKEM768"]
    for value in existing:
        for g in re.split(r"[\s,:]+", value):
            info = group_by_name(g)
            if kind == "caddy" and g.lower() not in gr.CADDY_NAMES:
                continue
            if g and info and not info.pq and g.lower() in allowed_l and g.lower() not in {o.lower() for o in out}:
                out.append(g)
    if not any(o.lower() == "x25519" for o in out):
        out.insert(1, "X25519")
    return ":".join(out)


class RulesPlanner:
    name = "rules"

    def run(self, tb: Toolbox, only: list[str] | None = None) -> RunSummary:
        tb.ws.audit.append("agent.started", {"planner": self.name, "services": only}, actor="agent")
        calls = 0
        rolled: list[str] = []
        try:
            for row in tb.list_services()["services"]:
                name = row["service"]
                if only and name not in only:
                    continue
                if row["status"] == "pq_ready":
                    continue
                if not row["managed"]:
                    tb.note(name, advice_for(row.get("platform"), row["protocol"]))
                    tb.state[name].outcome = "skipped"
                    continue
                if row["status"] in ("unreachable", "error", "plaintext", "legacy_tls"):
                    tb.note(name, f"status {row['status']}: needs a TLS 1.3 deployment, not a two-line patch")
                    tb.state[name].outcome = "skipped"
                    continue
                calls += self._migrate(tb, name, row)
        finally:
            rolled = tb.finalize()
            try:
                tb.write_report()
            except Exception as e:
                log.warning("report generation failed: %s", e)
        summary = _summarize(tb, self.name, "rules planner finished", calls, rolled)
        tb.ws.audit.append("agent.finished", {"planner": self.name, "outcomes": summary.outcomes}, actor="agent")
        return summary

    def _migrate(self, tb: Toolbox, name: str, row: dict[str, Any]) -> int:
        calls = 0

        def call(tool: str, **kw: Any) -> dict[str, Any]:
            nonlocal calls
            calls += 1
            out, err = dispatch(tb, tool, kw)
            data: dict[str, Any] = json.loads(out)
            if err:
                raise ToolError(data.get("error", "tool failed"))
            return data

        try:
            cfg = call("read_config", service=name)
            if cfg.get("kind") == "sshd":
                kex = desired_ssh_kex(
                    cfg["directives"]["KexAlgorithms"], cfg.get("openssh_version"), tb.policy.allowed_ssh_kex
                )
                if kex is None:
                    tb.note(
                        name,
                        f"OpenSSH {cfg.get('openssh_version') or '?'} has no post-quantum key exchange: "
                        "upgrade to OpenSSH 9.9+",
                    )
                    tb.state[name].outcome = "skipped"
                    return calls
                prop = call(
                    "propose_patch",
                    service=name,
                    kex_algorithms=kex,
                    rationale=f"Rank {row['rank']} (margin {row['margin']:+.1f} y): prefer a hybrid post-quantum SSH "
                    f"key exchange on OpenSSH {cfg.get('openssh_version') or '(unknown version)'}, keeping classical "
                    "methods for older clients.",
                )
                self._approve_apply_verify(tb, name, prop, call)
                return calls
            if cfg.get("kind") != "nginx":
                if row["status"] == "tls12_only":
                    tb.note(name, "TLS 1.3 is off: hybrid key exchange needs TLS 1.3, so enable it first")
                    tb.state[name].outcome = "skipped"
                    return calls
                prop = call(
                    "propose_patch",
                    service=name,
                    groups=desired_groups(cfg.get("groups", []), tb.policy.allowed_groups, cfg["kind"]),
                    rationale=f"Rank {row['rank']} (margin {row['margin']:+.1f} y): prefer hybrid ML-KEM key exchange "
                    f"on {cfg['kind']}, keeping classical groups for older clients.",
                )
                self._approve_apply_verify(tb, name, prop, call)
                return calls
            directives = cfg["directives"]
            curve = desired_groups(directives["ssl_ecdh_curve"], tb.policy.allowed_groups)
            protocols = None
            if row["status"] == "tls12_only" or any("TLSv1.3" not in v.split() for v in directives["ssl_protocols"]):
                protocols = "TLSv1.3" if tb.policy.min_tls_version == "TLSv1.3" else "TLSv1.2 TLSv1.3"
            prop = call(
                "propose_patch",
                service=name,
                ssl_ecdh_curve=curve,
                ssl_protocols=protocols,
                rationale=f"Rank {row['rank']} (margin {row['margin']:+.1f} y): enable hybrid ML-KEM key exchange "
                "with a classical fallback for older clients.",
            )
            self._approve_apply_verify(tb, name, prop, call)
        except ToolError as e:
            tb.note(name, f"stopped: {e}")
            if not tb.state[name].outcome:
                tb.state[name].outcome = "failed"
        return calls

    @staticmethod
    def _approve_apply_verify(
        tb: Toolbox, name: str, prop: dict[str, Any], call: Callable[..., dict[str, Any]]
    ) -> None:
        decision = call("request_approval", proposal_id=prop["proposal_id"])
        if decision["status"] != "approved":
            return
        applied = call("apply_patch", proposal_id=prop["proposal_id"])
        if not applied.get("applied"):
            diag = applied.get("diagnosis") or {}
            if diag:
                tb.note(name, f"recommendation: {diag.get('recommendation')}")
            return
        v = call("verify", service=name)
        if not v["fixed"]:
            call("rollback", service=name, reason="verification failed")


# ---------------------------------------------------------- system prompt ---

SYSTEM_PROMPT = """You are AegisQ's migration agent. You move a fleet of TLS and SSH servers (web, proxy, mail and \
SSH) to hybrid post-quantum key exchange (X25519MLKEM768 for TLS, mlkem768x25519-sha256 or sntrup761x25519 for SSH) \
to stop "harvest now, decrypt later" attacks.

Work the fleet in the order list_services returns (highest risk first). For each managed service that is not \
already pq_ready:
1. read_config, then propose_patch with the smallest change. nginx: set ssl_ecdh_curve to X25519MLKEM768 first, \
then the classical groups it already uses (keep X25519 so older clients still connect); only touch ssl_protocols if \
TLSv1.3 is missing. apache, haproxy, caddy, postfix, dovecot: give groups with X25519MLKEM768 first, then the \
classical groups read_config reports (keep X25519). sshd: set kex_algorithms to mlkem768x25519-sha256 \
(OpenSSH 9.9+) and/or sntrup761x25519-sha512@openssh.com (OpenSSH 8.5+) first, then the classical methods it already \
uses (keep curve25519-sha256); read_config reports openssh_version. OpenSSH older than 8.5 cannot be fixed by config.
2. request_approval and wait. If the human rejects it, note it and move on.
3. apply_patch. If the config test fails, the old config is already restored; read the diagnosis, explain the \
root cause, and move on. Do not retry a patch the TLS library cannot support.
4. verify. If verification fails, call rollback.
Skip services that are not managed, unreachable or plaintext; mention what their owners should do.

Rules are enforced by the tools, so a refused call means the action is not allowed: do not try to work around it. \
Never apply anything without an approval. When every service has been handled, call write_report, then reply with \
a short summary per service: outcome, and for failures the root cause and the recommended fix."""


# ---------------------------------------------------------- Gemma planner ---

GEMINI_OPENAI_URL = "https://generativelanguage.googleapis.com/v1beta/openai"
OLLAMA_URL = "http://127.0.0.1:11434/v1"
GEMINI_MODEL = "gemma-4-31b-it"
GEMINI_FALLBACKS = {
    "gemma-4-31b-it": ("gemma-4-26b-a4b-it",),
    "gemma-4-26b-a4b-it": ("gemma-4-31b-it",),
}  # Gemma 4 31B on Google's Gemini API
OLLAMA_MODEL = "gemma4:e4b"  # Gemma 4 E4B, pulled with `ollama pull gemma4:e4b`; set AEGISQ_LLM_MODEL for 12b/26b/31b
_RETRY_STATUS = {429, 500, 502, 503, 504}
_THOUGHT_RE = re.compile(r"<thought>.*?</thought>", re.S)
# Gemini puts the wait in the body ("Please retry in 33.02s" / "retryDelay": "33s"), not in Retry-After.
_RETRY_HINT_RE = re.compile(r'(?:retry in|"retryDelay":\s*")\s*([0-9]+(?:\.[0-9]+)?)\s*s', re.I)
_MAX_RETRY_WAIT_S = 90.0
_SYSTEM_REFUSED_RE = re.compile(r"developer instruction|system (?:role|instruction|message)", re.I)


def fold_system(messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Move system messages into the first user message, for endpoints without a system role."""
    system = "\n\n".join(str(m.get("content", "")) for m in messages if m.get("role") == "system")
    rest = [dict(m) for m in messages if m.get("role") != "system"]
    if not system:
        return rest
    for m in rest:
        if m.get("role") == "user":
            c = m.get("content")
            if isinstance(c, list):
                m["content"] = [{"type": "text", "text": system}, *c]
            else:
                m["content"] = f"{system}\n\n{c}"
            return rest
    return [{"role": "user", "content": system}, *rest]


def _retry_delay(retry_after: str | None, body: str, attempt: int) -> float:
    """Seconds to wait before retrying: the server's hint if it gave one, else exponential backoff."""
    try:
        if retry_after:
            return min(float(retry_after), _MAX_RETRY_WAIT_S)
    except ValueError:
        pass
    m = _RETRY_HINT_RE.search(body)
    if m:
        return min(float(m.group(1)) + 1.0, _MAX_RETRY_WAIT_S)
    return min(float(2 ** (attempt + 1)), _MAX_RETRY_WAIT_S)


@dataclass(frozen=True)
class LocalEndpoint:
    base_url: str
    model: str
    api_key: str | None
    api: str = "openai"
    fallback_models: tuple[str, ...] = ()

    @property
    def label(self) -> str:
        host = urllib.parse.urlsplit(self.base_url).hostname or "?"
        return f"{self.model} @ {host}" + (" (native API)" if self.api == "native" else "")


def _gemini_key() -> str | None:
    return os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY") or None


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def resolve_local_endpoint(cfg: AgentConfig) -> LocalEndpoint:
    """Where --planner local sends requests. Environment variables win over the config file."""
    gem_key = _gemini_key()
    base = (
        os.environ.get("AEGISQ_LLM_BASE_URL") or cfg.base_url or (GEMINI_OPENAI_URL if gem_key else OLLAMA_URL)
    ).rstrip("/")
    parts = urllib.parse.urlsplit(base)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise RuntimeError(f"AEGISQ_LLM_BASE_URL must be an http(s) URL, got {base!r}")
    key = os.environ.get("AEGISQ_LLM_API_KEY") or None
    if key is None and parts.hostname == "generativelanguage.googleapis.com":
        key = gem_key
        if key is None:
            raise RuntimeError("the Gemini API needs GEMINI_API_KEY (get one at https://aistudio.google.com/apikey)")
    if key and parts.scheme == "http" and not _is_loopback(parts.hostname):
        raise RuntimeError(f"refusing to send an API key over plain http to {parts.hostname}; use https")
    model = os.environ.get("AEGISQ_LLM_MODEL") or cfg.model
    google = parts.hostname == "generativelanguage.googleapis.com"
    if not model:
        model = GEMINI_MODEL if google else OLLAMA_MODEL
    api = (os.environ.get("AEGISQ_LLM_API") or ("native" if google else "openai")).lower()
    if api not in ("openai", "native"):
        raise RuntimeError(f"AEGISQ_LLM_API must be 'openai' or 'native', got {api!r}")
    if api == "native" and not google:
        raise RuntimeError("AEGISQ_LLM_API=native only works with the Gemini API")
    raw = os.environ.get("AEGISQ_LLM_FALLBACK_MODELS")
    if raw is None:
        fallbacks = tuple(m for m in GEMINI_FALLBACKS.get(model, ()) if google)
    else:
        fallbacks = tuple(m.strip() for m in raw.split(",") if m.strip() and m.strip() != model)
    return LocalEndpoint(base, model, key, api, fallbacks)


def openai_tool_specs() -> list[dict[str, Any]]:
    return [
        {
            "type": "function",
            "function": {"name": s["name"], "description": s["description"], "parameters": s["input_schema"]},
        }
        for s in tool_specs()
    ]


class _Busy(Exception):
    def __init__(self, why: str, retry_after: str | None, text: str) -> None:
        super().__init__(why)
        self.why, self.retry_after, self.text = why, retry_after, text


class GemmaPlanner:
    """Gemma 4 drives the toolbox through an OpenAI-compatible ``/chat/completions`` endpoint: Google's
    Gemini API, or a local server (Ollama, LM Studio, llama.cpp, vLLM). The guardrails live in the tools,
    so they are the same as for the rules planner.
    """

    name = "gemma"

    def __init__(
        self,
        endpoint: LocalEndpoint,
        max_turns: int = 80,
        post: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
        timeout: float = 300.0,
        retries: int = 6,
    ) -> None:
        self.endpoint = endpoint
        self.max_turns = max_turns
        self.timeout = timeout
        self.retries = retries
        self._post = post or self._http_post
        self._fold_system = False
        self._preferred = endpoint.model
        self.models_used: set[str] = set()

    def _http_post(self, body: dict[str, Any]) -> dict[str, Any]:
        """One model call. A busy model (429/5xx, no connection) hands over to the next Gemma 4 model at once;
        when every model is busy, wait (Google's retry hint, else backoff) and go round again."""
        attempt = 0
        while True:
            busy: list[str] = []
            delay = 0.0
            for model in self._model_order():
                try:
                    out = self._send_once(model, body)
                except _Busy as b:
                    busy.append(f"{model}: {b.why}")
                    delay = max(delay, _retry_delay(b.retry_after, b.text, attempt))
                    log.warning("Gemma 4: %s is busy (%s)", model, b.why)
                    continue
                if model != self._preferred:
                    log.warning("Gemma 4: using %s while %s is busy", model, self._preferred)
                    self._preferred = model
                self.models_used.add(model)
                out["model"] = model
                return out
            if attempt == self.retries:
                if all("cannot connect" in b for b in busy):
                    raise RuntimeError(f"cannot reach {self.endpoint.base_url}: {'; '.join(busy)}")
                raise RuntimeError(f"{self.endpoint.label}: every model is busy: {'; '.join(busy)}")
            log.warning("Gemma 4: every model is busy, retrying in %.0fs (attempt %d)", delay, attempt + 1)
            time.sleep(delay)
            attempt += 1

    def _model_order(self) -> list[str]:
        models = list(dict.fromkeys([self.endpoint.model, *self.endpoint.fallback_models]))
        return [self._preferred, *(m for m in models if m != self._preferred)]

    def _native_url(self, model: str) -> str:
        quoted = urllib.parse.quote(model, safe="-._")
        return f"{native.native_base(self.endpoint.base_url)}/models/{quoted}:generateContent"

    def _send_once(self, model: str, body: dict[str, Any]) -> dict[str, Any]:
        is_native = self.endpoint.api == "native"
        headers = {"Content-Type": "application/json"}
        if self.endpoint.api_key:
            if is_native:
                headers["x-goog-api-key"] = self.endpoint.api_key
            else:
                headers["Authorization"] = f"Bearer {self.endpoint.api_key}"
        url = self._native_url(model) if is_native else self.endpoint.base_url + "/chat/completions"
        for _ in range(2):
            payload: dict[str, Any] = {**body, "model": model}
            if self._fold_system and not is_native:
                payload["messages"] = fold_system(payload.get("messages", []))
            data = json.dumps(native.to_native(payload) if is_native else payload).encode()
            req = urllib.request.Request(url, data=data, headers=headers, method="POST")  # noqa: S310 - scheme checked
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310
                    parsed: dict[str, Any] = json.load(resp)
                    return native.from_native(parsed) if is_native else parsed
            except urllib.error.HTTPError as e:
                text = e.read().decode("utf-8", "replace")
                if e.code == 400 and _SYSTEM_REFUSED_RE.search(text) and not self._fold_system and not is_native:
                    # Some Gemma deployments reject the system role; send the same instructions as user text.
                    self._fold_system = True
                    log.warning("Gemma 4: endpoint rejects system messages; folding them into the user turn")
                    continue
                if e.code in _RETRY_STATUS:
                    why = "rate limited" if e.code == 429 else f"HTTP {e.code}"
                    raise _Busy(why, e.headers.get("Retry-After"), text) from None
                raise RuntimeError(
                    f"{model} @ {urllib.parse.urlsplit(url).hostname}: HTTP {e.code}: {text[:500]}"
                ) from None
            except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
                raise _Busy(f"cannot connect: {e}", None, "") from None
        raise RuntimeError("the endpoint rejected the request twice")

    def _create(self, messages: list[dict[str, Any]]) -> dict[str, Any]:
        return self._post(
            {"model": self.endpoint.model, "messages": messages, "tools": openai_tool_specs(), "tool_choice": "auto"}
        )

    def run(self, tb: Toolbox, only: list[str] | None = None) -> RunSummary:
        tb.ws.audit.append(
            "agent.started",
            {"planner": self.name, "model": self.endpoint.model, "endpoint": self.endpoint.base_url, "services": only},
            actor="agent",
        )
        task = "Migrate the fleet." if not only else f"Migrate only these services: {', '.join(only)}."
        messages: list[dict[str, Any]] = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": task},
        ]
        calls = 0
        final = ""
        nudged = False
        try:
            for _turn in range(self.max_turns):
                try:
                    resp = self._create(messages)
                    choice = resp["choices"][0]
                    msg = choice["message"]
                except RuntimeError as e:
                    final = f"The model endpoint failed; no further changes were made. {e}"
                    tb.ws.audit.append("agent.error", {"error": str(e)[:1000]}, actor="agent")
                    break
                except (KeyError, IndexError, TypeError):
                    final = "The model endpoint returned an unexpected response; no further changes were made."
                    tb.ws.audit.append("agent.error", {"error": json.dumps(resp, default=str)[:1000]}, actor="agent")
                    break
                # Send the assistant message back as returned (Gemini needs its tool-call thought signatures),
                # minus the model's visible <thought> text, which only costs input tokens on every later turn.
                kept = dict(msg)
                if isinstance(kept.get("content"), str):
                    kept["content"] = _THOUGHT_RE.sub("", kept["content"]).strip()
                messages.append(kept)
                tool_calls = msg.get("tool_calls") or []
                if tool_calls:
                    for tc in tool_calls:
                        calls += 1
                        fn = tc.get("function") or {}
                        name = str(fn.get("name", ""))
                        raw = fn.get("arguments") or {}
                        try:
                            args = json.loads(raw) if isinstance(raw, str) else raw
                        except json.JSONDecodeError:
                            args = None
                        if not isinstance(args, dict):
                            out = json.dumps({"error": "arguments must be a JSON object"})
                            tb.ws.audit.append(
                                "agent.tool_call",
                                {"tool": name, "input": str(raw)[:1000], "is_error": True, "result": out},
                                actor="agent",
                            )
                        else:
                            out, _ = run_tool_call(tb, only, name, args)
                        messages.append({"role": "tool", "tool_call_id": tc.get("id", ""), "content": out})
                    continue
                reason = choice.get("finish_reason")
                if reason == "content_filter":
                    final = "The model declined to continue; no further changes were made."
                    tb.ws.audit.append("agent.refusal", {"details": "content_filter"}, actor="agent")
                    break
                if reason == "length":
                    messages.append({"role": "user", "content": "Continue."})
                    continue
                if calls == 0 and not nudged:  # small models sometimes answer in prose first
                    nudged = True
                    messages.append(
                        {"role": "user", "content": "Use the tools to do the work. Start with list_services."}
                    )
                    continue
                final = _THOUGHT_RE.sub("", str(msg.get("content") or "")).strip()
                break
            else:
                final = f"Stopped after {self.max_turns} turns."
        finally:
            rolled = tb.finalize()
        summary = _summarize(tb, self.name, final, calls, rolled)
        tb.ws.audit.append(
            "agent.finished",
            {
                "planner": self.name,
                "outcomes": summary.outcomes,
                "final_message": final[:4000],
                "models_used": sorted(self.models_used),
            },
            actor="agent",
        )
        return summary


Planner = RulesPlanner | GemmaPlanner


def _ollama_models(base_url: str = OLLAMA_URL, timeout: float = 0.5) -> list[str] | None:
    """Model names a local Ollama serves, or None when nothing answers."""
    root = base_url.rstrip("/").removesuffix("/v1")
    try:
        with urllib.request.urlopen(root + "/api/tags", timeout=timeout) as r:  # noqa: S310 - loopback URL
            data = json.loads(r.read(1_000_000))
    except (OSError, ValueError):
        return None
    return [str(m.get("name", "")) for m in data.get("models", []) if isinstance(m, dict)]


def gemma_status(cfg: AgentConfig) -> tuple[bool, str]:
    """Can the Gemma 4 planner run here? (ok, what it will use or what to do)."""
    try:
        ep = resolve_local_endpoint(cfg)
    except RuntimeError as e:
        return False, str(e)
    if ep.api_key or os.environ.get("AEGISQ_LLM_BASE_URL") or cfg.base_url:
        return True, ep.label
    models = _ollama_models(ep.base_url)
    if models is None:
        return False, "set GEMINI_API_KEY, or install Ollama and run `ollama pull gemma4:e4b`"
    if not any(m == ep.model or (":" not in ep.model and m.split(":")[0] == ep.model) for m in models):
        return False, f"Ollama is running but has no {ep.model}: run `ollama pull {ep.model}`"
    return True, f"{ep.model} on this machine (Ollama)"


def choose_planner(kind: str, cfg: AgentConfig) -> Planner:
    """auto: Gemma 4 when it is available (GEMINI_API_KEY, AEGISQ_LLM_BASE_URL or a local Ollama), else rules."""
    if kind == "local":
        kind = "gemma"
    if kind == "auto":
        kind = "gemma" if gemma_status(cfg)[0] else "rules"
    if kind == "gemma":
        return GemmaPlanner(resolve_local_endpoint(cfg), max_turns=cfg.max_turns)
    if kind == "rules":
        return RulesPlanner()
    raise ValueError(f"unknown planner {kind!r}")
