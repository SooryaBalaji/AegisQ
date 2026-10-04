"""Agent drivers. All call the same Toolbox, so the guardrails are identical:

* ``ClaudePlanner`` - Claude chooses the next tool call (tool use via the Anthropic API).
* ``LocalPlanner`` - an open model (e.g. Gemma 4) chooses the next tool call through any
  OpenAI-compatible chat endpoint: the Gemini API, or Ollama / LM Studio / llama.cpp / vLLM.
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

from aegisq.agent.tools import Toolbox, ToolError
from aegisq.config import AgentConfig
from aegisq.crypto_registry import group_by_name

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
    "read_config": "Return a managed service's nginx config (read-only), its sha256, and the current "
    "ssl_ecdh_curve / ssl_protocols values.",
    "propose_patch": "Record a minimal config change for a managed service and store it on a git branch. Give "
    "either directive values (ssl_ecdh_curve, ssl_protocols; preferred) or a unified diff. Code rejects any change "
    "outside those two directives, groups outside the allowlist, a list without a PQ hybrid first, a list without a "
    "classical fallback, and any protocol other than TLSv1.2/TLSv1.3. Returns proposal_id and the diff.",
    "request_approval": "Show the proposal's diff to a human on the dashboard and block until they approve or "
    "reject it (or it times out). Returns the decision.",
    "apply_patch": "Apply an approved proposal: back up the config, write the patch, run the config test "
    "(nginx -t), and reload. If the test or reload fails the old config is restored automatically and a "
    "diagnosis is returned. Refused without a recorded human approval for this exact diff.",
    "verify": "Re-run the post-quantum handshake probe and an HTTP health check against the service. The service "
    "is marked fixed only if both pass.",
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


def desired_groups(existing: list[str], allowed: list[str]) -> str:
    """X25519MLKEM768 first, then the classical groups already configured (X25519 guaranteed)."""
    allowed_l = {a.lower() for a in allowed}
    out = ["X25519MLKEM768"]
    for value in existing:
        for g in value.split(":"):
            info = group_by_name(g)
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
                    tb.note(name, _unmanaged_advice(row))
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
            decision = call("request_approval", proposal_id=prop["proposal_id"])
            if decision["status"] != "approved":
                return calls
            applied = call("apply_patch", proposal_id=prop["proposal_id"])
            if not applied.get("applied"):
                diag = applied.get("diagnosis") or {}
                if diag:
                    tb.note(name, f"recommendation: {diag.get('recommendation')}")
                return calls
            v = call("verify", service=name)
            if not v["fixed"]:
                call("rollback", service=name, reason="verification failed")
        except ToolError as e:
            tb.note(name, f"stopped: {e}")
            if not tb.state[name].outcome:
                tb.state[name].outcome = "failed"
        return calls


def _unmanaged_advice(row: dict[str, Any]) -> str:
    if row["protocol"] == "ssh":
        return (
            "SSH is scan-only: upgrade to OpenSSH 9.9+ (mlkem768x25519-sha256 is the default from 10.0) or add "
            "'KexAlgorithms mlkem768x25519-sha256,sntrup761x25519-sha512@openssh.com,curve25519-sha256' to sshd_config."
        )
    return "not managed by AegisQ: hand the CBOM entry to the owning team"


# --------------------------------------------------------- Claude planner ---

SYSTEM_PROMPT = """You are AegisQ's migration agent. You move a fleet of TLS servers to hybrid \
post-quantum key exchange (X25519MLKEM768) to stop "harvest now, decrypt later" attacks.

Work the fleet in the order list_services returns (highest risk first). For each managed service that is not \
already pq_ready:
1. read_config, then propose_patch with the smallest change: set ssl_ecdh_curve to X25519MLKEM768 first, then the \
classical groups it already uses (keep X25519 so older clients still connect). Only touch ssl_protocols if TLSv1.3 \
is missing.
2. request_approval and wait. If the human rejects it, note it and move on.
3. apply_patch. If the config test fails, the old config is already restored; read the diagnosis, explain the \
root cause, and move on. Do not retry a patch the TLS library cannot support.
4. verify. If verification fails, call rollback.
Skip services that are not managed, unreachable, plaintext or SSH; mention what their owners should do.

Rules are enforced by the tools, so a refused call means the action is not allowed: do not try to work around it. \
Never apply anything without an approval. When every service has been handled, call write_report, then reply with \
a short summary per service: outcome, and for failures the root cause and the recommended fix."""


class ClaudePlanner:
    name = "claude"

    def __init__(self, model: str, effort: str = "high", max_turns: int = 80, client: Any = None) -> None:
        self.model = model
        self.effort = effort
        self.max_turns = max_turns
        if client is None:
            import anthropic

            client = anthropic.Anthropic()
        self.client = client

    def _create(self, messages: list[dict[str, Any]]) -> Any:
        return self.client.messages.create(
            model=self.model,
            max_tokens=16000,
            system=SYSTEM_PROMPT,
            tools=tool_specs(),
            messages=messages,
            thinking={"type": "adaptive"},
            output_config={"effort": self.effort},
            # Server-side fallback: if the model declines, the API reroutes the same request.
            extra_headers={"anthropic-beta": "server-side-fallback-2026-07-01"},
            extra_body={"fallbacks": "default"},
        )

    def run(self, tb: Toolbox, only: list[str] | None = None) -> RunSummary:
        tb.ws.audit.append(
            "agent.started", {"planner": self.name, "model": self.model, "services": only}, actor="agent"
        )
        task = "Migrate the fleet." if not only else f"Migrate only these services: {', '.join(only)}."
        messages: list[dict[str, Any]] = [{"role": "user", "content": task}]
        calls = 0
        final = ""
        rolled: list[str] = []
        try:
            for _turn in range(self.max_turns):
                resp = self._create(messages)
                # Append the full content (thinking, fallback and tool_use blocks) unchanged.
                messages.append({"role": "assistant", "content": resp.content})
                if resp.stop_reason == "refusal":
                    final = "The model declined to continue; no further changes were made."
                    tb.ws.audit.append(
                        "agent.refusal", {"details": str(getattr(resp, "stop_details", ""))}, actor="agent"
                    )
                    break
                if resp.stop_reason == "tool_use":
                    results = []
                    for block in resp.content:
                        if getattr(block, "type", None) != "tool_use":
                            continue
                        calls += 1
                        out, err = run_tool_call(tb, only, block.name, block.input)
                        results.append(
                            {"type": "tool_result", "tool_use_id": block.id, "content": out, "is_error": err}
                        )
                    messages.append({"role": "user", "content": results})
                    continue
                if resp.stop_reason in ("max_tokens", "pause_turn"):
                    messages.append({"role": "user", "content": "Continue."})
                    continue
                final = "\n".join(b.text for b in resp.content if getattr(b, "type", None) == "text").strip()
                break
            else:
                final = f"Stopped after {self.max_turns} turns."
        finally:
            rolled = tb.finalize()
        summary = _summarize(tb, self.name, final, calls, rolled)
        tb.ws.audit.append(
            "agent.finished",
            {"planner": self.name, "outcomes": summary.outcomes, "final_message": final[:4000]},
            actor="agent",
        )
        return summary


# ---------------------------------------------------------- local planner ---

GEMINI_OPENAI_URL = "https://generativelanguage.googleapis.com/v1beta/openai"
OLLAMA_URL = "http://127.0.0.1:11434/v1"
_RETRY_STATUS = {429, 500, 502, 503, 504}
_THOUGHT_RE = re.compile(r"<thought>.*?</thought>", re.S)
# Gemini puts the wait in the body ("Please retry in 33.02s" / "retryDelay": "33s"), not in Retry-After.
_RETRY_HINT_RE = re.compile(r'(?:retry in|"retryDelay":\s*")\s*([0-9]+(?:\.[0-9]+)?)\s*s', re.I)
_MAX_RETRY_WAIT_S = 90.0


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

    @property
    def label(self) -> str:
        host = urllib.parse.urlsplit(self.base_url).hostname or "?"
        return f"{self.model} @ {host}"


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
        os.environ.get("AEGISQ_LLM_BASE_URL") or cfg.local_base_url or (GEMINI_OPENAI_URL if gem_key else OLLAMA_URL)
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
    return LocalEndpoint(base, os.environ.get("AEGISQ_LLM_MODEL") or cfg.local_model, key)


def openai_tool_specs() -> list[dict[str, Any]]:
    return [
        {
            "type": "function",
            "function": {"name": s["name"], "description": s["description"], "parameters": s["input_schema"]},
        }
        for s in tool_specs()
    ]


class LocalPlanner:
    """An open model drives the toolbox through an OpenAI-compatible ``/chat/completions`` endpoint.

    Works with Gemma 4 on the Gemini API and with any model served by Ollama, LM Studio, llama.cpp or vLLM
    that supports tool calling. The guardrails are the same as for Claude because they live in the tools.
    """

    name = "local"

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

    def _http_post(self, body: dict[str, Any]) -> dict[str, Any]:
        url = self.endpoint.base_url + "/chat/completions"
        headers = {"Content-Type": "application/json"}
        if self.endpoint.api_key:
            headers["Authorization"] = f"Bearer {self.endpoint.api_key}"
        data = json.dumps(body).encode()
        for attempt in range(self.retries + 1):
            req = urllib.request.Request(url, data=data, headers=headers, method="POST")  # noqa: S310 - scheme checked
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310
                    parsed: dict[str, Any] = json.load(resp)
                    return parsed
            except urllib.error.HTTPError as e:
                text = e.read().decode("utf-8", "replace")
                if e.code not in _RETRY_STATUS or attempt == self.retries:
                    raise RuntimeError(f"{self.endpoint.label}: HTTP {e.code}: {text[:500]}") from None
                delay = _retry_delay(e.headers.get("Retry-After"), text, attempt)
                why = "rate limited" if e.code == 429 else f"HTTP {e.code}"
            except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
                if attempt == self.retries:
                    raise RuntimeError(f"cannot reach {self.endpoint.base_url}: {e}") from None
                delay = _retry_delay(None, "", attempt)
                why = "connection failed"
            log.warning("local planner: %s, retrying in %.0fs (attempt %d)", why, delay, attempt + 1)
            time.sleep(delay)
        raise AssertionError("unreachable")

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
            {"planner": self.name, "outcomes": summary.outcomes, "final_message": final[:4000]},
            actor="agent",
        )
        return summary


Planner = RulesPlanner | ClaudePlanner | LocalPlanner


def _has_anthropic_creds() -> bool:
    return bool(os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN"))


def choose_planner(kind: str, cfg: AgentConfig) -> Planner:
    if kind == "auto":
        if _has_anthropic_creds():
            kind = "claude"
        elif _gemini_key() or os.environ.get("AEGISQ_LLM_BASE_URL"):
            kind = "local"
        else:
            kind = "rules"
    if kind == "claude":
        try:
            return ClaudePlanner(model=cfg.model, effort=cfg.effort, max_turns=cfg.max_turns)
        except ImportError as e:
            raise RuntimeError("the claude planner needs the 'anthropic' package: pip install 'aegisq[agent]'") from e
    if kind == "local":
        return LocalPlanner(resolve_local_endpoint(cfg), max_turns=cfg.max_turns)
    if kind == "rules":
        return RulesPlanner()
    raise ValueError(f"unknown planner {kind!r}")
