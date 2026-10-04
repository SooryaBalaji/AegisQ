"""--planner local: an open model (Gemma 4 on the Gemini API, Ollama, ...) drives the same guarded toolbox."""

import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, ClassVar

import pytest

from aegisq.agent.runner import (
    GEMINI_OPENAI_URL,
    OLLAMA_URL,
    LocalEndpoint,
    LocalPlanner,
    RulesPlanner,
    _retry_delay,
    choose_planner,
    openai_tool_specs,
    resolve_local_endpoint,
)
from aegisq.config import AgentConfig
from test_agent import approver, events, toolbox
from test_agent import verify_stub as _verify_stub  # noqa: F401 - shared fixture

ENV = ("GEMINI_API_KEY", "GOOGLE_API_KEY", "AEGISQ_LLM_BASE_URL", "AEGISQ_LLM_MODEL", "AEGISQ_LLM_API_KEY")


@pytest.fixture(autouse=True)
def clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for k in (*ENV, "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN"):
        monkeypatch.delenv(k, raising=False)


EP = LocalEndpoint("http://127.0.0.1:1/v1", "gemma-4-31b-it", None)


def call(i: int, name: str, args: Any = None, **kw: Any) -> dict[str, Any]:
    raw = json.dumps(kw) if args is None else args
    # extra_content mimics Gemini's thought signature, which must be sent back unchanged
    return {
        "id": f"c{i}",
        "type": "function",
        "function": {"name": name, "arguments": raw},
        "extra_content": {"google": {"thought_signature": f"sig{i}"}},
    }


def reply(*tool_calls: dict[str, Any], text: str = "", finish: str | None = None) -> dict[str, Any]:
    msg: dict[str, Any] = {"role": "assistant", "content": text}
    if tool_calls:
        msg["tool_calls"] = list(tool_calls)
    return {"choices": [{"message": msg, "finish_reason": finish or ("tool_calls" if tool_calls else "stop")}]}


class ScriptedModel:
    """Plays back fixed chat-completion responses and records every request body."""

    def __init__(self, turns: list[Any]) -> None:
        self.turns = turns
        self.bodies: list[dict[str, Any]] = []

    def __call__(self, body: dict[str, Any]) -> dict[str, Any]:
        self.bodies.append(json.loads(json.dumps(body)))
        turn = self.turns[len(self.bodies) - 1]
        return turn(self) if callable(turn) else turn

    def tool_result(self, n: int, call_id: str) -> dict[str, Any]:
        for m in self.bodies[n]["messages"]:
            if m.get("role") == "tool" and m["tool_call_id"] == call_id:
                return json.loads(m["content"])
        raise AssertionError(f"no result for {call_id}")


@pytest.mark.usefixtures("_verify_stub")
def test_local_planner_cannot_bypass_guardrails(ws, cfg, fake_nginx) -> None:
    def approve_and_apply(model: ScriptedModel) -> dict[str, Any]:
        pid = model.tool_result(5, "c5")["proposal_id"]
        return reply(call(6, "request_approval", proposal_id=pid), call(7, "apply_patch", proposal_id=pid))

    turns = [
        reply(text="<thought>I should list first.</thought>"),  # prose first: nudged to use tools
        reply(call(1, "list_services")),
        reply(call(2, "read_config", service="web")),
        # a misbehaving model: smuggle another directive in, then apply without approval
        reply(
            call(
                3,
                "propose_patch",
                service="web",
                diff="@@ -8 +8 @@\n-    ssl_ecdh_curve X25519:prime256v1;  # set by "
                "platform team\n+    ssl_ecdh_curve X25519MLKEM768:X25519; include /etc/passwd;\n",
            ),
            call(4, "apply_patch", proposal_id="whatever"),
        ),
        reply(call(5, "propose_patch", service="web", ssl_ecdh_curve="X25519MLKEM768:X25519")),
        approve_and_apply,
        reply(call(8, "verify", service="web"), call(9, "write_report")),
        reply(text="<thought>all done</thought>web: fixed."),
    ]
    model = ScriptedModel(turns)
    tb = toolbox(ws, cfg, fake_nginx, approval_waiter=approver(ws))
    summary = LocalPlanner(EP, post=model).run(tb)

    assert "guardrail" in model.tool_result(4, "c3")["error"]
    assert "unknown proposal" in model.tool_result(4, "c4")["error"]
    assert summary.outcomes["web"] == "fixed"
    assert summary.final_message == "web: fixed."
    assert summary.planner == "local" and summary.tool_calls == 9
    conf = Path(fake_nginx["conf"]).read_text()
    assert "X25519MLKEM768:X25519" in conf and "include" not in conf

    first = model.bodies[0]
    assert first["model"] == "gemma-4-31b-it"
    assert first["messages"][0]["role"] == "system" and "X25519MLKEM768" in first["messages"][0]["content"]
    assert {t["function"]["name"] for t in first["tools"]} == {t["function"]["name"] for t in openai_tool_specs()}
    assert "Use the tools" in model.bodies[1]["messages"][-1]["content"]
    # assistant turns go back verbatim, including the thought signatures
    sent = [m for m in model.bodies[-1]["messages"] if m.get("tool_calls")]
    assert sent[0]["tool_calls"][0]["extra_content"]["google"]["thought_signature"] == "sig1"
    assert not any("<thought>" in str(m.get("content")) for m in model.bodies[-1]["messages"])
    assert events(ws).count("agent.tool_call") == 9
    started = next(e for e in ws.audit.entries() if e["event"] == "agent.started")
    assert started["data"]["planner"] == "local" and started["data"]["model"] == "gemma-4-31b-it"


@pytest.mark.usefixtures("_verify_stub")
def test_local_planner_scope_bad_args_and_refusal(ws, cfg, fake_nginx) -> None:
    turns = [
        reply(call(1, "read_config", service="scanonly"), call(2, "read_config", args="{not json")),
        reply(call(3, "read_config", args='["web"]'), call(4, "no_such_tool")),
        reply(finish="content_filter"),
    ]
    model = ScriptedModel(turns)
    summary = LocalPlanner(EP, post=model).run(toolbox(ws, cfg, fake_nginx), only=["web"])
    assert "outside the scope" in model.tool_result(1, "c1")["error"]
    assert "JSON object" in model.tool_result(1, "c2")["error"]
    assert "JSON object" in model.tool_result(2, "c3")["error"]
    assert "unknown tool" in model.tool_result(2, "c4")["error"]
    assert "declined" in summary.final_message
    assert "agent.refusal" in events(ws)
    assert events(ws).count("agent.tool_call") == 4


@pytest.mark.usefixtures("_verify_stub")
def test_local_planner_safety_net_on_endpoint_failure(ws, cfg, fake_nginx) -> None:
    """The model dies mid-run after a change was applied: code rolls it back."""

    def approve_apply(model: ScriptedModel) -> dict[str, Any]:
        pid = model.tool_result(1, "c1")["proposal_id"]
        return reply(call(2, "request_approval", proposal_id=pid), call(3, "apply_patch", proposal_id=pid))

    def boom(model: ScriptedModel) -> dict[str, Any]:
        raise RuntimeError("HTTP 503: overloaded")

    turns = [
        reply(call(1, "propose_patch", service="web", ssl_ecdh_curve="X25519MLKEM768:X25519")),
        approve_apply,
        boom,
    ]
    before = Path(fake_nginx["conf"]).read_text()
    summary = LocalPlanner(EP, post=ScriptedModel(turns)).run(
        toolbox(ws, cfg, fake_nginx, approval_waiter=approver(ws))
    )
    assert "endpoint failed" in summary.final_message and "503" in summary.final_message
    assert summary.safety_rollbacks == ["web"]
    assert Path(fake_nginx["conf"]).read_text() == before
    assert "agent.error" in events(ws)


@pytest.mark.usefixtures("_verify_stub")
def test_local_planner_turn_limit_length_and_malformed(ws, cfg, fake_nginx) -> None:
    model = ScriptedModel([reply(call(i, "list_services")) for i in range(5)])
    summary = LocalPlanner(EP, max_turns=3, post=model).run(toolbox(ws, cfg, fake_nginx))
    assert "Stopped after 3 turns" in summary.final_message

    model = ScriptedModel([reply(call(1, "list_services")), reply(text="partial", finish="length"), {"oops": 1}])
    summary = LocalPlanner(EP, post=model).run(toolbox(ws, cfg, fake_nginx))
    assert model.bodies[2]["messages"][-1] == {"role": "user", "content": "Continue."}
    assert "unexpected response" in summary.final_message


# ------------------------------------------------------- endpoint resolution ---


def test_resolve_endpoint_defaults_and_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = AgentConfig()
    ep = resolve_local_endpoint(cfg)
    assert (ep.base_url, ep.model, ep.api_key) == (OLLAMA_URL, "gemma-4-31b-it", None)

    monkeypatch.setenv("GEMINI_API_KEY", "g-key")
    ep = resolve_local_endpoint(cfg)
    assert ep.base_url == GEMINI_OPENAI_URL and ep.api_key == "g-key"
    assert ep.label == "gemma-4-31b-it @ generativelanguage.googleapis.com"

    monkeypatch.setenv("AEGISQ_LLM_BASE_URL", "http://localhost:1234/v1/")
    monkeypatch.setenv("AEGISQ_LLM_MODEL", "gemma4:27b")
    ep = resolve_local_endpoint(cfg)
    # the Gemini key is never sent to some other endpoint
    assert (ep.base_url, ep.model, ep.api_key) == ("http://localhost:1234/v1", "gemma4:27b", None)

    monkeypatch.setenv("AEGISQ_LLM_API_KEY", "k")
    assert resolve_local_endpoint(cfg).api_key == "k"  # loopback http is fine
    monkeypatch.setenv("AEGISQ_LLM_BASE_URL", "http://10.0.0.9:8000/v1")
    with pytest.raises(RuntimeError, match="plain http"):
        resolve_local_endpoint(cfg)
    monkeypatch.setenv("AEGISQ_LLM_BASE_URL", "ftp://x")
    with pytest.raises(RuntimeError, match="http"):
        resolve_local_endpoint(cfg)


def test_resolve_endpoint_gemini_needs_key(monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = AgentConfig(local_base_url=GEMINI_OPENAI_URL)
    with pytest.raises(RuntimeError, match="GEMINI_API_KEY"):
        resolve_local_endpoint(cfg)
    monkeypatch.setenv("GOOGLE_API_KEY", "alt")
    assert resolve_local_endpoint(cfg).api_key == "alt"


def test_choose_planner_auto(monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = AgentConfig()
    assert isinstance(choose_planner("auto", cfg), RulesPlanner)
    monkeypatch.setenv("GEMINI_API_KEY", "g")
    p = choose_planner("auto", cfg)
    assert isinstance(p, LocalPlanner) and p.endpoint.base_url == GEMINI_OPENAI_URL
    assert isinstance(choose_planner("local", cfg), LocalPlanner)
    with pytest.raises(ValueError):
        choose_planner("nope", cfg)


# ------------------------------------------------------------ real HTTP path ---


class _Handler(BaseHTTPRequestHandler):
    script: ClassVar[list[tuple[int, dict[str, str], dict[str, Any]]]] = []
    seen: ClassVar[list[tuple[str, dict[str, Any], str | None]]] = []

    def do_POST(self) -> None:
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        type(self).seen.append((self.path, body, self.headers.get("Authorization")))
        status, headers, payload = type(self).script.pop(0)
        data = json.dumps(payload).encode()
        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args: Any) -> None:
        pass


@pytest.fixture
def chat_server():
    _Handler.script, _Handler.seen = [], []
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    yield f"http://127.0.0.1:{srv.server_port}/v1", _Handler
    srv.shutdown()
    srv.server_close()


def test_http_post_retries_and_auth(chat_server) -> None:
    url, handler = chat_server
    handler.script = [
        (503, {"Retry-After": "0"}, {"error": "busy"}),
        (200, {}, reply(text="ok")),
        (400, {}, {"error": {"message": "bad model name"}}),
    ]
    planner = LocalPlanner(LocalEndpoint(url, "m", "secret"), timeout=5)
    out = planner._create([{"role": "user", "content": "hi"}])
    assert out["choices"][0]["message"]["content"] == "ok"
    path, body, auth = handler.seen[0]
    assert path == "/v1/chat/completions" and auth == "Bearer secret"
    assert body["model"] == "m" and body["tool_choice"] == "auto"
    with pytest.raises(RuntimeError, match="HTTP 400.*bad model name"):
        planner._create([])
    assert len(handler.seen) == 3


def test_retry_delay_hints() -> None:
    gemini_429 = '{"error": {"code": 429, "message": "Quota exceeded ... Please retry in 33.020487226s."}}'
    assert _retry_delay(None, gemini_429, 0) == pytest.approx(34.02, abs=0.01)
    assert _retry_delay(None, '"retryDelay": "12s"', 0) == 13.0
    assert _retry_delay("5", gemini_429, 0) == 5.0
    assert _retry_delay("soon", "", 1) == 4.0
    assert _retry_delay(None, "retry in 999s", 0) == 90.0
    assert _retry_delay(None, "", 10) == 90.0


def test_http_post_unreachable() -> None:
    planner = LocalPlanner(LocalEndpoint("http://127.0.0.1:9/v1", "m", None), timeout=2, retries=0)
    with pytest.raises(RuntimeError, match="cannot reach"):
        planner._create([])
