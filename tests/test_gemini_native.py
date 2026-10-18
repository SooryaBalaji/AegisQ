from __future__ import annotations

import base64
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import pytest

from aegisq.agent import native
from aegisq.agent import runner as runner_mod
from aegisq.agent.runner import GemmaPlanner, LocalEndpoint, openai_tool_specs, resolve_local_endpoint
from aegisq.config import AgentConfig
from test_agent import toolbox
from test_agent import verify_stub as _verify_stub  # noqa: F401

PNG = base64.b64encode(b"\x89PNG\r\n\x1a\nfake").decode()


def test_request_translation() -> None:
    body = {
        "model": "gemma-4-31b-it",
        "messages": [
            {"role": "system", "content": "rules"},
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "read this"},
                    {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{PNG}"}},
                ],
            },
            {
                "role": "assistant",
                "content": "",
                "tool_calls": [
                    {
                        "id": "call_0",
                        "type": "function",
                        "function": {"name": "read_config", "arguments": '{"service": "web"}'},
                        "thought_signature": "sig",
                    }
                ],
            },
            {"role": "tool", "tool_call_id": "call_0", "content": '{"text": "x"}'},
        ],
        "tools": openai_tool_specs(),
        "tool_choice": "auto",
        "temperature": 0,
    }
    out = native.to_native(body)
    assert out["systemInstruction"] == {"parts": [{"text": "rules"}]}
    assert out["contents"][0]["parts"][1] == {"inlineData": {"mimeType": "image/png", "data": PNG}}
    call = out["contents"][1]
    assert call["role"] == "model"
    assert call["parts"][0] == {
        "functionCall": {"name": "read_config", "args": {"service": "web"}},
        "thoughtSignature": "sig",
    }
    assert out["contents"][2]["parts"][0]["functionResponse"] == {
        "name": "read_config",
        "response": {"content": '{"text": "x"}'},
    }
    decls = out["tools"][0]["functionDeclarations"]
    assert {d["name"] for d in decls} == {t["function"]["name"] for t in openai_tool_specs()}
    assert all("parametersJsonSchema" in d for d in decls)
    assert out["toolConfig"] == {"functionCallingConfig": {"mode": "AUTO"}}
    assert out["generationConfig"] == {"temperature": 0}


def test_remote_images_are_refused() -> None:
    body = {"messages": [{"role": "user", "content": [{"type": "image_url", "image_url": {"url": "https://x/y.png"}}]}]}
    with pytest.raises(ValueError, match="inline"):
        native.to_native(body)


def test_response_translation() -> None:
    resp = {
        "candidates": [
            {
                "content": {
                    "parts": [
                        {"text": "private reasoning", "thought": True},
                        {"text": "Listing."},
                        {"functionCall": {"name": "list_services", "args": {}}, "thoughtSignature": "s1"},
                    ]
                },
                "finishReason": "STOP",
            }
        ]
    }
    choice = native.from_native(resp)["choices"][0]
    assert choice["finish_reason"] == "tool_calls"
    assert choice["message"]["content"] == "Listing."
    tc = choice["message"]["tool_calls"][0]
    assert tc["function"] == {"name": "list_services", "arguments": "{}"} and tc["thought_signature"] == "s1"
    assert (
        native.from_native({"promptFeedback": {"blockReason": "SAFETY"}})["choices"][0]["finish_reason"]
        == "content_filter"
    )
    limit = {"candidates": [{"content": {"parts": [{"text": "a"}]}, "finishReason": "MAX_TOKENS"}]}
    assert native.from_native(limit)["choices"][0]["finish_reason"] == "length"


def test_native_base_strips_openai_suffix() -> None:
    assert native.native_base(runner_mod.GEMINI_OPENAI_URL) == native.GEMINI_NATIVE_URL


def test_gemini_defaults_to_native_and_can_be_switched(monkeypatch: pytest.MonkeyPatch) -> None:
    for k in ("AEGISQ_LLM_BASE_URL", "AEGISQ_LLM_MODEL", "AEGISQ_LLM_API_KEY", "AEGISQ_LLM_API", "GOOGLE_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("GEMINI_API_KEY", "g")
    assert resolve_local_endpoint(AgentConfig()).api == "native"
    monkeypatch.setenv("AEGISQ_LLM_API", "openai")
    assert resolve_local_endpoint(AgentConfig()).api == "openai"
    monkeypatch.setenv("AEGISQ_LLM_API", "grpc")
    with pytest.raises(RuntimeError, match="AEGISQ_LLM_API"):
        resolve_local_endpoint(AgentConfig())
    monkeypatch.delenv("GEMINI_API_KEY")
    monkeypatch.setenv("AEGISQ_LLM_API", "native")
    with pytest.raises(RuntimeError, match="only works with the Gemini API"):
        resolve_local_endpoint(AgentConfig())


def fc(name: str, sig: str, **args: Any) -> dict[str, Any]:
    return {
        "candidates": [
            {
                "content": {
                    "role": "model",
                    "parts": [{"functionCall": {"name": name, "args": args}, "thoughtSignature": sig}],
                },
                "finishReason": "STOP",
            }
        ]
    }


class NativeServer:
    def __init__(self, turns: list[Any]) -> None:
        self.turns = turns
        self.requests: list[tuple[str, dict[str, str], dict[str, Any]]] = []
        outer = self

        class H(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                outer.requests.append((self.path, {k.lower(): v for k, v in self.headers.items()}, body))
                turn = outer.turns[len(outer.requests) - 1]
                code, payload = turn if isinstance(turn, tuple) else (200, turn)
                data = json.dumps(payload).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *a: Any) -> None:
                pass

        self.httpd = HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.httpd.server_port}/v1beta"

    def close(self) -> None:
        self.httpd.shutdown()


@pytest.mark.usefixtures("_verify_stub")
def test_planner_over_native_api_keeps_guardrails(ws, cfg, fake_nginx, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runner_mod.time, "sleep", lambda s: None)
    bad = "@@ -8 +8 @@\n-    ssl_ecdh_curve X25519:prime256v1;  # set by platform team\n+    ssl_ecdh_curve X25519MLKEM768:X25519; include /etc/passwd;\n"
    srv = NativeServer(
        [
            (429, {"error": {"details": [{"retryDelay": "0s"}]}}),
            fc("list_services", "s1"),
            fc("propose_patch", "s2", service="web", diff=bad),
            {"candidates": [{"content": {"parts": [{"text": "web: refused."}]}, "finishReason": "STOP"}]},
        ]
    )
    try:
        ep = LocalEndpoint(srv.url, "gemma-4-31b-it", "k", "native")
        summary = GemmaPlanner(ep).run(toolbox(ws, cfg, fake_nginx))
    finally:
        srv.close()
    assert summary.final_message == "web: refused." and summary.tool_calls == 2
    path, headers, first = srv.requests[1]
    assert path == "/v1beta/models/gemma-4-31b-it:generateContent"
    assert headers["x-goog-api-key"] == "k" and "authorization" not in headers
    assert "X25519MLKEM768" in first["systemInstruction"]["parts"][0]["text"]
    last = srv.requests[-1][2]["contents"]
    sent = [p for c in last if c["role"] == "model" for p in c["parts"]]
    assert [p["thoughtSignature"] for p in sent] == ["s1", "s2"]
    answer = json.loads(last[-1]["parts"][0]["functionResponse"]["response"]["content"])
    assert "guardrail" in answer["error"]
    assert "include" not in Path(fake_nginx["conf"]).read_text()


def _busy() -> tuple[int, dict[str, Any]]:
    return 503, {"error": {"code": 503, "message": "This model is currently experiencing high demand."}}


def _text(t: str) -> dict[str, Any]:
    return {"candidates": [{"content": {"parts": [{"text": t}]}, "finishReason": "STOP"}]}


def test_busy_model_hands_over_to_the_other_gemma_4(monkeypatch: pytest.MonkeyPatch) -> None:
    slept: list[float] = []
    monkeypatch.setattr(runner_mod.time, "sleep", slept.append)
    srv = NativeServer([_busy(), _text("from 26b"), _text("again 26b")])
    try:
        ep = LocalEndpoint(srv.url, "gemma-4-31b-it", "k", "native", ("gemma-4-26b-a4b-it",))
        g = GemmaPlanner(ep, retries=2)
        first = g._http_post({"messages": [{"role": "user", "content": "hi"}]})
        second = g._http_post({"messages": [{"role": "user", "content": "hi"}]})
    finally:
        srv.close()
    paths = [r[0].split("/models/")[1] for r in srv.requests]
    assert paths == ["gemma-4-31b-it:generateContent", "gemma-4-26b-a4b-it:generateContent"] * 1 + [
        "gemma-4-26b-a4b-it:generateContent"
    ]
    assert first["model"] == "gemma-4-26b-a4b-it" and first["choices"][0]["message"]["content"] == "from 26b"
    assert second["model"] == "gemma-4-26b-a4b-it" and slept == []
    assert g.models_used == {"gemma-4-26b-a4b-it"}


def test_when_both_models_are_busy_it_waits_and_tries_again(monkeypatch: pytest.MonkeyPatch) -> None:
    slept: list[float] = []
    monkeypatch.setattr(runner_mod.time, "sleep", slept.append)
    srv = NativeServer([_busy(), _busy(), _text("ok")])
    try:
        ep = LocalEndpoint(srv.url, "gemma-4-31b-it", "k", "native", ("gemma-4-26b-a4b-it",))
        out = GemmaPlanner(ep, retries=2)._http_post({"messages": [{"role": "user", "content": "hi"}]})
    finally:
        srv.close()
    assert out["model"] == "gemma-4-31b-it" and len(slept) == 1


def test_both_busy_for_too_long_is_an_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(runner_mod.time, "sleep", lambda s: None)
    srv = NativeServer([_busy()] * 4)
    try:
        ep = LocalEndpoint(srv.url, "gemma-4-31b-it", "k", "native", ("gemma-4-26b-a4b-it",))
        with pytest.raises(RuntimeError, match="every model is busy"):
            GemmaPlanner(ep, retries=1)._http_post({"messages": [{"role": "user", "content": "hi"}]})
    finally:
        srv.close()
    assert len(srv.requests) == 4


def test_a_real_error_does_not_switch_models(monkeypatch: pytest.MonkeyPatch) -> None:
    srv = NativeServer([(400, {"error": {"message": "API key not valid"}})])
    try:
        ep = LocalEndpoint(srv.url, "gemma-4-31b-it", "k", "native", ("gemma-4-26b-a4b-it",))
        with pytest.raises(RuntimeError, match="API key not valid"):
            GemmaPlanner(ep)._http_post({"messages": [{"role": "user", "content": "hi"}]})
    finally:
        srv.close()
    assert len(srv.requests) == 1


def test_fallback_models_default_and_override(monkeypatch: pytest.MonkeyPatch) -> None:
    for k in ("AEGISQ_LLM_BASE_URL", "AEGISQ_LLM_MODEL", "AEGISQ_LLM_API_KEY", "AEGISQ_LLM_API", "GOOGLE_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.delenv("AEGISQ_LLM_FALLBACK_MODELS", raising=False)
    monkeypatch.setenv("GEMINI_API_KEY", "g")
    assert resolve_local_endpoint(AgentConfig()).fallback_models == ("gemma-4-26b-a4b-it",)
    monkeypatch.setenv("AEGISQ_LLM_MODEL", "gemma-4-26b-a4b-it")
    assert resolve_local_endpoint(AgentConfig()).fallback_models == ("gemma-4-31b-it",)
    monkeypatch.setenv("AEGISQ_LLM_FALLBACK_MODELS", "")
    assert resolve_local_endpoint(AgentConfig()).fallback_models == ()
    monkeypatch.delenv("GEMINI_API_KEY")
    monkeypatch.delenv("AEGISQ_LLM_FALLBACK_MODELS")
    monkeypatch.delenv("AEGISQ_LLM_MODEL")
    assert resolve_local_endpoint(AgentConfig()).fallback_models == ()
