"""Gemma 4 through the Gemini API's native ``generateContent`` method.

AegisQ speaks the OpenAI chat format everywhere (planner, claim check, live check). Google documents Gemma on
the Gemini API with the native method, so this module translates one request and one response between the
two formats. Nothing else changes: the same tools, the same guardrails, the same audit log.
"""

from __future__ import annotations

import json
import re
from typing import Any

GEMINI_NATIVE_URL = "https://generativelanguage.googleapis.com/v1beta"

_DATA_URL_RE = re.compile(r"^data:([\w.+-]+/[\w.+-]+);base64,(.+)$", re.S)
_FINISH = {
    "STOP": "stop",
    "MAX_TOKENS": "length",
    "SAFETY": "content_filter",
    "RECITATION": "content_filter",
    "PROHIBITED_CONTENT": "content_filter",
    "BLOCKLIST": "content_filter",
    "SPII": "content_filter",
}


def native_base(base_url: str) -> str:
    """The native API root for a configured base URL (the OpenAI-compatible path ends in /openai)."""
    base = base_url.rstrip("/")
    return base[: -len("/openai")] if base.endswith("/openai") else base


def _parts(content: Any) -> list[dict[str, Any]]:
    if content is None:
        return []
    if isinstance(content, str):
        return [{"text": content}] if content else []
    out: list[dict[str, Any]] = []
    for p in content:
        if not isinstance(p, dict):
            continue
        if p.get("type") == "text":
            out.append({"text": str(p.get("text", ""))})
        elif p.get("type") == "image_url":
            url = str((p.get("image_url") or {}).get("url", ""))
            m = _DATA_URL_RE.match(url)
            if not m:
                raise ValueError("only inline (data:) images can be sent to the native API")
            out.append({"inlineData": {"mimeType": m.group(1), "data": m.group(2)}})
    return out


def to_native(body: dict[str, Any]) -> dict[str, Any]:
    """An OpenAI ``/chat/completions`` body as a native ``generateContent`` body."""
    system: list[dict[str, Any]] = []
    contents: list[dict[str, Any]] = []
    names: dict[str, str] = {}
    for m in body.get("messages", []):
        role = m.get("role")
        if role == "system":
            system.extend(_parts(m.get("content")))
        elif role == "user":
            contents.append({"role": "user", "parts": _parts(m.get("content"))})
        elif role == "assistant":
            parts = _parts(m.get("content"))
            for tc in m.get("tool_calls") or []:
                fn = tc.get("function") or {}
                names[str(tc.get("id", ""))] = str(fn.get("name", ""))
                raw = fn.get("arguments") or "{}"
                try:
                    args = json.loads(raw) if isinstance(raw, str) else raw
                except json.JSONDecodeError:
                    args = {}
                part: dict[str, Any] = {"functionCall": {"name": fn.get("name", ""), "args": args or {}}}
                if tc.get("thought_signature"):
                    part["thoughtSignature"] = tc["thought_signature"]
                parts.append(part)
            if parts:
                contents.append({"role": "model", "parts": parts})
        elif role == "tool":
            name = names.get(str(m.get("tool_call_id", "")), "tool")
            reply = {"functionResponse": {"name": name, "response": {"content": str(m.get("content", ""))}}}
            if contents and contents[-1]["role"] == "user" and "functionResponse" in contents[-1]["parts"][0]:
                contents[-1]["parts"].append(reply)
            else:
                contents.append({"role": "user", "parts": [reply]})
    out: dict[str, Any] = {"contents": contents}
    if system:
        out["systemInstruction"] = {"parts": system}
    tools = body.get("tools") or []
    if tools:
        out["tools"] = [
            {
                "functionDeclarations": [
                    {
                        "name": t["function"]["name"],
                        "description": t["function"].get("description", ""),
                        "parametersJsonSchema": t["function"].get("parameters") or {"type": "object"},
                    }
                    for t in tools
                    if t.get("type") == "function"
                ]
            }
        ]
        mode = {"auto": "AUTO", "none": "NONE", "required": "ANY"}.get(str(body.get("tool_choice", "auto")), "AUTO")
        out["toolConfig"] = {"functionCallingConfig": {"mode": mode}}
    if "temperature" in body:
        out["generationConfig"] = {"temperature": body["temperature"]}
    return out


def from_native(resp: dict[str, Any]) -> dict[str, Any]:
    """A native ``generateContent`` response as an OpenAI ``/chat/completions`` response."""
    block = (resp.get("promptFeedback") or {}).get("blockReason")
    cands = resp.get("candidates") or []
    if block or not cands:
        return {"choices": [{"message": {"role": "assistant", "content": ""}, "finish_reason": "content_filter"}]}
    cand = cands[0]
    text: list[str] = []
    calls: list[dict[str, Any]] = []
    for part in (cand.get("content") or {}).get("parts") or []:
        if part.get("thought"):
            continue
        if "functionCall" in part:
            fc = part["functionCall"]
            call: dict[str, Any] = {
                "id": f"call_{len(calls)}",
                "type": "function",
                "function": {"name": fc.get("name", ""), "arguments": json.dumps(fc.get("args") or {})},
            }
            if part.get("thoughtSignature"):
                call["thought_signature"] = part["thoughtSignature"]
            calls.append(call)
        elif "text" in part:
            text.append(str(part["text"]))
    message: dict[str, Any] = {"role": "assistant", "content": "".join(text)}
    if calls:
        message["tool_calls"] = calls
    reason = "tool_calls" if calls else _FINISH.get(str(cand.get("finishReason", "STOP")), "stop")
    return {"choices": [{"message": message, "finish_reason": reason}]}
