"""Live checks against the configured Gemma 4 endpoint: run these before relying on the model.

Each check sends one real request and passes only on the expected answer: a tool call, an answer about an
image, and a claim extraction from a known config snippet.
"""

from __future__ import annotations

import json
import struct
import time
import zlib
from collections.abc import Callable
from typing import Any

from aegisq.agent.claims import ClaimError, extract

Post = Callable[[dict[str, Any]], dict[str, Any]]

SAMPLE = """# /etc/postfix/main.cf on mail.example.com
smtpd_tls_security_level = may
tls_eecdh_auto_curves = X25519MLKEM768, X25519, prime256v1
"""


def solid_png(rgb: tuple[int, int, int] = (220, 30, 30), size: int = 32) -> bytes:
    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack("!I", len(data)) + kind + data + struct.pack("!I", zlib.crc32(kind + data) & 0xFFFFFFFF)

    row = b"\x00" + bytes(rgb) * size
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack("!IIBBBBB", size, size, 8, 2, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(row * size))
        + chunk(b"IEND", b"")
    )


def _text(resp: dict[str, Any]) -> str:
    content = resp["choices"][0]["message"].get("content") or ""
    if isinstance(content, list):
        content = "".join(p.get("text", "") for p in content if isinstance(p, dict))
    return str(content)


def _tool_call(post: Post, model: str) -> str:
    from aegisq.agent.runner import openai_tool_specs

    resp = post(
        {
            "model": model,
            "messages": [
                {"role": "system", "content": "You operate a server fleet through tools."},
                {"role": "user", "content": "Call list_services now. Do not answer in text."},
            ],
            "tools": openai_tool_specs(),
            "tool_choice": "auto",
        }
    )
    calls = resp["choices"][0]["message"].get("tool_calls") or []
    names = [str((c.get("function") or {}).get("name")) for c in calls]
    if "list_services" not in names:
        raise AssertionError(f"expected a list_services call, got {names or 'text: ' + _text(resp)[:120]!r}")
    json.loads((calls[names.index("list_services")].get("function") or {}).get("arguments") or "{}")
    return "called list_services with valid JSON arguments"


def _image(post: Post, model: str) -> str:
    import base64

    url = "data:image/png;base64," + base64.b64encode(solid_png()).decode()
    resp = post(
        {
            "model": model,
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "What single color fills this image? Answer with one word."},
                        {"type": "image_url", "image_url": {"url": url}},
                    ],
                }
            ],
            "temperature": 0,
        }
    )
    answer = _text(resp).strip()
    if "red" not in answer.lower():
        raise AssertionError(f"expected 'red' for a red image, got {answer[:80]!r}")
    return f"read the test image: {answer[:40]!r}"


def _claims(post: Post, model: str) -> str:
    ext = extract(post, model, text=SAMPLE)
    hit = [c for c in ext.endpoints if c.host == "mail.example.com"]
    if not hit:
        raise AssertionError(f"expected mail.example.com, got {[c.label for c in ext.endpoints]}")
    c = hit[0]
    if c.pq_expected is not True:
        raise AssertionError("did not read the post-quantum group list as a post-quantum claim")
    if c.grounded is not True:
        raise AssertionError(f"evidence {c.evidence[:80]!r} is not quoted from the input")
    return f"extracted {c.label}, post-quantum claim, evidence quoted from the input"


CHECKS: tuple[tuple[str, Callable[[Post, str], str]], ...] = (
    ("tool calling", _tool_call),
    ("image input", _image),
    ("claim extraction", _claims),
)


def run_checks(post: Post, model: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for name, fn in CHECKS:
        t0 = time.perf_counter()
        try:
            detail, ok = fn(post, model), True
        except (AssertionError, ClaimError, RuntimeError, KeyError, IndexError, TypeError, ValueError) as e:
            detail, ok = str(e)[:300], False
        out.append({"check": name, "ok": ok, "seconds": round(time.perf_counter() - t0, 2), "detail": detail})
    return out
