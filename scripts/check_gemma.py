import base64
import json
import os
import re
import struct
import sys
import time
import urllib.error
import urllib.request
import zlib


def load_env():
    for path in (".env", os.path.join("demo", ".env")):
        if os.path.isfile(path):
            for line in open(path, encoding="utf-8"):
                name, sep, value = line.strip().partition("=")
                if sep and not name.startswith("#") and name.strip() not in os.environ:
                    os.environ[name.strip()] = value.strip().strip('"').strip("'")


load_env()
KEY = os.environ.get("GEMINI_API_KEY", "")
MODEL = os.environ.get("AEGISQ_LLM_MODEL", "gemma-4-31b-it")
OTHER = {"gemma-4-31b-it": "gemma-4-26b-a4b-it", "gemma-4-26b-a4b-it": "gemma-4-31b-it"}
MODELS = [MODEL] + ([OTHER[MODEL]] if MODEL in OTHER else [])
USED = {"model": MODEL}
BASE = os.environ.get("GEMINI_BASE", "https://generativelanguage.googleapis.com/v1beta")


def red_png(size=32):
    def chunk(kind, data):
        return struct.pack("!I", len(data)) + kind + data + struct.pack("!I", zlib.crc32(kind + data) & 0xFFFFFFFF)

    raw = (b"\x00" + bytes((220, 30, 30)) * size) * size
    ihdr = struct.pack("!IIBBBBB", size, size, 8, 2, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b"")


def call(model, body):
    req = urllib.request.Request(
        f"{BASE}/models/{model}:generateContent",
        data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", "x-goog-api-key": KEY},
    )
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.load(r)


def ask(body, rounds=4):
    order = [USED["model"]] + [m for m in MODELS if m != USED["model"]]
    for attempt in range(rounds):
        wait = 0
        for model in order:
            try:
                out = call(model, body)
            except urllib.error.HTTPError as e:
                if e.code not in (429, 500, 502, 503, 504):
                    raise
                text = e.read().decode(errors="replace")
                hint = re.search(r'(?:retry in|"retryDelay":\s*")\s*([0-9.]+)\s*s', text)
                wait = max(wait, min(float(hint.group(1)) + 1 if hint else 5 * 2**attempt, 60))
                print(f"      {model} is busy (HTTP {e.code})", flush=True)
                continue
            if model != USED["model"]:
                print(f"      switched to {model}", flush=True)
                USED["model"] = model
            return out
        if attempt == rounds - 1:
            raise RuntimeError("every Gemma 4 model is busy; try again in a few minutes")
        print(f"      every model is busy; retrying in {wait:.0f}s", flush=True)
        time.sleep(wait)


def parts(resp):
    return [p for p in resp["candidates"][0]["content"]["parts"] if not p.get("thought")]


def text(resp):
    return "".join(p.get("text", "") for p in parts(resp)).strip()


def check_text():
    out = text(ask({"contents": [{"role": "user", "parts": [{"text": "Reply with exactly the word: ready"}]}]}))
    assert "ready" in out.lower(), out
    return out


def check_image():
    img = base64.b64encode(red_png()).decode()
    body = {
        "contents": [
            {
                "role": "user",
                "parts": [
                    {"text": "What single color fills this image? Answer with one word."},
                    {"inlineData": {"mimeType": "image/png", "data": img}},
                ],
            }
        ]
    }
    out = text(ask(body))
    assert "red" in out.lower(), out
    return out


def check_tool():
    body = {
        "contents": [{"role": "user", "parts": [{"text": "Scan the server example.com on port 443 using the tool."}]}],
        "tools": [
            {
                "functionDeclarations": [
                    {
                        "name": "scan_server",
                        "description": "Scan one server for post-quantum key exchange.",
                        "parameters": {
                            "type": "object",
                            "properties": {"host": {"type": "string"}, "port": {"type": "integer"}},
                            "required": ["host", "port"],
                        },
                    }
                ]
            }
        ],
    }
    calls = [p["functionCall"] for p in parts(ask(body)) if "functionCall" in p]
    assert calls and calls[0]["name"] == "scan_server", calls
    args = calls[0].get("args", {})
    assert args.get("host") == "example.com" and int(args.get("port", 0)) == 443, args
    return json.dumps(args)


def main():
    if not KEY:
        sys.exit("Set GEMINI_API_KEY in demo/.env or your shell (free key: https://aistudio.google.com/apikey)")
    print(f"Testing {MODEL}" + (f" (falls back to {OTHER[MODEL]} when busy)" if MODEL in OTHER else ""))
    failed = 0
    for name, fn in (("text", check_text), ("image", check_image), ("tool call", check_tool)):
        t0 = time.time()
        try:
            detail, ok = fn(), True
        except urllib.error.HTTPError as e:
            detail, ok = f"HTTP {e.code}: {e.read().decode(errors='replace')[:200]}", False
        except Exception as e:
            detail, ok = f"{type(e).__name__}: {e}"[:200], False
        failed += not ok
        print(f"{'PASS' if ok else 'FAIL'}  {name:<10} {time.time() - t0:5.1f}s  [{USED['model']}]  {detail}")
    print("Gemma 4 is working." if not failed else f"{failed} check(s) failed.")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
