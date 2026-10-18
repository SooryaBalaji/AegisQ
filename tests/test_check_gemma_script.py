from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check_gemma.py"


def serve(answers: dict[str, Any]) -> tuple[HTTPServer, list[dict[str, Any]]]:
    seen: list[dict[str, Any]] = []

    class H(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            seen.append({"path": self.path, "key": self.headers.get("x-goog-api-key"), "body": body})
            parts = body["contents"][0]["parts"]
            kind = "tool" if "tools" in body else "image" if any("inlineData" in p for p in parts) else "text"
            data = json.dumps({"candidates": [{"content": {"parts": answers[kind]}}]}).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *a: Any) -> None:
            pass

    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, seen


def run(srv: HTTPServer, key: str = "k") -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "GEMINI_API_KEY": key, "GEMINI_BASE": f"http://127.0.0.1:{srv.server_port}/v1beta"}
    env.pop("AEGISQ_LLM_MODEL", None)
    return subprocess.run(
        [sys.executable, str(SCRIPT)], env=env, capture_output=True, text=True, timeout=60, check=False
    )


GOOD = {
    "text": [{"text": "ready"}],
    "image": [{"text": "thinking", "thought": True}, {"text": "Red"}],
    "tool": [{"functionCall": {"name": "scan_server", "args": {"host": "example.com", "port": 443}}}],
}


def test_passes_when_gemma_answers_correctly() -> None:
    srv, seen = serve(GOOD)
    try:
        res = run(srv)
    finally:
        srv.shutdown()
    assert res.returncode == 0, res.stdout + res.stderr
    assert res.stdout.count("PASS") == 3 and "Gemma 4 is working." in res.stdout
    assert {s["path"] for s in seen} == {"/v1beta/models/gemma-4-31b-it:generateContent"}
    assert all(s["key"] == "k" for s in seen)


def test_fails_on_a_wrong_answer() -> None:
    srv, _ = serve({**GOOD, "image": [{"text": "Blue"}]})
    try:
        res = run(srv)
    finally:
        srv.shutdown()
    assert res.returncode == 1 and "FAIL  image" in res.stdout and "1 check(s) failed." in res.stdout


def test_needs_a_key() -> None:
    env = {k: v for k, v in os.environ.items() if k != "GEMINI_API_KEY"}
    res = subprocess.run(
        [sys.executable, str(SCRIPT)], env=env, capture_output=True, text=True, timeout=30, check=False
    )
    assert res.returncode == 1 and "GEMINI_API_KEY" in res.stderr
