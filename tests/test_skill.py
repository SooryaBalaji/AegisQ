"""The Agent Skill in skills/ follows the Agent Skills specification, and its script works end to end."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from fakes import ssh_server, tls_server

SKILL = Path(__file__).resolve().parents[1] / "skills" / "aegisq-pq-scan"


def frontmatter() -> dict[str, object]:
    text = (SKILL / "SKILL.md").read_text(encoding="utf-8")
    m = re.match(r"^---\n(.*?)\n---\n", text, re.S)
    assert m, "SKILL.md must start with YAML frontmatter"
    data = yaml.safe_load(m.group(1))
    assert isinstance(data, dict)
    return data


def test_frontmatter_follows_the_spec() -> None:
    fm = frontmatter()
    name = str(fm["name"])
    assert name == SKILL.name
    assert re.fullmatch(r"[a-z0-9]+(-[a-z0-9]+)*", name) and len(name) <= 64
    assert 0 < len(str(fm["description"])) <= 1024
    assert len(str(fm.get("compatibility", ""))) <= 500
    assert all(isinstance(v, str) for v in dict(fm.get("metadata") or {}).values())
    assert len((SKILL / "SKILL.md").read_text(encoding="utf-8").splitlines()) < 500
    assert (SKILL / "scripts" / "pq_check.py").is_file() and (SKILL / "references" / "REFERENCE.md").is_file()


def test_reference_validator_if_installed() -> None:
    skills_ref = pytest.importorskip("skills_ref")
    assert skills_ref.validate(SKILL) == []


def test_script_scans_and_writes_a_cbom(tmp_path: Path) -> None:
    with tls_server("pq") as pq, tls_server("classical") as classical, ssh_server("classical") as ssh:
        res = subprocess.run(
            [
                sys.executable,
                str(SKILL / "scripts" / "pq_check.py"),
                f"127.0.0.1:{pq.port}",
                f"127.0.0.1:{classical.port}",
                f"127.0.0.1:{ssh.port}",
                "ssh",
                "--cbom",
                str(tmp_path / "cbom.json"),
            ],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    assert res.returncode == 0, res.stderr
    out = json.loads(res.stdout)
    assert out["summary"] == {"servers": 3, "pq_ready": 1, "reached": 3}
    by = {s["status"]: s for s in out["servers"]}
    assert by["pq_ready"]["key_exchange"] == "X25519MLKEM768" and "fix" not in by["pq_ready"]
    assert any("KexAlgorithms" in s.get("fix", "") for s in out["servers"])
    assert json.loads((tmp_path / "cbom.json").read_text())["specVersion"] == "1.6"
