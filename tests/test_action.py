from __future__ import annotations

from pathlib import Path

import yaml
from click.testing import CliRunner

from aegisq.cli import main

ACTION = Path(__file__).resolve().parents[1] / "action.yml"


def test_action_is_composite_and_read_only() -> None:
    a = yaml.safe_load(ACTION.read_text())
    assert a["runs"]["using"] == "composite"
    assert a["inputs"]["inventory"]["required"] is True
    script = "\n".join(s.get("run", "") for s in a["runs"]["steps"])
    for forbidden in ("migrate", "approve", "serve"):
        assert f"aegisq {forbidden}" not in script


def test_action_uses_real_cli_options() -> None:
    a = yaml.safe_load(ACTION.read_text())
    script = "\n".join(s.get("run", "") for s in a["runs"]["steps"])
    for cmd, flags in {
        "scan": ["--out", "--fail-on"],
        "risk": ["--scan", "--z", "--json"],
        "cbom": ["--scan", "--out"],
    }.items():
        assert f"aegisq {cmd}" in script
        help_text = CliRunner().invoke(main, [cmd, "--help"]).output
        assert all(f in help_text for f in flags), cmd
    assert "at-risk" in CliRunner().invoke(main, ["scan", "--help"]).output
