"""Load the service inventory: a YAML/JSON fleet file or a plain host list."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from aegisq.models import Protocol, ServiceTarget
from aegisq.netutil import TargetError, parse_endpoint

MAX_SERVICES = 100_000


class InventoryError(ValueError):
    pass


def load_inventory(path: str | Path) -> list[ServiceTarget]:
    p = Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as e:
        raise InventoryError(f"cannot read inventory {p}: {e}") from e
    if p.suffix.lower() in (".yaml", ".yml", ".json"):
        try:
            data = json.loads(text) if p.suffix.lower() == ".json" else yaml.safe_load(text)
        except (yaml.YAMLError, json.JSONDecodeError) as e:
            raise InventoryError(f"{p}: not valid {p.suffix[1:].upper()}: {e}") from e
        targets = parse_inventory_doc(data, base_dir=p.parent)
    else:
        targets = parse_host_list(text)
    _check_unique(targets)
    return targets


def parse_inventory_doc(data: Any, base_dir: Path | None = None) -> list[ServiceTarget]:
    if not isinstance(data, dict) or not isinstance(data.get("services"), list):
        raise InventoryError("inventory must be a mapping with a 'services' list")
    defaults = data.get("defaults") or {}
    if not isinstance(defaults, dict):
        raise InventoryError("'defaults' must be a mapping")
    if len(data["services"]) > MAX_SERVICES:
        raise InventoryError(f"more than {MAX_SERVICES} services")
    out: list[ServiceTarget] = []
    for i, raw in enumerate(data["services"]):
        if not isinstance(raw, dict):
            raise InventoryError(f"services[{i}] must be a mapping")
        merged = {**defaults, **raw}
        if "port" not in merged:
            proto = str(merged.get("protocol", "tls")).lower()
            merged["port"] = 22 if proto == "ssh" else 443
        if "name" not in merged and "host" in merged:
            merged["name"] = _auto_name(str(merged["host"]), int(merged["port"]))
        managed = merged.get("managed")
        if isinstance(managed, dict) and base_dir is not None and "config_path" in managed:
            cp = Path(str(managed["config_path"]))
            merged["managed"] = {**managed, "config_path": str(cp if cp.is_absolute() else (base_dir / cp).resolve())}
        try:
            out.append(ServiceTarget.model_validate(merged))
        except ValidationError as e:
            raise InventoryError(f"services[{i}] ({raw.get('name', '?')}): {_fmt(e)}") from None
    return out


def parse_host_list(text: str) -> list[ServiceTarget]:
    """One target per line: ``host[:port] [tls|ssh] [data_category]``. '#' starts a comment."""
    out: list[ServiceTarget] = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) > 3:
            raise InventoryError(f"line {lineno}: expected 'host[:port] [tls|ssh] [category]'")
        proto = parts[1].lower() if len(parts) > 1 else None
        if proto not in (None, "tls", "ssh"):
            raise InventoryError(f"line {lineno}: protocol must be tls or ssh, got {parts[1]!r}")
        try:
            host, port = parse_endpoint(parts[0], default_port=22 if proto == "ssh" else 443)
        except (TargetError, ValueError) as e:
            raise InventoryError(f"line {lineno}: {e}") from None
        protocol = Protocol(proto) if proto else (Protocol.SSH if port == 22 else Protocol.TLS)
        try:
            out.append(
                ServiceTarget(
                    name=_auto_name(host, port),
                    host=host,
                    port=port,
                    protocol=protocol,
                    data_category=parts[2] if len(parts) > 2 else "unknown",
                )
            )
        except ValidationError as e:
            raise InventoryError(f"line {lineno}: {_fmt(e)}") from None
        if len(out) > MAX_SERVICES:
            raise InventoryError(f"more than {MAX_SERVICES} services")
    return out


def _auto_name(host: str, port: int) -> str:
    safe = "".join(c if c.isalnum() or c in "._-" else "-" for c in host).strip("-.") or "host"
    return f"{safe[:56]}-{port}"


def _check_unique(targets: list[ServiceTarget]) -> None:
    seen: set[str] = set()
    for t in targets:
        if t.name in seen:
            raise InventoryError(f"duplicate service name {t.name!r}")
        seen.add(t.name)


def _fmt(e: ValidationError) -> str:
    return "; ".join(f"{'.'.join(map(str, err['loc'])) or 'value'}: {err['msg']}" for err in e.errors())
