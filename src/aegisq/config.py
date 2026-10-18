"""Configuration: a YAML file (``--config`` / ``AEGISQ_CONFIG``) plus environment overrides.

Secrets (the audit HMAC key and the Gemini API key) are read from the
environment only, never from the config file, so the file can be committed. For convenience
the CLI also reads a ``.env`` file (see ``load_env_file``) into the environment.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

# Years data must stay secret, by category. Illustrative defaults; set them from your retention policy.
DEFAULT_RETENTION: dict[str, float] = {
    "health": 25.0,
    "government": 25.0,
    "legal": 15.0,
    "identity": 15.0,
    "pii": 10.0,
    "intellectual-property": 10.0,
    "financial": 7.0,
    "payments": 7.0,
    "internal": 3.0,
    "marketing": 1.0,
    "public": 0.0,
}


# Y: years to migrate, by what the scan found.
DEFAULT_MIGRATION: dict[str, float] = {
    "pq_ready": 0.0,
    "classical": 0.5,  # TLS 1.3, stack unknown: probably a config change
    "classical_modern_stack": 0.1,  # TLS 1.3 on OpenSSL >= 3.5: one config line
    "classical_old_stack": 1.5,  # TLS 1.3 on an older OpenSSL: library upgrade first
    "tls12_only": 2.0,
    "legacy_tls": 3.0,
    "plaintext": 3.0,
    "ssh_classical": 1.0,
}


class RiskConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    z_years: float = Field(default=10.0, ge=0, le=100)
    # X: years the data must stay secret, by category. Illustrative defaults; set from retention policy.
    data_categories: dict[str, float] = Field(default_factory=lambda: dict(DEFAULT_RETENTION))
    default_retention_years: float = Field(default=10.0, ge=0)
    # Y: years to migrate, by what the scan found.
    migration_years: dict[str, float] = Field(default_factory=lambda: dict(DEFAULT_MIGRATION))

    @field_validator("migration_years")
    @classmethod
    def _merge_y(cls, v: dict[str, float]) -> dict[str, float]:
        unknown = set(v) - set(DEFAULT_MIGRATION)
        if unknown:
            raise ValueError(f"unknown migration_years keys: {sorted(unknown)}")
        if any(x < 0 for x in v.values()):
            raise ValueError("migration years must be >= 0")
        return {**DEFAULT_MIGRATION, **{k: float(x) for k, x in v.items()}}

    @field_validator("data_categories")
    @classmethod
    def _lower(cls, v: dict[str, float]) -> dict[str, float]:
        if any(x < 0 for x in v.values()):
            raise ValueError("retention years must be >= 0")
        return {**DEFAULT_RETENTION, **{k.strip().lower(): float(x) for k, x in v.items()}}


class ScopeConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    allow: list[str] = Field(default_factory=list)
    deny: list[str] = Field(default_factory=list)


class ScanConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    timeout: float = Field(default=5.0, gt=0, le=120)
    concurrency: int = Field(default=50, ge=1, le=1000)
    legacy_protocols: bool = True
    scope: ScopeConfig = Field(default_factory=ScopeConfig)


class AgentConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # Gemma 4 planner. Unset base_url: Google's Gemini API when GEMINI_API_KEY is set, else Ollama on this machine.
    # Unset model: gemma-4-31b-it on the Gemini API, gemma4:e4b on Ollama. AEGISQ_LLM_BASE_URL / AEGISQ_LLM_MODEL
    # override both; the key comes only from the environment.
    model: str | None = Field(default=None, min_length=1, max_length=200)
    base_url: str | None = Field(default=None, pattern=r"^https?://")

    @model_validator(mode="before")
    @classmethod
    def _older_keys(cls, data: Any) -> Any:
        """Configs written for earlier versions: local_model / local_base_url were renamed; effort is gone."""
        if not isinstance(data, dict):
            return data
        data = dict(data)
        if "local_model" in data or "effort" in data:  # old layout: `model` named the removed hosted planner
            data.pop("model", None)
        for old, new in (("local_model", "model"), ("local_base_url", "base_url")):
            if old in data:
                data.setdefault(new, data.pop(old))
        data.pop("effort", None)
        return data

    max_turns: int = Field(default=80, ge=1, le=500)
    approval_timeout_s: float = Field(default=1800, gt=0)
    approval_ttl_s: float = Field(default=3600, gt=0)
    require_classical_fallback: bool = True
    # The person who starts a migration may not approve its changes; turn off only for one-person setups.
    separation_of_duties: bool = True
    min_tls_version: str = Field(default="TLSv1.2", pattern=r"^TLSv1\.[23]$")
    allowed_groups: list[str] = Field(
        default_factory=lambda: [
            "X25519MLKEM768",
            "SecP256r1MLKEM768",
            "SecP384r1MLKEM1024",
            "X25519",
            "secp256r1",
            "prime256v1",
            "P-256",
            "secp384r1",
            "P-384",
            "secp521r1",
            "P-521",
            "X448",
        ]
    )
    # OpenSSH KexAlgorithms the agent may write: PQ hybrids plus OpenSSH's classical defaults.
    allowed_ssh_kex: list[str] = Field(
        default_factory=lambda: [
            "mlkem768x25519-sha256",
            "sntrup761x25519-sha512",
            "sntrup761x25519-sha512@openssh.com",
            "curve25519-sha256",
            "curve25519-sha256@libssh.org",
            "ecdh-sha2-nistp256",
            "ecdh-sha2-nistp384",
            "ecdh-sha2-nistp521",
            "diffie-hellman-group-exchange-sha256",
            "diffie-hellman-group16-sha512",
            "diffie-hellman-group18-sha512",
            "diffie-hellman-group14-sha256",
        ]
    )
    verify_attempts: int = Field(default=5, ge=1, le=30)
    verify_interval_s: float = Field(default=1.0, ge=0, le=30)


class ServerConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    host: str = "127.0.0.1"
    port: int = Field(default=8000, ge=1, le=65535)


class AegisQConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    home: str = ".aegisq"
    risk: RiskConfig = Field(default_factory=RiskConfig)
    scan: ScanConfig = Field(default_factory=ScanConfig)
    agent: AgentConfig = Field(default_factory=AgentConfig)
    server: ServerConfig = Field(default_factory=ServerConfig)

    @property
    def home_path(self) -> Path:
        return Path(os.environ.get("AEGISQ_HOME") or self.home).expanduser().resolve()


def load_config(path: str | Path | None = None) -> AegisQConfig:
    path = path or os.environ.get("AEGISQ_CONFIG")
    if not path:
        return AegisQConfig()
    p = Path(path)
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as e:
        raise ValueError(f"cannot load config {p}: {e}") from e
    if not isinstance(data, dict):
        raise ValueError(f"config {p} must be a mapping")
    return AegisQConfig.model_validate(data)


_ENV_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$")


def load_env_file(path: str | Path | None = None) -> tuple[Path, int] | None:
    """Read KEY=VALUE lines from a .env file into the environment, like Docker Compose does.

    The file is ``path``, else ``$AEGISQ_ENV_FILE``, else ``.env``, else ``demo/.env`` in the current
    directory, so the same file serves the Docker demo and the native CLI. Variables already set to a
    non-empty value win. Returns (file, number of variables set), or None if there is no file.
    """
    if path is None and os.environ.get("AEGISQ_ENV_FILE"):
        path = os.environ["AEGISQ_ENV_FILE"]
    candidates = [Path(path)] if path is not None else [Path(".env"), Path("demo") / ".env"]
    for f in candidates:
        if not f.is_file():
            continue
        n = 0
        for line in f.read_text(encoding="utf-8-sig").splitlines():
            m = _ENV_LINE.match(line)
            if not m or line.lstrip().startswith("#"):
                continue
            key, value = m.groups()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            if value and not os.environ.get(key):
                os.environ[key] = value
                n += 1
        return f, n
    return None
