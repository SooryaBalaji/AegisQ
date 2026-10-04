"""Configuration: a YAML file (``--config`` / ``AEGISQ_CONFIG``) plus environment overrides.

Secrets (API tokens, the audit HMAC key, model and IBM keys) are read from the
environment only, never from the config file, so the file can be committed. For convenience
the CLI also reads a ``.env`` file (see ``load_env_file``) into the environment.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator

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
    model: str = "claude-opus-5-5"
    # --planner local: any OpenAI-compatible chat endpoint (Gemini API, Ollama, LM Studio, llama.cpp, vLLM).
    # Unset base URL: the Gemini API when GEMINI_API_KEY is set, else Ollama on this machine.
    # Overridden by AEGISQ_LLM_BASE_URL / AEGISQ_LLM_MODEL; the key comes only from the environment.
    local_model: str = Field(default="gemma-4-31b-it", min_length=1, max_length=200)
    local_base_url: str | None = Field(default=None, pattern=r"^https?://")
    effort: str = Field(default="high", pattern="^(low|medium|high|xhigh|max)$")
    max_turns: int = Field(default=80, ge=1, le=500)
    approval_timeout_s: float = Field(default=1800, gt=0)
    approval_ttl_s: float = Field(default=3600, gt=0)
    require_classical_fallback: bool = True
    min_tls_version: str = Field(default="TLSv1.2", pattern=r"^TLSv1\.[23]$")
    allowed_groups: list[str] = Field(
        default_factory=lambda: [
            "X25519MLKEM768",
            "SecP256r1MLKEM768",
            "SecP384r1MLKEM1024",
            "X25519",
            "secp256r1",
            "prime256v1",
            "secp384r1",
            "secp521r1",
            "X448",
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


def api_tokens() -> dict[str, str]:
    """Parse AEGISQ_API_TOKENS='alice:tok1,bob:tok2' into {token: identity}."""
    raw = os.environ.get("AEGISQ_API_TOKENS", "").strip()
    out: dict[str, str] = {}
    for item in filter(None, (s.strip() for s in raw.split(","))):
        if ":" not in item:
            raise ValueError("AEGISQ_API_TOKENS entries must look like name:token")
        name, tok = item.split(":", 1)
        if len(tok) < 16:
            raise ValueError(f"API token for {name!r} is shorter than 16 characters")
        out[tok] = name.strip()
    return out
