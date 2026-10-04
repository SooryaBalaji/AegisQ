"""Typed data model shared by every pipeline stage."""

from __future__ import annotations

import datetime as dt
from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from aegisq.netutil import validate_host, validate_port


def utcnow() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


class Protocol(str, Enum):
    TLS = "tls"
    SSH = "ssh"


class Status(str, Enum):
    PQ_READY = "pq_ready"  # completes a hybrid post-quantum key exchange when it is the only option
    CLASSICAL = "classical"  # TLS 1.3 / modern SSH, but classical key exchange only
    TLS12_ONLY = "tls12_only"  # needs a TLS upgrade before any PQ fix
    LEGACY_TLS = "legacy_tls"  # only TLS 1.0 / 1.1
    PLAINTEXT = "plaintext"  # answers unencrypted HTTP: the worst case
    UNREACHABLE = "unreachable"  # could not connect
    ERROR = "error"  # connected, but the answer was not understood

    @property
    def scanned(self) -> bool:
        return self not in (Status.UNREACHABLE, Status.ERROR)


# ----------------------------------------------------------- inventory ---


class ManagedNginx(BaseModel):
    """How the migration agent may touch a service it owns. Commands are argv lists, never shell strings."""

    model_config = ConfigDict(extra="forbid")

    kind: Literal["nginx"] = "nginx"
    config_path: str
    test_cmd: list[str] = Field(default_factory=lambda: ["nginx", "-t"])
    reload_cmd: list[str] = Field(default_factory=lambda: ["nginx", "-s", "reload"])
    version_cmd: list[str] | None = Field(default_factory=lambda: ["nginx", "-V"])
    health_url: str | None = None
    health_expect: list[int] = Field(default_factory=lambda: list(range(200, 400)))
    command_timeout: float = Field(default=30.0, gt=0, le=600)

    @field_validator("test_cmd", "reload_cmd")
    @classmethod
    def _non_empty(cls, v: list[str]) -> list[str]:
        if not v or any(not isinstance(a, str) or a == "" for a in v):
            raise ValueError("command must be a non-empty argv list of non-empty strings")
        return v


class ServiceTarget(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
    host: str
    port: int
    protocol: Protocol = Protocol.TLS
    sni: str | None = None
    data_category: str = "unknown"
    owner: str | None = None
    tags: list[str] = Field(default_factory=list)
    retention_years: float | None = Field(default=None, ge=0, le=200)  # overrides X
    migration_years: float | None = Field(default=None, ge=0, le=50)  # overrides Y
    stack: dict[str, str] = Field(default_factory=dict)  # e.g. {"openssl": "3.0.11"}
    managed: ManagedNginx | None = None

    @field_validator("host")
    @classmethod
    def _host(cls, v: str) -> str:
        return validate_host(v)

    @field_validator("sni")
    @classmethod
    def _sni(cls, v: str | None) -> str | None:
        return validate_host(v) if v else v

    @field_validator("port")
    @classmethod
    def _port(cls, v: int) -> int:
        return validate_port(v)

    @field_validator("data_category")
    @classmethod
    def _cat(cls, v: str) -> str:
        return v.strip().lower() or "unknown"

    @property
    def endpoint(self) -> str:
        h = f"[{self.host}]" if ":" in self.host else self.host
        return f"{h}:{self.port}"

    @property
    def server_name(self) -> str:
        return self.sni or self.host


# ------------------------------------------------------------- results ---


class ProbeOutcome(BaseModel):
    """Result of one handshake attempt."""

    outcome: Literal["accepted", "rejected", "unreachable", "not_tls", "error", "skipped"]
    version: str | None = None
    group: str | None = None
    cipher_suite: str | None = None
    hello_retry: bool = False
    alert: str | None = None
    detail: str | None = None
    client_hello_bytes: int | None = None
    client_key_share_bytes: int | None = None
    server_key_share_bytes: int | None = None
    elapsed_ms: float | None = None


class CertInfo(BaseModel):
    subject: str
    issuer: str
    serial: str
    not_before: dt.datetime
    not_after: dt.datetime
    days_to_expiry: int
    expired: bool
    self_signed: bool
    key_type: str  # RSA, EC, Ed25519, Ed448, DSA, ML-DSA, ...
    key_size: int | None = None
    curve: str | None = None
    signature_algorithm: str | None = None
    signature_hash: str | None = None
    san: list[str] = Field(default_factory=list)
    sha256_fingerprint: str
    quantum_safe: bool = False


class TLSDetails(BaseModel):
    pq_ready: bool | None = None
    pq_group: str | None = None
    pq_probe: ProbeOutcome | None = None
    modern_probe: ProbeOutcome | None = None  # browser-like offer: what a modern client gets
    tls12_probe: ProbeOutcome | None = None
    supports: dict[str, bool | None] = Field(default_factory=dict)  # "TLSv1.3": True, ...
    tls12_key_exchange: str | None = None
    certificate: CertInfo | None = None
    plaintext_http: bool = False
    http_server: str | None = None


class SSHDetails(BaseModel):
    banner: str | None = None
    software: str | None = None
    kex_algorithms: list[str] = Field(default_factory=list)
    host_key_algorithms: list[str] = Field(default_factory=list)
    ciphers: list[str] = Field(default_factory=list)
    macs: list[str] = Field(default_factory=list)
    pq_ready: bool | None = None
    pq_kex_offered: list[str] = Field(default_factory=list)
    negotiated_kex: str | None = None  # what a PQ-only client would agree on
    weak_kex: list[str] = Field(default_factory=list)
    weak_ciphers: list[str] = Field(default_factory=list)
    weak_macs: list[str] = Field(default_factory=list)
    weak_host_keys: list[str] = Field(default_factory=list)


class ServiceScan(BaseModel):
    service: ServiceTarget
    status: Status
    backend: str = "native"
    scanned_at: dt.datetime = Field(default_factory=utcnow)
    duration_ms: float = 0.0
    resolved_ip: str | None = None
    tls: TLSDetails | None = None
    ssh: SSHDetails | None = None
    errors: list[str] = Field(default_factory=list)
    findings: list[str] = Field(default_factory=list)

    @property
    def pq_ready(self) -> bool:
        return self.status == Status.PQ_READY


class ScanReport(BaseModel):
    scan_id: str
    started_at: dt.datetime
    finished_at: dt.datetime
    tool_version: str
    backend: str
    results: list[ServiceScan]
    environment: dict[str, str] = Field(default_factory=dict)

    def summary(self) -> dict[str, int]:
        out: dict[str, int] = {s.value: 0 for s in Status}
        for r in self.results:
            out[r.status.value] += 1
        out["total"] = len(self.results)
        return out
