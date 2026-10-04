"""Risk scoring with Mosca's inequality: a service is at risk when X + Y > Z.

X  years the data must stay secret (from its data category or an explicit override)
Y  years to migrate (from what the scan found about the service)
Z  years until a cryptographically relevant quantum computer (a slider; nobody knows it)

The score is the margin X + Y - Z. Positive means recorded traffic is already
at risk; bigger margins are fixed first. Services that already complete a
post-quantum key exchange score zero.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass

from aegisq.config import RiskConfig
from aegisq.models import Protocol, ServiceScan, Status


@dataclass
class RiskScore:
    service: str
    status: str
    data_category: str
    x_retention: float
    y_migration: float
    z_quantum: float
    margin: float
    score: float  # margin for exposed services, 0 for ready ones
    at_risk: bool
    severity: str  # critical | high | medium | low | none | unknown
    breaks_even_z: float | None  # at risk for every Z below this value; None = at risk for every Z
    y_reason: str
    rank: int = 0

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def retention_years(scan: ServiceScan, cfg: RiskConfig) -> float:
    if scan.service.retention_years is not None:
        return float(scan.service.retention_years)
    return float(cfg.data_categories.get(scan.service.data_category, cfg.default_retention_years))


def _openssl_known_modern(stack: dict[str, str]) -> bool | None:
    v = stack.get("openssl")
    if not v:
        return None
    try:
        parts = tuple(int(p) for p in v.split(".")[:2])
    except ValueError:
        return None
    return parts >= (3, 5)


def migration_years(scan: ServiceScan, cfg: RiskConfig) -> tuple[float, str]:
    if scan.service.migration_years is not None:
        return float(scan.service.migration_years), "set in inventory"
    m = cfg.migration_years
    st = scan.status
    if st == Status.PQ_READY:
        return m["pq_ready"], "already post-quantum"
    if st == Status.PLAINTEXT:
        return m["plaintext"], "plaintext: readable today whatever Z is; deploy TLS 1.3 first"
    if st == Status.LEGACY_TLS:
        return m["legacy_tls"], "TLS 1.0/1.1 only: stack replacement"
    if st == Status.TLS12_ONLY:
        return m["tls12_only"], "TLS 1.2 only: TLS upgrade before any PQ change"
    if scan.service.protocol == Protocol.SSH:
        return m["ssh_classical"], "OpenSSH upgrade or KexAlgorithms change"
    modern = _openssl_known_modern(scan.service.stack)
    if modern is True:
        return m["classical_modern_stack"], "TLS 1.3 on OpenSSL 3.5+: one config line"
    if modern is False:
        return m["classical_old_stack"], f"TLS 1.3 on OpenSSL {scan.service.stack.get('openssl')}: upgrade first"
    return m["classical"], "TLS 1.3, TLS library version unknown"


def _severity(margin: float, ready: bool) -> str:
    if ready:
        return "none"
    if margin >= 10:
        return "critical"
    if margin > 0:
        return "high"
    if margin > -5:
        return "medium"
    return "low"


def score_service(scan: ServiceScan, cfg: RiskConfig, z: float | None = None) -> RiskScore:
    z = cfg.z_years if z is None else z
    if z < 0:
        raise ValueError("Z must be >= 0")
    x = retention_years(scan, cfg)
    if not scan.status.scanned:
        return RiskScore(
            scan.service.name,
            scan.status.value,
            scan.service.data_category,
            x,
            0.0,
            z,
            0.0,
            0.0,
            False,
            "unknown",
            0.0,
            "not scanned: " + "; ".join(scan.errors)[:200],
        )
    y, why = migration_years(scan, cfg)
    ready = scan.status == Status.PQ_READY
    # Plaintext is readable today: no quantum computer is needed, so Z does not discount it.
    z_eff = 0.0 if scan.status == Status.PLAINTEXT else z
    margin = round(x + y - z_eff, 3)
    return RiskScore(
        service=scan.service.name,
        status=scan.status.value,
        data_category=scan.service.data_category,
        x_retention=x,
        y_migration=y,
        z_quantum=z,
        margin=margin,
        score=0.0 if ready else margin,
        at_risk=(not ready) and margin > 0,
        severity="critical" if scan.status == Status.PLAINTEXT else _severity(margin, ready),
        breaks_even_z=0.0 if ready else (None if scan.status == Status.PLAINTEXT else round(x + y, 3)),
        y_reason=why,
    )


def rank(scans: list[ServiceScan], cfg: RiskConfig, z: float | None = None) -> list[RiskScore]:
    """Priority order: exposed services by descending margin, then unknowns, then ready ones."""
    scores = [score_service(s, cfg, z) for s in scans]

    def key(r: RiskScore) -> tuple[int, float, float, str]:
        group = 0 if r.severity not in ("none", "unknown") else (1 if r.severity == "unknown" else 2)
        return (group, -r.margin, -r.x_retention, r.service)

    scores.sort(key=key)
    for i, r in enumerate(scores, 1):
        r.rank = i
    return scores


def sweep(scans: list[ServiceScan], cfg: RiskConfig, z_values: list[float]) -> dict[str, list[bool]]:
    """For each service, whether it is at risk at each assumed Z. Shows robustness across assumptions."""
    out: dict[str, list[bool]] = {}
    for s in scans:
        out[s.service.name] = [score_service(s, cfg, z).at_risk for z in z_values]
    return out


# Published resource estimates shown beside the Z slider, so the assumption has a visible source.
RESOURCE_ESTIMATES = [
    {
        "estimate": "Google Quantum AI, March 2026",
        "target": "256-bit elliptic curve",
        "logical_qubits": "≤ 1,200 (≤ 90M Toffoli) or ≤ 1,450 (≤ 70M Toffoli)",
        "physical_qubits": "Under 500,000 superconducting",
        "runtime": "Minutes",
    },
    {
        "estimate": "IonQ, 2026",
        "target": "256-bit elliptic curve",
        "logical_qubits": "1,457 (39M Toffoli)",
        "physical_qubits": "About 20,000 trapped-ion",
        "runtime": "About 26 days per attempt",
    },
    {
        "estimate": "Gidney, May 2025",
        "target": "RSA-2048",
        "logical_qubits": "n/a",
        "physical_qubits": "Under 1,000,000 superconducting",
        "runtime": "Under a week",
    },
]
RESOURCE_ESTIMATE_NOTE = (
    "These estimates target secp256k1; X25519 uses Curve25519, a different curve of the same size, "
    "so they are a close proxy rather than an exact figure. Current IBM processors have ~156 physical "
    "qubits and no error-corrected logical qubits at this scale: the threat is future, but traffic "
    "recorded today is already exposed."
)
