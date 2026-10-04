from aegisq.config import RiskConfig
from aegisq.models import Protocol, ServiceScan, ServiceTarget, Status
from aegisq.risk import rank, score_service, sweep


def scan(name, status, cat="health", protocol=Protocol.TLS, **svc):
    return ServiceScan(
        service=ServiceTarget(name=name, host="h.example", port=443, protocol=protocol, data_category=cat, **svc),
        status=status,
    )


CFG = RiskConfig()


def test_mosca_margin() -> None:
    r = score_service(scan("a", Status.CLASSICAL, "health"), CFG, z=10)
    assert (r.x_retention, r.y_migration, r.margin, r.at_risk, r.severity) == (25, 0.5, 15.5, True, "critical")
    assert r.breaks_even_z == 25.5
    r = score_service(scan("b", Status.CLASSICAL, "marketing"), CFG, z=10)
    assert r.margin == -8.5 and not r.at_risk and r.severity == "low"
    r = score_service(scan("c", Status.TLS12_ONLY, "payments"), CFG, z=8)
    assert r.y_migration == 2 and r.margin == 1 and r.severity == "high"


def test_ready_scores_zero_and_unknown() -> None:
    r = score_service(scan("a", Status.PQ_READY, "health"), CFG, z=0)
    assert r.score == 0 and not r.at_risk and r.severity == "none"
    r = score_service(scan("u", Status.UNREACHABLE), CFG)
    assert r.severity == "unknown" and not r.at_risk


def test_plaintext_ignores_z() -> None:
    r = score_service(scan("p", Status.PLAINTEXT, "marketing"), CFG, z=50)
    assert r.at_risk and r.severity == "critical" and r.breaks_even_z is None


def test_overrides_and_stack() -> None:
    s = scan("o", Status.CLASSICAL, "health", retention_years=2, migration_years=0.25)
    r = score_service(s, CFG, z=1)
    assert (r.x_retention, r.y_migration) == (2, 0.25)
    assert score_service(scan("n", Status.CLASSICAL, stack={"openssl": "3.5.1"}), CFG).y_migration == 0.1
    assert score_service(scan("o2", Status.CLASSICAL, stack={"openssl": "3.0.11"}), CFG).y_migration == 1.5
    assert score_service(scan("s", Status.CLASSICAL, protocol=Protocol.SSH), CFG).y_migration == 1.0
    assert score_service(scan("d", Status.CLASSICAL, cat="never-heard-of-it"), CFG).x_retention == 10


def test_rank_order_and_sweep() -> None:
    scans = [
        scan("ready", Status.PQ_READY, "health"),
        scan("low", Status.CLASSICAL, "marketing"),
        scan("down", Status.UNREACHABLE),
        scan("top", Status.CLASSICAL, "health"),
        scan("mid", Status.TLS12_ONLY, "payments"),
    ]
    assert [r.service for r in rank(scans, CFG, 10)] == ["top", "mid", "low", "down", "ready"]
    assert [r.rank for r in rank(scans, CFG)] == [1, 2, 3, 4, 5]
    sw = sweep(scans, CFG, [0, 10, 30])
    assert sw["top"] == [True, True, False] and sw["ready"] == [False, False, False]


def test_config_merges_partial_maps(tmp_path) -> None:
    import pytest

    from aegisq.config import load_config

    p = tmp_path / "c.yaml"
    p.write_text("risk:\n  migration_years: {tls12_only: 4}\n  data_categories: {Telemetry: 2}\n")
    c = load_config(p)
    assert c.risk.migration_years["tls12_only"] == 4 and c.risk.migration_years["plaintext"] == 3
    assert c.risk.data_categories["telemetry"] == 2 and c.risk.data_categories["health"] == 25
    p.write_text("risk:\n  migration_years: {typo: 1}\n")
    with pytest.raises(Exception, match="unknown"):
        load_config(p)
    p.write_text("nope: 1\n")
    with pytest.raises(Exception):
        load_config(p)
    from pathlib import Path

    example = Path(__file__).resolve().parent.parent / "aegisq.example.yaml"
    assert load_config(example).scan.timeout == 5
