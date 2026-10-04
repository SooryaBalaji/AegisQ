import copy
import datetime as dt

import pytest

from aegisq.cbom import CBOMValidationError, build_cbom, validate_cbom
from aegisq.models import (
    ProbeOutcome,
    Protocol,
    ScanReport,
    ServiceScan,
    ServiceTarget,
    SSHDetails,
    Status,
    TLSDetails,
)
from aegisq.scanner.tls_probe import parse_certificate
from fakes import make_cert_der


def report() -> ScanReport:
    cert = parse_certificate(make_cert_der())
    now = dt.datetime.now(dt.timezone.utc)
    t = lambda n, **kw: ServiceTarget(name=n, host="127.0.0.1", port=443, **kw)  # noqa: E731
    results = [
        ServiceScan(
            service=t("app1"),
            status=Status.PQ_READY,
            tls=TLSDetails(
                pq_ready=True,
                pq_group="X25519MLKEM768",
                pq_probe=ProbeOutcome(
                    outcome="accepted", group="X25519MLKEM768", cipher_suite="TLS_AES_128_GCM_SHA256"
                ),
                modern_probe=ProbeOutcome(outcome="accepted", group="x25519", version="TLSv1.3"),
                supports={"TLSv1.3": True, "TLSv1.2": True},
                certificate=cert,
            ),
        ),
        ServiceScan(
            service=t("app2"),
            status=Status.CLASSICAL,
            tls=TLSDetails(
                pq_ready=False,
                modern_probe=ProbeOutcome(
                    outcome="accepted", group="x25519", version="TLSv1.3", cipher_suite="TLS_AES_256_GCM_SHA384"
                ),
                supports={"TLSv1.3": True},
            ),
        ),
        ServiceScan(
            service=t("app3"),
            status=Status.TLS12_ONLY,
            tls=TLSDetails(
                tls12_probe=ProbeOutcome(
                    outcome="accepted", group="secp256r1", cipher_suite="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
                ),
                supports={"TLSv1.3": False, "TLSv1.2": True},
                tls12_key_exchange="ECDHE secp256r1",
            ),
        ),
        ServiceScan(service=t("web"), status=Status.PLAINTEXT, tls=TLSDetails(plaintext_http=True)),
        ServiceScan(
            service=t("ssh1", protocol=Protocol.SSH),
            status=Status.PQ_READY,
            ssh=SSHDetails(
                pq_ready=True, negotiated_kex="mlkem768x25519-sha256", kex_algorithms=["mlkem768x25519-sha256"]
            ),
        ),
        ServiceScan(
            service=t("ssh2", protocol=Protocol.SSH),
            status=Status.CLASSICAL,
            ssh=SSHDetails(
                pq_ready=False,
                kex_algorithms=["curve25519-sha256", "diffie-hellman-group1-sha1"],
                weak_kex=["diffie-hellman-group1-sha1"],
            ),
        ),
        ServiceScan(service=t("down"), status=Status.UNREACHABLE),
    ]
    return ScanReport(
        scan_id="s1", started_at=now, finished_at=now, tool_version="t", backend="native", results=results
    )


def comp(bom, ref):
    return next(c for c in bom["components"] if c["bom-ref"] == ref)


def test_cbom_is_valid_and_correct() -> None:
    bom = build_cbom(report())
    validate_cbom(bom)
    assert bom["specVersion"] == "1.6" and bom["serialNumber"].startswith("urn:uuid:")
    pq = comp(bom, "kex-app1")
    assert pq["name"] == "X25519MLKEM768"
    ap = pq["cryptoProperties"]["algorithmProperties"]
    assert ap == {**ap, "primitive": "kem", "parameterSetIdentifier": "768", "nistQuantumSecurityLevel": 3}
    assert {"name": "aegisq:host", "value": "127.0.0.1:443"} in pq["properties"]
    classical = comp(bom, "kex-app2")
    assert classical["name"] == "X25519"
    assert classical["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"] == 0
    assert comp(bom, "kex-app3")["name"] == "secp256r1"
    assert comp(bom, "cert-app1")["cryptoProperties"]["certificateProperties"]["signatureAlgorithmRef"] == "sig-app1"
    proto = comp(bom, "proto-app1")["cryptoProperties"]["protocolProperties"]
    assert proto["version"] == "1.3" and proto["cipherSuites"][0]["identifiers"] == ["0x13", "0x01"]
    assert comp(bom, "kex-ssh1")["cryptoProperties"]["algorithmProperties"]["nistQuantumSecurityLevel"] == 3
    assert comp(bom, "kex-ssh2-diffie-hellman-group1-sha1")
    assert comp(bom, "proto-web")["cryptoProperties"]["protocolProperties"]["type"] == "other"
    assert not any("down" in c["bom-ref"] for c in bom["components"])
    assert {"name": "aegisq:notScanned", "value": "down"} in bom["metadata"]["properties"]


@pytest.mark.parametrize(
    "mutate",
    [
        lambda b: b.update(specVersion="9.9"),
        lambda b: b["components"][0]["cryptoProperties"].update(assetType="spaceship"),
        lambda b: b["components"][0]["cryptoProperties"]["algorithmProperties"].update(nistQuantumSecurityLevel=7),
        lambda b: b["components"][0].update(type="cryptographic-thing"),
        lambda b: b["components"][1].update({"bom-ref": b["components"][0]["bom-ref"]}),
        lambda b: b["dependencies"][0]["dependsOn"].append("ghost"),
        lambda b: next(c for c in b["components"] if c["bom-ref"] == "cert-app1")["cryptoProperties"][
            "certificateProperties"
        ].update(signatureAlgorithmRef="ghost"),
    ],
)
def test_cbom_validation_catches_errors(mutate) -> None:
    bom = copy.deepcopy(build_cbom(report()))
    mutate(bom)
    with pytest.raises(CBOMValidationError):
        validate_cbom(bom)
