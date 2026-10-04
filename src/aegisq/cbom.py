"""Cryptographic Bill of Materials in CycloneDX 1.6 (``cryptographic-asset`` components).

One component per algorithm per service, with the host recorded as a
property, plus protocol and certificate assets linked by ``bom-ref``.
Validated against the official CycloneDX 1.6 JSON schema bundled with AegisQ
(and a referential-integrity check the schema cannot express).
"""

from __future__ import annotations

import datetime as dt
import json
import re
import uuid
from functools import lru_cache
from importlib import resources
from typing import Any

from jsonschema import Draft7Validator
from referencing import Registry, Resource

from aegisq import __version__
from aegisq.crypto_registry import (
    SSH_KEX_INFO,
    TLS12_SUITES,
    TLS13_SUITES,
    group_by_name,
)
from aegisq.models import Protocol, ScanReport, ServiceScan, Status

_DISPLAY = {"x25519": "X25519", "x448": "X448"}
_SUITE_CODES = {v: k for k, v in {**TLS13_SUITES, **TLS12_SUITES}.items()}


class CBOMValidationError(ValueError):
    def __init__(self, errors: list[str]) -> None:
        super().__init__("; ".join(errors[:5]) + (f" (+{len(errors) - 5} more)" if len(errors) > 5 else ""))
        self.errors = errors


def _slug(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "-", s).strip("-") or "x"


def _props(scan: ServiceScan, **extra: str) -> list[dict[str, str]]:
    props = [
        {"name": "aegisq:host", "value": scan.service.endpoint},
        {"name": "aegisq:service", "value": scan.service.name},
        {"name": "aegisq:status", "value": scan.status.value},
        {"name": "aegisq:dataCategory", "value": scan.service.data_category},
    ]
    props += [{"name": f"aegisq:{k}", "value": v} for k, v in extra.items()]
    return props


class _Builder:
    def __init__(self) -> None:
        self.components: list[dict[str, Any]] = []
        self.deps: dict[str, list[str]] = {}
        self._refs: set[str] = set()

    def add(self, comp: dict[str, Any]) -> str:
        ref = comp["bom-ref"]
        if ref in self._refs:
            raise ValueError(f"duplicate bom-ref {ref}")
        self._refs.add(ref)
        self.components.append(comp)
        return ref

    # ------------------------------------------------------------- algos
    def kex_tls(self, scan: ServiceScan, group: str, role: str) -> str:
        info = group_by_name(group)
        name = _DISPLAY.get(group.lower(), info.name if info else group)
        algo: dict[str, Any] = {
            "primitive": info.primitive if info else "unknown",
            "cryptoFunctions": ["encapsulate", "decapsulate"] if info and info.primitive == "kem" else ["keygen"],
            "nistQuantumSecurityLevel": info.nist_level if info else 0,
        }
        if info:
            algo["classicalSecurityLevel"] = info.classical_bits
            if info.parameter_set:
                algo["parameterSetIdentifier"] = info.parameter_set
            if info.curve:
                algo["curve"] = info.curve
        return self.add(
            {
                "type": "cryptographic-asset",
                "bom-ref": f"kex-{_slug(scan.service.name)}" + ("" if role == "primary" else f"-{_slug(name)}"),
                "name": name,
                "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": algo},
                "properties": _props(scan, role=role),
            }
        )

    def kex_ssh(self, scan: ServiceScan, method: str, role: str) -> str:
        prim, level, classical = SSH_KEX_INFO.get(method, ("unknown", 0, 0))
        algo: dict[str, Any] = {
            "primitive": prim,
            "nistQuantumSecurityLevel": level,
            "cryptoFunctions": ["encapsulate", "decapsulate"] if prim == "kem" else ["keygen"],
        }
        if classical:
            algo["classicalSecurityLevel"] = classical
        if method.startswith("mlkem768"):
            algo["parameterSetIdentifier"] = "768"
        elif method.startswith("mlkem1024"):
            algo["parameterSetIdentifier"] = "1024"
        if "25519" in method:
            algo["curve"] = "Curve25519"
        return self.add(
            {
                "type": "cryptographic-asset",
                "bom-ref": f"kex-{_slug(scan.service.name)}" + ("" if role == "primary" else f"-{_slug(method)}"),
                "name": method,
                "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": algo},
                "properties": _props(scan, role=role),
            }
        )

    # ------------------------------------------------------- certificate
    def certificate(self, scan: ServiceScan) -> str | None:
        c = scan.tls.certificate if scan.tls else None
        if not c:
            return None
        svc = _slug(scan.service.name)
        sig_ref = self.add(
            {
                "type": "cryptographic-asset",
                "bom-ref": f"sig-{svc}",
                "name": c.signature_algorithm or "unknown",
                "cryptoProperties": {
                    "assetType": "algorithm",
                    "algorithmProperties": {
                        "primitive": "signature",
                        "cryptoFunctions": ["sign", "verify"],
                        "nistQuantumSecurityLevel": 2 if c.quantum_safe else 0,
                    },
                },
                "properties": _props(scan, role="certificate-signature"),
            }
        )
        key_name = f"{c.key_type}-{c.key_size}" if c.key_size else c.key_type
        key_algo: dict[str, Any] = {
            "primitive": "signature",
            "nistQuantumSecurityLevel": 2 if c.quantum_safe else 0,
        }
        if c.curve:
            key_algo["curve"] = c.curve
        key_algo_ref = self.add(
            {
                "type": "cryptographic-asset",
                "bom-ref": f"keyalg-{svc}",
                "name": key_name,
                "cryptoProperties": {"assetType": "algorithm", "algorithmProperties": key_algo},
                "properties": _props(scan, role="certificate-key-algorithm"),
            }
        )
        rcm: dict[str, Any] = {"type": "public-key", "algorithmRef": key_algo_ref}
        if c.key_size:
            rcm["size"] = c.key_size
        pub_ref = self.add(
            {
                "type": "cryptographic-asset",
                "bom-ref": f"pubkey-{svc}",
                "name": f"{key_name} public key",
                "cryptoProperties": {"assetType": "related-crypto-material", "relatedCryptoMaterialProperties": rcm},
                "properties": _props(scan, role="certificate-public-key"),
            }
        )
        cert_ref = self.add(
            {
                "type": "cryptographic-asset",
                "bom-ref": f"cert-{svc}",
                "name": c.subject or "certificate",
                "cryptoProperties": {
                    "assetType": "certificate",
                    "certificateProperties": {
                        "subjectName": c.subject,
                        "issuerName": c.issuer,
                        "notValidBefore": _iso(c.not_before),
                        "notValidAfter": _iso(c.not_after),
                        "signatureAlgorithmRef": sig_ref,
                        "subjectPublicKeyRef": pub_ref,
                        "certificateFormat": "X.509",
                    },
                },
                "properties": _props(scan, sha256Fingerprint=c.sha256_fingerprint, daysToExpiry=str(c.days_to_expiry)),
            }
        )
        self.deps[cert_ref] = [sig_ref, pub_ref]
        self.deps[pub_ref] = [key_algo_ref]
        return cert_ref

    # ---------------------------------------------------------- protocol
    def protocol(self, scan: ServiceScan, ptype: str, version: str, refs: list[str], suites: list[str]) -> str:
        pp: dict[str, Any] = {"type": ptype, "version": version}
        cs = []
        for s in suites:
            entry: dict[str, Any] = {"name": s, "algorithms": [r for r in refs if r.startswith("kex-")]}
            code = _SUITE_CODES.get(s)
            if code is not None:
                entry["identifiers"] = [f"0x{code >> 8:02X}", f"0x{code & 0xFF:02X}"]
            cs.append(entry)
        if cs:
            pp["cipherSuites"] = cs
        if refs:
            pp["cryptoRefArray"] = refs
        ref = self.add(
            {
                "type": "cryptographic-asset",
                "bom-ref": f"proto-{_slug(scan.service.name)}",
                "name": f"{ptype.upper()} {version}" if ptype != "other" else version,
                "cryptoProperties": {"assetType": "protocol", "protocolProperties": pp},
                "properties": _props(scan),
            }
        )
        if refs:
            self.deps[ref] = refs
        return ref


def _iso(d: dt.datetime) -> str:
    return d.astimezone(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def _tls_components(b: _Builder, scan: ServiceScan) -> None:
    tls = scan.tls
    if scan.status == Status.PLAINTEXT:
        b.protocol(scan, "other", "HTTP (plaintext)", [], [])
        return
    if tls is None:
        return
    refs: list[str] = []
    suites: list[str] = []
    if tls.pq_ready and tls.pq_group:
        refs.append(b.kex_tls(scan, tls.pq_group, "primary"))
        if tls.pq_probe and tls.pq_probe.cipher_suite:
            suites.append(tls.pq_probe.cipher_suite)
        mp = tls.modern_probe
        if mp and mp.outcome == "accepted" and mp.group and mp.group != tls.pq_group:
            refs.append(b.kex_tls(scan, mp.group, "preferred-classical"))
    else:
        mp = tls.modern_probe
        t12 = tls.tls12_probe
        if mp and mp.outcome == "accepted" and mp.group:
            refs.append(b.kex_tls(scan, mp.group, "primary"))
            if mp.cipher_suite:
                suites.append(mp.cipher_suite)
        elif t12 and t12.outcome == "accepted":
            name = t12.group or ("RSA" if tls.tls12_key_exchange == "RSA" else None)
            if name:
                refs.append(b.kex_tls(scan, name, "primary"))
            if t12.cipher_suite:
                suites.append(t12.cipher_suite)
    cert = b.certificate(scan)
    if cert:
        refs.append(cert)
    if tls.supports.get("TLSv1.3"):
        version = "1.3"
    elif tls.supports.get("TLSv1.2"):
        version = "1.2"
    elif tls.supports.get("TLSv1.1"):
        version = "1.1"
    elif tls.supports.get("TLSv1.0"):
        version = "1.0"
    elif tls.pq_ready:
        version = "1.3"
    else:
        version = "unknown"
    b.protocol(scan, "tls", version, refs, list(dict.fromkeys(suites)))


def _ssh_components(b: _Builder, scan: ServiceScan) -> None:
    s = scan.ssh
    if s is None:
        return
    refs: list[str] = []
    if s.pq_ready and s.negotiated_kex:
        primary: str | None = s.negotiated_kex
    else:
        primary = s.kex_algorithms[0] if s.kex_algorithms else None
    if primary:
        refs.append(b.kex_ssh(scan, primary, "primary"))
    for weak in dict.fromkeys(s.weak_kex):
        if weak != primary:
            refs.append(b.kex_ssh(scan, weak, "weak-enabled"))
    b.protocol(scan, "ssh", "2.0", refs, [])


def build_cbom(report: ScanReport, *, serial: str | None = None) -> dict[str, Any]:
    b = _Builder()
    skipped = []
    for scan in report.results:
        if not scan.status.scanned:
            skipped.append(scan.service.name)
            continue
        if scan.service.protocol == Protocol.SSH and scan.ssh is not None:
            _ssh_components(b, scan)
        else:
            _tls_components(b, scan)
    summary = report.summary()
    bom: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": serial or f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": _iso(report.finished_at),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "aegisq",
                        "version": __version__,
                        "description": "Post-quantum readiness scanner",
                    }
                ]
            },
            "properties": [
                {"name": "aegisq:scanId", "value": report.scan_id},
                {"name": "aegisq:backend", "value": report.backend},
                *({"name": f"aegisq:count:{k}", "value": str(v)} for k, v in summary.items()),
                *({"name": "aegisq:notScanned", "value": n} for n in skipped),
            ],
        },
        "components": b.components,
    }
    if b.deps:
        bom["dependencies"] = [{"ref": k, "dependsOn": v} for k, v in b.deps.items()]
    return bom


# ---------------------------------------------------------- validation ---


@lru_cache(maxsize=1)
def _validator() -> Draft7Validator:
    pkg = resources.files("aegisq") / "schemas"
    docs = {
        n: json.loads((pkg / n).read_text(encoding="utf-8"))
        for n in ("bom-1.6.schema.json", "spdx.schema.json", "jsf-0.82.schema.json")
    }
    registry: Registry = Registry()
    base = "http://cyclonedx.org/schema/"
    for name, doc in docs.items():
        res = Resource.from_contents(doc, default_specification=_draft7())
        registry = registry.with_resource(base + name, res)
        if "$id" in doc:
            registry = registry.with_resource(doc["$id"], res)
    schema = docs["bom-1.6.schema.json"]
    Draft7Validator.check_schema(schema)
    return Draft7Validator(schema, registry=registry)


def _draft7() -> Any:
    from referencing.jsonschema import DRAFT7

    return DRAFT7


def validate_cbom(bom: dict[str, Any]) -> None:
    """Raise CBOMValidationError unless the BOM passes the official 1.6 schema and every ref resolves."""
    errors = [
        f"{'/'.join(map(str, e.absolute_path)) or '<root>'}: {e.message}"
        for e in sorted(_validator().iter_errors(bom), key=lambda e: list(e.absolute_path))
    ]
    if bom.get("specVersion") != "1.6":
        errors.append(f"specVersion: expected '1.6', got {bom.get('specVersion')!r} (this validator is the 1.6 schema)")
    refs = [c.get("bom-ref") for c in bom.get("components", [])]
    known = {r for r in refs if r}
    if len(known) != len([r for r in refs if r]):
        errors.append("duplicate bom-ref values")
    for c in bom.get("components", []):
        for ref in _collect_refs(c.get("cryptoProperties", {})):
            if ref not in known:
                errors.append(f"{c.get('bom-ref')}: dangling reference {ref}")
    for d in bom.get("dependencies", []):
        for ref in [d.get("ref"), *d.get("dependsOn", [])]:
            if ref not in known:
                errors.append(f"dependencies: dangling reference {ref}")
    if errors:
        raise CBOMValidationError(errors)


def _collect_refs(obj: Any) -> list[str]:
    out: list[str] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k.endswith("Ref") and isinstance(v, str):
                out.append(v)
            elif k in ("cryptoRefArray", "algorithms") and isinstance(v, list):
                out.extend(x for x in v if isinstance(x, str))
            else:
                out.extend(_collect_refs(v))
    elif isinstance(obj, list):
        for v in obj:
            out.extend(_collect_refs(v))
    return out
