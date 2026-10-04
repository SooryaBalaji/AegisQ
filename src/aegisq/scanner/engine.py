"""Scan orchestration: bounded concurrency, per-probe timeouts, failures isolated per service."""

from __future__ import annotations

import asyncio
import logging
import platform
import time
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field

from aegisq import __version__
from aegisq.models import (
    ProbeOutcome,
    Protocol,
    ScanReport,
    ServiceScan,
    ServiceTarget,
    SSHDetails,
    Status,
    TLSDetails,
    utcnow,
)
from aegisq.netutil import Scope, TargetError, resolve
from aegisq.scanner import external, ssh_probe, tls_probe

log = logging.getLogger(__name__)


@dataclass
class ScanOptions:
    timeout: float = 5.0
    concurrency: int = 50
    tls_backend: str = "native"  # native | openssl
    ssh_backend: str = "native"  # native | openssh
    cross_check: bool = False  # run both backends and flag disagreement
    legacy_protocols: bool = True  # probe TLS 1.0 / 1.1
    fetch_certificate: bool = True
    pq_only: bool = False  # real-world mode: one PQ handshake per site, nothing else
    scope: Scope = field(default_factory=Scope)
    openssl_binary: str = "openssl"
    ssh_binary: str = "ssh"

    def validate(self) -> None:
        if not 0.1 <= self.timeout <= 120:
            raise ValueError("timeout must be between 0.1 and 120 seconds")
        if not 1 <= self.concurrency <= 1000:
            raise ValueError("concurrency must be between 1 and 1000")
        if self.tls_backend not in ("native", "openssl"):
            raise ValueError("tls_backend must be 'native' or 'openssl'")
        if self.ssh_backend not in ("native", "openssh"):
            raise ValueError("ssh_backend must be 'native' or 'openssh'")
        if self.tls_backend == "openssl" or self.cross_check:
            external.require_openssl_mlkem(self.openssl_binary)
        if self.ssh_backend == "openssh":
            external.require_ssh_pq(self.ssh_binary)


ProgressCB = Callable[[ServiceScan], None]


async def scan_all(
    targets: Sequence[ServiceTarget], opts: ScanOptions | None = None, progress: ProgressCB | None = None
) -> ScanReport:
    opts = opts or ScanOptions()
    opts.validate()
    names = [t.name for t in targets]
    if len(set(names)) != len(names):
        raise ValueError("service names must be unique")
    started = utcnow()
    sem = asyncio.Semaphore(opts.concurrency)

    async def one(t: ServiceTarget) -> ServiceScan:
        async with sem:
            try:
                res = await scan_service(t, opts)
            except Exception as e:  # a bug in one probe must never sink the whole scan
                log.exception("scan of %s failed", t.name)
                res = ServiceScan(service=t, status=Status.ERROR, errors=[f"internal error: {type(e).__name__}: {e}"])
            if progress:
                progress(res)
            return res

    results = await asyncio.gather(*(one(t) for t in targets))
    return ScanReport(
        scan_id=uuid.uuid4().hex,
        started_at=started,
        finished_at=utcnow(),
        tool_version=__version__,
        backend=f"tls={opts.tls_backend},ssh={opts.ssh_backend}" + (",cross-check" if opts.cross_check else ""),
        results=list(results),
        environment={"python": platform.python_version(), "platform": platform.platform(terse=True)},
    )


async def scan_service(t: ServiceTarget, opts: ScanOptions) -> ServiceScan:
    t0 = time.perf_counter()
    backend = opts.tls_backend if t.protocol == Protocol.TLS else opts.ssh_backend
    try:
        ips = await resolve(t.host, t.port, opts.timeout)
        if not ips:
            raise OSError("no addresses")
        opts.scope.check(t.host, ips)
    except TargetError as e:
        return ServiceScan(service=t, status=Status.ERROR, backend=backend, errors=[f"refused by scope: {e}"])
    except (OSError, asyncio.TimeoutError) as e:
        msg = "DNS timeout" if isinstance(e, asyncio.TimeoutError) else f"DNS resolution failed: {e}"
        return ServiceScan(service=t, status=Status.UNREACHABLE, backend=backend, errors=[msg])
    ip = ips[0]
    if t.protocol == Protocol.TLS:
        res = await _scan_tls(t, ip, opts)
    else:
        res = await _scan_ssh(t, ip, opts)
    res.backend = backend
    res.resolved_ip = ip
    res.duration_ms = round((time.perf_counter() - t0) * 1000, 2)
    res.findings = derive_findings(res)
    return res


# ------------------------------------------------------------------ TLS ---


async def _pq_probe(t: ServiceTarget, ip: str, opts: ScanOptions) -> tuple[ProbeOutcome, list[str]]:
    notes: list[str] = []
    if opts.tls_backend == "openssl":
        pq = await external.openssl_pq_probe(ip, t.port, t.server_name, opts.timeout, binary=opts.openssl_binary)
    else:
        pq = await tls_probe.probe_pq(ip, t.port, t.server_name, opts.timeout)
    if opts.cross_check and pq.outcome in ("accepted", "rejected"):
        other = (
            await tls_probe.probe_pq(ip, t.port, t.server_name, opts.timeout)
            if opts.tls_backend == "openssl"
            else await external.openssl_pq_probe(ip, t.port, t.server_name, opts.timeout, binary=opts.openssl_binary)
        )
        if other.outcome != pq.outcome:
            notes.append(f"backends disagree on PQ support: {pq.outcome} vs {other.outcome} ({other.detail})")
    return pq, notes


async def _scan_tls(t: ServiceTarget, ip: str, opts: ScanOptions) -> ServiceScan:
    det = TLSDetails()
    errors: list[str] = []
    pq, notes = await _pq_probe(t, ip, opts)
    errors += notes
    det.pq_probe = pq

    if pq.outcome == "unreachable":
        return ServiceScan(service=t, status=Status.UNREACHABLE, tls=det, errors=[pq.detail or "unreachable"])
    if pq.outcome == "not_tls":
        is_http, server = await tls_probe.http_plaintext_check(ip, t.port, t.server_name, opts.timeout)
        det.plaintext_http, det.http_server = is_http, server
        if is_http:
            return ServiceScan(service=t, status=Status.PLAINTEXT, tls=det)
        return ServiceScan(service=t, status=Status.ERROR, tls=det, errors=[pq.detail or "not a TLS service"])

    det.pq_ready = pq.outcome == "accepted"
    det.pq_group = pq.group if det.pq_ready else None
    if opts.pq_only:
        status = Status.PQ_READY if det.pq_ready else (Status.ERROR if pq.outcome == "error" else Status.CLASSICAL)
        if pq.outcome == "error":
            errors.append(pq.detail or "PQ probe error")
        return ServiceScan(service=t, status=status, tls=det, errors=errors)

    det.modern_probe = await tls_probe.probe_modern(ip, t.port, t.server_name, opts.timeout)
    t12 = await tls_probe.probe_tls12(ip, t.port, t.server_name, opts.timeout)
    det.tls12_probe = t12.outcome
    det.tls12_key_exchange = t12.key_exchange

    tls13 = det.pq_ready or (det.modern_probe.outcome == "accepted" and det.modern_probe.version == "TLSv1.3")
    det.supports = {"TLSv1.3": bool(tls13), "TLSv1.2": t12.outcome.outcome == "accepted"}
    if opts.legacy_protocols:
        for ver, name in ((0x0302, "TLSv1.1"), (0x0301, "TLSv1.0")):
            lp = await tls_probe.probe_legacy(ip, t.port, t.server_name, opts.timeout, ver)
            det.supports[name] = lp.outcome == "accepted" if lp.outcome in ("accepted", "rejected") else None

    if opts.fetch_certificate:
        der = await tls_probe.fetch_certificate(ip, t.port, t.server_name, opts.timeout)
        if der is None and t12.certificates:
            der = t12.certificates[0]  # TLS 1.2 sends the chain in the clear
        if der is not None:
            try:
                det.certificate = tls_probe.parse_certificate(der)
            except Exception as e:
                errors.append(f"certificate unparseable: {e}")

    if det.pq_ready:
        status = Status.PQ_READY
    elif tls13:
        status = Status.CLASSICAL
    elif det.supports.get("TLSv1.2"):
        status = Status.TLS12_ONLY
    elif det.supports.get("TLSv1.1") or det.supports.get("TLSv1.0"):
        status = Status.LEGACY_TLS
    else:
        status = Status.ERROR
        errors.append(
            "TLS port completed no handshake: "
            + "; ".join(filter(None, [pq.detail, det.modern_probe.detail, t12.outcome.detail]))
        )
    return ServiceScan(service=t, status=status, tls=det, errors=errors)


# ------------------------------------------------------------------ SSH ---


async def _scan_ssh(t: ServiceTarget, ip: str, opts: ScanOptions) -> ServiceScan:
    errors: list[str] = []
    try:
        det = await ssh_probe.probe_ssh(ip, t.port, opts.timeout)
    except ssh_probe.SSHProbeError as e:
        status = Status.UNREACHABLE if e.kind == "unreachable" else Status.ERROR
        if e.kind == "not_ssh":
            # An HTTP answer on an "SSH" port is still a plaintext exposure worth surfacing.
            is_http, server = await tls_probe.http_plaintext_check(ip, t.port, t.server_name, opts.timeout)
            if is_http:
                return ServiceScan(
                    service=t, status=Status.PLAINTEXT, tls=TLSDetails(plaintext_http=True, http_server=server)
                )
        return ServiceScan(service=t, status=status, errors=[e.detail])

    if opts.ssh_backend == "openssh" or opts.cross_check:
        try:
            outcome, kex = await external.openssh_pq_probe(ip, t.port, opts.timeout, binary=opts.ssh_binary)
        except external.BackendUnavailable as e:
            outcome, kex = "error", None
            errors.append(str(e))
        if outcome in ("accepted", "rejected"):
            if (outcome == "accepted") != bool(det.pq_ready):
                errors.append(f"backends disagree on SSH PQ support: native={det.pq_ready} openssh={outcome}")
            if opts.ssh_backend == "openssh":
                det = det.model_copy(update={"pq_ready": outcome == "accepted", "negotiated_kex": kex})
    status = Status.PQ_READY if det.pq_ready else Status.CLASSICAL
    return ServiceScan(service=t, status=status, ssh=det, errors=errors)


# ------------------------------------------------------------- findings ---


def derive_findings(r: ServiceScan) -> list[str]:
    f: list[str] = []
    if r.status == Status.PLAINTEXT:
        f.append("Service answers unencrypted HTTP: traffic is readable today, not just after a quantum computer.")
    if r.status == Status.CLASSICAL and r.service.protocol == Protocol.TLS:
        f.append("Key exchange is classical-only: recorded sessions are exposed to harvest-now-decrypt-later.")
    if r.status == Status.TLS12_ONLY:
        f.append("TLS 1.3 unsupported: the server needs a TLS upgrade before any post-quantum fix.")
    if r.status == Status.LEGACY_TLS:
        f.append("Only TLS 1.0/1.1 available: deprecated protocols (RFC 8996).")
    tls = r.tls
    if tls:
        if tls.supports.get("TLSv1.0") or tls.supports.get("TLSv1.1"):
            f.append("Deprecated TLS 1.0/1.1 still enabled.")
        mp = tls.modern_probe
        if tls.pq_ready and mp and mp.outcome == "accepted" and mp.group and mp.group != tls.pq_group:
            f.append(
                f"Supports {tls.pq_group} but chose {mp.group} when a client offered both; "
                "browsers will get classical key exchange."
            )
        if tls.tls12_key_exchange == "RSA":
            f.append("TLS 1.2 uses static RSA key transport (no forward secrecy).")
        c = tls.certificate
        if c:
            if c.expired:
                f.append(f"Certificate expired on {c.not_after.date()}.")
            elif c.days_to_expiry < 30:
                f.append(f"Certificate expires in {c.days_to_expiry} days.")
            if c.key_type == "RSA" and (c.key_size or 0) < 2048:
                f.append(f"Weak RSA certificate key ({c.key_size} bits).")
            if c.signature_hash in ("sha1", "md5"):
                f.append(f"Certificate signed with {c.signature_hash.upper()}.")
            if c.self_signed:
                f.append("Self-signed certificate.")
            if not c.quantum_safe:
                f.append(
                    f"Certificate key ({c.key_type}) is not quantum-safe; lower urgency than key exchange "
                    "because forged signatures only matter live."
                )
    s: SSHDetails | None = r.ssh
    if s:
        if not s.pq_ready:
            f.append("SSH offers no post-quantum hybrid key exchange (needs OpenSSH 9.0+, mlkem768x25519 in 9.9+).")
        if s.weak_kex:
            f.append(f"Weak SSH key exchange enabled: {', '.join(s.weak_kex)}.")
        if s.weak_ciphers:
            f.append(f"Weak SSH ciphers enabled: {', '.join(s.weak_ciphers)}.")
        if s.weak_macs:
            f.append(f"Weak SSH MACs enabled: {', '.join(s.weak_macs)}.")
        if s.weak_host_keys:
            f.append(f"SHA-1/DSA host key algorithms enabled: {', '.join(s.weak_host_keys)}.")
    return f
