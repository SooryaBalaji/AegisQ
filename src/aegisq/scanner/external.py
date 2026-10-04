"""Probes that drive the reference tools named in the design: ``openssl s_client`` and ``ssh -v``.

The native probes are the default because they work on any scanning host.
These backends exist for cross-checking and for teams that want the result to
come from the stock tools. Both refuse to run when the local tool is too old
to speak ML-KEM, since a "failure" from such a tool would be a false negative.
"""

from __future__ import annotations

import re
import shutil
from functools import lru_cache

from aegisq.crypto_registry import SSH_PQ_PROBE_ORDER
from aegisq.models import ProbeOutcome
from aegisq.netutil import validate_host, validate_port
from aegisq.proc import run_async, run_sync

_ALERT_RE = re.compile(r"SSL alert number (\d+)")
_GROUP_RE = re.compile(r"Negotiated TLS1\.3 group: (\S+)")
_TEMP_KEY_RE = re.compile(r"(?:Server|Peer) Temp Key: ([A-Za-z0-9_-]+)")
_PROTO_RE = re.compile(r"Protocol\s*: (TLSv[\d.]+)")
# What OpenSSL says when the peer is not speaking TLS at all (plain HTTP, SSH, ...).
_NOT_TLS_RE = re.compile(r"(packet length too long|wrong version number|http request|unknown protocol)")
_SSH_KEX_RE = re.compile(r"kex: algorithm: (\S+)")


class BackendUnavailable(RuntimeError):
    pass


@lru_cache(maxsize=8)
def openssl_version(binary: str = "openssl") -> tuple[int, int, int] | None:
    path = shutil.which(binary)
    if not path:
        return None
    res = run_sync([path, "version"], timeout=10)
    m = re.search(r"OpenSSL (\d+)\.(\d+)\.(\d+)", res.stdout)
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else None


@lru_cache(maxsize=8)
def ssh_supported_kex(binary: str = "ssh") -> tuple[str, ...]:
    path = shutil.which(binary)
    if not path:
        return ()
    res = run_sync([path, "-Q", "kex"], timeout=10)
    return tuple(line.strip() for line in res.stdout.splitlines() if line.strip())


def require_openssl_mlkem(binary: str = "openssl") -> str:
    v = openssl_version(binary)
    if v is None:
        raise BackendUnavailable(f"{binary!r} not found")
    if v < (3, 5, 0):
        raise BackendUnavailable(
            f"OpenSSL {'.'.join(map(str, v))} has no ML-KEM; the openssl backend needs 3.5 or later "
            "(use the native backend, which works with any local OpenSSL)"
        )
    return shutil.which(binary) or binary


def require_ssh_pq(binary: str = "ssh") -> tuple[str, list[str]]:
    kex = ssh_supported_kex(binary)
    offer = [k for k in SSH_PQ_PROBE_ORDER if k in kex]
    if not offer:
        raise BackendUnavailable(f"{binary!r} missing or offers no post-quantum key exchange (need OpenSSH 9.9+)")
    if "mlkem768x25519-sha256" not in offer:
        raise BackendUnavailable("local OpenSSH lacks mlkem768x25519-sha256 (need OpenSSH 9.9+)")
    return shutil.which(binary) or binary, offer


async def openssl_pq_probe(
    ip: str, port: int, sni: str | None, timeout: float, group: str = "X25519MLKEM768", binary: str = "openssl"
) -> ProbeOutcome:
    exe = require_openssl_mlkem(binary)
    ip = validate_host(ip)
    port = validate_port(port)
    connect = f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"
    argv = [exe, "s_client", "-connect", connect, "-tls1_3", "-groups", group]
    if sni:
        argv += ["-servername", validate_host(sni)]
    res = await run_async(argv, timeout=timeout, stdin_data=b"")
    text = res.output
    if res.timed_out:
        return ProbeOutcome(outcome="error", detail=f"openssl: {res.error}")
    if "connect:errno" in text or "Connection refused" in text or "No route to host" in text:
        return ProbeOutcome(outcome="unreachable", detail=_last_line(text))
    if _NOT_TLS_RE.search(text) and not _ALERT_RE.search(text):
        return ProbeOutcome(outcome="not_tls", detail=f"openssl s_client: {_NOT_TLS_RE.search(text).group(1)}")  # type: ignore[union-attr]
    m = _GROUP_RE.search(text) or _TEMP_KEY_RE.search(text)
    negotiated = m.group(1) if m and m.group(1) != "<NULL>" else None
    proto = _PROTO_RE.search(text)
    if negotiated and negotiated.lower() == group.lower():
        return ProbeOutcome(outcome="accepted", version="TLSv1.3", group=negotiated, detail="openssl s_client")
    alert = _ALERT_RE.search(text)
    from aegisq.crypto_registry import TLS_ALERTS

    alert_name = TLS_ALERTS.get(int(alert.group(1))) if alert else None
    return ProbeOutcome(
        outcome="rejected",
        version=proto.group(1) if proto else None,
        alert=alert_name,
        detail=f"openssl s_client: {alert_name or _last_line(text)}",
    )


async def openssh_pq_probe(ip: str, port: int, timeout: float, binary: str = "ssh") -> tuple[str, str | None]:
    """Returns (outcome, negotiated kex). outcome is accepted | rejected | unreachable | error."""
    exe, offer = require_ssh_pq(binary)
    ip = validate_host(ip)
    port = validate_port(port)
    argv = [
        exe,
        "-v",
        "-F",
        "/dev/null",
        "-o",
        "BatchMode=yes",
        "-o",
        f"ConnectTimeout={max(1, int(timeout))}",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "PreferredAuthentications=publickey",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "IdentityFile=/dev/null",
        "-o",
        f"KexAlgorithms={','.join(offer)}",
        "-p",
        str(port),
        "-l",
        "aegisq-probe",
        "--",
        ip,
        "exit",
    ]
    res = await run_async(argv, timeout=timeout + 2)
    text = res.output
    for m in _SSH_KEX_RE.finditer(text):
        if m.group(1) != "(no":
            return "accepted", m.group(1)
    if "no matching key exchange method found" in text or "kex: algorithm: (no match)" in text:
        return "rejected", None
    if "Connection refused" in text or "timed out" in text or "No route to host" in text:
        return "unreachable", None
    return "error", None


def _last_line(text: str) -> str:
    lines = [ln for ln in text.strip().splitlines() if ln.strip()]
    return lines[-1][:200] if lines else "no output"
