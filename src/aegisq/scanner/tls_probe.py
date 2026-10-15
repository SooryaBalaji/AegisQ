"""Asynchronous TLS probes built on the wire codec, plus certificate and plaintext-HTTP checks."""

from __future__ import annotations

import asyncio
import contextlib
import datetime as dt
import hashlib
import ssl
import struct
import time
import warnings
from contextvars import ContextVar
from dataclasses import dataclass, field
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa

from aegisq.crypto_registry import (
    TLS12_SUITES,
    TLS13_SUITES,
    X25519,
    X25519MLKEM768,
    group_by_code,
    group_name,
    suite_key_exchange,
    suite_name,
)
from aegisq.models import CertInfo, ProbeOutcome
from aegisq.scanner import tls_wire as w

MAX_READ = 256 * 1024
STARTTLS_PROTOCOLS = ("smtp", "imap", "pop3")
# Set per scan task: when it names a protocol, every connection negotiates STARTTLS before the ClientHello.
STARTTLS: ContextVar[str | None] = ContextVar("aegisq_starttls", default=None)


class StartTLSRefused(Exception):
    """The server did not upgrade the connection with STARTTLS."""


@dataclass
class RawExchange:
    kind: str  # "server_hello" | "alert" | "closed" | "not_tls" | "unreachable" | "error"
    server_hello: w.ServerHello | None = None
    alert: str | None = None
    detail: str | None = None
    certificates: list[bytes] = field(default_factory=list)
    server_key_exchange: w.ServerKeyExchange | None = None
    peek: bytes = b""
    elapsed_ms: float = 0.0


async def _open(ip: str, port: int, timeout: float) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout)
    proto = STARTTLS.get()
    if proto:
        try:
            await asyncio.wait_for(starttls(reader, writer, proto), timeout)
        except BaseException:
            await _close(writer)
            raise
    return reader, writer


async def _reply_line(reader: asyncio.StreamReader) -> str:
    raw = await reader.readline()
    if not raw:
        raise StartTLSRefused("connection closed during STARTTLS")
    return raw.decode("latin-1").rstrip("\r\n")


async def _smtp_reply(reader: asyncio.StreamReader) -> tuple[str, list[str]]:
    lines: list[str] = []
    while len(lines) < 200:
        line = await _reply_line(reader)
        if len(line) < 3 or not line[:3].isdigit():
            raise StartTLSRefused(f"not an SMTP reply: {line[:60]!r}")
        lines.append(line)
        if line[3:4] != "-":
            return line[:3], lines
    raise StartTLSRefused("SMTP reply too long")


async def starttls(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, proto: str) -> None:
    """Upgrade a plaintext SMTP, IMAP or POP3 session (RFC 3207, 3501, 2595) so a ClientHello can follow."""
    if proto == "smtp":
        code, _ = await _smtp_reply(reader)
        if code != "220":
            raise StartTLSRefused(f"SMTP greeting {code}")
        writer.write(b"EHLO aegisq.invalid\r\n")
        code, lines = await _smtp_reply(reader)
        if code != "250":
            raise StartTLSRefused(f"EHLO answered {code}")
        if not any(line[4:].strip().upper().split()[:1] == ["STARTTLS"] for line in lines):
            raise StartTLSRefused("server does not offer STARTTLS")
        writer.write(b"STARTTLS\r\n")
        code, _ = await _smtp_reply(reader)
        if code != "220":
            raise StartTLSRefused(f"STARTTLS answered {code}")
    elif proto == "imap":
        greeting = await _reply_line(reader)
        if not greeting.upper().startswith(("* OK", "* PREAUTH")):
            raise StartTLSRefused(f"not an IMAP greeting: {greeting[:60]!r}")
        writer.write(b"A1 STARTTLS\r\n")
        for _ in range(50):
            line = await _reply_line(reader)
            if line.upper().startswith("A1 "):
                if line.upper().startswith("A1 OK"):
                    return
                raise StartTLSRefused(f"STARTTLS refused: {line[:80]!r}")
        raise StartTLSRefused("no tagged STARTTLS reply")
    elif proto == "pop3":
        greeting = await _reply_line(reader)
        if not greeting.startswith("+OK"):
            raise StartTLSRefused(f"not a POP3 greeting: {greeting[:60]!r}")
        writer.write(b"STLS\r\n")
        line = await _reply_line(reader)
        if not line.startswith("+OK"):
            raise StartTLSRefused(f"STLS refused: {line[:80]!r}")
    else:
        raise ValueError(f"unsupported STARTTLS protocol {proto!r}")


async def _close(writer: asyncio.StreamWriter) -> None:
    writer.close()
    with contextlib.suppress(Exception):
        await asyncio.wait_for(writer.wait_closed(), 1.0)


async def exchange(ip: str, port: int, hello: bytes, timeout: float, *, follow_tls12: bool = False) -> RawExchange:
    """Send one ClientHello and read the server's plaintext answer."""
    t0 = time.perf_counter()
    try:
        reader, writer = await _open(ip, port, timeout)
    except StartTLSRefused as e:
        return RawExchange("not_tls", detail=f"STARTTLS failed: {e}", elapsed_ms=_ms(t0))
    except asyncio.TimeoutError:
        detail = "no STARTTLS answer in time" if STARTTLS.get() else "timed out"
        return RawExchange("unreachable" if not STARTTLS.get() else "not_tls", detail=detail, elapsed_ms=_ms(t0))
    except OSError as e:
        return RawExchange("unreachable", detail=_err(e), elapsed_ms=_ms(t0))
    try:
        writer.write(hello)
        await asyncio.wait_for(writer.drain(), timeout)
        res = await asyncio.wait_for(_read_answer(reader, follow_tls12), timeout)
    except asyncio.TimeoutError:
        res = RawExchange("error", detail=f"no TLS answer within {timeout:g}s")
    except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError) as e:  # Windows reports aborts
        res = RawExchange("closed", detail=f"connection closed by server ({_err(e)})")
    except OSError as e:
        res = RawExchange("error", detail=_err(e))
    except w.TLSDecodeError as e:
        res = RawExchange("error", detail=f"malformed TLS from server: {e}")
    finally:
        await _close(writer)
    res.elapsed_ms = _ms(t0)
    return res


async def _read_answer(reader: asyncio.StreamReader, follow_tls12: bool) -> RawExchange:
    hs = bytearray()
    total = 0
    out: RawExchange | None = None
    kex_family = "unknown"
    while True:
        try:
            header = await reader.readexactly(5)
        except asyncio.IncompleteReadError as e:
            if out is not None:
                return out
            if e.partial:
                return _classify_non_tls(e.partial + await _drain_some(reader))
            return RawExchange("closed", detail="connection closed without a TLS answer")
        ctype, version, length = struct.unpack("!BHH", header)
        if ctype not in (20, 21, 22, 23, 24) or (version >> 8) != 3:
            if out is not None:
                return out
            return _classify_non_tls(header + await _drain_some(reader))
        if length > w.MAX_RECORD:
            raise w.TLSDecodeError(f"record too large ({length} bytes)")
        total += length + 5
        if total > MAX_READ:
            raise w.TLSDecodeError("server sent too much data before ServerHelloDone")
        payload = await reader.readexactly(length)

        if ctype == w.CT_ALERT:
            if out is not None:
                return out
            return RawExchange("alert", alert=w.describe_alert(payload))
        if ctype == w.CT_CHANGE_CIPHER_SPEC:
            continue
        if ctype != w.CT_HANDSHAKE:
            # Encrypted records: the plaintext part of the handshake is over.
            if out is None:
                raise w.TLSDecodeError("encrypted data before ServerHello")
            return out

        hs += payload
        while len(hs) >= 4:
            mtype = hs[0]
            mlen = int.from_bytes(hs[1:4], "big")
            if len(hs) < 4 + mlen:
                break
            body = bytes(hs[4 : 4 + mlen])
            del hs[: 4 + mlen]
            if out is None:
                if mtype != w.HS_SERVER_HELLO:
                    raise w.TLSDecodeError(f"expected ServerHello, got handshake type {mtype}")
                sh = w.parse_server_hello(body)
                out = RawExchange("server_hello", server_hello=sh)
                if not follow_tls12 or sh.hello_retry or sh.version >= 0x0304:
                    return out
                kex_family = suite_key_exchange(suite_name(sh.cipher_suite) or "")
                continue
            if mtype == w.HS_CERTIFICATE:
                out.certificates = w.parse_certificate_tls12(body)
            elif mtype == w.HS_SERVER_KEY_EXCHANGE:
                out.server_key_exchange = w.parse_server_key_exchange(body, kex_family)
            elif mtype == w.HS_SERVER_HELLO_DONE:
                return out


async def _drain_some(reader: asyncio.StreamReader) -> bytes:
    with contextlib.suppress(Exception):
        return await asyncio.wait_for(reader.read(512), 0.5)
    return b""


def _classify_non_tls(data: bytes) -> RawExchange:
    if data.startswith(b"HTTP/"):
        return RawExchange("not_tls", detail="plaintext HTTP response to a ClientHello", peek=data[:200])
    if data.startswith(b"SSH-"):
        return RawExchange("not_tls", detail="SSH server on this port", peek=data[:200])
    return RawExchange("not_tls", detail="non-TLS response", peek=data[:200])


def _err(e: BaseException) -> str:
    if isinstance(e, asyncio.TimeoutError):
        return "timed out"
    return f"{type(e).__name__}: {e}".strip()


def _ms(t0: float) -> float:
    return round((time.perf_counter() - t0) * 1000, 2)


# --------------------------------------------------------------- probes ---


def _outcome_from(
    ex: RawExchange, built: w.BuiltHello, offered_groups: tuple[int, ...], *, accept_version: int | None
) -> ProbeOutcome:
    base: dict[str, Any] = {
        "client_hello_bytes": len(built.record),
        "client_key_share_bytes": built.key_share_bytes or None,
        "elapsed_ms": ex.elapsed_ms,
    }
    if ex.kind == "unreachable":
        return ProbeOutcome(outcome="unreachable", detail=ex.detail, **base)
    if ex.kind == "not_tls":
        return ProbeOutcome(outcome="not_tls", detail=ex.detail, **base)
    if ex.kind == "alert":
        return ProbeOutcome(outcome="rejected", alert=ex.alert, detail=f"server alert: {ex.alert}", **base)
    if ex.kind == "closed":
        return ProbeOutcome(outcome="rejected", detail=ex.detail, **base)
    if ex.kind == "error" or ex.server_hello is None:
        return ProbeOutcome(outcome="error", detail=ex.detail, **base)

    sh = ex.server_hello
    common: dict[str, Any] = {
        "version": sh.version_name,
        "cipher_suite": suite_name(sh.cipher_suite),
        "group": group_name(sh.key_share_group),
        "hello_retry": sh.hello_retry,
        "server_key_share_bytes": sh.key_share_len,
        **base,
    }
    if sh.hello_retry and sh.key_share_group not in offered_groups:
        return ProbeOutcome(
            outcome="rejected",
            detail=f"HelloRetryRequest for un-offered group {group_name(sh.key_share_group)}",
            **common,
        )
    if accept_version is not None and sh.version != accept_version:
        return ProbeOutcome(outcome="rejected", detail=f"server negotiated {sh.version_name}", **common)
    if sh.version >= 0x0304 and sh.key_share_group is not None and sh.key_share_group not in offered_groups:
        return ProbeOutcome(
            outcome="error",
            detail=f"protocol violation: server chose un-offered group {group_name(sh.key_share_group)}",
            **common,
        )
    return ProbeOutcome(outcome="accepted", **common)


async def probe_pq(
    ip: str, port: int, sni: str | None, timeout: float, group: int = X25519MLKEM768.code
) -> ProbeOutcome:
    """Offer only a hybrid post-quantum group: the server must use it or fail."""
    built = w.build_client_hello(w.ClientHelloSpec(sni, (0x0304,), tuple(TLS13_SUITES), (group,), (group,)))
    ex = await exchange(ip, port, built.record, timeout)
    out = _outcome_from(ex, built, (group,), accept_version=0x0304)
    if out.outcome == "accepted":
        info = group_by_code(group)
        if out.hello_retry or not (info and info.pq) or out.group != (info.name if info else None):
            return out.model_copy(update={"outcome": "rejected", "detail": "server did not complete the PQ share"})
    return out


async def probe_modern(ip: str, port: int, sni: str | None, timeout: float) -> ProbeOutcome:
    """A browser-like offer: hybrid + X25519 shares, TLS 1.3 and 1.2."""
    groups = (X25519MLKEM768.code, X25519.code, 0x0017, 0x0018)
    built = w.build_client_hello(
        w.ClientHelloSpec(sni, (0x0304, 0x0303), tuple(TLS13_SUITES) + tuple(TLS12_SUITES), groups, groups[:2])
    )
    ex = await exchange(ip, port, built.record, timeout)
    return _outcome_from(ex, built, groups, accept_version=None)


async def probe_classical(ip: str, port: int, sni: str | None, timeout: float) -> ProbeOutcome:
    """A client with no post-quantum support: X25519 and P-256 only, TLS 1.3 and 1.2."""
    groups = (X25519.code, 0x0017, 0x0018)
    built = w.build_client_hello(
        w.ClientHelloSpec(sni, (0x0304, 0x0303), tuple(TLS13_SUITES) + tuple(TLS12_SUITES), groups, groups[:1])
    )
    ex = await exchange(ip, port, built.record, timeout)
    return _outcome_from(ex, built, groups, accept_version=None)


@dataclass
class TLS12Result:
    outcome: ProbeOutcome
    certificates: list[bytes]
    key_exchange: str | None


async def probe_tls12(ip: str, port: int, sni: str | None, timeout: float) -> TLS12Result:
    groups = (X25519.code, 0x0017, 0x0018, 0x0019)
    built = w.build_client_hello(w.ClientHelloSpec(sni, (0x0303,), tuple(TLS12_SUITES), groups))
    ex = await exchange(ip, port, built.record, timeout, follow_tls12=True)
    out = _outcome_from(ex, built, groups, accept_version=0x0303)
    kex = None
    if out.outcome == "accepted" and out.cipher_suite:
        fam = suite_key_exchange(out.cipher_suite)
        ske = ex.server_key_exchange
        if fam == "ECDHE" and ske and ske.group is not None:
            kex = f"ECDHE {group_name(ske.group)}"
            out = out.model_copy(update={"group": group_name(ske.group)})
        elif fam == "DHE" and ske and ske.dh_bits:
            kex = f"DHE {ske.dh_bits}-bit"
        else:
            kex = fam
    return TLS12Result(out, ex.certificates, kex)


async def probe_legacy(ip: str, port: int, sni: str | None, timeout: float, version: int) -> ProbeOutcome:
    suites = (0xC013, 0xC014, 0xC009, 0xC00A, 0x002F, 0x0035, 0x000A)
    groups = (X25519.code, 0x0017, 0x0018)
    built = w.build_client_hello(w.ClientHelloSpec(sni, (version,), suites, groups, alpn=()))
    ex = await exchange(ip, port, built.record, timeout)
    return _outcome_from(ex, built, groups, accept_version=version)


# ---------------------------------------------------------- certificate ---


async def fetch_certificate(ip: str, port: int, sni: str | None, timeout: float) -> bytes | None:
    """Fetch the leaf certificate with the local TLS stack (verification off: we inspect, not trust)."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with contextlib.suppress(ssl.SSLError):
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    with contextlib.suppress(ValueError, ssl.SSLError), warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        ctx.minimum_version = ssl.TLSVersion.TLSv1  # inspect old servers too
    server_hostname = sni if sni and not w._is_ip(sni) else None
    if STARTTLS.get():
        return await _starttls_certificate(ip, port, ctx, server_hostname, timeout)
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port, ssl=ctx, server_hostname=server_hostname), timeout
        )
    except (OSError, asyncio.TimeoutError, ssl.SSLError):
        return None
    try:
        sslobj = writer.get_extra_info("ssl_object")
        return sslobj.getpeercert(binary_form=True) if sslobj else None
    finally:
        del reader
        await _close(writer)


async def _starttls_certificate(
    ip: str, port: int, ctx: ssl.SSLContext, server_hostname: str | None, timeout: float
) -> bytes | None:
    try:
        reader, writer = await _open(ip, port, timeout)
    except (OSError, asyncio.TimeoutError, StartTLSRefused):
        return None
    loop = asyncio.get_running_loop()
    try:
        tls = await asyncio.wait_for(
            loop.start_tls(writer.transport, writer.transport.get_protocol(), ctx, server_hostname=server_hostname),
            timeout,
        )
    except (OSError, asyncio.TimeoutError, ssl.SSLError):
        await _close(writer)
        return None
    try:
        sslobj = tls.get_extra_info("ssl_object") if tls else None
        return sslobj.getpeercert(binary_form=True) if sslobj else None
    finally:
        del reader
        if tls:
            tls.abort()


def parse_certificate(der: bytes, now: dt.datetime | None = None) -> CertInfo:
    cert = x509.load_der_x509_certificate(der)
    now = now or dt.datetime.now(dt.timezone.utc)
    pub = cert.public_key()
    key_size: int | None = None
    curve: str | None = None
    if isinstance(pub, rsa.RSAPublicKey):
        key_type, key_size = "RSA", pub.key_size
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        key_type, key_size, curve = "EC", pub.key_size, pub.curve.name
    elif isinstance(pub, ed25519.Ed25519PublicKey):
        key_type, key_size = "Ed25519", 256
    elif isinstance(pub, ed448.Ed448PublicKey):
        key_type, key_size = "Ed448", 456
    elif isinstance(pub, dsa.DSAPublicKey):
        key_type, key_size = "DSA", pub.key_size
    else:
        key_type = type(pub).__name__.replace("PublicKey", "").replace("_", "-") or "unknown"
    try:
        sig_hash = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None
    except Exception:
        sig_hash = None
    sig_name = getattr(cert.signature_algorithm_oid, "_name", None) or cert.signature_algorithm_oid.dotted_string
    san: list[str] = []
    with contextlib.suppress(x509.ExtensionNotFound, ValueError):
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        san = [str(n) for n in ext.value.get_values_for_type(x509.DNSName)]
        san += [str(n) for n in ext.value.get_values_for_type(x509.IPAddress)]
    not_after = cert.not_valid_after_utc
    return CertInfo(
        subject=cert.subject.rfc4514_string(),
        issuer=cert.issuer.rfc4514_string(),
        serial=format(cert.serial_number, "x"),
        not_before=cert.not_valid_before_utc,
        not_after=not_after,
        days_to_expiry=(not_after - now).days,
        expired=not_after < now,
        self_signed=cert.issuer == cert.subject,
        key_type=key_type,
        key_size=key_size,
        curve=curve,
        signature_algorithm=sig_name,
        signature_hash=sig_hash,
        san=san,
        sha256_fingerprint=hashlib.sha256(der).hexdigest(),
        quantum_safe=key_type.upper().startswith(("ML-DSA", "MLDSA", "SLH-DSA")),
    )


# ------------------------------------------------------------ plaintext ---


async def http_plaintext_check(ip: str, port: int, host: str, timeout: float) -> tuple[bool, str | None]:
    """Does the port answer an unencrypted HTTP request? Returns (is_http, Server header)."""
    try:
        reader, writer = await _open(ip, port, timeout)
    except (OSError, asyncio.TimeoutError):
        return False, None
    try:
        host_hdr = f"[{host}]" if ":" in host else host
        writer.write(f"HEAD / HTTP/1.0\r\nHost: {host_hdr}\r\nUser-Agent: aegisq\r\n\r\n".encode("ascii"))
        await asyncio.wait_for(writer.drain(), timeout)
        data = await asyncio.wait_for(reader.read(4096), timeout)
    except (OSError, asyncio.TimeoutError):
        return False, None
    finally:
        await _close(writer)
    if not data.startswith(b"HTTP/"):
        return False, None
    server = None
    for line in data.split(b"\r\n")[1:]:
        if line.lower().startswith(b"server:"):
            server = line.split(b":", 1)[1].strip().decode("latin-1")[:120]
    return True, server
