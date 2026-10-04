"""SSH key-exchange probe.

SSH negotiates in the clear: after the version banners each side sends
SSH_MSG_KEXINIT listing every algorithm it supports. Reading the server's
KEXINIT therefore reveals all of its key-exchange methods without credentials
and without completing the key exchange. The method a post-quantum-only client
would end up with is the first entry of AegisQ's offer that the server also
lists (RFC 4253 §7.1), which is exactly what ``ssh -v`` would report.
"""

from __future__ import annotations

import asyncio
import contextlib
import struct
from dataclasses import dataclass

from aegisq import __version__
from aegisq.crypto_registry import (
    SSH_PQ_KEX,
    SSH_PQ_PROBE_ORDER,
    SSH_WEAK_HOSTKEYS,
    SSH_WEAK_KEX,
    SSH_WEAK_MACS,
    ssh_cipher_is_weak,
)
from aegisq.models import SSHDetails

SSH_MSG_KEXINIT = 20
MAX_PACKET = 35000
MAX_BANNER_LINES = 50
# Signalling pseudo-algorithms (RFC 8308 ext-info, OpenSSH strict-kex), not key exchanges.
PSEUDO_KEX_PREFIXES = ("ext-info-", "kex-strict-")
CLIENT_BANNER = f"SSH-2.0-AegisQ_{__version__}\r\n".encode("ascii")


class SSHProbeError(Exception):
    def __init__(self, kind: str, detail: str) -> None:
        super().__init__(detail)
        self.kind = kind  # "unreachable" | "not_ssh" | "error"
        self.detail = detail


@dataclass
class KexInit:
    kex: list[str]
    host_keys: list[str]
    ciphers_c2s: list[str]
    ciphers_s2c: list[str]
    macs_c2s: list[str]
    macs_s2c: list[str]
    compression_c2s: list[str]
    compression_s2c: list[str]
    first_kex_follows: bool


def _namelist(buf: bytes, off: int) -> tuple[list[str], int]:
    if off + 4 > len(buf):
        raise SSHProbeError("error", "truncated KEXINIT name-list")
    (n,) = struct.unpack_from("!I", buf, off)
    off += 4
    if off + n > len(buf):
        raise SSHProbeError("error", "truncated KEXINIT name-list")
    raw = buf[off : off + n]
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        raise SSHProbeError("error", "non-ASCII algorithm name") from None
    return ([s for s in text.split(",") if s] if text else []), off + n


def parse_kexinit(payload: bytes) -> KexInit:
    if not payload or payload[0] != SSH_MSG_KEXINIT:
        raise SSHProbeError("error", f"expected SSH_MSG_KEXINIT, got message {payload[:1].hex() or 'none'}")
    off = 1 + 16  # message number + cookie
    lists = []
    for _ in range(10):
        lst, off = _namelist(payload, off)
        lists.append(lst)
    if off + 5 > len(payload):
        raise SSHProbeError("error", "truncated KEXINIT trailer")
    kex, host_keys, enc_cs, enc_sc, mac_cs, mac_sc, comp_cs, comp_sc = lists[:8]
    return KexInit(kex, host_keys, enc_cs, enc_sc, mac_cs, mac_sc, comp_cs, comp_sc, bool(payload[off]))


def parse_packet(data: bytes) -> tuple[bytes, int]:
    """Parse one unencrypted binary packet; returns (payload, bytes consumed)."""
    if len(data) < 5:
        raise ValueError("need more data")
    plen, padlen = struct.unpack_from("!IB", data, 0)
    if plen > MAX_PACKET or plen < padlen + 1:
        raise SSHProbeError("error", f"invalid packet length {plen}")
    if len(data) < 4 + plen:
        raise ValueError("need more data")
    payload = data[5 : 4 + plen - padlen]
    return payload, 4 + plen


async def _read_banner(reader: asyncio.StreamReader) -> str:
    for _ in range(MAX_BANNER_LINES):
        try:
            line = await reader.readuntil(b"\n")
        except asyncio.IncompleteReadError as e:
            raise SSHProbeError("not_ssh", "connection closed before an SSH banner") from e
        except asyncio.LimitOverrunError as e:
            raise SSHProbeError("not_ssh", "over-long line instead of an SSH banner") from e
        if line.startswith(b"SSH-"):
            return line.rstrip(b"\r\n").decode("ascii", "replace")[:255]
        if line.startswith(b"HTTP/"):
            raise SSHProbeError("not_ssh", "HTTP server on this port")
        if line[:1] == b"\x16":
            raise SSHProbeError("not_ssh", "TLS server on this port")
    raise SSHProbeError("not_ssh", "no SSH banner in the first lines")


async def fetch_kexinit(ip: str, port: int, timeout: float) -> tuple[str, KexInit]:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port, limit=8192), timeout)
    except (OSError, asyncio.TimeoutError) as e:
        raise SSHProbeError("unreachable", "timed out" if isinstance(e, asyncio.TimeoutError) else str(e)) from e
    try:
        writer.write(CLIENT_BANNER)
        await asyncio.wait_for(writer.drain(), timeout)
        banner = await asyncio.wait_for(_read_banner(reader), timeout)
        proto = banner.split("-", 2)[1] if banner.count("-") >= 2 else ""
        if proto not in ("2.0", "1.99"):
            raise SSHProbeError("error", f"server speaks SSH protocol {proto or '?'} only: {banner}")
        buf = b""
        while True:
            try:
                payload, _used = parse_packet(buf)
                break
            except ValueError:
                chunk = await asyncio.wait_for(reader.read(4096), timeout)
                if not chunk:
                    raise SSHProbeError("error", "connection closed before KEXINIT") from None
                buf += chunk
                if len(buf) > MAX_PACKET + 4:
                    raise SSHProbeError("error", "KEXINIT too large") from None
        return banner, parse_kexinit(payload)
    except asyncio.TimeoutError as e:
        raise SSHProbeError("error", f"no SSH answer within {timeout:g}s") from e
    except OSError as e:
        raise SSHProbeError("error", f"{type(e).__name__}: {e}") from e
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(writer.wait_closed(), 1.0)


def analyze(banner: str, ki: KexInit) -> SSHDetails:
    software = banner.split("-", 2)[2] if banner.count("-") >= 2 else None
    kex = [k for k in ki.kex if not k.startswith(PSEUDO_KEX_PREFIXES)]
    pq_offered = [k for k in kex if k in SSH_PQ_KEX]
    negotiated = next((k for k in SSH_PQ_PROBE_ORDER if k in kex), None)
    if negotiated is None and pq_offered:
        negotiated = pq_offered[0]
    ciphers = list(dict.fromkeys(ki.ciphers_c2s + ki.ciphers_s2c))
    macs = list(dict.fromkeys(ki.macs_c2s + ki.macs_s2c))
    return SSHDetails(
        banner=banner,
        software=software,
        kex_algorithms=kex,
        host_key_algorithms=ki.host_keys,
        ciphers=ciphers,
        macs=macs,
        pq_ready=bool(pq_offered),
        pq_kex_offered=pq_offered,
        negotiated_kex=negotiated,
        weak_kex=[k for k in kex if k in SSH_WEAK_KEX],
        weak_ciphers=[c for c in ciphers if ssh_cipher_is_weak(c)],
        weak_macs=[m for m in macs if m in SSH_WEAK_MACS],
        weak_host_keys=[h for h in ki.host_keys if h in SSH_WEAK_HOSTKEYS],
    )


async def probe_ssh(ip: str, port: int, timeout: float) -> SSHDetails:
    banner, ki = await fetch_kexinit(ip, port, timeout)
    return analyze(banner, ki)
