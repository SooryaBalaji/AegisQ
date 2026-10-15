"""Post-change verification: the PQ probe again, plus an HTTP health check."""

from __future__ import annotations

import asyncio
import contextlib
import ssl
from dataclasses import dataclass
from urllib.parse import urlsplit

from aegisq.models import ManagedNginx, ManagedServer, ServiceTarget
from aegisq.netutil import resolve
from aegisq.scanner import ssh_probe, tls_probe


@dataclass
class HealthResult:
    ok: bool
    status: int | None
    detail: str


async def http_health(service: ServiceTarget, timeout: float = 5.0) -> HealthResult:
    m = service.managed if isinstance(service.managed, (ManagedNginx, ManagedServer)) else None
    url = m.health_url if m and m.health_url else f"https://{service.endpoint}/"
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return HealthResult(False, None, f"bad health URL {url!r}")
    host = parts.hostname
    port = parts.port or (443 if parts.scheme == "https" else 80)
    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    ctx = None
    if parts.scheme == "https":
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE  # availability check, not trust evaluation
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                host,
                port,
                ssl=ctx,
                server_hostname=service.server_name if ctx and not _is_ip(service.server_name) else None,
            ),
            timeout,
        )
    except (OSError, asyncio.TimeoutError, ssl.SSLError) as e:
        return HealthResult(False, None, f"connect failed: {type(e).__name__}: {e}")
    try:
        hosthdr = service.server_name
        writer.write(
            f"GET {path} HTTP/1.1\r\nHost: {hosthdr}\r\nUser-Agent: aegisq-verify\r\nConnection: close\r\n\r\n".encode(
                "ascii"
            )
        )
        await asyncio.wait_for(writer.drain(), timeout)
        line = await asyncio.wait_for(reader.readline(), timeout)
    except (OSError, asyncio.TimeoutError, ssl.SSLError) as e:
        return HealthResult(False, None, f"request failed: {type(e).__name__}: {e}")
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await asyncio.wait_for(writer.wait_closed(), 1)
    try:
        status = int(line.split()[1])
    except (IndexError, ValueError):
        return HealthResult(False, None, f"not an HTTP response: {line[:60]!r}")
    expect = m.health_expect if m else list(range(200, 400))
    return HealthResult(status in expect, status, f"HTTP {status}")


def _is_ip(s: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


async def pq_check(service: ServiceTarget, timeout: float = 5.0) -> tuple[bool, str]:
    tls_probe.STARTTLS.set(service.starttls)
    ips = await resolve(service.host, service.port, timeout)
    out = await tls_probe.probe_pq(ips[0], service.port, service.server_name, timeout)
    if out.outcome == "accepted":
        return True, f"negotiated {out.group} ({out.server_key_share_bytes}-byte server share)"
    return False, out.detail or out.outcome


async def tls_health(service: ServiceTarget, timeout: float = 5.0) -> HealthResult:
    """For mail servers: a client with no post-quantum support must still complete a handshake."""
    tls_probe.STARTTLS.set(service.starttls)
    try:
        ips = await resolve(service.host, service.port, timeout)
    except (OSError, asyncio.TimeoutError) as e:
        return HealthResult(False, None, f"unreachable: {type(e).__name__}: {e}")
    out = await tls_probe.probe_classical(ips[0], service.port, service.server_name, timeout)
    if out.outcome == "accepted":
        return HealthResult(True, None, f"a classical-only client still connects ({out.version}, {out.group})")
    return HealthResult(False, None, f"a classical-only client failed: {out.detail or out.outcome}")


async def ssh_check(service: ServiceTarget, timeout: float = 5.0) -> tuple[bool, bool, str]:
    """(pq_ok, reachable, detail): read the server's KEXINIT again, as a fresh client would."""
    try:
        ips = await resolve(service.host, service.port, timeout)
        d = await ssh_probe.probe_ssh(ips[0], service.port, timeout)
    except ssh_probe.SSHProbeError as e:
        return False, False, f"{e.kind}: {e.detail}"
    except (OSError, asyncio.TimeoutError) as e:
        return False, False, f"unreachable: {type(e).__name__}: {e}"
    if d.pq_ready:
        return True, True, f"offers {', '.join(d.pq_kex_offered)}; a PQ-only client negotiates {d.negotiated_kex}"
    return False, True, f"no post-quantum key exchange offered ({', '.join(d.kex_algorithms[:3])}...)"
