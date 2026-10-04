"""Input validation for anything that becomes a network target or a subprocess argument."""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
from collections.abc import Iterable
from dataclasses import dataclass, field

_LABEL = re.compile(r"^(?!-)[A-Za-z0-9_-]{1,63}(?<!-)$")


class TargetError(ValueError):
    """Raised for a host, port or scope that AegisQ refuses to use."""


def validate_host(host: str) -> str:
    """Return a normalized host (IP literal or DNS name) or raise TargetError.

    Rejects anything that could be read as a command-line option or carry shell
    or URL metacharacters, because hosts are handed to openssl/ssh as argv.
    """
    if not isinstance(host, str):
        raise TargetError("host must be a string")
    h = host.strip()
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    if not h or len(h) > 253:
        raise TargetError(f"invalid host length: {host!r}")
    if h.startswith("-"):
        raise TargetError(f"host may not start with '-': {host!r}")
    try:
        return str(ipaddress.ip_address(h))
    except ValueError:
        pass
    try:
        ascii_host = h.encode("idna").decode("ascii") if not h.isascii() else h
    except UnicodeError as e:
        raise TargetError(f"invalid internationalized host {host!r}: {e}") from None
    ascii_host = ascii_host.rstrip(".").lower()
    labels = ascii_host.split(".")
    if not all(_LABEL.match(lbl) for lbl in labels):
        raise TargetError(f"invalid host name: {host!r}")
    return ascii_host


def validate_port(port: int) -> int:
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise TargetError(f"invalid port: {port!r}")
    return port


def parse_endpoint(text: str, default_port: int = 443) -> tuple[str, int]:
    """Parse 'host', 'host:port', '[v6]:port' or a bare IPv6 literal."""
    s = text.strip()
    if s.startswith("["):
        end = s.find("]")
        if end < 0:
            raise TargetError(f"unterminated IPv6 literal: {text!r}")
        host, rest = s[1:end], s[end + 1 :]
        if rest and not rest.startswith(":"):
            raise TargetError(f"bad endpoint: {text!r}")
        port = int(rest[1:]) if rest else default_port
    elif s.count(":") == 1:
        host, p = s.split(":")
        if not p.isdigit():
            raise TargetError(f"bad port in {text!r}")
        port = int(p)
    else:
        host, port = s, default_port
    return validate_host(host), validate_port(port)


@dataclass
class Scope:
    """Allow/deny list applied before any packet is sent.

    Empty ``allow`` means "everything not denied". Entries are CIDRs or DNS
    suffixes such as ``.corp.example.com``.
    """

    allow: list[str] = field(default_factory=list)
    deny: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self._allow_nets, self._allow_names = _split(self.allow)
        self._deny_nets, self._deny_names = _split(self.deny)

    def check(self, host: str, ips: Iterable[str] = ()) -> None:
        ip_objs = []
        for ip in [host, *ips]:
            try:
                ip_objs.append(ipaddress.ip_address(ip))
            except ValueError:
                continue
        name = host.lower()
        for net in self._deny_nets:
            if any(ip in net for ip in ip_objs if ip.version == net.version):
                raise TargetError(f"{host} is inside denied range {net}")
        if any(_suffix_match(name, s) for s in self._deny_names):
            raise TargetError(f"{host} matches a denied name")
        if not self.allow:
            return
        if any(ip in net for net in self._allow_nets for ip in ip_objs if ip.version == net.version):
            return
        if any(_suffix_match(name, s) for s in self._allow_names):
            return
        raise TargetError(f"{host} is outside the allowed scan scope")


def _split(entries: Iterable[str]) -> tuple[list[ipaddress.IPv4Network | ipaddress.IPv6Network], list[str]]:
    nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    names: list[str] = []
    for raw in entries:
        e = raw.strip()
        if not e:
            continue
        try:
            nets.append(ipaddress.ip_network(e, strict=False))
        except ValueError:
            names.append(e.lower())
    return nets, names


def _suffix_match(name: str, pattern: str) -> bool:
    if pattern.startswith("."):
        return name.endswith(pattern) or name == pattern[1:]
    return name == pattern


async def resolve(host: str, port: int, timeout: float) -> list[str]:
    """Resolve to a de-duplicated list of IP strings (IPv4 first)."""
    try:
        ipaddress.ip_address(host)
        return [host]
    except ValueError:
        pass
    loop = asyncio.get_running_loop()
    infos = await asyncio.wait_for(
        loop.getaddrinfo(host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP), timeout
    )
    seen: list[str] = []
    for info in sorted(infos, key=lambda i: 0 if i[0] == socket.AF_INET else 1):
        ip = str(info[4][0])
        if ip not in seen:
            seen.append(ip)
    return seen
