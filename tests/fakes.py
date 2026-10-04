"""Scriptable fake servers for offline tests."""

from __future__ import annotations

import asyncio
import contextlib
import os
import struct
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from aegisq.scanner import tls_wire as w

HRR = w.HRR_RANDOM


# ----------------------------------------------------------- ClientHello parse ---


@dataclass
class ParsedHello:
    versions: list[int] = field(default_factory=list)
    groups: list[int] = field(default_factory=list)
    shares: dict[int, int] = field(default_factory=dict)  # group -> share length
    suites: list[int] = field(default_factory=list)
    sni: str | None = None
    session_id: bytes = b""
    legacy_version: int = 0


def parse_client_hello(record_payload: bytes) -> ParsedHello:
    b = w._Buf(record_payload)
    assert b.u8() == 1
    body = w._Buf(b.vec24())
    out = ParsedHello()
    out.legacy_version = body.u16()
    body.take(32)
    out.session_id = body.vec8()
    sb = w._Buf(body.vec16())
    while sb.left:
        out.suites.append(sb.u16())
    body.vec8()
    ext = w._Buf(body.vec16())
    while ext.left:
        et, data = ext.u16(), ext.vec16()
        d = w._Buf(data)
        if et == w.EXT_SUPPORTED_VERSIONS:
            v = w._Buf(d.vec8())
            while v.left:
                out.versions.append(v.u16())
        elif et == w.EXT_SUPPORTED_GROUPS:
            g = w._Buf(d.vec16())
            while g.left:
                out.groups.append(g.u16())
        elif et == w.EXT_KEY_SHARE:
            s = w._Buf(d.vec16())
            while s.left:
                grp = s.u16()
                out.shares[grp] = len(s.vec16())
        elif et == w.EXT_SERVER_NAME:
            lst = w._Buf(d.vec16())
            lst.u8()
            out.sni = lst.vec16().decode()
    return out


# ---------------------------------------------------------- server responses ---


def _rec(ctype: int, payload: bytes, version: int = 0x0303) -> bytes:
    return struct.pack("!BHH", ctype, version, len(payload)) + payload


def _hs(mtype: int, body: bytes) -> bytes:
    return struct.pack("!B", mtype) + struct.pack("!I", len(body))[1:] + body


def server_hello(
    version: int, suite: int, group: int | None, share_len: int | None, session_id: bytes, hrr: bool = False
) -> bytes:
    exts = b""
    if version == 0x0304:
        exts += struct.pack("!HHH", w.EXT_SUPPORTED_VERSIONS, 2, 0x0304)
    if group is not None:
        if hrr:
            exts += struct.pack("!HHH", w.EXT_KEY_SHARE, 2, group)
        else:
            ks = struct.pack("!HH", group, share_len or 0) + os.urandom(share_len or 0)
            exts += struct.pack("!HH", w.EXT_KEY_SHARE, len(ks)) + ks
    body = (
        struct.pack("!H", min(version, 0x0303))
        + (HRR if hrr else os.urandom(32))
        + bytes([len(session_id)])
        + session_id
        + struct.pack("!HB", suite, 0)
        + struct.pack("!H", len(exts))
        + exts
    )
    return _hs(w.HS_SERVER_HELLO, body)


def alert(desc: int) -> bytes:
    return _rec(w.CT_ALERT, bytes([2, desc]))


def make_cert_der(cn: str = "fake.test", days: int = 60) -> bytes:
    import datetime as dt

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def tls12_flight(session_id: bytes, cert: bytes, group: int = 0x001D) -> bytes:
    sh = server_hello(0x0303, 0xC02B, None, None, session_id)
    chain = struct.pack("!I", len(cert))[1:] + cert
    certmsg = _hs(w.HS_CERTIFICATE, struct.pack("!I", len(chain))[1:] + chain)
    ske = _hs(w.HS_SERVER_KEY_EXCHANGE, struct.pack("!BHB", 3, group, 32) + os.urandom(32) + b"\x04\x03\x00\x00")
    done = _hs(w.HS_SERVER_HELLO_DONE, b"")
    return _rec(w.CT_HANDSHAKE, sh + certmsg + ske + done)


class FakeTLSServer:
    """Modes:
    pq        hybrid ML-KEM and classical, TLS 1.3 + 1.2
    classical TLS 1.3 + 1.2, x25519/P-256 only
    tls12     TLS 1.2 only
    tls10     TLS 1.0 only
    http      plaintext HTTP
    hrr       answers PQ-only with a HelloRetryRequest
    badgroup  picks a group the client did not offer
    fragment  pq, but the ServerHello is split over several records and writes
    garbage   random bytes
    hang      never answers
    close     closes immediately
    """

    def __init__(self, mode: str) -> None:
        self.mode = mode
        self.cert = make_cert_der()
        self.hellos: list[ParsedHello] = []
        self.port = 0
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._server: asyncio.base_events.Server | None = None
        self._ready = threading.Event()

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            await self._respond(reader, writer)
        except (asyncio.IncompleteReadError, ConnectionError):
            pass
        finally:
            with contextlib.suppress(Exception):
                writer.close()

    async def _respond(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        mode = self.mode
        if mode == "close":
            return
        if mode == "hang":
            await asyncio.sleep(30)
            return
        head = await reader.readexactly(5)
        if mode == "http":
            await reader.read(65536)
            writer.write(b"HTTP/1.1 400 Bad Request\r\nServer: fakehttp/1.0\r\nContent-Length: 0\r\n\r\n")
            await writer.drain()
            return
        if mode == "garbage":
            writer.write(os.urandom(64))
            await writer.drain()
            return
        _ctype, _ver, length = struct.unpack("!BHH", head)
        payload = await reader.readexactly(length)
        hello = parse_client_hello(payload)
        self.hellos.append(hello)
        sid = hello.session_id
        tls13 = 0x0304 in hello.versions
        out = b""
        if mode in ("pq", "fragment", "classical"):
            groups = [0x11EC, 0x001D, 0x0017] if mode != "classical" else [0x001D, 0x0017]
            if tls13:
                pick = next((g for g in groups if g in hello.shares), None)
                if pick is None:
                    out = alert(40)
                else:
                    share = 1120 if pick == 0x11EC else (32 if pick == 0x001D else 65)
                    sh = server_hello(0x0304, 0x1301, pick, share, sid)
                    if mode == "fragment":
                        recs = [_rec(w.CT_HANDSHAKE, sh[i : i + 7]) for i in range(0, len(sh), 7)]
                        for r in recs:
                            for i in range(0, len(r), 3):
                                writer.write(r[i : i + 3])
                                await writer.drain()
                        writer.write(_rec(w.CT_CHANGE_CIPHER_SPEC, b"\x01") + _rec(w.CT_APPLICATION_DATA, b"x" * 40))
                        await writer.drain()
                        return
                    out = _rec(w.CT_HANDSHAKE, sh) + _rec(w.CT_CHANGE_CIPHER_SPEC, b"\x01")
                    out += _rec(w.CT_APPLICATION_DATA, os.urandom(60))
            elif hello.legacy_version == 0x0303:
                out = tls12_flight(sid, self.cert)
            else:
                out = alert(70)
        elif mode == "tls12":
            if 0x0303 in hello.versions or (not hello.versions and hello.legacy_version == 0x0303):
                out = tls12_flight(sid, self.cert)
            else:
                out = alert(70)
        elif mode == "tls10":
            if not hello.versions and hello.legacy_version == 0x0301:
                sh = server_hello(0x0301, 0xC013, None, None, sid)
                out = _rec(w.CT_HANDSHAKE, sh + _hs(w.HS_SERVER_HELLO_DONE, b""), 0x0301)
            else:
                out = alert(70)
        elif mode == "hrr":
            out = _rec(w.CT_HANDSHAKE, server_hello(0x0304, 0x1301, 0x001D, None, sid, hrr=True))
        elif mode == "badgroup":
            out = _rec(w.CT_HANDSHAKE, server_hello(0x0304, 0x1301, 0x0018, 97, sid))
        writer.write(out)
        await writer.drain()
        await asyncio.sleep(0.05)

    def _run(self) -> None:
        loop = asyncio.new_event_loop()
        self._loop = loop

        async def start() -> None:
            self._server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
            self.port = self._server.sockets[0].getsockname()[1]
            self._ready.set()

        loop.run_until_complete(start())
        loop.run_forever()
        loop.close()

    def __enter__(self) -> FakeTLSServer:
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()
        self._ready.wait(5)
        return self

    def __exit__(self, *exc: object) -> None:
        assert self._loop
        loop = self._loop

        async def stop() -> None:
            if self._server:
                self._server.close()
            for t in asyncio.all_tasks(loop):
                if t is not asyncio.current_task():
                    t.cancel()

        asyncio.run_coroutine_threadsafe(stop(), loop).result(5)
        loop.call_soon_threadsafe(loop.stop)
        if self._thread:
            self._thread.join(5)


# ------------------------------------------------------------------- SSH ---


def kexinit_packet(
    kex: list[str], hostkeys: list[str] | None = None, ciphers: list[str] | None = None, macs: list[str] | None = None
) -> bytes:
    def nl(items: list[str]) -> bytes:
        s = ",".join(items).encode()
        return struct.pack("!I", len(s)) + s

    hostkeys = hostkeys or ["ssh-ed25519", "rsa-sha2-512"]
    ciphers = ciphers or ["chacha20-poly1305@openssh.com", "aes256-gcm@openssh.com"]
    macs = macs or ["hmac-sha2-256-etm@openssh.com"]
    payload = (
        bytes([20])
        + os.urandom(16)
        + nl(kex)
        + nl(hostkeys)
        + nl(ciphers)
        + nl(ciphers)
        + nl(macs)
        + nl(macs)
        + nl(["none"])
        + nl(["none"])
        + nl([])
        + nl([])
        + b"\x00"
        + b"\x00\x00\x00\x00"
    )
    pad = 8 - ((len(payload) + 5) % 8)
    pad = pad + 8 if pad < 4 else pad
    return struct.pack("!IB", len(payload) + pad + 1, pad) + payload + os.urandom(pad)


class FakeSSHServer(FakeTLSServer):
    """Modes: pq, classical, prebanner, ssh1, oversize, truncated, http."""

    async def _respond(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        mode = self.mode
        if mode == "http":
            await reader.readline()
            writer.write(b"HTTP/1.1 400 Bad Request\r\n\r\n")
            await writer.drain()
            return
        if mode == "prebanner":
            writer.write(b"Welcome to the jump host\r\nAuthorized use only\r\n")
        banner = b"SSH-1.5-OldSSH\r\n" if mode == "ssh1" else b"SSH-2.0-OpenSSH_9.6p1 FakeOS\r\n"
        writer.write(banner)
        await writer.drain()
        await reader.readline()
        if mode == "oversize":
            writer.write(struct.pack("!IB", 10_000_000, 4) + b"\x14")
        elif mode == "truncated":
            writer.write(kexinit_packet(["curve25519-sha256"])[:30])
        else:
            kex = ["curve25519-sha256", "ecdh-sha2-nistp256", "diffie-hellman-group14-sha1", "ext-info-s"]
            if mode in ("pq", "prebanner"):
                kex = ["mlkem768x25519-sha256", "sntrup761x25519-sha512@openssh.com", *kex]
            writer.write(kexinit_packet(kex, ciphers=["aes128-ctr", "aes128-cbc"], macs=["hmac-sha2-256", "hmac-md5"]))
        await writer.drain()
        await asyncio.sleep(0.05)


@contextlib.contextmanager
def tls_server(mode: str) -> Iterator[FakeTLSServer]:
    with FakeTLSServer(mode) as s:
        yield s


@contextlib.contextmanager
def ssh_server(mode: str) -> Iterator[FakeSSHServer]:
    with FakeSSHServer(mode) as s:
        yield s


# ------------------------------------------------------------ fake nginx ---

FAKE_NGINX = r'''#!/usr/bin/env python3
"""Stand-in for `nginx -t` / `nginx -s reload` / `nginx -V`.
Behaves like an nginx linked against $FAKE_OPENSSL (default 3.5.0)."""
import os, re, sys, pathlib
ver = os.environ.get("FAKE_OPENSSL", "3.5.0")
conf = pathlib.Path(os.environ["FAKE_NGINX_CONF"])
state = pathlib.Path(os.environ["FAKE_NGINX_STATE"])
cmd = sys.argv[1:]
if cmd == ["-V"]:
    print(f"nginx version: nginx/1.25.0\nbuilt with OpenSSL {ver} 1 Jan 2025", file=sys.stderr); sys.exit(0)
def check():
    text = conf.read_text()
    if text.count("{") != text.count("}"):
        print("nginx: [emerg] unexpected end of file", file=sys.stderr); return 1
    major_minor = tuple(int(x) for x in ver.split(".")[:2])
    for m in re.finditer(r"ssl_ecdh_curve\s+([^;]+);", text):
        for g in m.group(1).split(":"):
            if "mlkem" in g.lower() and major_minor < (3, 5):
                print(f'nginx: [emerg] SSL_CTX_set1_curves_list("{m.group(1)}") failed (SSL: error:0A0000A0:SSL routines::unknown group)', file=sys.stderr)
                print("nginx: configuration file test failed", file=sys.stderr); return 1
    print("nginx: configuration file syntax is ok", file=sys.stderr); return 0
if cmd == ["-t"]:
    sys.exit(check())
if cmd == ["-s", "reload"]:
    if os.environ.get("FAKE_RELOAD_FAIL"):
        print("nginx: [error] reload failed", file=sys.stderr); sys.exit(1)
    rc = check()
    if rc == 0:
        state.write_text(conf.read_text())
    sys.exit(rc)
sys.exit(2)
'''
