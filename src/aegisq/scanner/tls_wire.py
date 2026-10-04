"""Minimal, strict TLS wire codec: build ClientHellos and parse the plaintext part of a server's reply.

AegisQ never completes a handshake. Everything it needs (the negotiated
version, cipher suite and key-exchange group, and for TLS 1.2 the certificate
chain and ServerKeyExchange curve) is sent in the clear before the first
encrypted record, so a ClientHello plus a careful parser answers the
post-quantum question on any machine, whatever its OpenSSL version.
"""

from __future__ import annotations

import hashlib
import ipaddress
import os
import struct
from dataclasses import dataclass, field

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519

from aegisq.crypto_registry import TLS_ALERTS, TLS_VERSIONS, group_name

# RFC 8446 §4.1.3: a ServerHello with this random is a HelloRetryRequest.
HRR_RANDOM = hashlib.sha256(b"HelloRetryRequest").digest()

CT_CHANGE_CIPHER_SPEC = 20
CT_ALERT = 21
CT_HANDSHAKE = 22
CT_APPLICATION_DATA = 23

HS_CLIENT_HELLO = 1
HS_SERVER_HELLO = 2
HS_CERTIFICATE = 11
HS_SERVER_KEY_EXCHANGE = 12
HS_SERVER_HELLO_DONE = 14

EXT_SERVER_NAME = 0
EXT_SUPPORTED_GROUPS = 10
EXT_EC_POINT_FORMATS = 11
EXT_SIGNATURE_ALGORITHMS = 13
EXT_ALPN = 16
EXT_EXTENDED_MASTER_SECRET = 23
EXT_SESSION_TICKET = 35
EXT_SUPPORTED_VERSIONS = 43
EXT_PSK_KEY_EXCHANGE_MODES = 45
EXT_KEY_SHARE = 51
EXT_RENEGOTIATION_INFO = 0xFF01

MAX_RECORD = 16384 + 2048  # plaintext limit plus slack allowed for ciphertext records

SIGNATURE_ALGORITHMS = (
    0x0403,
    0x0503,
    0x0603,  # ecdsa_secp{256,384,521}r1_sha{256,384,512}
    0x0807,
    0x0808,  # ed25519, ed448
    0x0804,
    0x0805,
    0x0806,  # rsa_pss_rsae_sha{256,384,512}
    0x0809,
    0x080A,
    0x080B,  # rsa_pss_pss_sha{256,384,512}
    0x0401,
    0x0501,
    0x0601,  # rsa_pkcs1_sha{256,384,512}
    0x0904,
    0x0905,
    0x0906,  # mldsa{44,65,87} (draft-ietf-tls-mldsa)
    0x0203,
    0x0201,  # ecdsa_sha1, rsa_pkcs1_sha1 (legacy servers only)
)


class TLSDecodeError(ValueError):
    """The peer sent bytes that are not a well-formed TLS message."""


# ----------------------------------------------------------- key shares ---


def _mlkem_public(level: int) -> bytes:
    """A genuine ML-KEM encapsulation key (falls back to a well-formed synthetic one)."""
    try:
        from cryptography.hazmat.primitives.asymmetric import mlkem

        cls = mlkem.MLKEM768PrivateKey if level == 768 else mlkem.MLKEM1024PrivateKey
        return cls.generate().public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    except Exception:
        return synthetic_mlkem_ek(3 if level == 768 else 4)


def synthetic_mlkem_ek(k: int) -> bytes:
    """Encode k*256 uniformly random coefficients mod q=3329 plus a 32-byte rho (FIPS 203 ByteEncode12).

    Every coefficient is < q, so the key passes the FIPS 203 encapsulation-key modulus check.
    """
    q = 3329
    out = bytearray()
    coeffs: list[int] = []
    while len(coeffs) < 256 * k:
        pool = os.urandom(2048)
        for i in range(0, len(pool), 2):
            v = int.from_bytes(pool[i : i + 2], "little") & 0x0FFF
            if v < q:  # rejection sampling keeps the distribution uniform mod q
                coeffs.append(v)
                if len(coeffs) == 256 * k:
                    break
    for a, b in zip(coeffs[0::2], coeffs[1::2], strict=True):
        out += bytes((a & 0xFF, (a >> 8) | ((b & 0x0F) << 4), b >> 4))
    return bytes(out) + os.urandom(32)


def _x25519_public() -> bytes:
    return (
        x25519.X25519PrivateKey.generate()
        .public_key()
        .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    )


def _ec_public(curve: ec.EllipticCurve) -> bytes:
    return (
        ec.generate_private_key(curve)
        .public_key()
        .public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    )


def make_key_share(group: int) -> bytes:
    """Client key_share payload for a group, laid out as the hybrid drafts specify."""
    if group == 0x001D:
        return _x25519_public()
    if group == 0x0017:
        return _ec_public(ec.SECP256R1())
    if group == 0x0018:
        return _ec_public(ec.SECP384R1())
    if group == 0x0019:
        return _ec_public(ec.SECP521R1())
    if group == 0x11EC:  # X25519MLKEM768: ML-KEM first, then X25519 (1184 + 32 = 1216 bytes)
        return _mlkem_public(768) + _x25519_public()
    if group == 0x11EB:  # SecP256r1MLKEM768: ECDH first (65 + 1184)
        return _ec_public(ec.SECP256R1()) + _mlkem_public(768)
    if group == 0x11ED:  # SecP384r1MLKEM1024 (97 + 1568)
        return _ec_public(ec.SECP384R1()) + _mlkem_public(1024)
    if group == 0x0201:
        return _mlkem_public(768)
    if group == 0x0202:
        return _mlkem_public(1024)
    raise ValueError(f"no key share generator for group 0x{group:04X}")


# ------------------------------------------------------------- builders ---


def _u8(b: bytes) -> bytes:
    if len(b) > 0xFF:
        raise ValueError("vector too long for u8 length")
    return struct.pack("!B", len(b)) + b


def _u16(b: bytes) -> bytes:
    if len(b) > 0xFFFF:
        raise ValueError("vector too long for u16 length")
    return struct.pack("!H", len(b)) + b


def _u24(b: bytes) -> bytes:
    return struct.pack("!I", len(b))[1:] + b


def _ext(etype: int, data: bytes) -> bytes:
    return struct.pack("!H", etype) + _u16(data)


@dataclass
class ClientHelloSpec:
    server_name: str | None
    versions: tuple[int, ...]  # e.g. (0x0304,) or (0x0304, 0x0303) or (0x0303,)
    cipher_suites: tuple[int, ...]
    groups: tuple[int, ...] = ()
    key_share_groups: tuple[int, ...] = ()
    alpn: tuple[str, ...] = ("http/1.1",)


@dataclass
class BuiltHello:
    record: bytes
    key_share_bytes: int  # total key_exchange bytes the client sent


def build_client_hello(spec: ClientHelloSpec) -> BuiltHello:
    if not spec.versions:
        raise ValueError("at least one version is required")
    tls13 = 0x0304 in spec.versions
    max_legacy = min(max(spec.versions), 0x0303)
    exts = bytearray()

    if spec.server_name and not _is_ip(spec.server_name):
        name = spec.server_name.encode("ascii")
        exts += _ext(EXT_SERVER_NAME, _u16(b"\x00" + _u16(name)))
    if spec.groups:
        exts += _ext(EXT_SUPPORTED_GROUPS, _u16(b"".join(struct.pack("!H", g) for g in spec.groups)))
    exts += _ext(EXT_EC_POINT_FORMATS, _u8(b"\x00"))
    if max(spec.versions) >= 0x0303:
        exts += _ext(EXT_SIGNATURE_ALGORITHMS, _u16(b"".join(struct.pack("!H", s) for s in SIGNATURE_ALGORITHMS)))
    if spec.alpn:
        exts += _ext(EXT_ALPN, _u16(b"".join(_u8(p.encode()) for p in spec.alpn)))
    exts += _ext(EXT_EXTENDED_MASTER_SECRET, b"")
    exts += _ext(EXT_SESSION_TICKET, b"")
    exts += _ext(EXT_RENEGOTIATION_INFO, b"\x00")
    share_total = 0
    if tls13:
        exts += _ext(EXT_SUPPORTED_VERSIONS, _u8(b"".join(struct.pack("!H", v) for v in spec.versions)))
        exts += _ext(EXT_PSK_KEY_EXCHANGE_MODES, _u8(b"\x01"))
        shares = bytearray()
        for g in spec.key_share_groups:
            ks = make_key_share(g)
            share_total += len(ks)
            shares += struct.pack("!H", g) + _u16(ks)
        exts += _ext(EXT_KEY_SHARE, _u16(bytes(shares)))

    body = (
        struct.pack("!H", max_legacy)
        + os.urandom(32)
        + _u8(os.urandom(32))  # legacy_session_id: non-empty for middlebox compatibility
        + _u16(b"".join(struct.pack("!H", c) for c in spec.cipher_suites))
        + _u8(b"\x00")
        + _u16(bytes(exts))
    )
    hs = struct.pack("!B", HS_CLIENT_HELLO) + _u24(body)
    record = struct.pack("!BHH", CT_HANDSHAKE, 0x0301, len(hs)) + hs
    return BuiltHello(record=record, key_share_bytes=share_total)


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


# -------------------------------------------------------------- parsers ---


class _Buf:
    def __init__(self, data: bytes) -> None:
        self.d = data
        self.i = 0

    def take(self, n: int) -> bytes:
        if n < 0 or self.i + n > len(self.d):
            raise TLSDecodeError("truncated message")
        out = self.d[self.i : self.i + n]
        self.i += n
        return out

    def u8(self) -> int:
        return self.take(1)[0]

    def u16(self) -> int:
        return int(struct.unpack("!H", self.take(2))[0])

    def u24(self) -> int:
        return int.from_bytes(self.take(3), "big")

    def vec8(self) -> bytes:
        return self.take(self.u8())

    def vec16(self) -> bytes:
        return self.take(self.u16())

    def vec24(self) -> bytes:
        return self.take(self.u24())

    @property
    def left(self) -> int:
        return len(self.d) - self.i


@dataclass
class ServerHello:
    legacy_version: int
    version: int  # negotiated (supported_versions overrides legacy_version)
    random: bytes
    cipher_suite: int
    hello_retry: bool
    key_share_group: int | None
    key_share_len: int | None
    extensions: dict[int, bytes] = field(default_factory=dict)

    @property
    def version_name(self) -> str:
        return TLS_VERSIONS.get(self.version, f"0x{self.version:04X}")


def parse_server_hello(body: bytes) -> ServerHello:
    b = _Buf(body)
    legacy_version = b.u16()
    random = b.take(32)
    b.vec8()  # session id echo
    suite = b.u16()
    if b.u8() != 0:
        raise TLSDecodeError("server selected a compression method")
    exts: dict[int, bytes] = {}
    if b.left:
        eb = _Buf(b.vec16())
        while eb.left:
            et = eb.u16()
            if et in exts:
                raise TLSDecodeError(f"duplicate extension {et}")
            exts[et] = eb.vec16()
    if b.left:
        raise TLSDecodeError("trailing bytes in ServerHello")

    version = legacy_version
    if EXT_SUPPORTED_VERSIONS in exts:
        sv = exts[EXT_SUPPORTED_VERSIONS]
        if len(sv) != 2:
            raise TLSDecodeError("bad supported_versions in ServerHello")
        version = int(struct.unpack("!H", sv)[0])

    hrr = random == HRR_RANDOM
    group = share_len = None
    if EXT_KEY_SHARE in exts:
        kb = _Buf(exts[EXT_KEY_SHARE])
        group = kb.u16()
        if not hrr:
            share_len = len(kb.vec16())
        if kb.left:
            raise TLSDecodeError("trailing bytes in key_share")
    return ServerHello(legacy_version, version, random, suite, hrr, group, share_len, exts)


def parse_certificate_tls12(body: bytes) -> list[bytes]:
    b = _Buf(body)
    chain = _Buf(b.vec24())
    certs = []
    while chain.left:
        certs.append(chain.vec24())
    return certs


@dataclass
class ServerKeyExchange:
    kind: str  # "ECDHE" or "DHE" or "unknown"
    group: int | None = None
    dh_bits: int | None = None


def parse_server_key_exchange(body: bytes, kex_family: str) -> ServerKeyExchange:
    b = _Buf(body)
    if kex_family == "ECDHE":
        if b.u8() != 3:  # named_curve
            return ServerKeyExchange("ECDHE")
        return ServerKeyExchange("ECDHE", group=b.u16())
    if kex_family == "DHE":
        p = b.vec16()
        return ServerKeyExchange("DHE", dh_bits=len(p.lstrip(b"\x00")) * 8)
    return ServerKeyExchange("unknown")


def describe_alert(payload: bytes) -> str:
    if len(payload) < 2:
        return "malformed_alert"
    return TLS_ALERTS.get(payload[1], f"alert_{payload[1]}")


def describe_group(code: int | None) -> str | None:
    return group_name(code)
