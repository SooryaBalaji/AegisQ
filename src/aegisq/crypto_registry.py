"""Registry of key-exchange groups and SSH methods, with their post-quantum classification.

Codepoints come from the IANA "TLS Supported Groups" registry and
draft-ietf-tls-ecdhe-mlkem / draft-ietf-tls-mlkem. SSH names come from the
OpenSSH sources and draft-ietf-sshm-mlkem-hybrid-kex.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class GroupInfo:
    code: int
    name: str
    pq: bool  # contains a post-quantum component
    hybrid: bool  # also contains a classical component
    primitive: str  # CycloneDX primitive: "kem" or "key-agree"
    nist_level: int  # NIST PQ security category; 0 = broken by Shor
    classical_bits: int  # classical security level in bits
    parameter_set: str | None = None
    curve: str | None = None
    obsolete: bool = False


_GROUPS: tuple[GroupInfo, ...] = (
    GroupInfo(0x0017, "secp256r1", False, False, "key-agree", 0, 128, curve="secp256r1"),
    GroupInfo(0x0018, "secp384r1", False, False, "key-agree", 0, 192, curve="secp384r1"),
    GroupInfo(0x0019, "secp521r1", False, False, "key-agree", 0, 256, curve="secp521r1"),
    GroupInfo(0x001D, "x25519", False, False, "key-agree", 0, 128, curve="Curve25519"),
    GroupInfo(0x001E, "x448", False, False, "key-agree", 0, 224, curve="Curve448"),
    GroupInfo(0x0100, "ffdhe2048", False, False, "key-agree", 0, 103),
    GroupInfo(0x0101, "ffdhe3072", False, False, "key-agree", 0, 125),
    GroupInfo(0x0102, "ffdhe4096", False, False, "key-agree", 0, 150),
    GroupInfo(0x0200, "MLKEM512", True, False, "kem", 1, 128, "512"),
    GroupInfo(0x0201, "MLKEM768", True, False, "kem", 3, 192, "768"),
    GroupInfo(0x0202, "MLKEM1024", True, False, "kem", 5, 256, "1024"),
    GroupInfo(0x11EB, "SecP256r1MLKEM768", True, True, "kem", 3, 128, "768", "secp256r1"),
    GroupInfo(0x11EC, "X25519MLKEM768", True, True, "kem", 3, 128, "768", "Curve25519"),
    GroupInfo(0x11ED, "SecP384r1MLKEM1024", True, True, "kem", 5, 192, "1024", "secp384r1"),
    GroupInfo(0x6399, "X25519Kyber768Draft00", True, True, "kem", 3, 128, "768", "Curve25519", True),
    GroupInfo(0x639A, "SecP256r1Kyber768Draft00", True, True, "kem", 3, 128, "768", "secp256r1", True),
)

GROUPS_BY_CODE: dict[int, GroupInfo] = {g.code: g for g in _GROUPS}
GROUPS_BY_NAME: dict[str, GroupInfo] = {g.name.lower(): g for g in _GROUPS}
# OpenSSL / nginx aliases accepted in ssl_ecdh_curve.
_ALIASES = {"prime256v1": "secp256r1", "p-256": "secp256r1", "p-384": "secp384r1", "p-521": "secp521r1"}

X25519MLKEM768 = GROUPS_BY_NAME["x25519mlkem768"]
X25519 = GROUPS_BY_NAME["x25519"]
SECP256R1 = GROUPS_BY_NAME["secp256r1"]
SECP384R1 = GROUPS_BY_NAME["secp384r1"]


def group_by_code(code: int) -> GroupInfo | None:
    return GROUPS_BY_CODE.get(code)


def group_name(code: int | None) -> str | None:
    if code is None:
        return None
    g = GROUPS_BY_CODE.get(code)
    return g.name if g else f"0x{code:04X}"


def group_by_name(name: str) -> GroupInfo | None:
    key = name.strip().lower()
    return GROUPS_BY_NAME.get(_ALIASES.get(key, key))


# ---------------------------------------------------------------- SSH ---

SSH_PQ_KEX = (
    "mlkem768x25519-sha256",
    "sntrup761x25519-sha512",
    "sntrup761x25519-sha512@openssh.com",
    "mlkem768nistp256-sha256",
    "mlkem1024nistp384-sha384",
)
# Methods AegisQ offers when probing, in preference order.
SSH_PQ_PROBE_ORDER = ("mlkem768x25519-sha256", "sntrup761x25519-sha512@openssh.com", "sntrup761x25519-sha512")

SSH_WEAK_KEX = {
    "diffie-hellman-group1-sha1",
    "diffie-hellman-group14-sha1",
    "diffie-hellman-group-exchange-sha1",
    "gss-group1-sha1-",
    "rsa1024-sha1",
}
SSH_WEAK_CIPHERS_PREFIX = ("arcfour", "3des", "blowfish", "cast128", "des", "rijndael-cbc")
SSH_WEAK_CIPHERS_SUFFIX = ("-cbc",)
SSH_WEAK_MACS = {"hmac-md5", "hmac-md5-96", "hmac-sha1-96", "hmac-md5-etm@openssh.com", "umac-32@openssh.com"}
SSH_WEAK_HOSTKEYS = {"ssh-dss", "ssh-rsa"}  # ssh-rsa means RSA with SHA-1 signatures

SSH_KEX_INFO: dict[str, tuple[str, int, int]] = {
    # name: (primitive, nist_level, classical_bits)
    "mlkem768x25519-sha256": ("kem", 3, 128),
    "sntrup761x25519-sha512": ("kem", 2, 128),
    "sntrup761x25519-sha512@openssh.com": ("kem", 2, 128),
    "mlkem768nistp256-sha256": ("kem", 3, 128),
    "mlkem1024nistp384-sha384": ("kem", 5, 192),
    "curve25519-sha256": ("key-agree", 0, 128),
    "curve25519-sha256@libssh.org": ("key-agree", 0, 128),
    "curve448-sha512": ("key-agree", 0, 224),
    "ecdh-sha2-nistp256": ("key-agree", 0, 128),
    "ecdh-sha2-nistp384": ("key-agree", 0, 192),
    "ecdh-sha2-nistp521": ("key-agree", 0, 256),
    "diffie-hellman-group-exchange-sha256": ("key-agree", 0, 112),
    "diffie-hellman-group16-sha512": ("key-agree", 0, 150),
    "diffie-hellman-group18-sha512": ("key-agree", 0, 200),
    "diffie-hellman-group14-sha256": ("key-agree", 0, 112),
    "diffie-hellman-group14-sha1": ("key-agree", 0, 80),
    "diffie-hellman-group1-sha1": ("key-agree", 0, 0),
    "diffie-hellman-group-exchange-sha1": ("key-agree", 0, 80),
}


def ssh_kex_is_pq(name: str) -> bool:
    return name in SSH_PQ_KEX


def ssh_cipher_is_weak(name: str) -> bool:
    return name.startswith(SSH_WEAK_CIPHERS_PREFIX) or name.endswith(SSH_WEAK_CIPHERS_SUFFIX)


# ----------------------------------------------------------- TLS misc ---

TLS_VERSIONS = {0x0300: "SSLv3", 0x0301: "TLSv1.0", 0x0302: "TLSv1.1", 0x0303: "TLSv1.2", 0x0304: "TLSv1.3"}

TLS_ALERTS = {
    0: "close_notify",
    10: "unexpected_message",
    20: "bad_record_mac",
    22: "record_overflow",
    40: "handshake_failure",
    42: "bad_certificate",
    47: "illegal_parameter",
    50: "decode_error",
    51: "decrypt_error",
    70: "protocol_version",
    71: "insufficient_security",
    80: "internal_error",
    86: "inappropriate_fallback",
    90: "user_canceled",
    109: "missing_extension",
    110: "unsupported_extension",
    112: "unrecognized_name",
    120: "no_application_protocol",
}

# Cipher suites AegisQ offers. Names follow IANA.
TLS13_SUITES = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
}
TLS12_SUITES = {
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    0xC009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    0xC00A: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    0x009E: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    0x009F: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
}
ALL_SUITES = {**TLS13_SUITES, **TLS12_SUITES}


def suite_name(code: int | None) -> str | None:
    if code is None:
        return None
    return ALL_SUITES.get(code, f"0x{code:04X}")


def suite_key_exchange(name: str) -> str:
    """Classical key exchange family of a TLS 1.2 suite ('ECDHE', 'DHE', 'RSA')."""
    if name.startswith("TLS_ECDHE_"):
        return "ECDHE"
    if name.startswith("TLS_DHE_"):
        return "DHE"
    if name.startswith("TLS_RSA_"):
        return "RSA"
    return "TLS13"
