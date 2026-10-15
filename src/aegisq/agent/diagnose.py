"""Deterministic root-cause analysis for failed config tests, so the explanation never depends on the model."""

from __future__ import annotations

import re
from dataclasses import dataclass

_OPENSSL_BUILT = re.compile(r"built with OpenSSL (\d+)\.(\d+)\.(\d+)")
_OPENSSL_RUNNING = re.compile(r"(?:running with|Running on OpenSSL version :) OpenSSL (\d+)\.(\d+)\.(\d+)")
_OPENSSL_ANY = re.compile(r"OpenSSL[ /](\d+)\.(\d+)\.(\d+)")
_BORINGSSL = re.compile(r"built with BoringSSL", re.I)
_OPENSSH = re.compile(r"OpenSSH_(\d+)\.(\d+)")
_SSH_BAD_KEX = re.compile(
    r"Bad SSH2 KexAlgorithms|Unsupported KEX|unsupported kex|KexAlgorithms.*(?:bad|invalid)", re.I
)
_GROUP_FAIL = re.compile(
    r"(SSL_CTX_set1_(?:curves|groups)_list|SSL_CTX_set_ecdh_auto|Unknown group|unknown curve|"
    r"invalid curve|ssl_ecdh_curve|unable to set SSL curves|SSLOpenSSLConfCmd (?:Groups|Curves)|"
    r"cannot be set|unrecognized curve|unsupported curve|curves)",
    re.I,
)
SERVER_NAMES = {
    "nginx": "nginx",
    "apache": "Apache",
    "haproxy": "HAProxy",
    "caddy": "Caddy",
    "postfix": "Postfix",
    "dovecot": "Dovecot",
}
_TEST_CMD = {
    "nginx": "nginx -t",
    "apache": "apachectl configtest",
    "haproxy": "haproxy -c",
    "caddy": "caddy validate",
    "postfix": "postfix check",
    "dovecot": "doveconf -n",
}
_UPGRADE = {
    "nginx": "an nginx build linked against OpenSSL 3.5 or later (for example nginx 1.29 on Alpine 3.22+, "
    "Ubuntu 26.04 or Debian 13)",
    "apache": "an Apache httpd whose mod_ssl loads OpenSSL 3.5 or later (for example Ubuntu 26.04 or Debian 13)",
    "haproxy": "HAProxy linked against OpenSSL 3.5 or later, or a build with AWS-LC",
    "caddy": "Caddy 2.10 or later",
    "postfix": "Postfix linked against OpenSSL 3.5 or later (Postfix 3.11 also changes the default list)",
    "dovecot": "Dovecot linked against OpenSSL 3.5 or later",
}


@dataclass
class Diagnosis:
    root_cause: str
    recommendation: str
    openssl_version: str | None = None
    category: str = "unknown"  # tls_library_too_old | syntax | permission | unknown

    def to_dict(self) -> dict[str, str | None]:
        return dict(self.__dict__)


def openssl_version_from(text: str) -> tuple[int, int, int] | None:
    m = _OPENSSL_RUNNING.search(text) or _OPENSSL_BUILT.search(text) or _OPENSSL_ANY.search(text)
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else None


def library_too_old(server: str, version: str | None) -> Diagnosis:
    name = SERVER_NAMES.get(server, server)
    ver = openssl_version_from(version or "")
    ver_s = ".".join(map(str, ver)) if ver else None
    lib = f"OpenSSL {ver_s}" if ver_s else (version or "its TLS library")
    return Diagnosis(
        root_cause=(
            f"{name} uses {lib}, which has no ML-KEM. X25519MLKEM768 was added in OpenSSL 3.5, "
            "so the TLS library rejects the group list."
        ),
        recommendation=(
            f"Upgrade this server to {_UPGRADE.get(server, 'a build linked against OpenSSL 3.5 or later')}, then "
            "re-run AegisQ. No config change can fix this on the current library."
        ),
        openssl_version=ver_s,
        category="tls_library_too_old",
    )


def server_too_old(server: str, version_output: str) -> Diagnosis | None:
    """Servers whose own code, not the TLS library, decides whether a group name is usable."""
    if server == "postfix":
        m = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", version_output or "")
        if m and (int(m.group(1)), int(m.group(2))) < (3, 10):
            ver = m.group(0)
            return Diagnosis(
                root_cause=(
                    f"Postfix {ver} checks tls_eecdh_auto_curves names itself and ignores X25519MLKEM768 "
                    "('ignoring unknown key exchange group'), even when OpenSSL supports it."
                ),
                recommendation="Upgrade to Postfix 3.10 or later with OpenSSL 3.5 or later, then re-run AegisQ.",
                category="server_too_old",
            )
    return None


def diagnose(test_output: str, version_output: str = "", server: str = "nginx") -> Diagnosis:
    name = SERVER_NAMES.get(server, server)
    test_cmd = _TEST_CMD.get(server, "config test")
    ver = openssl_version_from(version_output) or openssl_version_from(test_output)
    ver_s = ".".join(map(str, ver)) if ver else None
    if _GROUP_FAIL.search(test_output):
        if ver and ver < (3, 5, 0):
            return library_too_old(server, f"OpenSSL {ver_s}")
        if _BORINGSSL.search(version_output):
            return Diagnosis(
                root_cause=f"{name} is built with BoringSSL, which names groups differently.",
                recommendation="Use the BoringSSL group name for the ML-KEM hybrid, or rebuild against OpenSSL 3.5+.",
                category="tls_library_too_old",
            )
        return Diagnosis(
            root_cause=f"The TLS library rejected the {name} group list.",
            recommendation=f"Check which TLS library {name} runs with; ML-KEM groups need OpenSSL 3.5+.",
            openssl_version=ver_s,
            category="tls_library_too_old",
        )
    if re.search(r"unknown directive|invalid parameter|unexpected|syntax error|unknown keyword", test_output, re.I):
        return Diagnosis(
            root_cause=f"{name} reported a configuration syntax error.",
            recommendation=f"Inspect the {test_cmd} output; the patch was rolled back automatically.",
            openssl_version=ver_s,
            category="syntax",
        )
    if re.search(r"permission denied", test_output, re.I):
        return Diagnosis(
            root_cause=f"{name} could not read a file it needs (permission denied).",
            recommendation="Fix file permissions on the server; the patch was rolled back automatically.",
            openssl_version=ver_s,
            category="permission",
        )
    return Diagnosis(
        root_cause="The config test failed for a reason AegisQ does not recognise.",
        recommendation="Read the test output below; the previous config was restored.",
        openssl_version=ver_s,
    )


def openssh_version_from(text: str) -> tuple[int, int] | None:
    m = _OPENSSH.search(text or "")
    return (int(m.group(1)), int(m.group(2))) if m else None


def diagnose_sshd(test_output: str, version_output: str = "") -> Diagnosis:
    ver = openssh_version_from(version_output) or openssh_version_from(test_output)
    ver_s = ".".join(map(str, ver)) if ver else None
    if _SSH_BAD_KEX.search(test_output):
        if ver and ver < (9, 9):
            return Diagnosis(
                root_cause=(
                    f"sshd is OpenSSH {ver_s}, which does not know mlkem768x25519-sha256 (added in OpenSSH 9.9), "
                    "so it rejected the KexAlgorithms list."
                ),
                recommendation=(
                    "Use sntrup761x25519-sha512@openssh.com (OpenSSH 8.5+) as the post-quantum hybrid, or upgrade "
                    "to OpenSSH 9.9+ (mlkem768x25519-sha256 is the default from 10.0)."
                ),
                category="ssh_too_old",
            )
        return Diagnosis(
            root_cause="sshd rejected an algorithm in the KexAlgorithms list.",
            recommendation="Check `sshd -V` and `ssh -Q kex` on the server for the methods this build supports.",
            category="ssh_too_old",
        )
    if re.search(r"permission denied", test_output, re.I):
        return Diagnosis(
            root_cause="sshd could not read a file it needs (permission denied).",
            recommendation="Fix file permissions on the server; the previous config was restored.",
            category="permission",
        )
    if re.search(r"Bad configuration option|bad option|unsupported option|missing argument", test_output, re.I):
        return Diagnosis(
            root_cause="sshd reported a configuration syntax error.",
            recommendation="Inspect the sshd -t output; the previous config was restored.",
            category="syntax",
        )
    return Diagnosis(
        root_cause="The sshd config test failed for a reason AegisQ does not recognise.",
        recommendation="Read the test output below; the previous config was restored.",
    )
