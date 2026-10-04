"""Deterministic root-cause analysis for failed config tests, so the explanation never depends on the model."""

from __future__ import annotations

import re
from dataclasses import dataclass

_OPENSSL_BUILT = re.compile(r"built with OpenSSL (\d+)\.(\d+)\.(\d+)")
_OPENSSL_RUNNING = re.compile(r"running with OpenSSL (\d+)\.(\d+)\.(\d+)")
_BORINGSSL = re.compile(r"built with BoringSSL", re.I)
_GROUP_FAIL = re.compile(
    r"(SSL_CTX_set1_(?:curves|groups)_list|SSL_CTX_set_ecdh_auto|Unknown group|unknown curve|"
    r"invalid curve|ssl_ecdh_curve)",
    re.I,
)


@dataclass
class Diagnosis:
    root_cause: str
    recommendation: str
    openssl_version: str | None = None
    category: str = "unknown"  # tls_library_too_old | syntax | permission | unknown

    def to_dict(self) -> dict[str, str | None]:
        return dict(self.__dict__)


def openssl_version_from(text: str) -> tuple[int, int, int] | None:
    m = _OPENSSL_RUNNING.search(text) or _OPENSSL_BUILT.search(text)
    return (int(m.group(1)), int(m.group(2)), int(m.group(3))) if m else None


def diagnose(test_output: str, version_output: str = "") -> Diagnosis:
    ver = openssl_version_from(version_output)
    ver_s = ".".join(map(str, ver)) if ver else None
    if _GROUP_FAIL.search(test_output):
        if ver and ver < (3, 5, 0):
            return Diagnosis(
                root_cause=(
                    f"nginx is linked against OpenSSL {ver_s}, which has no ML-KEM. X25519MLKEM768 was "
                    "added in OpenSSL 3.5, so the TLS library rejected the group list."
                ),
                recommendation=(
                    "Upgrade this server to an nginx build linked against OpenSSL 3.5 or later (for example "
                    "nginx 1.29 on Alpine 3.22+, Ubuntu 26.04 or Debian 13), then re-run AegisQ. "
                    "No config change can fix this on the current library."
                ),
                openssl_version=ver_s,
                category="tls_library_too_old",
            )
        if _BORINGSSL.search(version_output):
            return Diagnosis(
                root_cause="nginx is built with BoringSSL, which names groups differently.",
                recommendation="Use the BoringSSL group name for the ML-KEM hybrid, or rebuild against OpenSSL 3.5+.",
                category="tls_library_too_old",
            )
        return Diagnosis(
            root_cause="The TLS library rejected the ssl_ecdh_curve group list.",
            recommendation=("Check the OpenSSL version nginx runs with (`nginx -V`); ML-KEM groups need OpenSSL 3.5+."),
            openssl_version=ver_s,
            category="tls_library_too_old",
        )
    if re.search(r"unknown directive|invalid parameter|unexpected", test_output, re.I):
        return Diagnosis(
            root_cause="nginx reported a configuration syntax error.",
            recommendation="Inspect the nginx -t output; the patch was rolled back automatically.",
            openssl_version=ver_s,
            category="syntax",
        )
    if re.search(r"permission denied", test_output, re.I):
        return Diagnosis(
            root_cause="nginx could not read a file it needs (permission denied).",
            recommendation="Fix file permissions on the server; the patch was rolled back automatically.",
            openssl_version=ver_s,
            category="permission",
        )
    return Diagnosis(
        root_cause="The config test failed for a reason AegisQ does not recognise.",
        recommendation="Read the test output below; the previous config was restored.",
        openssl_version=ver_s,
    )
