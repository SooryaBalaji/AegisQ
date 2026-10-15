"""What the owner of a service should change, per platform, when AegisQ does not manage it.

Every line here comes from the vendor's own documentation or release notes (see README, "Supported servers").
"""

from __future__ import annotations

ADVICE: dict[str, str] = {
    "nginx": "set 'ssl_ecdh_curve X25519MLKEM768:X25519:prime256v1;' in each TLS server block; nginx must be linked "
    "against OpenSSL 3.5 or later (check 'nginx -V').",
    "apache": "add 'SSLOpenSSLConfCmd Groups X25519MLKEM768:X25519:prime256v1' to each TLS virtual host; mod_ssl must "
    "load OpenSSL 3.5 or later. 'apachectl configtest' does not check this line, and on an older OpenSSL Apache exits "
    "on reload, so confirm the library first.",
    "haproxy": "set 'ssl-default-bind-curves X25519MLKEM768:X25519:P-256' in the global section; HAProxy must be "
    "linked against OpenSSL 3.5 or later, or AWS-LC (check 'haproxy -vv').",
    "caddy": "upgrade to Caddy 2.10 or later, which prefers X25519MLKEM768 by default, and remove any 'curves' line "
    "that leaves it out.",
    "postfix": "set 'tls_eecdh_auto_curves = X25519MLKEM768, X25519, prime256v1, secp384r1' in main.cf with OpenSSL "
    "3.5 or later; Postfix 3.11 changes the default list itself when built with OpenSSL 3.5 or later.",
    "dovecot": "set 'ssl_curve_list = X25519MLKEM768:X25519:prime256v1:secp384r1' (Dovecot 2.3) with OpenSSL 3.5 or "
    "later, then 'doveadm reload'.",
    "openssh": "upgrade to OpenSSH 9.9+ (mlkem768x25519-sha256 is the default from 10.0) or set 'KexAlgorithms "
    "mlkem768x25519-sha256,sntrup761x25519-sha512@openssh.com,curve25519-sha256' in sshd_config.",
    "lighttpd": "upgrade to lighttpd 1.4.83 or later, which adds X25519MLKEM768 to its default TLS groups (OpenSSL "
    "3.5 or later is still required).",
    "envoy": "put X25519MLKEM768 first in the listener's tls_params.ecdh_curves (Envoy uses BoringSSL, which supports "
    "it), keeping X25519 and P-256 after it.",
    "windows": "Schannel on recent Windows Server 2025 and Windows 11 24H2+ builds supports x25519_mlkem768 for TLS "
    "1.3 but leaves it off: add it first in the 'ECC Curve Order' group policy (Network > SSL Configuration Settings), "
    "keeping curve25519, NistP256 and NistP384. Microsoft's 'TLS Supported Groups' page lists the minimum builds.",
    "aws-elb": "switch the HTTPS/TLS listener to a post-quantum security policy, for example "
    "'aws elbv2 modify-listener --listener-arn ARN --ssl-policy ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09' "
    "(AWS's recommended PQ policy).",
    "gcp-lb": "attach an SSL policy with post-quantum key exchange enabled: 'gcloud alpha compute ssl-policies create "
    "NAME --post-quantum-key-exchange ENABLED', then set it on the target HTTPS or SSL proxy.",
}

MANAGEABLE = ("nginx", "apache", "haproxy", "caddy", "postfix", "dovecot", "openssh")


def advice_for(platform: str | None, protocol: str) -> str:
    if protocol == "ssh":
        platform = platform or "openssh"
    if platform and platform in ADVICE:
        hand = (
            f" Or add a managed block (kind {'sshd' if platform == 'openssh' else platform}) so AegisQ can make "
            "the change with approval."
            if platform in MANAGEABLE
            else ""
        )
        return f"not managed by AegisQ: {ADVICE[platform]}{hand}"
    return (
        "not managed by AegisQ: hand the CBOM entry to the owning team, or set 'platform' in the inventory (nginx, "
        "apache, haproxy, caddy, postfix, dovecot, lighttpd, envoy, windows, aws-elb, gcp-lb) for specific steps"
    )
