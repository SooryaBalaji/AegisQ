#!/usr/bin/env python3
"""Prepare the demo fleet: copy pristine nginx configs into fleet/ and create a local CA + server cert.

Run again at any time to reset the fleet to its starting (mostly classical) state.
"""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import os
import shutil
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

HERE = Path(__file__).resolve().parent
SERVICES = ["app-modern", "app-legacy", "app-tls12", "app-ready", "app-plain"]


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AegisQ Demo"), x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def make_certs(out: Path) -> None:
    out.mkdir(parents=True, exist_ok=True)
    now = dt.datetime.now(dt.timezone.utc)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca = (
        x509.CertificateBuilder()
        .subject_name(_name("AegisQ Demo CA"))
        .issuer_name(_name("AegisQ Demo CA"))
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name("localhost"))
        .issuer_name(ca.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=90))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),
            critical=False,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    (out / "ca.crt").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    (out / "server.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM) + ca.public_bytes(serialization.Encoding.PEM))
    key_path = out / "server.key"
    key_path.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    key_path.chmod(0o644)  # read by nginx inside the container; demo-only key


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--configs-only", action="store_true", help="reset nginx configs, keep certificates")
    parser.add_argument("--if-missing", action="store_true", help="do nothing if the fleet is already set up")
    args = parser.parse_args()
    fleet = HERE / "fleet"
    if args.if_missing and (fleet / "certs" / "server.crt").exists() and all(
        (fleet / svc / "conf.d" / "site.conf").exists() for svc in SERVICES
    ):
        print(f"demo fleet already set up in {fleet}")
        return
    for svc in SERVICES:
        conf_dir = fleet / svc / "conf.d"
        conf_dir.mkdir(parents=True, exist_ok=True)
        tmp = conf_dir / ".site.conf.tmp"
        shutil.copyfile(HERE / "templates" / f"{svc}.conf", tmp)
        os.replace(tmp, conf_dir / "site.conf")
    if not args.configs_only or not (fleet / "certs" / "server.crt").exists():
        make_certs(fleet / "certs")
    print(f"demo fleet ready in {fleet} (if containers are running: `make demo-reload`)")


if __name__ == "__main__":
    main()
