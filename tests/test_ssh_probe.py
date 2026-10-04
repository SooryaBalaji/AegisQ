import asyncio

import pytest

from aegisq.models import Protocol, ServiceTarget, Status
from aegisq.scanner import ssh_probe as s
from aegisq.scanner.engine import ScanOptions, scan_service
from fakes import kexinit_packet, ssh_server


def test_parse_kexinit_roundtrip() -> None:
    pkt = kexinit_packet(["mlkem768x25519-sha256", "curve25519-sha256"])
    payload, used = s.parse_packet(pkt)
    assert used == len(pkt)
    ki = s.parse_kexinit(payload)
    assert ki.kex == ["mlkem768x25519-sha256", "curve25519-sha256"]
    assert ki.host_keys and not ki.first_kex_follows


def test_parse_errors() -> None:
    with pytest.raises(s.SSHProbeError):
        s.parse_kexinit(b"\x15" + b"\x00" * 40)
    with pytest.raises(s.SSHProbeError):
        s.parse_kexinit(kexinit_packet(["a"])[5:40])
    with pytest.raises(ValueError):
        s.parse_packet(b"\x00\x00")
    with pytest.raises(s.SSHProbeError):
        s.parse_packet(b"\x7f\xff\xff\xff\x04")


def test_analyze_flags_and_negotiation() -> None:
    ki = s.parse_kexinit(
        s.parse_packet(
            kexinit_packet(
                [
                    "sntrup761x25519-sha512@openssh.com",
                    "mlkem768x25519-sha256",
                    "diffie-hellman-group1-sha1",
                    "kex-strict-s-v00@openssh.com",
                ],
                hostkeys=["ssh-rsa", "ssh-ed25519"],
                ciphers=["3des-cbc", "aes128-ctr"],
                macs=["hmac-md5"],
            )
        )[0]
    )
    d = s.analyze("SSH-2.0-OpenSSH_9.9", ki)
    assert d.pq_ready and d.negotiated_kex == "mlkem768x25519-sha256"  # AegisQ's preference order wins
    assert "kex-strict-s-v00@openssh.com" not in d.kex_algorithms
    assert d.weak_kex == ["diffie-hellman-group1-sha1"]
    assert d.weak_ciphers == ["3des-cbc"] and d.weak_macs == ["hmac-md5"] and d.weak_host_keys == ["ssh-rsa"]
    assert d.software == "OpenSSH_9.9"


@pytest.mark.parametrize(
    ("mode", "status"),
    [
        ("pq", Status.PQ_READY),
        ("classical", Status.CLASSICAL),
        ("prebanner", Status.PQ_READY),
        ("ssh1", Status.ERROR),
        ("oversize", Status.ERROR),
        ("truncated", Status.ERROR),
        ("http", Status.PLAINTEXT),
    ],
)
def test_ssh_scan(mode: str, status: Status) -> None:
    with ssh_server(mode) as srv:
        t = ServiceTarget(name="s", host="127.0.0.1", port=srv.port, protocol=Protocol.SSH)
        res = asyncio.run(scan_service(t, ScanOptions(timeout=2)))
    assert res.status == status, res.errors
    if mode == "classical":
        assert res.ssh and res.ssh.weak_kex == ["diffie-hellman-group14-sha1"]
        assert res.ssh.weak_ciphers == ["aes128-cbc"] and res.ssh.weak_macs == ["hmac-md5"]
        assert any("no post-quantum" in f for f in res.findings)


def test_ssh_unreachable() -> None:
    t = ServiceTarget(name="s", host="127.0.0.1", port=1, protocol=Protocol.SSH)
    assert asyncio.run(scan_service(t, ScanOptions(timeout=1))).status == Status.UNREACHABLE
