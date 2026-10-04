import os
import random
import struct

import pytest

from aegisq.scanner import tls_wire as w
from fakes import parse_client_hello, server_hello


def build(versions=(0x0304,), groups=(0x11EC,), shares=(0x11EC,), sni="example.com"):
    return w.build_client_hello(w.ClientHelloSpec(sni, versions, (0x1301,), groups, shares))


def test_pq_client_hello_sizes_match_the_spec() -> None:
    b = build()
    assert b.key_share_bytes == 1216  # ML-KEM-768 ek (1184) + X25519 (32)
    rec = b.record
    assert rec[0] == 22 and struct.unpack("!H", rec[3:5])[0] == len(rec) - 5
    hello = parse_client_hello(rec[5:])
    assert hello.versions == [0x0304]
    assert hello.groups == [0x11EC]
    assert hello.shares == {0x11EC: 1216}
    assert hello.sni == "example.com"
    assert len(hello.session_id) == 32


@pytest.mark.parametrize(("group", "size"), [(0x001D, 32), (0x0017, 65), (0x0018, 97), (0x11EB, 1249), (0x11ED, 1665)])
def test_key_share_layouts(group: int, size: int) -> None:
    assert len(w.make_key_share(group)) == size


def test_hybrid_layout_order() -> None:
    share = w.make_key_share(0x11EB)
    assert share[0] == 0x04  # SecP256r1MLKEM768 puts the uncompressed EC point first
    with pytest.raises(ValueError):
        w.make_key_share(0x9999)


def test_no_sni_for_ip_literals() -> None:
    assert parse_client_hello(build(sni="192.0.2.1").record[5:]).sni is None


def test_tls12_hello_has_no_tls13_extensions() -> None:
    b = w.build_client_hello(w.ClientHelloSpec("a.example", (0x0303,), (0xC02F,), (0x001D,)))
    h = parse_client_hello(b.record[5:])
    assert h.versions == [] and h.shares == {} and h.legacy_version == 0x0303
    assert b.key_share_bytes == 0


def test_synthetic_mlkem_ek_is_well_formed() -> None:
    ek = w.synthetic_mlkem_ek(3)
    assert len(ek) == 1184
    body = ek[:-32]
    for i in range(0, len(body), 3):
        a = body[i] | ((body[i + 1] & 0x0F) << 8)
        b = (body[i + 1] >> 4) | (body[i + 2] << 4)
        assert a < 3329 and b < 3329


def test_parse_server_hello_tls13_and_hrr() -> None:
    sh = w.parse_server_hello(server_hello(0x0304, 0x1301, 0x11EC, 1120, b"s" * 32)[4:])
    assert (sh.version, sh.key_share_group, sh.key_share_len, sh.hello_retry) == (0x0304, 0x11EC, 1120, False)
    assert sh.version_name == "TLSv1.3"
    hrr = w.parse_server_hello(server_hello(0x0304, 0x1301, 0x001D, None, b"", hrr=True)[4:])
    assert hrr.hello_retry and hrr.key_share_group == 0x001D and hrr.key_share_len is None


def test_parse_server_hello_rejects_malformed() -> None:
    good = server_hello(0x0304, 0x1301, 0x11EC, 1120, b"")[4:]
    with pytest.raises(w.TLSDecodeError):
        w.parse_server_hello(good[:-5])
    with pytest.raises(w.TLSDecodeError):
        w.parse_server_hello(good + b"\x00")
    # compression method != 0
    bad = bytearray(good)
    bad[2 + 32 + 1 + 2] = 1
    with pytest.raises(w.TLSDecodeError):
        w.parse_server_hello(bytes(bad))
    # duplicate extension
    ext = struct.pack("!HHH", 43, 2, 0x0304)
    dup = good[: 2 + 32 + 1 + 3] + struct.pack("!H", len(ext) * 2) + ext + ext
    with pytest.raises(w.TLSDecodeError):
        w.parse_server_hello(dup)


def test_parser_fuzz_only_raises_decode_errors() -> None:
    rng = random.Random(1234)
    good = server_hello(0x0304, 0x1301, 0x11EC, 1120, b"x" * 32)[4:]
    for _ in range(3000):
        data = bytearray(good)
        for _ in range(rng.randint(1, 8)):
            op = rng.random()
            pos = rng.randrange(len(data))
            if op < 0.5:
                data[pos] = rng.randrange(256)
            elif op < 0.75:
                del data[pos : pos + rng.randint(1, 20)]
            else:
                data[pos:pos] = os.urandom(rng.randint(1, 20))
        try:
            w.parse_server_hello(bytes(data))
        except w.TLSDecodeError:
            pass
    for _ in range(500):
        with pytest.raises(w.TLSDecodeError):
            w.parse_certificate_tls12(os.urandom(rng.randint(0, 3)) + b"\xff\xff\xff")


def test_alert_and_ske() -> None:
    assert w.describe_alert(b"\x02\x28") == "handshake_failure"
    assert w.describe_alert(b"\x02") == "malformed_alert"
    ske = w.parse_server_key_exchange(struct.pack("!BH", 3, 0x001D) + b"\x20", "ECDHE")
    assert ske.group == 0x001D
    dhe = w.parse_server_key_exchange(struct.pack("!H", 256) + b"\x80" + b"\x00" * 255, "DHE")
    assert dhe.dh_bits == 2048
