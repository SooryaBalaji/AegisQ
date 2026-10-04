import pytest

from aegisq.netutil import Scope, TargetError, parse_endpoint, validate_host, validate_port


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("Example.COM", "example.com"),
        ("example.com.", "example.com"),
        ("10.0.0.1", "10.0.0.1"),
        ("[::1]", "::1"),
        ("2001:db8::1", "2001:db8::1"),
        ("bücher.de", "xn--bcher-kva.de"),
        ("under_score.internal", "under_score.internal"),
    ],
)
def test_valid_hosts(raw: str, expected: str) -> None:
    assert validate_host(raw) == expected


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "-oProxyCommand=touch /tmp/pwned",
        "host;rm -rf /",
        "a b",
        "$(id)",
        "`id`",
        "a/b",
        "a\nb",
        "x" * 254,
        "a..b",
        "-starts-dash.com",
        "ends-dash-.com",
        "host:22",
        "http://host",
        "a@b",
    ],
)
def test_hostile_hosts_rejected(raw: str) -> None:
    with pytest.raises(TargetError):
        validate_host(raw)


@pytest.mark.parametrize("port", [0, -1, 65536, True, "443", 1.5])
def test_bad_ports(port: object) -> None:
    with pytest.raises(TargetError):
        validate_port(port)  # type: ignore[arg-type]


def test_parse_endpoint() -> None:
    assert parse_endpoint("example.com") == ("example.com", 443)
    assert parse_endpoint("example.com:8443") == ("example.com", 8443)
    assert parse_endpoint("[2001:db8::1]:22", 443) == ("2001:db8::1", 22)
    assert parse_endpoint("2001:db8::1") == ("2001:db8::1", 443)
    for bad in ("example.com:abc", "[::1", "[::1]x", "a:99999"):
        with pytest.raises(TargetError):
            parse_endpoint(bad)


def test_scope() -> None:
    s = Scope(allow=["10.0.0.0/8", ".corp.example"], deny=["10.6.6.0/24", "bad.corp.example"])
    s.check("10.1.2.3")
    s.check("api.corp.example", ["192.0.2.1"])
    s.check("corp.example")
    with pytest.raises(TargetError):
        s.check("10.6.6.6")
    with pytest.raises(TargetError):
        s.check("bad.corp.example", ["10.1.1.1"])
    with pytest.raises(TargetError):
        s.check("example.org", ["192.0.2.1"])
    # DNS pointing into a denied range is refused even if the name is allowed
    with pytest.raises(TargetError):
        s.check("x.corp.example", ["10.6.6.1"])
    Scope().check("anything.example", ["127.0.0.1"])
