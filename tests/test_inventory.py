from pathlib import Path

import pytest

from aegisq.inventory import InventoryError, load_inventory
from aegisq.models import Protocol


def test_yaml_inventory(tmp_path: Path) -> None:
    (tmp_path / "conf").mkdir()
    (tmp_path / "inv.yaml").write_text(
        """
defaults: {host: 127.0.0.1, data_category: Health}
services:
  - {name: web, port: 8443, sni: www.example.com, managed: {config_path: conf/site.conf}}
  - {name: ssh, protocol: ssh}
  - {host: example.org}
"""
    )
    t = load_inventory(tmp_path / "inv.yaml")
    assert [x.name for x in t] == ["web", "ssh", "example.org-443"]
    assert t[0].data_category == "health" and t[0].server_name == "www.example.com"
    assert t[0].managed and t[0].managed.config_path == str((tmp_path / "conf" / "site.conf").resolve())
    assert t[0].managed.test_cmd == ["nginx", "-t"]
    assert t[1].protocol == Protocol.SSH and t[1].port == 22


@pytest.mark.parametrize(
    ("doc", "msg"),
    [
        ("services: {}", "services"),
        ("services: [1]", "mapping"),
        ("services: [{name: a, host: '-oProxyCommand=x', port: 1}]", "host"),
        ("services: [{name: 'bad name', host: a.com, port: 1}]", "name"),
        ("services: [{name: a, host: a.com, port: 1, unknown: 1}]", "unknown"),
        ("services: [{name: a, host: a.com, port: 1}, {name: a, host: b.com, port: 1}]", "duplicate"),
        ("services: [{name: a, host: a.com, port: 1, managed: {config_path: x, test_cmd: []}}]", "test_cmd"),
        ("services: [{name: a, host: a.com, port: 1, managed: {config_path: x, test_cmd: 'nginx -t'}}]", "test_cmd"),
        ("services: [", "YAML"),
    ],
)
def test_bad_inventory(tmp_path: Path, doc: str, msg: str) -> None:
    p = tmp_path / "inv.yaml"
    p.write_text(doc)
    with pytest.raises(InventoryError, match=msg):
        load_inventory(p)


def test_host_list(tmp_path: Path) -> None:
    p = tmp_path / "hosts.txt"
    p.write_text("# fleet\nexample.com\nexample.com:8443 tls payments\n10.0.0.5:22\n[2001:db8::1]:2222 ssh\n\n")
    t = load_inventory(p)
    assert [(x.host, x.port, x.protocol.value, x.data_category) for x in t] == [
        ("example.com", 443, "tls", "unknown"),
        ("example.com", 8443, "tls", "payments"),
        ("10.0.0.5", 22, "ssh", "unknown"),
        ("2001:db8::1", 2222, "ssh", "unknown"),
    ]
    for bad in ("a.com udp", "a.com:x", "a b c d", "$(id)"):
        p.write_text(bad)
        with pytest.raises(InventoryError):
            load_inventory(p)


def test_missing_file(tmp_path: Path) -> None:
    with pytest.raises(InventoryError):
        load_inventory(tmp_path / "nope.yaml")
