"""Microsoft 365 server IP ranges: the generated file, the lookup, and the update script (offline)."""

import importlib.util
import ipaddress
import json
from pathlib import Path

import microsoft_nets

_PATH = Path(__file__).resolve().parent.parent / "scripts" / "update_microsoft_nets.py"
_spec = importlib.util.spec_from_file_location("update_microsoft_nets", _PATH)
script = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(script)


def test_service_ips():
    assert microsoft_nets.is_service_ip("2603:1036:303:2832::5")     # Teams meeting prep (Exchange front end)
    assert microsoft_nets.is_service_ip("2603:10b6:930:d1::7")       # INTERNAL_NETS: Outlook mobile sync
    assert not microsoft_nets.is_service_ip("52.96.11.5")            # Office 365 range, but in an Azure tag
    assert not microsoft_nets.is_service_ip("20.42.0.1")             # Azure
    assert not microsoft_nets.is_service_ip("81.2.69.160")
    assert not microsoft_nets.is_service_ip("not an ip") and not microsoft_nets.is_service_ip(None)


def test_generated_file():
    data = json.loads(microsoft_nets.DATA_FILE.read_text(encoding="utf-8"))
    nets = [ipaddress.ip_network(p) for p in data["prefixes"]]
    assert len(nets) > 500 and data["service_tags"].startswith("ServiceTags_Public_")
    assert data["prefixes"] == [str(n) for n in nets]                 # canonical form
    for internal in map(ipaddress.ip_network, microsoft_nets.INTERNAL_NETS):
        assert internal.prefixlen >= 24 if internal.version == 4 else internal.prefixlen >= 32


def test_missing_file_keeps_internal_nets_only(tmp_path):
    assert microsoft_nets.load_prefixes(tmp_path / "none.json") == []


def test_subtract_service_tags():
    endpoints = ["40.96.0.0/13", "2603:1036::/36", "13.107.6.152/31"]
    tags = ["40.96.46.0/24", "40.100.0.0/14", "2603:1036:903::/48", "13.107.6.152/31", "2603:1030::/32"]
    out = [ipaddress.ip_network(p) for p in script.safe_prefixes(endpoints, tags)]
    covered = lambda ip: any(ipaddress.ip_address(ip) in n for n in out)   # noqa: E731
    assert covered("40.96.45.255") and covered("40.96.47.0") and covered("40.99.255.255")
    assert not covered("40.96.46.1") and not covered("40.100.0.1") and not covered("13.107.6.152")
    assert covered("2603:1036:303:2832::5") and not covered("2603:1036:903::1")
    assert sum(n.num_addresses for n in out if n.version == 4) == 2**19 - 256 - 2**18


def test_internal_net_in_a_service_tag():
    tags = {"AzureCloud": ["2603:1030::/36", "2603:10b6:930::/48"], "Other": ["2603::/16"]}
    assert script.tag_overlaps(["2603:10b6::/32"], tags) == [
        ("2603:10b6::/32", "AzureCloud", "2603:10b6:930::/48"), ("2603:10b6::/32", "Other", "2603::/16")]
    assert script.tag_overlaps(["2603:10b6::/32"], {"AzureCloud": ["2603:1036::/36"]}) == []
