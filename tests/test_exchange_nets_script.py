"""scripts/check_exchange_nets.py: reading the prefix list and finding overlaps (offline)."""

import importlib.util
import ipaddress
from pathlib import Path

import mail_access

_PATH = Path(__file__).resolve().parent.parent / "scripts" / "check_exchange_nets.py"
_spec = importlib.util.spec_from_file_location("check_exchange_nets", _PATH)
script = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(script)


def test_reads_the_same_prefixes_as_the_function():
    assert script.configured_nets(script.SOURCE.read_text(encoding="utf-8")) == list(mail_access.EXCHANGE_SERVER_NETS)


def test_overlap():
    nets = [ipaddress.ip_network("2603:10b6::/32")]
    published = {"AzureCloud": ["2603:1030::/36", "2603:10b6:930::/48", "20.0.0.0/8"], "Office": ["2603:1036::/36"]}
    assert script.overlaps(nets, published) == [("2603:10b6::/32", "AzureCloud", "2603:10b6:930::/48")]
    assert script.overlaps(nets, {"AzureCloud": ["2603::/16"]})             # a wider published prefix
    assert script.overlaps(nets, {"Office": ["2603:1036::/36"]}) == []
