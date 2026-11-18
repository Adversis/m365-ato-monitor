"""proxycheck.io v3: the adapter to the v2 shape, the batch request, and the alert text.

The answers have the shape of real v3 answers (November 2026). IPs are documentation
ranges and networks are made up.
"""

from unittest.mock import MagicMock, patch

import pytest

import config
import ip_checker
from tests.fakes import FakeTable


def _v3(**det):
    """A v3 answer. ``det`` sets detections; ``net``, ``operator``, ``attacks`` set the other parts."""
    net = det.pop("net", "Hosting")
    operator = det.pop("operator", None)
    attacks = det.pop("attacks", None)
    risk = det.pop("risk", 0)
    detections = {"proxy": False, "vpn": False, "compromised": False, "scraper": False, "tor": False,
                  "hosting": False, "anonymous": False, "risk": risk, "confidence": 100,
                  "first_seen": None, "last_seen": None, "times_seen": None}
    detections.update(det)
    return {
        "network": {"asn": "AS64500", "range": "203.0.113.0/24", "hostname": "exit-1.example.net",
                    "provider": "Example Hosting", "organisation": "Example Org", "type": net},
        "location": {"continent_name": "Europe", "continent_code": "EU", "country_name": "Sweden",
                     "country_code": "SE", "region_name": "Stockholm", "region_code": "AB",
                     "city_name": "Stockholm", "postal_code": "103 59", "latitude": 59.3, "longitude": 18.0,
                     "timezone": "Europe/Stockholm", "currency": {"name": "Krona", "code": "SEK", "symbol": "kr"}},
        "device_estimate": {"address": 1, "subnet": 20},
        "detections": detections,
        "detection_history": None,
        "attack_history": attacks,
        "operator": operator,
        "last_updated": "2026-11-18T17:45:54Z",
    }


VPN_OPERATOR = {"name": "ExampleVPN", "url": "https://vpn.example/", "anonymity": "high", "popularity": "high",
                "services": ["datacenter_vpns"], "protocols": ["WireGuard"], "policies": {},
                "additional_operators": None}

# The same IP in v2 (production flags) and v3: the confidence must not change.
PAIRS = [
    ("tor", {"proxy": "yes", "type": "TOR", "risk": 100}, _v3(tor=True, anonymous=True, risk=75, net="Business")),
    ("vpn", {"proxy": "yes", "type": "VPN", "risk": 73},
     _v3(vpn=True, hosting=True, anonymous=True, risk=50, operator=VPN_OPERATOR)),
    # v2 calls a cloud host a VPN; v3 says hosting. Both medium.
    ("hosting", {"proxy": "yes", "type": "VPN", "risk": 66}, _v3(hosting=True, risk=33)),
    ("clean", {"proxy": "no", "type": "Wireless", "risk": 0}, _v3(net="Wireless")),
    ("compromised", {"proxy": "yes", "type": "Compromised Server", "risk": 100},
     _v3(compromised=True, anonymous=True, risk=100, net="Residential")),
    ("inferred", {"proxy": "yes", "type": "Inference Engine", "risk": 66}, _v3(anonymous=True, risk=100, net="Business")),
]


@pytest.mark.parametrize("name,v2,v3", PAIRS, ids=[p[0] for p in PAIRS])
def test_same_confidence_as_v2(name, v2, v3):
    old, new = ip_checker.analyze_ip(v2), ip_checker.analyze_ip(ip_checker.from_v3(v3))
    assert (new["confidence"], new["is_suspicious"]) == (old["confidence"], old["is_suspicious"])


@pytest.mark.parametrize("net", ["Residential", "Wireless", "Hosting", "Business"])
def test_proxy_is_high_on_any_network(net):
    a = ip_checker.analyze_ip(ip_checker.from_v3(_v3(proxy=True, anonymous=True, risk=100, net=net)))
    assert a["confidence"] == "high" and a["is_suspicious"]


def test_adapter_fields():
    data = ip_checker.from_v3(_v3(vpn=True, anonymous=True, risk=50, operator=VPN_OPERATOR,
                                  attacks={"login_attempt": 2, "vulnerability_probing": 0}))
    assert data["proxy"] == "yes" and data["type"] == "VPN" and data["risk"] == 50
    assert data["isocode"] == "SE" and data["country"] == "Sweden" and data["city"] == "Stockholm"
    assert data["asn"] == "AS64500" and data["organisation"] == "Example Org"
    assert data["operator"] == "ExampleVPN" and data["hostname"] == "exit-1.example.net"
    assert data["attacks"] == {"login_attempt": 2}
    a = ip_checker.analyze_ip(data)
    assert a["operator"] == "ExampleVPN" and a["attacks"] == {"login_attempt": 2}


def test_v2_answer_passes_unchanged():
    v2 = {"proxy": "yes", "type": "SOCKS5", "risk": 100, "isocode": "SE"}
    assert ip_checker.from_v3(v2) is v2
    assert ip_checker.analyze_ip(v2)["confidence"] == "high"      # an old cache entry keeps its verdict
    assert ip_checker.analyze_ip(v2)["operator"] == ""


def test_missing_sections_do_not_raise():
    data = ip_checker.from_v3({"detections": None, "network": None, "location": None, "operator": None})
    assert data["proxy"] == "no" and data["type"] == "" and data["isocode"] == ""


def _resp(status_code, body):
    r = MagicMock(status_code=status_code)
    r.json.return_value = body
    return r


def test_batch_uses_v3_and_caches_the_v2_shape():
    cache = FakeTable()
    body = {"status": "ok", "203.0.113.9": _v3(tor=True, anonymous=True, risk=75),
            "2001:db8::1": _v3(net="Residential")}
    with patch("config.http") as http, patch.object(config, "PROXYCHECK_API_KEY", ""):
        http.post.return_value = _resp(200, body)
        out = ip_checker.check_ips_batch(["203.0.113.9", "2001:db8::1"], cache)
    url = http.post.call_args.args[0]
    assert url.startswith("https://proxycheck.io/v3/?")           # a bare /v3/ redirects
    assert out["203.0.113.9"]["type"] == "TOR" and out["2001:db8::1"]["proxy"] == "no"
    cached = ip_checker.get_cached_ip("203.0.113.9", cache)
    assert cached["type"] == "TOR" and cached["api"] == 3


def test_denied_with_http_429_is_noted_and_negative_cached():
    cache = FakeTable()
    with patch("config.http") as http, patch("proxycheck_quota.note") as note:
        http.post.return_value = _resp(429, {"status": "denied", "message": "1,000 Free queries exhausted."})
        out = ip_checker.check_ips_batch(["203.0.113.9"], cache)
    assert out == {}
    note.assert_called_once()
    assert note.call_args.args[1] == "denied"
    assert ip_checker.get_cached_ip("203.0.113.9", cache) == {"_negative": True}


def test_alert_shows_service_hostname_and_attacks():
    import alerting
    analysis = ip_checker.analyze_ip(ip_checker.from_v3(
        _v3(vpn=True, anonymous=True, risk=50, operator=VPN_OPERATOR, attacks={"login_attempt": 2})))
    event = {"UserId": "jane@contoso.com", "CreationTime": "2026-06-12T14:00:00", "Operation": "UserLoggedIn"}
    sent = []
    with patch("alerting._send_email", side_effect=lambda s, b: sent.append(b) or True):
        alerting.send_suspicious_login_alert(event, "203.0.113.9", analysis)
        alerting.send_suspicious_login_alert(event, "203.0.113.9", ip_checker.analyze_ip(
            {"proxy": "yes", "type": "VPN", "risk": 73}))
    assert "ExampleVPN" in sent[0] and "exit-1.example.net" in sent[0] and "2 login attempts" in sent[0]
    assert "Service" not in sent[1] and "Attacks seen" not in sent[1]
