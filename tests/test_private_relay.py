"""iCloud Private Relay: Apple's egress list, lookups, and the effect on sign-in checks."""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

import config
import private_relay as pr
from ip_checker import analyze_ip, check_ips_batch

# Same format as https://mask-api.icloud.com/egress-ip-ranges.csv
SAMPLE = """172.224.226.0/27,GB,GB-EN,London,
172.224.226.32/31,GB,GB-SC,Aberdeen,
172.225.10.0/24,US,US-CA,Los Angeles,
2a02:26f7:b3c0:4000::/64,DE,DE-BE,Berlin,
2a02:26f7:b3c0:4001::/64,DE,DE-BE,Berlin,
bad line
10.0.0.0/33,US,,,
"""


@pytest.fixture
def relay_list():
    pr._set_index(pr.parse(SAMPLE))
    yield


class TestList:

    def test_parse_and_merge(self):
        index = pr.parse(SAMPLE)
        # The two adjacent GB ranges and the two adjacent DE ranges merge; bad lines are skipped.
        assert pr.size(index) == 3

    @pytest.mark.parametrize("ip,cc", [
        ("172.224.226.5", "GB"), ("172.224.226.33", "GB"), ("172.224.226.34", ""),
        ("172.225.10.200", "US"), ("2a02:26f7:b3c0:4001::1", "DE"), ("2a02:26f7:b3c0:4002::1", ""),
        ("8.8.8.8", ""), ("not-an-ip", ""),
    ])
    def test_country(self, relay_list, ip, cc):
        assert pr.country(ip) == cc

    def test_download_once_a_day(self):
        pr._set_index(None)
        resp = MagicMock(status_code=200, text=SAMPLE * 1)
        now = datetime(2026, 11, 8, tzinfo=timezone.utc)
        with patch.object(pr, "MIN_RANGES", 1), patch.object(config.http, "get", return_value=resp) as get:
            assert pr.country("172.224.226.5", now) == "GB"
            pr.country("172.225.10.1", now + timedelta(hours=1))
            assert get.call_count == 1
            pr.country("172.225.10.1", now + timedelta(hours=25))
            assert get.call_count == 2

    def test_failed_download_retries_later(self):
        pr._set_index(None)
        now = datetime(2026, 11, 8, tzinfo=timezone.utc)
        with patch.object(config.http, "get", side_effect=OSError("down")) as get:
            assert pr.country("172.224.226.5", now) == ""
            pr.country("172.224.226.5", now + timedelta(minutes=10))
            assert get.call_count == 1
            pr.country("172.224.226.5", now + timedelta(minutes=61))
            assert get.call_count == 2

    def test_short_list_is_a_failure(self):
        pr._set_index(None)
        with patch.object(config.http, "get", return_value=MagicMock(status_code=200, text=SAMPLE)):
            assert pr.country("172.224.226.5") == ""   # 3 ranges < MIN_RANGES
        assert pr.status()["last_failure"]


class TestSignIns:

    def test_trusted_relay_ip_not_sent_to_proxycheck(self, relay_list):
        with patch.object(config, "PRIVATE_RELAY_TRUSTED", True), \
                patch("ip_checker._proxycheck_batch", return_value={}) as proxycheck:
            results = check_ips_batch(["172.224.226.5", "8.8.8.8"])
        proxycheck.assert_called_once_with(["8.8.8.8"], None, False)
        data = results["172.224.226.5"]
        assert data["isocode"] == "GB" and data["private_relay"] is True
        assert analyze_ip(data)["is_suspicious"] is False
        assert analyze_ip(data)["org"] == "iCloud Private Relay"

    def test_untrusted_relay_ip_classified_and_labeled(self, relay_list):
        vpn = {"proxy": "yes", "type": "VPN", "risk": 66, "isocode": "NL", "organisation": "Akamai"}
        with patch.object(config, "PRIVATE_RELAY_TRUSTED", False), \
                patch("ip_checker._proxycheck_batch", return_value={"172.224.226.5": vpn}):
            data = check_ips_batch(["172.224.226.5"])["172.224.226.5"]
        assert analyze_ip(data)["is_suspicious"] is True
        assert data["isocode"] == "GB" and "iCloud Private Relay" in data["organisation"]

    def test_country_check_uses_apple_country(self, relay_list):
        import geo_monitor
        with patch.object(config, "PRIVATE_RELAY_TRUSTED", True):
            data = check_ips_batch(["2a02:26f7:b3c0:4000::5"])["2a02:26f7:b3c0:4000::5"]
        assert geo_monitor.country_of(data) == "DE"

    def test_setting_in_ui(self):
        import settings
        s = settings.BY_NAME["PRIVATE_RELAY_TRUSTED"]
        assert s.kind == "bool" and settings.DEFAULTS["PRIVATE_RELAY_TRUSTED"] is True
