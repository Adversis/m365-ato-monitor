"""Audit search on the user page: network, risk, and location of each IP (proxycheck.io).

Cached answers cost no query. At most SEARCH_IP_LOOKUPS new lookups per request, and none
when the daily quota is low or used up.
"""

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

import admin_api
import config
import ip_checker
from tests.fakes import FakeTable

VPN = {"proxy": "yes", "type": "VPN", "risk": 66, "isocode": "DE", "asn": "AS24940",
       "organisation": "Hetzner Online GmbH", "city": "Falkenstein", "country": "Germany"}
HOME = {"proxy": "no", "type": "Residential", "risk": 0, "isocode": "US", "asn": "AS7922",
        "organisation": "Comcast", "city": "Unknown", "country": "United States"}


def cached(table, ip, data):
    table.upsert_entity({"PartitionKey": "ipcache", "RowKey": ip_checker._ip_row_key(ip), "ip": ip,
                         "data": json.dumps(data), "cached_at": datetime.now(timezone.utc).isoformat(),
                         "is_negative": False})


def answer(ips, data=HOME):
    resp = MagicMock(status_code=200)
    resp.json.return_value = {"status": "ok", **{ip: data for ip in ips}}
    return resp


@pytest.fixture
def cache():
    table = FakeTable()
    with patch("function_app._get_table_clients", return_value=(None, table)), \
            patch("private_relay.country", return_value=""):
        yield table


def rows(*ips):
    return [{"ip": ip} for ip in ips]


def test_cached_private_and_allowed_ips_need_no_query(cache):
    cached(cache, "45.83.64.7", VPN)
    with patch("config.http") as http, \
            patch.object(config, "ALLOWED_NETWORKS", [__import__("ipaddress").ip_network("52.10.0.0/16")]):
        out = admin_api._search_ips(rows("45.83.64.7:443", "45.83.64.7", "10.0.0.5", "52.10.0.10", ""))
    http.post.assert_not_called()
    vpn = out["ips"]["45.83.64.7:443"]
    assert vpn == out["ips"]["45.83.64.7"]
    assert vpn["org"] == "Hetzner Online GmbH" and vpn["asn"] == "AS24940" and vpn["type"] == "VPN"
    assert vpn["risk"] == 66 and vpn["suspicious"] is True and vpn["flags"] == ["vpn"]
    assert (vpn["city"], vpn["country"]) == ("Falkenstein", "Germany")
    assert out["ips"]["10.0.0.5"] == {"note": "private"}
    assert out["ips"]["52.10.0.10"] == {"note": "allowed"}
    assert out["pending"] == 0 and out["failed"] == 0


def test_unknown_values_are_left_out(cache):
    cached(cache, "81.2.69.4", HOME)
    with patch("config.http"):
        home = admin_api._search_ips(rows("81.2.69.4"))["ips"]["81.2.69.4"]
    assert home["city"] == "" and home["country"] == "United States" and home["suspicious"] is False


def test_new_ips_are_looked_up_in_one_batch_up_to_the_limit(cache):
    ips = [f"81.2.69.{i}" for i in range(1, 26)]
    with patch("config.http") as http:
        http.post.side_effect = lambda url, data=None, timeout=None: answer(data["ips"].split(","))
        out = admin_api._search_ips(rows(*ips))
        assert http.post.call_count == 1
        sent = http.post.call_args.kwargs["data"]["ips"].split(",")
        assert sent == ips[:admin_api.SEARCH_IP_LOOKUPS]            # the newest first
        assert out["pending"] == 25 - admin_api.SEARCH_IP_LOOKUPS and out["batch"] == admin_api.SEARCH_IP_LOOKUPS
        assert set(out["ips"]) == set(ips[:admin_api.SEARCH_IP_LOOKUPS])
        again = admin_api._search_ips(rows(*ips))                  # "Look up more": the rest
        assert http.post.call_args.kwargs["data"]["ips"].split(",") == ips[admin_api.SEARCH_IP_LOOKUPS:]
    assert again["pending"] == 0 and set(again["ips"]) == set(ips)


@pytest.mark.parametrize("level", ["low", "exhausted", "refused"])
def test_no_new_lookup_when_the_quota_is_low(cache, level):
    cached(cache, "45.83.64.7", VPN)
    with patch("config.http") as http, patch("proxycheck_quota.status", return_value={"level": level}):
        out = admin_api._search_ips(rows("45.83.64.7", "81.2.69.1", "81.2.69.2"))
    http.post.assert_not_called()
    assert out["quota"] == level and out["pending"] == 2
    assert "45.83.64.7" in out["ips"]                            # the cached answer still shows


def test_a_failed_lookup_is_not_tried_again_at_once(cache):
    with patch("config.http") as http:
        http.post.return_value = MagicMock(status_code=500)
        out = admin_api._search_ips(rows("81.2.69.9"))
        assert out["ips"]["81.2.69.9"] == {"note": "failed"} and out["failed"] == 1 and out["pending"] == 0
        again = admin_api._search_ips(rows("81.2.69.9"))
    assert http.post.call_count == 1
    assert again["failed"] == 1 and again["pending"] == 0


def test_the_search_answer_has_the_ip_details(ui_on):
    """The GET of a finished search adds ip_info; an error there does not break the rows."""
    info = {"id": "q", "status": "succeeded", "limit_exceeded": False}
    row = {"at": "2026-11-11T10:00:00Z", "operation": "UserLoggedIn", "workload": "AzureActiveDirectory",
           "ip": "81.2.69.9", "result": "", "object": "", "client": "", "id": "r1"}
    from tests.test_admin_ui import _req
    with patch("o365_client.token_manager.granted_graph_roles", return_value=["AuditLogsQuery.Read.All"]), \
            patch("audit_search.get", return_value=(info, "")), \
            patch("audit_search.records", return_value=([{"x": 1}], "", "")), \
            patch("audit_search.to_record", return_value={"Id": "r1"}), \
            patch("audit_search.summary_row", return_value=row):
        with patch("admin_api._search_ips", return_value={"ips": {"81.2.69.9": {"note": "private"}},
                                                         "pending": 0, "failed": 0, "quota": "", "batch": 20}):
            ok = json.loads(admin_api.user_search(_req("GET", "/api/manage/api/usersearch",
                                                       params={"id": "q", "user": "jane@contoso.com"})).get_body())
        with patch("admin_api._search_ips", side_effect=RuntimeError("storage down")):
            broken = json.loads(admin_api.user_search(_req("GET", "/api/manage/api/usersearch",
                                                           params={"id": "q", "user": "jane@contoso.com"})).get_body())
    assert ok["ip_info"]["ips"]["81.2.69.9"] == {"note": "private"}
    assert broken["rows"] == [row] and broken["ip_info"]["error"] is True
