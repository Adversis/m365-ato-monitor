"""Mail access check: mail read or sent from a risky IP that did not sign in as the user.

The records follow real MailItemsAccessed and Send records from the Management
Activity API (Splunk attack_data, January 2025): Outlook on the web (Bind,
RecordType 50), Outlook desktop (Send, RecordType 2), and Graph (app-only).
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import config
import mail_access
from ip_checker import analyze_ip
from tests.fakes import FakeTable

NOW = datetime(2026, 11, 9, 12, 0, tzinfo=timezone.utc)
USER = "victim_1@contoso.com"
VPN = {"proxy": "yes", "type": "VPN", "risk": 66, "isocode": "US", "asn": "AS9009", "organisation": "M247 Europe"}
TOR = {"proxy": "yes", "type": "TOR", "risk": 100, "isocode": "DE", "asn": "AS60729", "organisation": "Tor exit"}
HOME = {"proxy": "no", "type": "Residential", "risk": 0, "isocode": "US", "asn": "AS7922", "organisation": "Comcast"}
ABROAD = {"proxy": "no", "type": "Residential", "risk": 0, "isocode": "NG", "asn": "AS29465", "organisation": "MTN"}


def owa_read(ip="81.2.69.160", when="2026-11-09T03:41:20", count=9):
    return {"AppAccessContext": {"AADSessionId": "5e55a0e1-0000-4000-8000-00000000a001", "UniqueTokenId": "tok1"},
            "AppId": "00000002-0000-0ff1-ce00-000000000000", "ClientAppId": "00000002-0000-0ff1-ce00-000000000000",
            "ClientIPAddress": ip, "ClientInfoString": "Client=OWA;Action=ViaProxy", "CreationTime": when,
            "ExternalAccess": False, "Folders": [{"FolderItems": [{"InternetMessageId": "<a@b>"}], "Path": "\\Inbox"}],
            "Id": f"read-{ip}-{when}", "LogonType": 0, "MailboxOwnerUPN": USER, "Operation": "MailItemsAccessed",
            "OperationCount": count, "OperationProperties": [{"Name": "MailAccessType", "Value": "Bind"},
                                                             {"Name": "IsThrottled", "Value": "False"}],
            "RecordType": 50, "ResultStatus": "Succeeded", "SessionId": "5e55a0e1-0000-4000-8000-00000000a001",
            "UserId": USER, "UserType": 0, "Workload": "Exchange"}


def desktop_send(ip="81.2.69.160", when="2026-11-09T04:31:08", subject="RE: Invoice 4471 - new bank details"):
    return {"AppAccessContext": {"APIId": ""}, "ClientIP": ip, "ClientIPAddress": ip,
            "ClientInfoString": "Client=MSExchangeRPC", "ClientProcessName": "OUTLOOK.EXE", "CreationTime": when,
            "Id": f"send-{ip}-{when}", "Item": {"InternetMessageId": "<c@d>", "ParentFolder": {"Path": "\\Outbox"},
                                                 "Subject": subject},
            "LogonType": 0, "MailboxOwnerUPN": USER, "Operation": "Send", "RecordType": 2,
            "ResultStatus": "Succeeded", "SessionId": "5e55a0e1-0000-4000-8000-00000000a002", "UserId": USER,
            "UserType": 0, "Workload": "Exchange"}


def graph_read():
    return {"AppAccessContext": {"APIId": "00000003-0000-0000-c000-000000000000",
                                 "ClientAppId": "c11e47a9-0000-4000-8000-00000000a003"},
            "AppId": "00000003-0000-0000-c000-000000000000", "ClientAppId": "c11e47a9-0000-4000-8000-00000000a003",
            "ClientIPAddress": "40.126.24.24", "ClientInfoString": "Client=REST;Client=RESTSystem;;",
            "CreationTime": "2026-11-09T05:07:17", "Id": "graph-1", "MailboxOwnerUPN": USER,
            "Operation": "MailItemsAccessed", "OperationProperties": [{"Name": "MailAccessType", "Value": "Bind"}],
            "RecordType": 50, "UserId": USER, "UserType": 5, "Workload": "Exchange"}


def _check(records, data, **kw):
    looked = []

    def lookup(ips):
        looked.extend(ips)
        return {ip: data[ip] for ip in ips if ip in data}
    return mail_access.check(records, lookup, analyze_ip, NOW, **kw), looked


class TestCheck:

    def test_read_from_vpn_ip_without_sign_in(self):
        found, looked = _check([owa_read(), owa_read(when="2026-11-09T03:50:00")], {"81.2.69.160": VPN})
        assert looked == ["81.2.69.160"] and len(found) == 1
        f = found[0]
        assert f["type"] == "mail_access" and f["severity"] == "medium" and f["user"] == USER
        assert "2 mail read records from a VPN IP (M247 Europe" in f["description"]
        assert "did not sign in as the user" in f["description"] and "Client=OWA" in f["description"]
        assert f["event"]["Id"].startswith("mailaccess-") and f["event"]["CreationTime"] == "2026-11-09T03:41:20"
        assert f["ip"] == "81.2.69.160" and f["ip_context"].startswith("Source IP: a VPN IP")

    def test_send_from_vpn_is_high_with_subject(self):
        found, _ = _check([desktop_send()], {"81.2.69.160": VPN})
        assert found[0]["severity"] == "high"
        assert "1 sent message" in found[0]["description"].lower()
        assert "'RE: Invoice 4471 - new bank details'" in found[0]["description"]

    def test_tor_read_is_high(self):
        found, _ = _check([owa_read(ip="185.220.101.4")], {"185.220.101.4": TOR})
        assert found[0]["severity"] == "high"

    def test_folder_download_from_hosting_is_high(self):
        sync = owa_read()
        sync["OperationProperties"] = [{"Name": "MailAccessType", "Value": "Sync"}]
        sync["ClientInfoString"] = "Client=MSExchangeRPC"
        hosting = {"proxy": "no", "type": "Hosting", "risk": 30, "isocode": "US", "asn": "AS14061",
                   "organisation": "DigitalOcean"}
        found, _ = _check([sync], {"81.2.69.160": hosting})
        assert found[0]["severity"] == "high" and "1 folder download" in found[0]["description"]

    def test_graph_records_are_skipped(self):
        found, looked = _check([graph_read()], {"40.126.24.24": VPN})
        assert found == [] and looked == []

    def test_exchange_server_ip_is_skipped(self):
        exo_ip = "2603:10b6:930:d1::7"
        record = owa_read(ip=exo_ip)
        record["ClientInfoString"] = "Client=OutlookService;Outlook-iOS/2.0;"
        found, looked = _check([record], {exo_ip: ABROAD})
        assert found == [] and looked == []
        assert mail_access.exchange_server_ip(exo_ip) and not mail_access.exchange_server_ip("2603:1036::1")
        assert not mail_access.exchange_server_ip("not an ip")

    def test_ip_that_signed_in_is_skipped(self):
        found, looked = _check([owa_read()], {"81.2.69.160": VPN}, known=lambda u, ip: True)
        assert found == [] and looked == []

    def test_clean_ip_alerts_only_for_a_new_country(self):
        assert _check([owa_read()], {"81.2.69.160": HOME})[0] == []
        found, _ = _check([owa_read()], {"81.2.69.160": ABROAD}, unusual=lambda u, cc: cc == "NG")
        assert found[0]["severity"] == "medium" and "new country for this user (MTN)" in found[0]["description"]

    def test_done_allowlisted_and_failed_lookup(self):
        rec = owa_read()
        key = f"mail_access_{mail_access.dedup_id(USER, '81.2.69.160', '2026-11-09')}"
        assert _check([rec], {"81.2.69.160": VPN}, done=lambda k: k == key)[0] == []
        assert _check([rec], {"81.2.69.160": VPN}, skip_ip=lambda ip: True)[1] == []
        assert _check([rec], {})[0] == []                                 # lookup failed: next run tries again

    def test_lookup_cap(self):
        records = [owa_read(ip=f"198.51.100.{i}") for i in range(1, 6)]
        _, looked = _check(records, {}, max_lookups=2)
        assert len(looked) == 2

    def test_ips_after_the_cap_are_checked_on_later_runs(self):
        """26 IPs, a cap of 25, and the risky IP last in the list: a later run looks it up."""
        ips = [f"198.51.100.{i}" for i in range(10, 36)]
        records = [owa_read(ip=ip) for ip in ips]
        data = {ip: HOME for ip in ips[:-1]} | {ips[-1]: VPN}
        cache, found_on = {}, None

        def lookup(batch):
            cache.update({ip: data[ip] for ip in batch})
            return {ip: data[ip] for ip in batch}
        for run in range(3):
            found = mail_access.check(records, lookup, analyze_ip, NOW + timedelta(minutes=2 * run),
                                      cached=lambda batch: {ip: cache[ip] for ip in batch if ip in cache},
                                      max_lookups=25)
            if found:
                found_on = run
                break
        assert found_on is not None and found[0]["ip"] == ips[-1]

    def test_rotation_without_a_cache(self):
        ips = [f"198.51.100.{i}" for i in range(10, 13)]
        seen = set()
        for run in range(3):
            looked = []
            mail_access.check([owa_read(ip=ip) for ip in ips], lambda b: looked.extend(b) or {}, analyze_ip,
                              NOW + timedelta(minutes=2 * run), max_lookups=1)
            seen.update(looked)
        assert seen == set(ips)

    def test_cached_answers_are_outside_the_cap(self):
        ips = [f"198.51.100.{i}" for i in range(10, 40)]
        cached = {ip: HOME for ip in ips[:-1]}
        looked = []
        found = mail_access.check([owa_read(ip=ip) for ip in ips],
                                  lambda b: looked.extend(b) or {b[0]: VPN}, analyze_ip, NOW,
                                  cached=lambda batch: {ip: cached[ip] for ip in batch if ip in cached},
                                  max_lookups=1)
        assert looked == [ips[-1]] and [f["ip"] for f in found] == [ips[-1]]

    def test_one_finding_per_user_ip_and_day(self):
        a = mail_access.dedup_id(USER, "1.2.3.4", "2026-11-09")
        assert a == mail_access.dedup_id(USER, "1.2.3.4", "2026-11-09")
        assert a != mail_access.dedup_id(USER, "1.2.3.4", "2026-11-10")


class TestSignInIps:

    def test_remember_and_expire(self):
        table = FakeTable()
        logins = [{"Operation": "UserLoggedIn", "UserId": "Victim_1@contoso.com", "ClientIP": "81.2.69.160"},
                  {"Operation": "UserLoginFailed", "UserId": USER, "ClientIP": "203.0.113.66"}]
        mail_access.remember_signins(table, logins, NOW - timedelta(days=2))
        assert mail_access.signed_in(table, USER, "81.2.69.160", NOW)
        assert not mail_access.signed_in(table, USER, "203.0.113.66", NOW)     # failed sign-in does not count
        assert not mail_access.signed_in(table, USER, "81.2.69.160", NOW + timedelta(days=6))


class TestMonitorRun:

    def _run(self, table, records, logins=()):
        import function_app as fa
        with patch("function_app.check_ips_batch", return_value={"81.2.69.160": VPN}) as lookup, \
                patch("function_app.send_compromise_alert", return_value=True) as send, \
                patch("journal.table_client", return_value=FakeTable()), \
                patch("geo_monitor.table_client", return_value=None):
            mail_access.remember_signins(table, list(logins), NOW)
            fa._run_mail_access_check(table, FakeTable(), set(), records, NOW)
        return send, lookup

    def test_alert_once_per_day(self):
        table = FakeTable()
        send, _ = self._run(table, [owa_read()])
        assert send.call_count == 1 and send.call_args.args[0]["type"] == "mail_access"
        send, lookup = self._run(table, [owa_read(when="2026-11-09T09:00:00")])
        assert send.call_count == 0
        assert all(c.kwargs.get("cache_only") for c in lookup.call_args_list)  # check for escalation from cache

    def test_sign_in_from_the_ip_in_the_same_run(self):
        login = {"Operation": "UserLoggedIn", "UserId": USER, "ClientIP": "81.2.69.160"}
        send, lookup = self._run(FakeTable(), [owa_read()], logins=[login])
        assert send.call_count == 0 and not lookup.called

    def test_setting_off_and_alert_type_off(self):
        with patch.object(config, "MAIL_ACCESS_CHECK", False):
            send, lookup = self._run(FakeTable(), [owa_read()])
        assert send.call_count == 0 and not lookup.called
        with patch.object(config, "ALERTS_OFF", {"mail_access"}):
            send, _ = self._run(FakeTable(), [owa_read()])
        assert send.call_count == 0


def test_self_test_detects_it():
    import selftest
    result = selftest.run(["mail_access"], False, [])
    assert result["passed"] and result["results"][0]["detected"] and result["results"][0]["severity"] == "high"


def test_cache_only_lookup_sends_no_query():
    import ip_checker
    cache = {"198.51.100.1": HOME}
    with patch("ip_checker.get_cached_ip", side_effect=lambda ip, t=None: cache.get(ip)), \
            patch.object(config, "http") as http:
        assert ip_checker.check_ips_batch(["198.51.100.1", "198.51.100.2"], cache_only=True) == cache
    http.post.assert_not_called()
