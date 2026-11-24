"""Session reuse: one Entra session seen from two countries.

Record shapes from real UAL data: UserLoggedIn carries DeviceProperties
[SessionId]; Exchange records carry SessionId and AppAccessContext.AADSessionId
(the same GUID).
"""

from datetime import datetime, timezone
from unittest.mock import patch

import pytest

import config
import session_monitor as sm
from tests.fakes import FakeTable

SID = "5e55a0e1-1111-4222-8333-000000000104"
NOW = datetime(2026, 11, 8, 12, 0, tzinfo=timezone.utc)

# Public-looking test addresses (Python treats documentation ranges as private).
HOME_IP, ABROAD_IP, MS_IP, HOME_IP2 = "81.2.69.1", "45.33.1.2", "52.123.162.160", "81.2.69.99"
VPN_IP, VPN_IP2, TOR_IP = "193.27.14.9", "193.27.14.10", "185.220.101.4"
DATA = {
    HOME_IP: {"isocode": "US", "asn": "AS7922", "organisation": "Comcast"},
    HOME_IP2: {"isocode": "US", "asn": "AS7922", "organisation": "Comcast"},
    ABROAD_IP: {"isocode": "NL", "asn": "AS63949", "organisation": "Akamai Connected Cloud"},
    MS_IP: {"isocode": "IE", "asn": "AS8075", "organisation": "Microsoft Corporation"},
    VPN_IP: {"isocode": "US", "asn": "AS9009", "organisation": "M247 Europe", "proxy": "yes", "type": "VPN",
             "risk": 66},
    VPN_IP2: {"isocode": "US", "asn": "AS9009", "organisation": "M247 Europe", "proxy": "yes", "type": "VPN",
              "risk": 66},
    TOR_IP: {"isocode": "US", "asn": "AS60729", "organisation": "Tor exit", "proxy": "yes", "type": "TOR",
             "risk": 100},
}


def signin(ip, minute, sid=SID, op="UserLoggedIn", user="victim@contoso.com"):
    return {"Id": f"s-{ip}-{minute}", "RecordType": 15, "Operation": op, "UserId": user, "ClientIP": ip,
            "CreationTime": f"2026-11-08T11:{minute:02d}:00",
            "DeviceProperties": [{"Name": "OS", "Value": "MacOs"}, {"Name": "SessionId", "Value": sid}]}


def mail_access(ip, minute, sid=SID):
    return {"Id": f"m-{ip}-{minute}", "RecordType": 50, "Operation": "MailItemsAccessed",
            "UserId": "victim@contoso.com", "ClientIPAddress": ip, "ClientIP": ip, "SessionId": sid,
            "CreationTime": f"2026-11-08T11:{minute:02d}:00",
            "AppAccessContext": {"AADSessionId": sid, "UniqueTokenId": "x"}}


def mailbox(ip, minute, sid=SID, op="MoveToDeletedItems"):
    """An Exchange mailbox record (not a mail read or send) in the session."""
    return {"Id": f"x-{ip}-{minute}", "RecordType": 2, "Operation": op, "UserId": "victim@contoso.com",
            "MailboxOwnerUPN": "victim@contoso.com", "ClientIPAddress": ip, "ClientIP": ip,
            "ClientInfoString": "Client=OWA;Action=ViaProxy", "CreationTime": f"2026-11-08T11:{minute:02d}:00",
            "AppAccessContext": {"AADSessionId": sid}}


class Lookup:
    def __init__(self, data=DATA):
        self.data, self.calls = data, []

    def __call__(self, ips):
        self.calls.append(list(ips))
        return {ip: self.data[ip] for ip in ips if ip in self.data}


class TestSessionId:

    @pytest.mark.parametrize("record,expected", [
        ({"DeviceProperties": [{"Name": "SessionId", "Value": SID.upper()}]}, SID),
        ({"SessionId": SID}, SID),
        ({"AppAccessContext": {"AADSessionId": SID}}, SID),
        ({"SessionId": "not-a-guid"}, ""),
        ({}, ""),
    ])
    def test_session_id(self, record, expected):
        assert sm.session_id(record) == expected

    def test_observations_skip(self):
        records = [signin(HOME_IP, 1, op="UserLoginFailed"), signin("10.0.0.1", 2),
                   {"Operation": "UserLoggedIn", "UserId": "u@contoso.com", "ClientIP": HOME_IP},
                   signin(HOME_IP, 3, user="ServicePrincipal_1")]
        assert sm.observations(records) == []

    def test_allowlisted_ip_skipped(self):
        with patch.object(config, "ALLOWED_NETWORKS", __import__("config")._parse_allowlist(ABROAD_IP)):
            assert [o[2] for o in sm.observations([signin(HOME_IP, 1), signin(ABROAD_IP, 2)])] == [HOME_IP]


class TestCheck:

    def test_cookie_replay_from_second_country(self):
        table, lookup = FakeTable(), Lookup()
        findings = sm.check(table, [signin(HOME_IP, 1), signin(ABROAD_IP, 9)], lookup, NOW)
        assert len(findings) == 1
        f = findings[0]
        assert f["type"] == "session_reuse" and f["severity"] == "high"
        assert f["user"] == "victim@contoso.com" and f["ip"] == ABROAD_IP and f["country"] == "NL"
        assert "US" in f["description"] and "NL" in f["description"] and "8 minutes later" in f["description"]

    def test_token_replay_seen_in_mail_access(self):
        findings = sm.check(FakeTable(), [signin(HOME_IP, 1), mail_access(ABROAD_IP, 20)], Lookup(), NOW)
        assert len(findings) == 1 and "MailItemsAccessed" in findings[0]["description"]

    def test_state_across_runs(self):
        table, lookup = FakeTable(), Lookup()
        assert sm.check(table, [signin(HOME_IP, 1)], lookup, NOW) == []
        findings = sm.check(table, [mail_access(ABROAD_IP, 30)], lookup, NOW)
        assert len(findings) == 1
        sm.mark_alerted(table, SID, "NL", NOW)
        # The same records come back in the next, overlapping window: no new finding.
        assert sm.check(table, [signin(HOME_IP, 1), mail_access(ABROAD_IP, 30)], lookup, NOW) == []
        # Known IPs are not looked up again.
        assert lookup.calls == [[HOME_IP], [ABROAD_IP]]

    def test_not_alerted_until_marked(self):
        table = FakeTable()
        assert sm.check(table, [signin(HOME_IP, 1)], Lookup(), NOW) == []
        assert len(sm.check(table, [signin(ABROAD_IP, 5)], Lookup(), NOW)) == 1
        # The send failed (not marked): the country is in the session now, so check()
        # does not make the finding again. It waits as a pending finding instead.
        assert sm.check(table, [signin(ABROAD_IP, 5)], Lookup(), NOW) == []
        pending = sm.pending_findings(table, NOW)
        assert len(pending) == 1 and pending[0]["mark"] == "NL" and pending[0]["event"]["Id"] == "s-45.33.1.2-5"
        sm.mark_alerted(table, SID, "NL", NOW)
        assert sm.pending_findings(table, NOW) == []

    def test_same_country_new_ip_ignored(self):
        assert sm.check(FakeTable(), [signin(HOME_IP, 1), signin(HOME_IP2, 2)], Lookup(), NOW) == []

    def test_microsoft_ip_does_not_establish_service_activity(self):
        table = FakeTable()
        findings = sm.check(table, [signin(HOME_IP, 1), mail_access(MS_IP, 2)], Lookup(), NOW)
        assert len(findings) == 1 and findings[0]["country"] == "IE"
        row = table.get_entity("session", SID)
        assert '"MS"' not in row["ips"] and '"IE"' in row["ips"]

    @pytest.mark.parametrize("owner,expected_findings", [
        ("f8cdef31-a31e-4b4a-93e4-5f571e91255a", 0),  # Microsoft Services
        ("aaaaaaaa-1111-4222-8333-000000000000", 1),  # another tenant
        (None, 1),                                   # ownership lookup unavailable
    ])
    def test_service_relay_requires_verified_microsoft_ownership(self, owner, expected_findings):
        # Public app IDs only; all user, session, IP, and event data is synthetic.
        from ip_checker import analyze_ip
        import mail_access as ma
        api = "bbbbbbbb-1111-4222-8333-000000000000"
        client = "27922004-5251-4030-b22d-91ecd9a37ea4"
        record = mail_access(VPN_IP, 20)
        record.update(Workload="Exchange", ClientInfoString="Client=REST;;", AppId=api, ClientAppId=client)
        record["AppAccessContext"].update(APIId=api, ClientAppId=client)
        assert ma.relaying_app(record) == api
        with patch("service_actors.app_owner_tenant", return_value=owner) as lookup_owner:
            findings = sm.check(FakeTable(), [signin(HOME_IP, 1), record], Lookup(), NOW, analyze=analyze_ip)
        lookup_owner.assert_called_once_with(api)
        assert len(findings) == expected_findings

    @staticmethod
    def _copilot_mail_read():
        # Public Microsoft app IDs; no customer identifiers or message contents.
        record = mail_access(VPN_IP, 20)
        api = "fb8d773d-7ef8-4ec0-a117-179f88add510"
        client = "27922004-5251-4030-b22d-91ecd9a37ea4"
        record.update(Workload="Exchange", ClientInfoString="Client=REST;;", AppId=api, ClientAppId=client)
        record["AppAccessContext"].update(APIId=api, ClientAppId=client)
        return record

    @pytest.mark.parametrize("country", ["US", "NL"])
    @pytest.mark.parametrize("nested_client", [False, True])
    def test_copilot_mail_read_skips_backend_ip_without_graph(self, country, nested_client):
        from ip_checker import analyze_ip
        import mail_access as ma
        record = self._copilot_mail_read()
        if nested_client:
            record.pop("ClientAppId")
        lookup = Lookup(dict(DATA, **{VPN_IP: dict(DATA[VPN_IP], isocode=country)}))
        with patch("service_actors.app_owner_tenant", side_effect=AssertionError("no Graph lookup")):
            assert ma.service_ip_client(record)
            assert sm.check(FakeTable(), [signin(HOME_IP, 1), record], lookup, NOW, analyze=analyze_ip) == []
            assert ma.observations([record]) == {}
        assert lookup.calls == [[HOME_IP]]  # no reputation lookup spent on the backend
        assert ma.count([record])["reads"] == 1  # mail-access reporting still counts it

    @pytest.mark.parametrize("changes,context", [
        ({"AppId": "00000002-0000-0ff1-ce00-000000000000"},
         {"APIId": "00000002-0000-0ff1-ce00-000000000000"}),  # direct Exchange access
        ({"AppId": "bbbbbbbb-1111-4222-8333-000000000000"},
         {"APIId": "bbbbbbbb-1111-4222-8333-000000000000"}),  # an unknown relay
        ({"AppId": ""}, {}),
        ({}, {"APIId": ""}),
        ({"ClientAppId": "fb8d773d-7ef8-4ec0-a117-179f88add510"}, {}),  # no relay
        ({"ClientAppId": ""}, {"ClientAppId": ""}),
        ({"ClientInfoString": "Client=OWA"}, {}),
        ({"Workload": "SharePoint"}, {}),
        ({"Operation": "UserLoggedIn"}, {}),
        ({"Operation": "UserLoginFailed"}, {}),
        ({"Operation": "Send"}, {}),  # this fallback covers observed mail reads only
    ])
    def test_copilot_id_alone_does_not_exempt_client_activity(self, changes, context):
        from ip_checker import analyze_ip
        import mail_access as ma
        record = self._copilot_mail_read()
        record.update(changes)
        record["AppAccessContext"].update(context)
        with patch("service_actors.app_owner_tenant", return_value=None):
            assert not ma.service_ip_client(record)
            if record["Operation"] not in ("UserLoggedIn", "UserLoginFailed"):
                findings = sm.check(FakeTable(), [signin(HOME_IP, 1), record], Lookup(), NOW,
                                    analyze=analyze_ip)
                assert len(findings) == 1  # the session check continues to cover direct/unknown access

    def test_exchange_server_ip_is_not_a_second_country(self):
        # Regression: an Outlook-iOS MailItemsAccessed record from an Exchange Online server IP
        # (shape of a real record) made a high "second country" alert.
        exo_ip = "2603:10b6:930:d1::7"
        record = mail_access(exo_ip, 23)
        record.update(Workload="Exchange", ClientInfoString="Client=OutlookService;Outlook-iOS/2.0;",
                      AppId="27922004-5251-4030-b22d-91ecd9a37ea4",
                      OperationProperties=[{"Name": "MailAccessType", "Value": "Bind"}])
        data = dict(DATA, **{exo_ip: {"isocode": "CA", "asn": "AS8075", "organisation": "Microsoft Corporation"}})
        lookup = Lookup(data)
        assert sm.check(FakeTable(), [signin(HOME_IP, 1), record], lookup, NOW) == []
        assert all(exo_ip not in call for call in lookup.calls)          # no lookup spent on it
        # The same record from an Azure IP (customer space) still counts.
        record.update(ClientIPAddress=MS_IP, ClientIP=MS_IP)
        assert len(sm.check(FakeTable(), [signin(HOME_IP, 1), record], Lookup(), NOW)) == 1

    def test_microsoft_service_ip_is_not_a_risky_move(self):
        # Regression: Teams meeting prep read an attachment with the user's session from an Exchange Online
        # front-end IP (Office 365 endpoints list, in no Azure service tag): a "VPN IP" session alert.
        from ip_checker import analyze_ip
        ip = "2603:1036:303:2832::5"
        record = mailbox(ip, 29, op="AttachmentAccess")
        record.update(Workload="Exchange", ClientInfoString="Client=REST;;",
                      AppId="66a88757-258c-4c72-893c-3e8bed4d6899",
                      ActorInfoString="Client=REST;search-recommendations-teams-meetingprep[AppId=66a88757];")
        data = dict(DATA, **{ip: {"isocode": "US", "asn": "AS8075", "organisation": "Microsoft Corporation",
                                  "proxy": "yes", "type": "VPN", "risk": 33}})
        lookup = Lookup(data)
        assert sm.check(FakeTable(), [signin(HOME_IP, 1), record], lookup, NOW, analyze=analyze_ip) == []
        assert all(ip not in call for call in lookup.calls)
        # A SharePoint record from the same range is skipped too; a sign-in from it is not.
        record.update(Workload="SharePoint", Operation="FileAccessed", RecordType=6)
        assert sm.observations([record]) == []
        assert sm.observations([signin(ip, 30)])

    def test_description_has_risk_and_place(self):
        from ip_checker import analyze_ip
        data = dict(DATA, **{VPN_IP: dict(DATA[VPN_IP], city="Ashburn", region="Virginia")})
        f = sm.check(FakeTable(), [signin(HOME_IP, 1), mailbox(VPN_IP, 20)], Lookup(data), NOW,
                     analyze=analyze_ip)[0]
        assert "VPN (M247 Europe, AS9009, score 66/100, estimated location: Ashburn, Virginia)" in f["description"]
        f = sm.check(FakeTable(), [signin(HOME_IP, 1), signin(ABROAD_IP, 2)],
                     Lookup(dict(DATA, **{ABROAD_IP: dict(DATA[ABROAD_IP], risk=0, city="Amsterdam")})), NOW)[0]
        assert "(IP 45.33.1.2, Akamai Connected Cloud, AS63949, score 0/100, estimated location: Amsterdam)" in f["description"]

    def test_sign_in_from_exchange_server_range_is_kept(self):
        exo_ip = "2603:10b6:930:d1::7"
        data = dict(DATA, **{exo_ip: {"isocode": "CA", "asn": "AS8075", "organisation": "Microsoft Corporation"}})
        assert len(sm.check(FakeTable(), [signin(HOME_IP, 1), signin(exo_ip, 2)], Lookup(data), NOW)) == 1

    def test_failed_lookup_retried(self):
        table = FakeTable()
        assert sm.check(table, [signin(HOME_IP, 1), signin(ABROAD_IP, 2)], Lookup({HOME_IP: DATA[HOME_IP]}), NOW) == []
        assert ABROAD_IP not in table.get_entity("session", SID)["ips"]
        assert len(sm.check(table, [signin(ABROAD_IP, 2)], Lookup(), NOW)) == 1

    def test_out_of_order_records(self):
        findings = sm.check(FakeTable(), [signin(ABROAD_IP, 9), signin(HOME_IP, 1)], Lookup(), NOW)
        assert findings[0]["country"] == "NL"

    def test_home_country_is_medium(self):
        with patch.object(config, "HOME_COUNTRIES", {"US", "NL"}):
            findings = sm.check(FakeTable(), [signin(HOME_IP, 1), signin(ABROAD_IP, 2)], Lookup(), NOW)
        assert findings[0]["severity"] == "medium"

    def test_different_sessions_independent(self):
        other = "aaaaaaaa-1111-4222-8333-000000000000"
        assert sm.check(FakeTable(), [signin(HOME_IP, 1), signin(ABROAD_IP, 2, sid=other)], Lookup(), NOW) == []

    def test_ip_list_capped(self):
        table = FakeTable()
        data = {f"81.2.70.{i}": {"isocode": "US", "asn": "AS7922"} for i in range(40)}
        sm.check(table, [signin(ip, i % 60) for i, ip in enumerate(data)], Lookup(data), NOW)
        import json
        assert len(json.loads(table.get_entity("session", SID)["ips"])) == sm.MAX_IPS


class TestRiskyNetworkSameCountry:
    """A session that starts on a normal network and is then used from a risky IP in the same country."""

    def _check(self, records, table=None, **kw):
        from ip_checker import analyze_ip
        return sm.check(table if table is not None else FakeTable(), records, Lookup(), NOW, analyze=analyze_ip, **kw)

    def test_token_used_from_vpn(self):
        findings = self._check([signin(HOME_IP, 1), mailbox(VPN_IP, 20)])
        assert len(findings) == 1
        f = findings[0]
        assert f["type"] == "session_reuse" and f["severity"] == "medium" and f["ip"] == VPN_IP
        assert f["country"] == "US" and f["mark"] == sm.NETWORK_MARK
        assert f"appeared from IP {HOME_IP} and then from {VPN_IP}" in f["description"]
        assert "classifies the later IP as VPN (M247 Europe, AS9009, score 66/100)" in f["description"]
        assert "same country (US)" in f["description"] and "MoveToDeletedItems" in f["description"]
        assert "No matching sign-in from this exact IP" in f["ip_context"]
        assert "7-day history" in f["ip_context"]
        assert "does not prove that no sign-in occurred" in f["ip_context"]

    def test_context_keeps_actual_times_across_runs_and_pending_delivery(self):
        table = FakeTable()
        self._check([signin(HOME_IP, 1), signin(HOME_IP, 10)], table)
        # An overlapping fetch must not move the previous observation back to 11:01.
        self._check([signin(HOME_IP, 1)], table)
        record = mailbox(VPN_IP, 20)
        record.update(AppId="resource-app", ClientAppId="client-app", UserAgent="Outlook <test>")
        record["AppAccessContext"]["APIId"] = "api-app"
        finding = self._check([record], table)[0]
        facts = dict(finding["session_context"])
        assert facts["Previous observation"] == f"{HOME_IP} at 2026-11-08 11:10:00 UTC"
        assert facts["Current observation"] == f"{VPN_IP} at 2026-11-08 11:20:00 UTC"
        assert facts["Elapsed"] == "10 minutes"
        assert facts["Client / protocol"] == "Client=OWA;Action=ViaProxy"
        assert facts["App ID"] == "resource-app" and facts["Client app ID"] == "client-app"
        assert facts["API ID"] == "api-app" and facts["User agent"] == "Outlook <test>"
        assert dict(sm.pending_findings(table, NOW)[0]["session_context"]) == facts

    def test_old_session_rows_do_not_invent_a_previous_time(self):
        table = FakeTable()
        self._check([signin(HOME_IP, 1)], table)
        # Simulate a row written before per-IP times existed.
        table.upsert_entity({"PartitionKey": "session", "RowKey": SID, "ip_times": "{}"})
        facts = dict(self._check([mailbox(VPN_IP, 20)], table)[0]["session_context"])
        assert facts["Previous observation"] == f"{HOME_IP} at time unavailable"
        assert "Elapsed" not in facts

    def test_hosting_context_keeps_provider_and_legacy_organisation(self):
        from ip_checker import analyze_ip
        data = dict(DATA, **{VPN_IP: {"isocode": "US", "type": "Hosting", "risk": 33,
                                    "provider": "Microsoft Corporation", "organisation": "Legacy allocation",
                                    "asn": "AS8075"}})
        finding = sm.check(FakeTable(), [signin(HOME_IP, 1), mailbox(VPN_IP, 20)], Lookup(data), NOW,
                           analyze=analyze_ip)[0]
        assert finding["severity"] == "medium"
        assert "Hosting (Microsoft Corporation, Legacy allocation, AS8075, score 33/100)" in finding["description"]

    def test_tor_is_high(self):
        assert self._check([signin(HOME_IP, 1), mailbox(TOR_IP, 20)])[0]["severity"] == "high"

    def test_sign_in_from_the_ip_is_left_to_the_sign_in_check(self):
        assert self._check([signin(HOME_IP, 1), signin(VPN_IP, 5)]) == []
        # A record from the IP after its sign-in: the IP is known in the session.
        assert self._check([signin(HOME_IP, 1), signin(VPN_IP, 5), mailbox(VPN_IP, 6)]) == []
        assert self._check([signin(HOME_IP, 1), mailbox(VPN_IP, 6)], known=lambda u, ip: ip == VPN_IP) == []

    def test_mail_records_skipped_when_another_check_reports_them(self):
        records = [signin(HOME_IP, 1), mail_access(VPN_IP, 6)]
        assert self._check(records, skip=lambda r: r["Operation"] == "MailItemsAccessed") == []
        assert len(self._check(records)) == 1

    def test_session_that_started_on_a_vpn(self):
        assert self._check([mailbox(VPN_IP, 1), mailbox(VPN_IP2, 5)]) == []
        record = mail_access(MS_IP, 1)
        record.update(ClientInfoString="Client=REST;Client=RESTSystem", AppId="00000003-0000-0000-c000-000000000000")
        assert self._check([record, mailbox(VPN_IP, 5)]) == []  # a service IP does not seed the session

    def test_once_per_session(self):
        table = FakeTable()
        findings = self._check([signin(HOME_IP, 1), mailbox(VPN_IP, 5), mailbox(TOR_IP, 6)], table)
        assert len(findings) == 1
        sm.mark_alerted(table, SID, findings[0]["mark"], NOW)
        assert self._check([signin(HOME_IP2, 7), mailbox(VPN_IP2, 8)], table) == []
        row = table.get_entity("session", SID)
        assert sm.NETWORK_MARK in row["alerted"] and VPN_IP in row["risky"]

    def test_normal_ip_from_an_earlier_run(self):
        table = FakeTable()
        assert self._check([signin(HOME_IP, 1)], table) == []
        assert len(self._check([mailbox(VPN_IP, 30)], table)) == 1

    def test_off_without_analysis(self):
        assert sm.check(FakeTable(), [signin(HOME_IP, 1), mailbox(VPN_IP, 20)], Lookup(), NOW) == []

    def test_new_country_finding_is_not_doubled(self):
        data = dict(DATA, **{VPN_IP: dict(DATA[VPN_IP], isocode="NL")})
        from ip_checker import analyze_ip
        findings = sm.check(FakeTable(), [signin(HOME_IP, 1), mailbox(VPN_IP, 20)], Lookup(data), NOW,
                            analyze=analyze_ip)
        assert len(findings) == 1 and findings[0]["mark"] == "NL"


class TestPipeline:

    def _run(self, records, processed=None, enabled=True):
        import function_app as fa
        events, cache, sessions = FakeTable(), FakeTable(), FakeTable()
        with patch.object(config, "SESSION_CHECK_ENABLED", enabled), \
                patch("session_monitor.table_client", return_value=sessions), \
                patch("function_app.check_ips_batch", side_effect=lambda ips, t: Lookup()(ips)), \
                patch("function_app.send_compromise_alert", return_value=True) as send:
            fa._run_session_check(events, cache, processed or set(), records, NOW)
        return send, sessions

    def test_alert_sent_and_marked(self):
        send, sessions = self._run([signin(HOME_IP, 1), signin(ABROAD_IP, 9)])
        assert send.call_count == 1
        finding, context = send.call_args[0][0], send.call_args[0][1]
        assert finding["type"] == "session_reuse" and finding["country"] == "NL"
        assert context == ""
        assert "NL" in sessions.get_entity("session", SID)["alerted"]

    def test_disabled(self):
        send, _ = self._run([signin(HOME_IP, 1), signin(ABROAD_IP, 9)], enabled=False)
        assert send.call_count == 0

    def test_risky_network_alert_marked(self):
        send, sessions = self._run([signin(HOME_IP, 1), mailbox(VPN_IP, 9)])
        assert send.call_count == 1 and "No matching sign-in from this exact IP" in send.call_args[0][1]
        assert sm.NETWORK_MARK in sessions.get_entity("session", SID)["alerted"]

    def test_mail_records_left_to_the_mail_access_check(self):
        record = {**mail_access(VPN_IP, 9), "ClientInfoString": "Client=OWA"}
        with patch.object(config, "MAIL_ACCESS_CHECK", True):
            send, _ = self._run([signin(HOME_IP, 1), record])
        assert send.call_count == 0
        with patch.object(config, "MAIL_ACCESS_CHECK", False):
            send, _ = self._run([signin(HOME_IP, 1), record])
        assert send.call_count == 1

    @pytest.mark.parametrize("client", [None, "Client=Unknown"])
    @pytest.mark.parametrize("operation", ["MailItemsAccessed", "Send"])
    def test_mail_record_without_supported_client_still_alerts(self, client, operation):
        import function_app as fa
        record = {**mail_access(VPN_IP, 9), "Operation": operation}
        if client is not None:
            record["ClientInfoString"] = client
        events, sessions = FakeTable(), FakeTable()
        with patch.object(config, "SESSION_CHECK_ENABLED", True), \
                patch.object(config, "MAIL_ACCESS_CHECK", True), \
                patch("session_monitor.table_client", return_value=sessions), \
                patch("geo_monitor.table_client", return_value=None), \
                patch("journal.table_client", return_value=FakeTable()), \
                patch("function_app.check_ips_batch", side_effect=lambda ips, *_a, **_kw: Lookup()(ips)), \
                patch("function_app.send_compromise_alert", return_value=True) as send:
            fa._run_session_check(events, FakeTable(), set(), [signin(HOME_IP, 1), record], NOW)
            fa._run_mail_access_check(events, FakeTable(), set(), [record], NOW)
            assert send.call_count == 1
            assert send.call_args.args[0]["type"] == "session_reuse"
            assert sm.NETWORK_MARK in sessions.get_entity("session", SID)["alerted"]

    def _run_on(self, sessions, events, records, sent=True):
        import function_app as fa
        with patch.object(config, "SESSION_CHECK_ENABLED", True), \
                patch("session_monitor.table_client", return_value=sessions), \
                patch("function_app.check_ips_batch", side_effect=lambda ips, t: Lookup()(ips)), \
                patch("function_app.send_compromise_alert", return_value=sent) as send:
            fa._run_session_check(events, FakeTable(), set(), records, NOW)
        return send

    @pytest.mark.parametrize("records,mark", [
        ([signin(HOME_IP, 1), signin(ABROAD_IP, 9)], "NL"),             # a second country
        ([signin(HOME_IP, 1), mailbox(VPN_IP, 9)], sm.NETWORK_MARK),    # a risky IP in the same country
    ])
    def test_alert_that_failed_is_sent_on_a_later_run(self, records, mark):
        """Send and outbox failed: the session state is saved, but the finding waits and goes out later."""
        sessions, events = FakeTable(), FakeTable()
        assert self._run_on(sessions, events, records, sent=False).call_count == 1
        assert mark not in sessions.get_entity("session", SID)["alerted"]
        send = self._run_on(sessions, events, [])                       # the next run, with no new record
        assert send.call_count == 1 and send.call_args[0][0]["mark"] == mark
        assert mark in sessions.get_entity("session", SID)["alerted"]
        assert sessions.partition(sm.PENDING_PARTITION) == {}
        assert self._run_on(sessions, events, []).call_count == 0       # not sent again

    def test_a_finding_of_this_run_is_not_sent_twice(self):
        sessions, events = FakeTable(), FakeTable()
        self._run_on(sessions, events, [signin(HOME_IP, 1), signin(ABROAD_IP, 9)], sent=False)
        send = self._run_on(sessions, events, [signin(ABROAD_IP, 9)])
        assert send.call_count == 1

    def test_sent_before_the_mark_failed(self):
        """The alert went out, then the run stopped before mark_alerted: no second email."""
        import function_app as fa
        sessions, events = FakeTable(), FakeTable()
        self._run_on(sessions, events, [signin(HOME_IP, 1), signin(ABROAD_IP, 9)], sent=False)
        finding = sm.pending_findings(sessions, NOW)[0]
        fa.mark_event_processed(fa.finding_key(finding), events)
        assert self._run_on(sessions, events, []).call_count == 0
        assert sessions.partition(sm.PENDING_PARTITION) == {}

    def test_pending_write_failure_stops_before_the_state_is_saved(self):
        sessions = FakeTable()
        sm.check(sessions, [signin(HOME_IP, 1)], Lookup(), NOW)
        with patch("session_monitor.save_pending", side_effect=RuntimeError("storage down")):
            with pytest.raises(RuntimeError):
                sm.check(sessions, [signin(ABROAD_IP, 9)], Lookup(), NOW)
        assert "NL" not in sessions.get_entity("session", SID)["countries"]    # the next run finds it again
        assert len(sm.check(sessions, [signin(ABROAD_IP, 9)], Lookup(), NOW)) == 1

    def test_pending_dropped_after_7_days(self):
        from datetime import timedelta
        sessions = FakeTable()
        sm.check(sessions, [signin(HOME_IP, 1)], Lookup(), NOW)
        sm.check(sessions, [signin(ABROAD_IP, 9)], Lookup(), NOW)
        assert sm.pending_findings(sessions, NOW + timedelta(days=8)) == []
        assert sessions.partition(sm.PENDING_PARTITION) == {}

    def test_dedup(self):
        import function_app as fa
        record = signin(ABROAD_IP, 9)
        key = fa.finding_key({"type": "session_reuse", "event": record})
        send, _ = self._run([signin(HOME_IP, 1), record], processed={key})
        assert send.call_count == 0
