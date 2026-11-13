"""The audit record of an alert in the management UI, the client column, and mutes for one network."""

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import admin_store
import alerting
import journal
import mail_access
from ip_checker import analyze_ip
from tests.fakes import FakeTable
from tests.test_admin_ui import _req

NOW = datetime.now(timezone.utc)
USER = "jane@contoso.com"
GTHOST = {"proxy": "yes", "type": "VPN", "risk": 66, "isocode": "US", "asn": "AS63023", "organisation": "GTHost"}


def _event(**over):
    event = {"Id": "rec-1", "Operation": "MailItemsAccessed", "UserId": USER,
             "CreationTime": (NOW - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S"),
             "ClientInfoString": "Client=OutlookService;Outlook-iOS/2.0;", "Workload": "Exchange"}
    event.update(over)
    return event


def _finding(**over):
    finding = {"type": "mail_access", "severity": "medium", "user": USER, "description": "x", "ip": "1.2.3.4",
               "event": _event(), "asn": "AS63023", "network": "GTHost"}
    finding.update(over)
    return finding


def _record(row_id):
    import admin_api
    resp = admin_api.finding_record(_req("GET", "/api/manage/api/record", params={"id": row_id}))
    return resp.status_code, json.loads(resp.get_body())


class TestJournalRecord:

    def test_record_kept_in_own_row(self):
        jt = FakeTable()
        journal.record(jt, _finding(), "k1", "emailed", now=NOW)
        row = journal.recent(jt, NOW - timedelta(days=1))[0]
        assert row["client"] == "Client=OutlookService;Outlook-iOS/2.0;"
        assert row["asn"] == "AS63023" and row["network"] == "GTHost"
        assert "event" not in row                                  # lists do not carry the record
        assert len(journal.recent(jt, NOW - timedelta(days=1))) == 1   # the record row is not a finding
        found = journal.audit_record(jt, row["id"])
        assert json.loads(found["record"])["Id"] == "rec-1"
        assert found["record_id"] == ""                     # not a GUID: no Purview search hint

    def test_sign_in_client_is_the_user_agent(self):
        event = _event(Operation="UserLoggedIn", ClientInfoString=None,
                       ExtendedProperties=[{"Name": "UserAgent", "Value": "Mozilla/5.0 (iPhone)"}])
        assert journal.client_of(event) == "Mozilla/5.0 (iPhone)"

    def test_long_record_is_cut(self):
        jt = FakeTable()
        journal.record(jt, _finding(event=_event(Folders=["x" * 40_000])), "k1", "emailed", now=NOW)
        text = journal.audit_record(jt, journal.recent(jt, NOW - timedelta(days=1))[0]["id"])["record"]
        assert len(text) < 32_000 and text.endswith("(truncated; see the unified audit log)")

    def test_old_row_without_record(self):
        jt = FakeTable()
        journal.record(jt, _finding(), "k1", "emailed", now=NOW)
        for key in [k for k in jt.rows if k[0].startswith("r-")]:
            del jt.rows[key]
        found = journal.audit_record(jt, journal.recent(jt, NOW - timedelta(days=1))[0]["id"])
        assert found == {"record": "", "record_id": ""}

    def test_real_record_id_is_returned(self):
        jt = FakeTable()
        guid = "7032213e-d17b-4875-8f49-77480daffd71"
        journal.record(jt, _finding(event=_event(Id=guid)), "k1", "emailed", now=NOW)
        assert journal.audit_record(jt, journal.recent(jt, NOW - timedelta(days=1))[0]["id"])["record_id"] == guid

    def test_purge_removes_record_rows(self):
        jt = FakeTable()
        journal.record(jt, _finding(), "k1", "emailed", now=NOW - timedelta(days=100))
        with patch.object(jt, "query_entities", wraps=jt.query_entities) as q:
            assert journal.purge(jt, NOW) == 1 and jt.rows == {}
        assert q.call_args.kwargs["select"] == ["PartitionKey", "RowKey"]   # keys only, not the records


class TestRecordEndpoint:

    def test_get_and_refuse(self, ui_on):
        jt = FakeTable()
        journal.record(jt, _finding(), "k1", "emailed", now=NOW)
        row_id = journal.recent(jt, NOW - timedelta(days=1))[0]["id"]
        with patch("journal.table_client", return_value=jt):
            code, body = _record(row_id)
            assert code == 200 and json.loads(body["record"])["Operation"] == "MailItemsAccessed"
            assert _record("u-x|' or 1 eq 1")[0] == 404
            assert _record("u-" + "0" * 32 + "|0000000000000-000000000000")[0] == 404
            import admin_api
            resp = admin_api.finding_record(_req("GET", "/api/manage/api/record", params={"id": row_id},
                                                 roles=("Other.Role",)))
            assert resp.status_code == 403

    def test_install_rows_hidden(self, ui_on):
        jt = FakeTable()
        journal.record(jt, _finding(), "k1", "install", now=NOW)
        (pk, rk), = [k for k in jt.rows if k[0].startswith("u-")]
        with patch("journal.table_client", return_value=jt):
            assert _record(f"{pk}|{rk}")[0] == 404


class TestNetworkMute:

    def _add(self, **over):
        body = {"type": "mail_access", "user": USER, "asn": "as63023", "network": "GTHost", "days": 365,
                "reason": "Known GTHost VPN of this user"}
        body.update(over)
        return admin_store.add_mute(FakeTable(), body, "admin@contoso.com", NOW)

    def test_matches_only_that_network(self):
        mute = self._add()
        match = admin_store.matching_mute
        assert mute["asn"] == "AS63023"
        assert match("mail_access", USER, "", "medium", NOW, asn="AS63023")["id"] == mute["id"]
        assert match("mail_access", USER, "", "medium", NOW, asn="AS9009") is None
        assert match("mail_access", USER, "", "medium", NOW) is None           # unknown network: not muted
        assert match("mail_access", USER, "", "high", NOW, asn="AS63023") is None
        assert match("mail_access", USER, "", "medium", NOW + timedelta(days=364), asn="63023")
        assert "network GTHost (AS63023)" in admin_store.describe_mute(mute)

    def test_network_name_must_be_printable(self):
        import pytest
        with pytest.raises(admin_store.ValidationError) as e:
            self._add(network="GT\x01Host")
        assert "asn" in e.value.errors

    def test_api_returns_the_added_mute(self, ui_on):
        import admin_api
        from tests.test_admin_ui import MUTATE
        body = {"action": "add", "type": "mail_access", "user": USER, "asn": "063023", "network": "GTHost",
                "days": 30, "reason": "Known VPN"}
        resp = admin_api.mutes(_req("POST", "/api/manage/api/mutes", body, headers=MUTATE))
        added = json.loads(resp.get_body())["added"]
        assert resp.status_code == 200 and added["asn"] == "AS63023" and added["active"]

    def test_sign_in_finding_uses_provider_when_no_organisation(self):
        import function_app
        finding = function_app._signin_finding({"UserId": USER, "Operation": "UserLoggedIn"}, "1.2.3.4",
                                               {"asn": "AS63023", "org": "Unknown", "provider": "GTHost",
                                                "flags": ["vpn"], "confidence": "medium"})
        assert finding["asn"] == "AS63023" and finding["network"] == "GTHost"

    def test_mute_without_network_matches_all(self):
        self._add(asn="", network="ignored")
        assert admin_store.matching_mute("mail_access", USER, "", "medium", NOW, asn="AS9009")

    def test_mail_access_finding_carries_network(self):
        record = {"ClientIPAddress": "81.2.69.160", "ClientInfoString": "Client=OutlookService", "Id": "r1",
                  "CreationTime": "2026-11-09T03:41:20", "MailboxOwnerUPN": USER, "UserId": USER,
                  "Operation": "MailItemsAccessed", "Workload": "Exchange", "RecordType": 50}
        found = mail_access.check([record], lambda ips: {"81.2.69.160": GTHOST}, analyze_ip, NOW)
        assert found[0]["asn"] == "AS63023" and found[0]["network"] == "GTHost"

    def test_email_mute_link(self, monkeypatch):
        monkeypatch.setenv("ADMIN_UI_ENABLED", "true")
        monkeypatch.setenv("WEBSITE_HOSTNAME", "func.azurewebsites.net")
        assert alerting.ui_link("mute", "mail_access", USER, "", "AS63023", "GTHost") == (
            "https://func.azurewebsites.net/api/manage#mute:mail_access:jane@contoso.com::AS63023:GTHost")
        assert alerting.ui_link("mute", "inbox_rule", USER, "News", "", "") == (
            "https://func.azurewebsites.net/api/manage#mute:inbox_rule:jane@contoso.com:News")
