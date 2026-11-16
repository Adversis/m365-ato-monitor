"""MFA methods that the user registered: email only after another alert or a sign-in from a new network.

All users, IDs, and IPs are made up (documentation ranges).
"""

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

import function_app as fa
import journal
import signin_networks as sn
from tests.fakes import FakeTable

USER = "victim@contoso.com"
HOME = "198.51.100.20"        # the user's usual network
HOME_NEW_ADDR = "198.51.100.77"
NEW = "203.0.113.9"           # a network the user did not use before
ADMIN = "admin@contoso.com"


def _t(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S")


def signin(ip, when, user=USER):
    return {"Id": f"s-{ip}-{_t(when)}", "Operation": "UserLoggedIn", "RecordType": 15, "UserId": user,
            "ClientIP": ip, "CreationTime": _t(when), "ResultStatus": "Success"}


def mfa_record(when, actor_upn=None):
    old = json.dumps([{"MethodType": 0, "Default": False}, {"MethodType": 5, "Default": True}])
    new = json.dumps([{"MethodType": 0, "Default": False}, {"MethodType": 5, "Default": True},
                      {"MethodType": 6, "Default": False}, {"MethodType": 7, "Default": False}])
    actor = ([{"ID": actor_upn, "Type": 5}] if actor_upn else
             [{"ID": "Azure MFA StrongAuthenticationService", "Type": 1},
              {"ID": "ServicePrincipal_00000000-0000-4000-8000-0000000000aa", "Type": 2}])
    return {"Id": f"m-{_t(when)}", "Operation": "Update user.", "RecordType": 8, "Workload": "AzureActiveDirectory",
            "ResultStatus": "Success", "CreationTime": _t(when),
            "UserId": actor_upn or "ServicePrincipal_00000000-0000-4000-8000-0000000000aa",
            "ObjectId": USER, "Actor": actor,
            "Target": [{"ID": "User_00000000-0000-4000-8000-0000000000bb", "Type": 2}, {"ID": USER, "Type": 5}],
            "ModifiedProperties": [{"Name": "StrongAuthenticationMethod", "OldValue": old, "NewValue": new}]}


class TestNetworks:
    def test_network_of(self):
        assert sn.network_of("198.51.100.20") == "198.51.100.0/24"
        assert sn.network_of("2001:db8:1234:5678::1") == "2001:db8:1234::/48"
        assert sn.network_of("not an ip") == ""

    def test_new_and_known_networks(self):
        now = datetime.now(timezone.utc)
        table = FakeTable()
        sn.record(table, [signin(HOME, now - timedelta(days=30))], now - timedelta(days=30))
        sn.record(table, [signin(HOME_NEW_ADDR, now - timedelta(minutes=20)),
                          signin(NEW, now - timedelta(minutes=10))], now)
        seen = sn.near(table, USER, now)
        assert seen == {"history": True, "ips": [HOME_NEW_ADDR, NEW], "new": [NEW]}

    def test_short_history(self):
        now = datetime.now(timezone.utc)
        table = FakeTable()
        sn.record(table, [signin(HOME, now - timedelta(days=3))], now - timedelta(days=3))
        sn.record(table, [signin(HOME, now - timedelta(minutes=10))], now)
        assert sn.near(table, USER, now)["history"] is False

    def test_late_record_keeps_the_earliest_first(self):
        now = datetime.now(timezone.utc)
        table = FakeTable()
        sn.record(table, [signin(NEW, now - timedelta(minutes=5))], now)
        sn.record(table, [signin(NEW, now - timedelta(days=20))], now)
        nets = json.loads(table.get_entity(partition_key="networks", row_key=sn._key(USER))["nets"])
        assert nets["203.0.113.0/24"][0] == _t(now - timedelta(days=20)) + "Z"

    def test_no_storage(self):
        sn.record(None, [signin(HOME, datetime.now(timezone.utc))], datetime.now(timezone.utc))
        assert sn.near(None, USER, datetime.now(timezone.utc))["history"] is False


class TestReview:
    def _run(self, signins, *, actor_upn=None, prior=None, prior_user=USER, prior_triage="", history_days=30):
        now = datetime.now(timezone.utc)
        change = now - timedelta(minutes=5)
        geo, jt = FakeTable(), FakeTable()
        signer = actor_upn or USER
        sn.record(geo, [signin(HOME, now - timedelta(days=history_days), signer)], now - timedelta(days=history_days))
        sn.record(geo, [signin(ip, change - timedelta(minutes=m), signer) for ip, m in signins], now)
        if prior:
            journal.record(jt, {"type": prior, "severity": "medium", "user": prior_user, "description": "d",
                                "event": {"CreationTime": _t(now - timedelta(days=2))}}, "k-prior", "emailed", now=now)
            if prior_triage:
                row = journal.for_user(jt, prior_user, now - timedelta(days=7))[0]
                journal.set_triage(jt, row["id"], prior_triage, "", "admin@contoso.com", now)
        with patch("geo_monitor.table_client", return_value=geo), \
                patch("journal.table_client", return_value=jt), \
                patch("function_app.check_ips_batch", return_value={}), \
                patch("function_app.send_compromise_alert", return_value=True) as send:
            fa._run_compromise_check(FakeTable(), None, set(), [mfa_record(change, actor_upn)])
        rows = journal.for_user(jt, USER, now - timedelta(days=1))
        return send, [r for r in rows if r["type"] == "mfa_change"]

    def test_known_network_sends_no_email(self):
        # Regression: a user added Authenticator in My Sign-ins from their usual connection.
        send, rows = self._run([(HOME_NEW_ADDR, 3)])
        assert not send.called
        assert rows[0]["status"] == "known sign-in" and HOME_NEW_ADDR in rows[0]["action"]

    def test_new_network_alerts(self):
        send, _ = self._run([(HOME, 30), (NEW, 3)])
        finding, context = send.call_args.args[:2]
        assert finding["severity"] == "medium" and finding["ip"] == NEW
        assert "did not use before" in context

    def test_prior_alert_makes_it_high(self):
        send, _ = self._run([(HOME, 3)], prior="inbox_rule")
        finding, context = send.call_args.args[:2]
        assert finding["severity"] == "high" and "Inbox rule" in context

    def test_benign_prior_alert_does_not_count(self):
        send, rows = self._run([(HOME, 3)], prior="inbox_rule", prior_triage="benign")
        assert not send.called and rows[0]["status"] == "known sign-in"

    @pytest.mark.parametrize("signins,history,expect", [
        ([], 30, "No sign-in by the user"),          # no sign-in seen: the monitor cannot tell
        ([(HOME, 3)], 5, ""),                        # history shorter than 14 days
    ], ids=["no-signin", "short-history"])
    def test_cannot_tell_alerts(self, signins, history, expect):
        send, _ = self._run(signins, history_days=history)
        finding, context = send.call_args.args[:2]
        assert finding["severity"] == "medium" and context.startswith(expect) and bool(context) == bool(expect)

    def test_admin_from_known_network_sends_no_email(self):
        send, rows = self._run([(HOME, 3)], actor_upn=ADMIN)
        assert not send.called and rows[0]["status"] == "known sign-in"
        assert ADMIN in rows[0]["action"] and "Changed by admin@contoso.com" in rows[0]["description"]

    def test_admin_from_new_network_alerts(self):
        send, _ = self._run([(NEW, 3)], actor_upn=ADMIN)
        finding, context = send.call_args.args[:2]
        assert finding["ip"] == NEW and f"by {ADMIN} from {NEW}" in context

    @pytest.mark.parametrize("prior_user", [USER, ADMIN], ids=["user-had-alert", "admin-had-alert"])
    def test_admin_change_after_an_alert_is_high(self, prior_user):
        send, _ = self._run([(HOME, 3)], actor_upn=ADMIN, prior="suspicious_signin", prior_user=prior_user)
        finding, context = send.call_args.args[:2]
        assert finding["severity"] == "high" and "Suspicious sign-in" in context

    def test_user_sign_in_does_not_cover_the_admin(self):
        # The user's sign-in from a known network says nothing about the admin who made the change.
        now = datetime.now(timezone.utc)
        geo = FakeTable()
        sn.record(geo, [signin(HOME, now - timedelta(days=30))], now - timedelta(days=30))
        sn.record(geo, [signin(HOME, now - timedelta(minutes=8))], now)
        with patch("geo_monitor.table_client", return_value=geo), \
                patch("journal.table_client", return_value=FakeTable()), \
                patch("function_app.send_compromise_alert", return_value=True) as send:
            fa._run_compromise_check(FakeTable(), None, set(), [mfa_record(now - timedelta(minutes=5), ADMIN)])
        assert send.called
