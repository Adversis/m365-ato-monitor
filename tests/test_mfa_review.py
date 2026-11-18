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
RULE_IP = "81.2.69.160"       # a public test address (MaxMind test data), not a real client


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
        seen = sn.near(sn.view(table, USER), now)
        assert seen == {"history": True, "ips": [HOME_NEW_ADDR, NEW], "new": [NEW]}

    def test_short_history(self):
        now = datetime.now(timezone.utc)
        table = FakeTable()
        sn.record(table, [signin(HOME, now - timedelta(days=3))], now - timedelta(days=3))
        sn.record(table, [signin(HOME, now - timedelta(minutes=10))], now)
        assert sn.near(sn.view(table, USER), now)["history"] is False

    def test_late_record_keeps_the_earliest_first(self):
        now = datetime.now(timezone.utc)
        table = FakeTable()
        sn.record(table, [signin(NEW, now - timedelta(minutes=5))], now)
        sn.record(table, [signin(NEW, now - timedelta(days=20))], now)
        nets = json.loads(table.get_entity(partition_key="networks", row_key=sn._key(USER))["nets"])
        assert nets["203.0.113.0/24"][0] == _t(now - timedelta(days=20)) + "Z"

    def test_no_storage(self):
        sn.record(None, [signin(HOME, datetime.now(timezone.utc))], datetime.now(timezone.utc))
        assert sn.near(sn.view(None, USER), datetime.now(timezone.utc))["history"] is False


@pytest.fixture
def settled():
    """Decide at once (the first-sight hold is tested in TestHeldDecision)."""
    with patch("function_app._settled", return_value=True):
        yield


@pytest.mark.usefixtures("settled")
class TestReview:
    def _run(self, signins, *, actor_upn=None, prior=None, prior_user=USER, prior_triage="", history_days=30):
        now = datetime.now(timezone.utc)
        change = now - timedelta(minutes=60)     # settled: older than the 45-minute hold
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

    def test_failed_source_ip_lookup_cannot_suppress_or_mute_mfa_change(self):
        import admin_store
        now = datetime.now(timezone.utc)
        change = now - timedelta(hours=1)
        geo, jt, events = FakeTable(), FakeTable(), FakeTable()
        sn.record(geo, [signin(HOME, now - timedelta(days=30))], now - timedelta(days=30))
        sn.record(geo, [signin(HOME_NEW_ADDR, change - timedelta(minutes=2))], now)
        event = {**mfa_record(change), "ClientIP": RULE_IP}
        admin_store.add_mute(FakeTable(), {"type": "mfa_change", "user": USER, "days": 7,
                                          "reason": "Expected method changes"}, ADMIN, now)
        with patch("geo_monitor.table_client", return_value=geo), \
                patch("journal.table_client", return_value=jt), \
                patch("function_app.check_ips_batch", return_value={}) as lookup, \
                patch("function_app.send_compromise_alert", return_value=True) as send:
            fa._run_compromise_check(events, None, set(), [event])
        lookup.assert_called_once_with([RULE_IP], None)
        assert send.call_count == 1 and "IP lookup failed" in send.call_args.args[1]
        rows = journal.for_user(jt, USER, now - timedelta(days=1))
        assert rows[0]["status"] == "emailed" and rows[0]["severity"] == "medium"

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

    def test_no_signin_seen_alerts(self):
        send, _ = self._run([], history_days=30)
        finding, context = send.call_args.args[:2]
        assert finding["severity"] == "medium" and context.startswith("No sign-in by the user")

    @pytest.mark.parametrize("signins", [[(HOME, 3)], [(NEW, 3)], []], ids=["known", "new", "none-in-window"])
    def test_learning_period_sends_no_email(self, signins):
        # History shorter than 14 days: a network cannot be told new from known.
        send, rows = self._run(signins, history_days=5)
        assert not send.called and rows[0]["status"] == "known sign-in"
        assert "less than 14 days (5 days so far)" in rows[0]["action"]

    def test_learning_period_still_alerts_after_another_alert(self):
        send, _ = self._run([(HOME, 3)], history_days=5, prior="inbox_rule")
        finding, context = send.call_args.args[:2]
        assert finding["severity"] == "high" and "Inbox rule" in context

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


@pytest.mark.usefixtures("settled")
class TestDeleteOnlyRule:
    """An inbox rule that only deletes mail: email only after another alert or a new-network sign-in."""

    def _rule(self, when, ip=None, **params):
        props = {"RuleName": "Newsletters", "RuleOperation": "AddMailboxRule",
                 "RuleActions": json.dumps([{"ActionType": "Delete"}]), **params}
        return {"Id": f"rule-{_t(when)}-{props['RuleName']}", "Operation": "UpdateInboxRules", "RecordType": 2, "Workload": "Exchange",
                "ResultStatus": "Succeeded", "CreationTime": _t(when), "UserId": USER, "MailboxOwnerUPN": USER,
                "ClientIP": ip or RULE_IP, "ClientInfoString": "Client=MSExchangeRPC",
                "OperationProperties": [{"Name": k, "Value": v} for k, v in props.items()]}

    def _run(self, signins=(), prior=None, ip_data=None, rule_ip=RULE_IP, lookup=None, extra=(), **params):
        now = datetime.now(timezone.utc)
        created = now - timedelta(minutes=60)
        geo, jt = FakeTable(), FakeTable()
        sn.record(geo, [signin(HOME, now - timedelta(days=30)), signin(RULE_IP, now - timedelta(days=30))],
                  now - timedelta(days=30))
        sn.record(geo, [signin(ip, created - timedelta(hours=h)) for ip, h in signins], now)
        if prior:
            journal.record(jt, {"type": prior, "severity": "medium", "user": USER, "description": "d",
                                "event": {"CreationTime": _t(now - timedelta(days=1))}}, "k-prior", "emailed", now=now)
        clean = {"isocode": "US", "asn": "AS64500", "organisation": "Home ISP", "proxy": "no", "type": "Residential"}
        with patch("geo_monitor.table_client", return_value=geo), \
                patch("geo_monitor.is_unusual", return_value=False), \
                patch("journal.table_client", return_value=jt), \
                patch("function_app.check_ips_batch",
                      return_value=lookup if lookup is not None else {rule_ip: ip_data or clean}), \
                patch("function_app.send_compromise_alert", return_value=True) as send:
            records = [self._rule(created, rule_ip, **params)]
            records += [self._rule(created - timedelta(minutes=i + 1), rule_ip, **e) for i, e in enumerate(extra)]
            fa._run_compromise_check(FakeTable(), None, set(), records)
        rows = [r for r in journal.for_user(jt, USER, now - timedelta(days=1)) if r["type"] == "inbox_rule"]
        return send, rows

    def test_no_context_sends_no_email(self):
        send, rows = self._run(signins=[(HOME_NEW_ADDR, 2)])
        assert not send.called and rows[0]["status"] == "known sign-in"

    def test_new_network_sign_in_alerts_high(self):
        send, _ = self._run(signins=[(NEW, 20)])
        finding, context = send.call_args.args[:2]
        assert finding["severity"] == "high" and NEW in context

    def test_prior_alert_alerts_high(self):
        send, _ = self._run(prior="suspicious_signin")
        finding, context = send.call_args.args[:2]
        assert finding["severity"] == "high" and "Suspicious sign-in" in context

    def test_flagged_rule_ip_still_alerts(self):
        vpn = {"isocode": "NL", "asn": "AS64501", "organisation": "Some VPN", "proxy": "yes", "type": "VPN", "risk": 80}
        send, _ = self._run(ip_data=vpn)
        assert send.call_args.args[0]["severity"] == "high"

    def test_rule_from_a_new_network_alerts_high(self):
        send, _ = self._run(rule_ip="89.160.20.112")          # not on a network the user used
        finding, context = send.call_args.args[:2]
        assert finding["severity"] == "high" and "89.160.20.112" in context

    def test_failed_ip_lookup_is_never_quiet(self):
        send, _ = self._run(lookup={})
        finding, context = send.call_args.args[:2]
        assert "not checked" in context

    def test_alert_in_the_same_batch_counts(self):
        # Regression: a forwarding rule and a delete-only rule in one batch. The forwarding alert is
        # journaled first, so the delete-only rule alerts too.
        send, _ = self._run(extra=[{"RuleName": "fwd", "RuleActions": json.dumps(
            [{"ActionType": "Forward", "Recipients": ["x@fabrikam.com"]}])}])
        assert send.call_count == 2
        assert all(c.args[0]["severity"] == "high" for c in send.call_args_list)

    def test_delete_with_another_sign_is_not_gated(self):
        # Deletes mail about payments: the classic way to hide a fraud reply. Always high.
        send, _ = self._run(RuleCondition="{(Subject Contains 'invoice')}")
        assert send.called and send.call_args.args[0]["severity"] == "high"


class TestHeldDecision:
    """A decision that a late sign-in record can change waits 30 minutes after first sight."""

    def _age(self, events, minutes):
        now = datetime.now(timezone.utc)
        for row in events.partition("heldreview").values():
            held = json.loads(row["finding"])
            held["_held_since"] = (now - timedelta(minutes=minutes)).isoformat()
            row["finding"] = json.dumps(held)

    def _env(self, geo, jt):
        return (patch("geo_monitor.table_client", return_value=geo), patch("journal.table_client", return_value=jt),
                patch("function_app.check_ips_batch", return_value={}))

    def test_late_new_network_sign_in_alerts(self):
        now = datetime.now(timezone.utc)
        change = now - timedelta(minutes=70)        # a late record: the hold counts from first sight
        geo, jt, events = FakeTable(), FakeTable(), FakeTable()
        sn.record(geo, [signin(HOME, now - timedelta(days=30))], now - timedelta(days=30))
        sn.record(geo, [signin(HOME_NEW_ADDR, change - timedelta(minutes=3))], now)
        a, b, c = self._env(geo, jt)
        with a, b, c, patch("function_app.send_compromise_alert", return_value=True) as send:
            fa._run_compromise_check(events, None, set(), [mfa_record(change)])
            assert not send.called and len(events.partition("heldreview")) == 1
            assert not [r for r in journal.for_user(jt, USER, now - timedelta(days=1)) if r["type"] == "mfa_change"]
            etag = next(iter(events.etags.values()))
            fa._run_compromise_check(events, None, set(), [])             # still held: not written again
            assert next(iter(events.etags.values())) == etag and not send.called
            # The attacker's sign-in from a new network arrives late.
            sn.record(geo, [signin(NEW, change - timedelta(minutes=2))], now)
            self._age(events, 31)
            fa._run_compromise_check(events, None, set(), [])
            assert send.called and NEW in send.call_args.args[1]
            assert events.partition("heldreview") == {}

    def test_no_sign_in_seen_waits_for_the_sign_in(self):
        now = datetime.now(timezone.utc)
        change = now - timedelta(minutes=10)
        geo, jt, events = FakeTable(), FakeTable(), FakeTable()
        sn.record(geo, [signin(HOME, now - timedelta(days=30))], now - timedelta(days=30))
        a, b, c = self._env(geo, jt)
        with a, b, c, patch("function_app.send_compromise_alert", return_value=True) as send:
            fa._run_compromise_check(events, None, set(), [mfa_record(change)])
            assert not send.called                                         # no sign-in yet: held
            sn.record(geo, [signin(HOME_NEW_ADDR, change - timedelta(minutes=4))], now)
            self._age(events, 31)
            fa._run_compromise_check(events, None, set(), [])
        assert not send.called and events.partition("heldreview") == {}
        rows = [r for r in journal.for_user(jt, USER, now - timedelta(days=1)) if r["type"] == "mfa_change"]
        assert rows[0]["status"] == "known sign-in"

    def test_overlapping_fetch_keeps_first_sight_and_decides_after_30_minutes(self):
        now = datetime.now(timezone.utc)
        change = now - timedelta(minutes=10)
        geo, jt, events = FakeTable(), FakeTable(), FakeTable()
        sn.record(geo, [signin(HOME, now - timedelta(days=30))], now - timedelta(days=30))
        a, b, c = self._env(geo, jt)
        with a, b, c, patch("function_app.send_compromise_alert", return_value=True) as send:
            fa._run_compromise_check(events, None, set(), [mfa_record(change)])
            original = next(iter(events.partition("heldreview").values()))["finding"]
            etag = dict(events.etags)
            fa._run_compromise_check(events, None, set(), [mfa_record(change)])
            assert next(iter(events.partition("heldreview").values()))["finding"] == original
            assert events.etags == etag
            self._age(events, 31)
            fa._run_compromise_check(events, None, set(), [mfa_record(change)])
            assert send.call_count == 1 and events.partition("heldreview") == {}

    def test_stale_held_row_is_removed(self):
        events = FakeTable()
        events.upsert_entity({"PartitionKey": "heldreview", "RowKey": "x", "finding": "{bad",
                              "held_at": (datetime.now(timezone.utc) - timedelta(days=3)).isoformat()})
        assert fa._held_reviews(events) == [] and events.partition("heldreview") == {}


class TestPriorAlertLimit:
    @pytest.mark.parametrize("with_prior", [False, True])
    def test_future_alerts_do_not_count_or_hide_a_prior_alert(self, with_prior):
        now = datetime.now(timezone.utc)
        change = now - timedelta(hours=2)
        jt = FakeTable()
        if with_prior:
            journal.record(jt, {"type": "inbox_rule", "severity": "medium", "user": USER,
                                "event": {"CreationTime": _t(change - timedelta(hours=1))}},
                           "before", "emailed", now=now)
        for i in range(3):
            journal.record(jt, {"type": "suspicious_signin", "severity": "medium", "user": USER,
                                "event": {"CreationTime": _t(change + timedelta(minutes=i + 1))}},
                           f"after-{i}", "emailed", now=now)
        with patch("journal.table_client", return_value=jt):
            prior = fa._prior_alert(USER, {"type": "mfa_change", "event": mfa_record(change)},
                                    change - timedelta(days=7))
        assert (prior["key"] if prior else None) == ("before" if with_prior else None)

    def test_many_quiet_rows_do_not_hide_a_prior_alert(self):
        # Regression: 60 "alert off" rows (a password spray) after an emailed alert.
        now = datetime.now(timezone.utc)
        jt = FakeTable()
        journal.record(jt, {"type": "suspicious_signin", "severity": "medium", "user": USER, "description": "d",
                            "event": {"CreationTime": _t(now - timedelta(days=3))}}, "k-alert", "emailed", now=now)
        for i in range(60):
            journal.record(jt, {"type": "attack_tool", "severity": "high", "user": USER, "description": "spray",
                                "event": {"CreationTime": _t(now - timedelta(hours=1, minutes=i))}},
                           f"k-off-{i}", "alert off", now=now)
        with patch("journal.table_client", return_value=jt):
            prior = fa._prior_alert(USER, {"type": "mfa_change", "event": {"Id": "x"}}, now - timedelta(days=7))
        assert prior and prior["type"] == "suspicious_signin"


class TestNetworkStore:
    def setup_method(self):
        sn._rows.clear()

    def test_one_failed_user_does_not_stop_the_batch(self):
        now = datetime.now(timezone.utc)
        table = FakeTable()
        real = table.create_entity
        calls = []

        def flaky(entity):
            calls.append(entity["upn"])
            if entity["upn"] == "a@contoso.com":
                raise OSError("503")
            return real(entity)
        table.create_entity = flaky
        sn.record(table, [signin(HOME, now, "a@contoso.com"), signin(HOME, now, "b@contoso.com")], now)
        assert calls == ["a@contoso.com", "b@contoso.com"]
        assert sn.near(sn.view(table, "b@contoso.com"), now)["ips"] == [HOME]

    def test_unchanged_sign_ins_are_not_written_again(self):
        now = datetime.now(timezone.utc)
        table = FakeTable()
        sn.record(table, [signin(HOME, now - timedelta(minutes=3))], now)
        sn.record(table, [signin(HOME, now - timedelta(minutes=2))], now)       # read again after a write
        etag = table.etags[("networks", sn._key(USER))]
        sn.record(table, [signin(HOME, now - timedelta(minutes=1))], now)       # same IP within 10 minutes
        assert table.etags[("networks", sn._key(USER))] == etag

    def test_conflict_reads_the_row_again(self):
        now = datetime.now(timezone.utc)
        table = FakeTable()
        sn.record(table, [signin(HOME, now - timedelta(minutes=30))], now)
        sn.record(table, [signin(HOME, now - timedelta(minutes=29))], now)      # cached with its etag
        # Another instance adds a sign-in: the cached etag is now stale.
        other = dict(table.rows[("networks", sn._key(USER))])
        other["recent"] = json.dumps(json.loads(other["recent"]) + [[_t(now - timedelta(minutes=5)) + "Z", NEW]])
        table.upsert_entity(other)
        sn.record(table, [signin(HOME_NEW_ADDR, now - timedelta(minutes=1))], now)
        assert set(sn.near(sn.view(table, USER), now)["ips"]) >= {NEW, HOME_NEW_ADDR}       # nothing lost

    def test_purge_and_known(self):
        now = datetime.now(timezone.utc)
        table = FakeTable()
        sn.record(table, [signin(HOME, now - timedelta(days=100), "old@contoso.com")], now - timedelta(days=100))
        sn.record(table, [signin(HOME, now - timedelta(days=30))], now - timedelta(days=30))
        assert sn.purge(table, now) == 1
        assert sn.known(sn.view(table, USER), HOME_NEW_ADDR, now) is True
        assert sn.known(sn.view(table, USER), NEW, now) is False
        assert sn.known(sn.view(table, "nobody@contoso.com"), NEW, now) is None


class TestReviewRoundTwo:
    def setup_method(self):
        sn._rows.clear()

    def test_dual_stack_cannot_tell(self):
        now = datetime.now(timezone.utc)
        table = FakeTable()
        sn.record(table, [signin(HOME, now - timedelta(days=30))], now - timedelta(days=30))
        row = sn.view(table, USER)
        assert sn.known(row, "2001:db8:1::5", now) is None          # no IPv6 history: no "new network"
        assert sn.known(row, NEW, now) is False

    def test_range_keeps_a_sign_in_inside_the_window(self):
        # Sign-ins at T and T+9 (one range). An MFA change at T+65: the window starts at T+5.
        now = datetime.now(timezone.utc)
        t = now - timedelta(hours=3)
        table = FakeTable()
        sn.record(table, [signin(HOME, now - timedelta(days=30))], now - timedelta(days=30))
        sn.record(table, [signin(HOME_NEW_ADDR, t), signin(HOME_NEW_ADDR, t + timedelta(minutes=9))], now)
        assert sn.near(sn.view(table, USER), t + timedelta(minutes=65))["ips"] == [HOME_NEW_ADDR]

    def test_old_row_format_is_read(self):
        now = datetime.now(timezone.utc)
        table = FakeTable()
        table.upsert_entity({"PartitionKey": "networks", "RowKey": sn._key(USER), "upn": USER,
                             "since": _t(now - timedelta(days=30)) + "Z",
                             "nets": json.dumps({"198.51.100.0/24": [_t(now - timedelta(days=30)) + "Z"] * 2}),
                             "recent": json.dumps([[_t(now - timedelta(minutes=20)) + "Z", HOME]])})
        assert sn.near(sn.view(table, USER), now)["ips"] == [HOME]
        old = dict(table.rows[("networks", sn._key(USER))])
        old["nets"] = json.dumps({"198.51.100.0/24": [_t(now - timedelta(days=120)) + "Z"] * 2})
        table.upsert_entity(old)
        assert sn.purge(table, now) == 1                             # no "updated": judged by its newest network

    def test_storage_outage_stops_after_three_failures(self):
        now = datetime.now(timezone.utc)
        table = FakeTable()
        calls = []

        def down(**kw):
            calls.append(1)
            raise OSError("503")
        table.get_entity = down
        sn.record(table, [signin(HOME, now, f"u{i}@contoso.com") for i in range(10)], now)
        assert len(calls) == 3

    def test_high_mfa_alert_keeps_the_sign_in_context(self):
        now = datetime.now(timezone.utc)
        change = now - timedelta(minutes=60)
        geo = FakeTable()
        sn.record(geo, [signin(HOME, now - timedelta(days=30))], now - timedelta(days=30))
        sn.record(geo, [signin(RULE_IP, change - timedelta(minutes=5))], now)     # a public IP, new network
        vpn = {"isocode": "NL", "asn": "AS64501", "organisation": "Some VPN", "proxy": "yes", "type": "VPN", "risk": 80}
        with patch("geo_monitor.table_client", return_value=geo), \
                patch("journal.table_client", return_value=FakeTable()), \
                patch("function_app.check_ips_batch", return_value={RULE_IP: vpn}), \
                patch("function_app.send_compromise_alert", return_value=True) as send:
            fa._run_compromise_check(FakeTable(), None, set(), [mfa_record(change)])
        finding, context = send.call_args.args[:2]
        assert finding["severity"] == "high" and "did not use before" in context and "VPN" in context


class TestMfaChangeText:
    """The alert names the methods before and after, the default, and changed contact details."""

    def test_names_old_and_new_methods_and_contact_details(self):
        import compromise_detector as cd
        old = json.dumps([{"MethodType": 6, "Default": True}, {"MethodType": 7, "Default": False}])
        new = json.dumps([{"MethodType": 7, "Default": False}, {"MethodType": 5, "Default": True},
                          {"MethodType": 2, "Default": False}])
        old_d = json.dumps([{"PhoneNumber": None, "Email": "help@fabrikam.com", "VoiceOnlyPhoneNumber": None}])
        new_d = json.dumps([{"PhoneNumber": "+1 5550111", "Email": "help@fabrikam.com",
                             "VoiceOnlyPhoneNumber": "+1 5550100"}])
        event = {**mfa_record(datetime.now(timezone.utc)), "ModifiedProperties": [
            {"Name": "StrongAuthenticationMethod", "OldValue": old, "NewValue": new},
            {"Name": "StrongAuthenticationUserDetails", "OldValue": old_d, "NewValue": new_d}]}
        text = cd.detect_mfa_changes([event])[0]["description"]
        assert "Added: text message code to mobile phone, voice call to office phone." in text
        assert "Removed: Authenticator app notification." in text
        assert "Default method changed: Authenticator app notification to text message code to mobile phone." in text
        assert "Methods before: Authenticator app notification (default), code from" in text
        assert "mobile phone none to +1 5550111; voice-only phone none to +1 5550100." in text
        assert "help@fabrikam.com" not in text           # unchanged details are not listed

    def test_unknown_method_type_and_count_fallback(self):
        import compromise_detector as cd
        event = {**mfa_record(datetime.now(timezone.utc)), "ModifiedProperties": [
            {"Name": "StrongAuthenticationMethod", "OldValue": json.dumps([{"MethodType": 6}]),
             "NewValue": json.dumps([{"MethodType": 6}, {"MethodType": 12}])}]}
        assert "Added: method type 12." in cd.detect_mfa_changes([event])[0]["description"]
        event["ModifiedProperties"][0].update(OldValue='[{"MethodType":6}', NewValue='[{"MethodType":6},{"MethodType":7}')
        assert "(MFA methods: 1 to 2)." in cd.detect_mfa_changes([event])[0]["description"]


@pytest.mark.usefixtures("settled")
class TestSameCountChanges:
    """A change that keeps the number of methods: a finding, decided by the same context check."""

    def _event(self, old, new, prop="StrongAuthenticationMethod", when=None):
        event = mfa_record(when or datetime.now(timezone.utc))
        event["ModifiedProperties"] = [{"Name": prop, "OldValue": json.dumps(old), "NewValue": json.dumps(new)}]
        return event

    @pytest.mark.parametrize("old,new,prop,expect", [
        ([{"MethodType": 6, "Default": True}, {"MethodType": 7}], [{"MethodType": 5, "Default": True}, {"MethodType": 7}],
         "StrongAuthenticationMethod", "Added: text message code to mobile phone."),
        ([{"MethodType": 6, "Default": True}, {"MethodType": 5}], [{"MethodType": 6}, {"MethodType": 5, "Default": True}],
         "StrongAuthenticationMethod", "Default method changed: Authenticator app notification to text message code"),
        ([{"DeviceName": "Pixel"}], [{"DeviceName": "Galaxy"}],
         "StrongAuthenticationPhoneAppDetail", "Authenticator app device added: Galaxy."),
    ], ids=["method-replaced", "default-changed", "device-replaced"])
    def test_creates_a_finding(self, old, new, prop, expect):
        import compromise_detector as cd
        found = cd.detect_mfa_changes([self._event(old, new, prop)])
        assert len(found) == 1 and expect in found[0]["description"]

    @pytest.mark.parametrize("old,new", [
        ([{"MethodType": 6, "Default": True}, {"MethodType": 7}], [{"MethodType": 7}, {"MethodType": 6, "Default": True}]),
        ([{"MethodType": 6, "Default": True}, {"MethodType": 7}], [{"MethodType": 6, "Default": True}]),
        ([], [{"MethodType": 6, "Default": True}]),
    ], ids=["reordered", "one-removed", "first-registration"])
    def test_no_finding(self, old, new):
        import compromise_detector as cd
        assert cd.detect_mfa_changes([self._event(old, new)]) == []

    def _run(self, signins, prior=None):
        now = datetime.now(timezone.utc)
        change = now - timedelta(minutes=60)
        geo, jt = FakeTable(), FakeTable()
        sn.record(geo, [signin(HOME, now - timedelta(days=30))], now - timedelta(days=30))
        sn.record(geo, [signin(ip, change - timedelta(minutes=m)) for ip, m in signins], now)
        if prior:
            journal.record(jt, {"type": prior, "severity": "medium", "user": USER, "description": "d",
                                "event": {"CreationTime": _t(change - timedelta(minutes=5))}}, "k-prior", "emailed", now=now)
        event = self._event([{"MethodType": 6, "Default": True}, {"MethodType": 7}],
                            [{"MethodType": 5, "Default": True}, {"MethodType": 7}], when=change)
        with patch("geo_monitor.table_client", return_value=geo), \
                patch("journal.table_client", return_value=jt), \
                patch("function_app.check_ips_batch", return_value={}), \
                patch("function_app.send_compromise_alert", return_value=True) as send:
            fa._run_compromise_check(FakeTable(), None, set(), [event])
        return send, [r for r in journal.for_user(jt, USER, now - timedelta(days=1)) if r["type"] == "mfa_change"]

    def test_after_a_suspicious_sign_in_alert_is_high(self):
        send, _ = self._run([(NEW, 3)], prior="suspicious_signin")
        finding, context = send.call_args.args[:2]
        assert finding["severity"] == "high" and "Suspicious sign-in" in context

    def test_from_a_known_network_sends_no_email(self):
        send, rows = self._run([(HOME_NEW_ADDR, 3)])
        assert not send.called and rows[0]["status"] == "known sign-in"


@pytest.mark.usefixtures("settled")
class TestMfaReset:
    """All methods removed: listed with no email, also after another alert."""

    def _reset(self, when, actor_upn=ADMIN):
        event = mfa_record(when, actor_upn)
        event["ModifiedProperties"] = [{"Name": "StrongAuthenticationMethod",
                                        "OldValue": json.dumps([{"MethodType": 6, "Default": True}, {"MethodType": 7}]),
                                        "NewValue": "[]"}]
        return event

    def test_finding_text(self):
        import compromise_detector as cd
        found = cd.detect_mfa_changes([self._reset(datetime.now(timezone.utc))])
        assert len(found) == 1 and found[0]["list_only"] and found[0]["user"] == USER
        text = found[0]["description"]
        assert "All MFA methods were removed from victim@contoso.com" in text
        assert "before: Authenticator app notification (default), code from" in text
        assert "Changed by admin@contoso.com." in text

    def test_listed_without_email_or_response(self):
        now = datetime.now(timezone.utc)
        jt = FakeTable()
        journal.record(jt, {"type": "suspicious_signin", "severity": "high", "user": USER, "description": "d",
                            "event": {"CreationTime": _t(now - timedelta(hours=1))}}, "k-prior", "emailed", now=now)
        with patch("geo_monitor.table_client", return_value=FakeTable()), \
                patch("journal.table_client", return_value=jt), \
                patch("function_app.check_ips_batch", return_value={}), \
                patch("responder.respond_to_finding") as respond, \
                patch("function_app.send_compromise_alert", return_value=True) as send:
            fa._run_compromise_check(FakeTable(), None, set(), [self._reset(now - timedelta(minutes=30))])
        assert not send.called and not respond.called
        rows = [r for r in journal.for_user(jt, USER, now - timedelta(days=1)) if r["type"] == "mfa_change"]
        assert rows[0]["status"] == "list only" and rows[0]["triage"] == ""


@pytest.mark.usefixtures("settled")
class TestKnownProvider:
    """A phone on a mobile carrier gets new networks often (IPv6 /48s): a known provider with a clean IP is known."""
    OLD_PHONE = "89.160.20.112"          # the carrier network of the user's earlier sign-ins (MaxMind test IP)
    NEW_PHONE = "81.2.69.160"            # another network of the same carrier (MaxMind test IP)
    CARRIER = "AS64510"

    def _run(self, answer, history_asn=CARRIER):
        now = datetime.now(timezone.utc)
        change = now - timedelta(minutes=60)
        geo, jt = FakeTable(), FakeTable()
        lookup = (lambda ips: {ip: history_asn for ip in ips}) if history_asn else None
        sn.record(geo, [signin(self.OLD_PHONE, now - timedelta(days=30))], now - timedelta(days=30), asn_lookup=lookup)
        sn.record(geo, [signin(self.NEW_PHONE, change - timedelta(minutes=3))], now)
        with patch("geo_monitor.table_client", return_value=geo), \
                patch("journal.table_client", return_value=jt), \
                patch("geo_monitor.is_unusual", return_value=False), \
                patch("function_app.check_ips_batch", return_value={self.NEW_PHONE: answer}), \
                patch("function_app.send_compromise_alert", return_value=True) as send:
            fa._run_compromise_check(FakeTable(), None, set(), [mfa_record(change)])
        rows = [r for r in journal.for_user(jt, USER, now - timedelta(days=1)) if r["type"] == "mfa_change"]
        return send, rows

    def test_same_carrier_clean_ip_is_a_known_sign_in(self):
        send, rows = self._run({"proxy": "no", "type": "Wireless", "risk": 0, "asn": self.CARRIER,
                                "organisation": "Example Wireless"})
        assert not send.called
        assert rows[0]["status"] == "known sign-in"
        assert "Example Wireless, AS64510" in rows[0]["action"]

    def test_new_carrier_still_alerts(self):
        send, _ = self._run({"proxy": "no", "type": "Wireless", "risk": 0, "asn": "AS64511"})
        assert send.called

    def test_flagged_ip_on_a_known_carrier_still_alerts(self):
        # A mobile proxy on the user's own carrier, which proxycheck.io flags.
        send, _ = self._run({"proxy": "yes", "type": "Proxy", "risk": 100, "asn": self.CARRIER})
        assert send.called and send.call_args.args[0]["severity"] == "high"

    def test_history_without_providers_still_alerts(self):
        # Rows written before the update have no providers: the alert stays.
        send, _ = self._run({"proxy": "no", "type": "Wireless", "risk": 0, "asn": self.CARRIER}, history_asn=None)
        assert send.called


def test_flagged_sign_in_does_not_make_a_known_provider():
    cache = FakeTable()
    from ip_checker import cache_ip_result
    cache_ip_result("81.2.69.160", {"proxy": "yes", "type": "VPN", "risk": 73, "asn": "AS64500"}, cache)
    cache_ip_result("89.160.20.112", {"proxy": "no", "type": "Wireless", "risk": 0, "asn": "AS64510"}, cache)
    assert fa._clean_asns(["81.2.69.160", "89.160.20.112", "192.0.2.1"], cache) == {"89.160.20.112": "AS64510"}
