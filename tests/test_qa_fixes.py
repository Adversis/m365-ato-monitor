"""Regression tests for the QA review: onboarding rescan, journal window, mutes
after a failed IP lookup, table client retry, ETag saves, response result on a
retried alert, the inbox rule sweep after a token error, and the alert mailbox
change."""

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

import admin_store
import config
import journal
from tests.fakes import FakeTable
from tests.test_admin_ui import MUTATE, _req

NOW = datetime(2026, 11, 8, 12, 0, tzinfo=timezone.utc)


def _row(user, i, sev="medium", ftype="suspicious_signin", when=None, status="emailed"):
    return ({"type": ftype, "severity": sev, "user": user, "description": "d", "ip": None,
             "event": {"Id": f"e{i}", "CreationTime": (when or NOW).strftime("%Y-%m-%dT%H:%M:%S")}},
            f"k{i}", status)


# ---------------------------------------------------------------------------
# Onboarding scan: a second scan, and records older than the window
# ---------------------------------------------------------------------------

def _forwarding_record(when):
    return {"Id": "h1", "RecordType": 1, "Operation": "New-InboxRule", "UserId": "jane@contoso.com",
            "CreationTime": when, "ClientIP": "198.51.100.5",
            "Parameters": [{"Name": "Name", "Value": "x1"}, {"Name": "ForwardTo", "Value": "a@evil.example"}]}


def _scan(events, jt, now, record):
    import function_app as fa
    import onboarding

    def fetch(ct, start, end):
        first = start == onboarding._parse(onboarding.load(events)["history"]["from"])
        return ([record] if ct == "Audit.Exchange" and first else []), True
    sent = MagicMock(return_value=True)
    with patch("journal.table_client", return_value=jt), \
            patch("onboarding.fetch_content_records", side_effect=fetch), \
            patch("onboarding.token_manager.granted_graph_roles", return_value=[]), \
            patch("geo_monitor.table_client", return_value=None):
        state = onboarding.run(events, FakeTable(), fa._DETECTORS, now, send_report=sent)
    return state, sent.call_args.args[1]


class TestOnboardingRescan:

    def test_second_full_scan_lists_the_same_finding(self):
        import onboarding
        events, jt = FakeTable(), FakeTable()
        record = _forwarding_record("2026-11-05T10:00:00")
        onboarding.start(events, NOW, "full")
        s1, f1 = _scan(events, jt, NOW, record)
        later = NOW + timedelta(hours=1)
        onboarding.start(events, later, "full", by="admin")
        s2, f2 = _scan(events, jt, later, record)
        assert s1["history"]["findings"] == 1 and len(f1) == 1
        assert s2["history"]["findings"] == 1 and len(f2) == 1 and f2[0]["run_id"] == s2["run_id"]
        # The monitor still does not email it: the row stays marked processed.
        assert ("events", f2[0]["key"]) in events.rows

    def test_finding_the_monitor_emailed_is_not_listed(self):
        import onboarding
        events, jt = FakeTable(), FakeTable()
        record = _forwarding_record("2026-11-05T10:00:00")
        onboarding.start(events, NOW, "full")
        _, f1 = _scan(events, jt, NOW, record)
        events.upsert_entity({"PartitionKey": "events", "RowKey": f1[0]["key"], "by": None})   # the monitor's mark
        events.rows[("events", f1[0]["key"])].pop("by")
        onboarding.start(events, NOW + timedelta(hours=1), "full")
        s2, f2 = _scan(events, jt, NOW + timedelta(hours=1), record)
        assert s2["history"]["findings"] == 0 and f2 == []

    def test_record_older_than_the_window_is_listed(self):
        import onboarding
        events, jt = FakeTable(), FakeTable()
        onboarding.start(events, NOW, "full")
        before = onboarding._parse(onboarding.load(events)["history"]["from"]) - timedelta(minutes=45)
        state, listed = _scan(events, jt, NOW, _forwarding_record(before.strftime("%Y-%m-%dT%H:%M:%S")))
        assert state["history"]["findings"] == 1 and len(listed) == 1

    def test_rule_sweep_waits_after_a_token_error(self):
        import onboarding
        events = FakeTable()
        onboarding.start(events, NOW, "rules")
        with patch("onboarding.token_manager.granted_graph_roles", return_value=None), \
                patch("journal.table_client", return_value=FakeTable()):
            for _ in range(9):
                state = onboarding.run(events, None, [], NOW, send_report=MagicMock(return_value=True))
                assert state["step"] == "rules" and not state["rules"]["skipped"]
            state = onboarding.run(events, None, [], NOW, send_report=MagicMock(return_value=True))
        assert state["step"] == "done" and "Graph token" in state["rules"]["skipped"]

    def test_save_stops_when_a_new_scan_starts_after_the_read(self):
        import onboarding
        events = FakeTable()
        old = onboarding.start(events, NOW, "full")
        real_load = onboarding._load
        stale = real_load(events)

        def load_then_restart(table):
            onboarding.start(events, NOW, "full", by="admin")      # a new scan starts between read and write
            return stale
        with patch("onboarding._load", side_effect=load_then_restart):
            assert onboarding._save(events, old) is False
        assert onboarding.load(events)["run_id"] != old["run_id"]


# ---------------------------------------------------------------------------
# Journal window: newest first across all partitions, exact counts
# ---------------------------------------------------------------------------

class TestJournalWindow:

    def test_newest_high_row_is_kept_and_counts_are_exact(self):
        jt = FakeTable()
        for i in range(600):
            f, k, st = _row(f"user{i}@contoso.com", i, when=NOW - timedelta(days=3))
            journal.record(jt, f, k, st, now=NOW)
        late = max((f"vip{i}@contoso.com" for i in range(50)), key=journal.partition)
        f, k, st = _row(late, 999, sev="high", ftype="mailbox_forwarding", when=NOW - timedelta(minutes=5))
        journal.record(jt, f, k, st, now=NOW)
        rows, totals = journal.window(jt, NOW - timedelta(days=7), limit=500)
        assert len(rows) == 500 and rows[0]["key"] == "k999"
        assert totals["total"] == 601 and totals["high"] == 1 and totals["users"] == 601
        assert journal.recent(jt, NOW - timedelta(days=7), limit=10)[0]["key"] == "k999"

    def test_high_first_and_filters(self):
        jt = FakeTable()
        journal.record(jt, *_row("a@contoso.com", 1, sev="high", when=NOW - timedelta(days=2)), now=NOW)
        for i in range(2, 8):
            journal.record(jt, *_row(f"u{i}@contoso.com", i, when=NOW - timedelta(hours=i)), now=NOW)
        journal.record(jt, *_row("b@contoso.com", 9, status="muted"), now=NOW)
        rows, totals = journal.window(jt, NOW - timedelta(days=7), limit=2, rank=journal.high_first)
        assert [r["key"] for r in rows] == ["k1", "k9"]
        rows, totals = journal.window(jt, NOW - timedelta(days=7), keep=lambda r: r["status"] == "muted")
        assert [r["key"] for r in rows] == ["k9"] and totals["total"] == 1
        assert journal.window(None, NOW) == ([], {"total": 0, "by_type": {}, "by_status": {}, "by_triage": {}, "high": 0,
                                                 "users": 0})

    def test_weekly_report_counts_rows_that_are_not_listed(self):
        import alerting
        rows = [{"type": "inbox_rule", "severity": "high", "user": "a@contoso.com", "status": "emailed",
                 "at": "2026-11-07T10:00:00Z", "description": "d"}]
        totals = {"total": 40, "high": 3, "by_type": {"inbox_rule": 40}, "by_status": {"emailed": 38, "muted": 2},
                  "users": 9}
        health = {"last_content": NOW - timedelta(hours=1), "queues": {}, "onboarding": None}
        stats = {"runs": 7 * 24 * 30, "total_events": 10, "gaps": 0, "errors": 0}
        with patch("alerting._deliver", return_value=True) as deliver:
            alerting.send_weekly_report(stats, rows, health, NOW, totals=totals)
        subject, body = deliver.call_args.args[:2]
        assert "3 high alerts" in subject and "And 2 more" in body


# ---------------------------------------------------------------------------
# A mute does not hide an alert whose source IP was not checked
# ---------------------------------------------------------------------------

class TestMuteAfterFailedLookup:

    FINDING = {"type": "inbox_rule", "severity": "medium", "user": "jane@contoso.com", "description": "d",
               "ip": "185.220.101.1", "rule_name": "r", "event": {"Id": "x1", "CreationTime": "2026-11-08T11:00:00"}}

    def _run(self, lookup):
        import function_app as fa
        admin_store.add_mute(FakeTable(), {"type": "inbox_rule", "user": "jane@contoso.com", "days": 7,
                                           "reason": "known rule"}, "a@contoso.com",
                             datetime.now(timezone.utc) - timedelta(hours=1))   # the run uses the real time
        events = FakeTable()
        with patch("function_app._DETECTORS", (lambda ev: [dict(self.FINDING)],)), \
                patch("function_app.check_ips_batch", return_value=lookup), \
                patch("function_app.send_compromise_alert", return_value=True) as send, \
                patch("journal.table_client", return_value=FakeTable()), \
                patch("geo_monitor.table_client", return_value=None):
            fa._run_compromise_check(events, None, set(), [{"Id": "x1"}])
        return send

    def test_lookup_failed_alert_is_sent(self):
        send = self._run({})
        assert send.called and "not checked" in send.call_args.args[1]

    def test_lookup_clean_alert_is_muted(self):
        clean = {"proxy": "no", "type": "Business", "risk": 0, "isocode": "US", "provider": "x"}
        assert not self._run({"185.220.101.1": clean}).called


# ---------------------------------------------------------------------------
# Table clients: a failure is retried
# ---------------------------------------------------------------------------

class TestCachedTable:

    def test_failure_is_retried_after_the_wait(self):
        calls = {"n": 0}
        table = FakeTable()

        def svc():
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("AuthorizationPermissionMismatch")
            m = MagicMock()
            m.create_table_if_not_exists.return_value = table
            return m
        cache = config.CachedTable("monitoradmin", "Admin table")
        clock = [1000.0]
        with patch.object(config, "STORAGE_ACCOUNT_NAME", "st1"), \
                patch("config.table_service", side_effect=svc), \
                patch("config.time.monotonic", side_effect=lambda: clock[0]):
            assert cache.get() is None
            clock[0] += 30
            assert cache.get() is None and calls["n"] == 1     # waits
            clock[0] += 31
            assert cache.get() is table and calls["n"] == 2
            assert cache.get() is table and calls["n"] == 2     # kept

    def test_not_configured(self):
        with patch.object(config, "STORAGE_ACCOUNT_NAME", ""), patch.object(config, "STORAGE_CONNECTION_STRING", ""):
            assert config.CachedTable("x", "X").get() is None


# ---------------------------------------------------------------------------
# Settings: a parallel save gets a conflict
# ---------------------------------------------------------------------------

class TestSettingsEtag:

    def test_parallel_saves(self):
        table = FakeTable()
        stale = admin_store.load(table)
        with patch("admin_store.load", side_effect=lambda t: dict(stale)):
            admin_store.save(table, {"LOGIN_ALERT_CONFIDENCE": "high"}, 0, "a@contoso.com")
            with pytest.raises(admin_store.ConflictError):
                admin_store.save(table, {"RISK_SCORE_THRESHOLD": 50}, 0, "b@contoso.com")
        stored = admin_store.load(table)
        assert stored["overrides"] == {"LOGIN_ALERT_CONFIDENCE": "high"} and stored["version"] == 1

        stale = admin_store.load(table)
        with patch("admin_store.load", side_effect=lambda t: dict(stale)):
            admin_store.save(table, {"RISK_SCORE_THRESHOLD": 50}, 1, "b@contoso.com")
            with pytest.raises(admin_store.ConflictError):
                admin_store.save(table, {"LOGIN_ALERT_CONFIDENCE": "low"}, 1, "a@contoso.com")
        assert admin_store.load(table)["version"] == 2


# ---------------------------------------------------------------------------
# A retried alert keeps the response result
# ---------------------------------------------------------------------------

class TestRetriedAlert:

    def test_response_result_is_in_the_retry_email(self):
        import function_app as fa
        events = FakeTable()
        finding = {"type": "inbox_rule", "severity": "high", "user": "jane@contoso.com", "description": "d",
                   "ip": "", "event": {"Id": "r1", "CreationTime": "2026-11-08T11:00:00"}}
        key = fa.finding_key(finding)
        with patch("function_app.responder.respond_to_finding", return_value="Block sign-in: done") as respond, \
                patch("function_app.send_compromise_alert", return_value=False) as send, \
                patch("journal.table_client", return_value=FakeTable()):
            assert not fa._deliver_finding(dict(finding), "", events, set(), None, NOW)
            assert send.call_args.kwargs["action_result"] == "Block sign-in: done"
            processed = {rk for (pk, rk) in events.rows if pk == "events"}
            assert f"response_{key}" in processed and key not in processed
            send.return_value = True
            assert fa._deliver_finding(dict(finding), "", events, processed, None, NOW)
        assert respond.call_count == 1
        assert send.call_args.kwargs["action_result"] == "Block sign-in: done"


# ---------------------------------------------------------------------------
# Alert mailbox change
# ---------------------------------------------------------------------------

class TestMailboxChange:

    def _put(self, changes, version=0):
        import admin_api
        return admin_api.put_settings(_req("PUT", "/api/manage/api/settings",
                                           {"version": version, "changes": changes}, headers=MUTATE))

    def test_conflict_sends_no_test_email(self, ui_on):
        with patch("admin_api.send_mailbox_test", return_value=(True, "")) as test:
            r = self._put({"ADMIN_EMAIL": "new@contoso.com"}, version=5)
        assert r.status_code == 409 and not test.called

    def test_bad_other_value_sends_no_test_email(self, ui_on):
        with patch("admin_api.send_mailbox_test", return_value=(True, "")) as test:
            r = self._put({"ADMIN_EMAIL": "new@contoso.com", "RISK_SCORE_THRESHOLD": "lots"})
        assert r.status_code == 400 and "RISK_SCORE_THRESHOLD" in json.loads(r.get_body())["errors"]
        assert not test.called

    def test_old_mailbox_comes_from_storage(self, ui_on):
        admin_store.save(ui_on["table"], {"ADMIN_EMAIL": "stored@contoso.com"}, 0, "x@contoso.com")
        with patch.object(config, "ADMIN_EMAIL", "stale@contoso.com"), \
                patch("admin_api.send_mailbox_test", return_value=(True, "")), \
                patch("admin_api.send_mailbox_changed_notice", return_value=True) as notice, \
                patch("health_alerts.set_email", return_value="ok") as ag:
            r = self._put({"ADMIN_EMAIL": "new@contoso.com"}, version=1)
        assert r.status_code == 200
        assert notice.call_args.args[:2] == ("stored@contoso.com", "new@contoso.com")
        ag.assert_called_once_with("new@contoso.com", "stored@contoso.com")

    @patch("health_alerts.token_manager")
    def test_action_group_keeps_other_receivers(self, tm):
        import health_alerts
        tm.get_arm_token.return_value = "t"
        group = "/subscriptions/s/resourceGroups/rg/providers/microsoft.insights/actionGroups/ag-x"
        current = {"location": "Global", "properties": {"emailReceivers": [
            {"name": "admin", "emailAddress": "old@contoso.com", "status": "Enabled", "useCommonAlertSchema": True},
            {"name": "soc", "emailAddress": "soc@partner.example", "status": "Enabled", "useCommonAlertSchema": True}]}}
        ok = MagicMock(status_code=200)
        ok.json.return_value = current
        with patch.object(config, "ACTION_GROUP_ID", group), \
                patch("config.http.get", return_value=ok), \
                patch("config.http.request", return_value=MagicMock(status_code=200)) as put:
            health_alerts.set_email("new@contoso.com", "OLD@contoso.com")
        sent = put.call_args.kwargs["json"]["properties"]["emailReceivers"]
        assert [(r["name"], r["emailAddress"]) for r in sent] == [("admin", "new@contoso.com"),
                                                                  ("soc", "soc@partner.example")]
        assert all("status" not in r for r in sent)

    @patch("health_alerts.token_manager")
    def test_action_group_without_the_old_address(self, tm):
        import health_alerts
        tm.get_arm_token.return_value = "t"
        group = "/subscriptions/s/resourceGroups/rg/providers/microsoft.insights/actionGroups/ag-x"
        current = {"location": "Global", "properties": {"emailReceivers": [
            {"name": "soc", "emailAddress": "soc@partner.example", "useCommonAlertSchema": True}]}}
        ok = MagicMock(status_code=200)
        ok.json.return_value = current
        with patch.object(config, "ACTION_GROUP_ID", group), \
                patch("config.http.get", return_value=ok), \
                patch("config.http.request", return_value=MagicMock(status_code=200)) as put:
            health_alerts.set_email("new@contoso.com", "old@contoso.com")
        sent = put.call_args.kwargs["json"]["properties"]["emailReceivers"]
        assert [(r["name"], r["emailAddress"]) for r in sent] == [("soc", "soc@partner.example"),
                                                                  ("admin", "new@contoso.com")]
