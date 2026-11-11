"""Mail access counts (MailItemsAccessed, Send): parsing, daily rows, status, report text."""

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import mail_access
from tests.fakes import FakeTable

NOW = datetime(2026, 11, 9, 12, 0, tzinfo=timezone.utc)


def _read(kind="Bind", count=1, ip="203.0.113.7", session="9a1b2c3d-0000-4000-8000-000000000001", app=None,
          throttled=False):
    r = {"Operation": "MailItemsAccessed", "Workload": "Exchange", "RecordType": 50,
         "UserId": "jane@contoso.com", "MailboxOwnerUPN": "jane@contoso.com", "ClientIPAddress": ip,
         "ClientInfoString": "Client=OWA;Action=ViaProxy", "OperationCount": count,
         "OperationProperties": [{"Name": "MailAccessType", "Value": kind},
                                 {"Name": "IsThrottled", "Value": "True" if throttled else "False"}]}
    if session:
        r["SessionId"] = session
    if app:
        r["AppId"] = app
    return r


class TestCount:

    def test_reads_sends_and_fields(self):
        records = [_read("Bind", 3), _read("Sync", session=None, ip=""), _read("Bind", app="00000003-0000-0ff1-ce00-000000000000"),
                   {"Operation": "Send", "ClientIPAddress": "203.0.113.7",
                    "AppAccessContext": {"AADSessionId": "x"}},
                   {"Operation": "New-InboxRule"}, "not a record"]
        c = mail_access.count(records)
        assert c == {"reads": 3, "sync": 1, "bind": 2, "messages": 5, "sends": 1, "with_ip": 3,
                     "with_session": 3, "with_app": 1, "throttled": 0}

    def test_throttled_and_bad_count(self):
        c = mail_access.count([_read(throttled=True, count="x")])
        assert c["throttled"] == 1 and c["messages"] == 1


class TestDailyRows:

    def test_record_adds_to_today_and_summary_totals(self):
        table = FakeTable()
        mail_access.record(table, [_read(), _read("Sync")], NOW)
        mail_access.record(table, [_read(), {"Operation": "Send"}], NOW + timedelta(minutes=2))
        mail_access.record(table, [_read()], NOW - timedelta(days=1))
        row = table.rows[("system", "mailaccess-2026-11-09")]
        assert row["reads"] == 3 and row["sends"] == 1 and row["sync"] == 1
        s = mail_access.summary(table, NOW)
        assert s["totals"]["reads"] == 4 and len(s["per_day"]) == 2 and s["last_seen"].startswith("2026-11-09T12:02")

    def test_no_mail_records_writes_nothing(self):
        table = FakeTable()
        mail_access.record(table, [{"Operation": "New-InboxRule"}], NOW)
        assert table.rows == {}
        assert mail_access.summary(table, NOW)["totals"]["reads"] == 0
        assert mail_access.summary(None, NOW) is None

    def test_old_rows_are_removed(self):
        table = FakeTable()
        mail_access.record(table, [_read()], NOW - timedelta(days=16))
        mail_access.record(table, [_read()], NOW)
        assert ("system", "mailaccess-2026-10-24") not in table.rows
        assert ("system", "mailaccess-2026-11-09") in table.rows


class TestUniqueRecords:
    """Each run fetches an 8-minute window every 2 minutes: a record counts once, on its own day."""

    @staticmethod
    def _rec(rid, when="2026-11-09T11:58:00", **kw):
        return {**_read(**kw), "Id": rid, "CreationTime": when}

    def test_record_fetched_twice_counts_once(self):
        table = FakeTable()
        mail_access.record(table, [self._rec("a")], NOW)
        mail_access.record(table, [self._rec("a"), self._rec("b")], NOW + timedelta(minutes=2))
        mail_access.record(table, [self._rec("a"), self._rec("b")], NOW + timedelta(minutes=4))
        assert table.rows[("system", "mailaccess-2026-11-09")]["reads"] == 2

    def test_counted_on_the_event_date(self):
        table = FakeTable()
        mail_access.record(table, [self._rec("late", when="2026-11-08T23:59:00"), self._rec("now")], NOW)
        assert table.rows[("system", "mailaccess-2026-11-08")]["reads"] == 1
        assert table.rows[("system", "mailaccess-2026-11-09")]["reads"] == 1

    def test_ids_expire(self):
        table = FakeTable()
        mail_access.record(table, [self._rec("a")], NOW)
        later = NOW + timedelta(minutes=mail_access.SEEN_MINUTES + 2)
        mail_access.record(table, [self._rec("b")], later)
        seen = table.rows[("system", "mailaccess-seen")]
        assert [k for k in seen if k.startswith("s")] == [f"s{int(later.timestamp() // 60)}_0"]

    def test_seen_row_failure_counts_nothing_now_and_all_later(self):
        table = FakeTable()
        with patch.object(table, "upsert_entity", side_effect=RuntimeError("storage down")):
            mail_access.record(table, [self._rec("a")], NOW)
        assert ("system", "mailaccess-2026-11-09") not in table.rows
        mail_access.record(table, [self._rec("a")], NOW + timedelta(minutes=2))
        assert table.rows[("system", "mailaccess-2026-11-09")]["reads"] == 1


class TestText:

    def test_describe(self):
        assert "not visible" in mail_access.describe({"days": 7, "totals": dict.fromkeys(mail_access.FIELDS, 0)})
        assert "not known" in mail_access.describe(None)
        t = dict.fromkeys(mail_access.FIELDS, 0)
        t.update(reads=90, sync=10, bind=80, sends=10, with_ip=100, with_session=50, with_app=0, throttled=2)
        text = mail_access.describe({"days": 7, "totals": t})
        assert "90 mail read records (10 sync, 80 bind)" in text and "With session ID: 50%" in text
        assert "Throttled: 2" in text

    def test_weekly_report_has_the_line(self):
        import alerting
        health = {"last_content": NOW - timedelta(hours=1), "queues": {}, "onboarding": None,
                  "mail_access": {"days": 7, "totals": dict.fromkeys(mail_access.FIELDS, 0)}}
        stats = {"runs": 7 * 24 * 30, "total_events": 10, "gaps": 0, "errors": 0}
        with patch("alerting._deliver", return_value=True) as deliver:
            alerting.send_weekly_report(stats, [], health, NOW)
        assert "Mail access logging" in deliver.call_args.args[1]


def test_monitor_run_records_counts():
    import function_app as fa
    table = FakeTable()
    exchange = [_read(), _read("Sync")]
    with patch("function_app._get_table_clients", return_value=(table, FakeTable())), \
            patch("function_app.get_processed_keys", return_value=set()), \
            patch("function_app.ensure_subscriptions"), \
            patch("function_app.fetch_content_records",
                  side_effect=lambda ct, s, e: (exchange if ct == "Audit.Exchange" else [], True)), \
            patch("function_app._check_setup_confirmation"), \
            patch("function_app.onboarding.ensure_started"), \
            patch("function_app.flush_outbox"), \
            patch("function_app._run_login_check"), \
            patch("function_app._run_compromise_check"), \
            patch("function_app._run_session_check"), \
            patch("function_app._maybe_flush_login_digest"):
        fa.audit_log_monitor(None)
    rows = [v for (pk, rk), v in table.rows.items() if rk.startswith("mailaccess-")]
    assert len(rows) == 1 and rows[0]["reads"] == 2 and rows[0]["sync"] == 1
