"""proxycheck.io quota: level from each answer, usage count, warning email once per day."""

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

import config
import proxycheck_quota as pq
from tests.fakes import FakeTable

NOW = datetime(2026, 11, 9, 15, 0, tzinfo=timezone.utc)
LOW_MSG = "You are within 10% of your query limit for the day."
FREE_OUT = "1,000 Free queries exhausted. Please try the API again tomorrow or purchase a higher paid plan."
NO_KEY_OUT = "100 queries exhausted, if you sign up for a free API key you'll be able to make 1,000 free queries per day."


@pytest.fixture(autouse=True)
def clean():
    pq.reset()
    with patch.object(config, "PROXYCHECK_API_KEY", ""):
        yield
    pq.reset()


def _usage(used, limit=1000, status=200):
    r = MagicMock(status_code=status)
    r.json.return_value = {"Burst Tokens Available": 1, "Queries Today": str(used), "Daily Limit": str(limit),
                           "Queries Total": "98523", "Plan Tier": "Free"}
    return r


class TestClassify:

    @pytest.mark.parametrize("status,msg,level", [
        ("ok", "", "ok"),
        ("warning", LOW_MSG, "low"),
        ("warning", "You have gone over your daily query allowance and a burst token has been consumed.", "low"),
        ("denied", FREE_OUT, "exhausted"),
        ("denied", NO_KEY_OUT, "exhausted"),
        ("denied", "Your access to the API has been blocked due to using a proxy server.", "refused"),
        ("warning", "You're sending more than 175 requests per second.", None),
        ("denied", "You're sending more than 200 requests per second.", None),
        ("error", "No valid IP addresses supplied.", None),
    ])
    def test_levels(self, status, msg, level):
        assert pq.classify(status, msg) == level


class TestNote:

    def test_writes_on_change_only(self):
        table = MagicMock()
        pq.note(table, "ok", "", NOW)
        pq.note(table, "ok", "", NOW)
        assert table.upsert_entity.call_count == 1
        pq.note(table, "warning", LOW_MSG, NOW)
        assert table.upsert_entity.call_count == 2
        pq.note(table, "warning", LOW_MSG, NOW + timedelta(days=1))   # a new day
        assert table.upsert_entity.call_count == 3

    def test_the_key_is_not_kept(self):
        table = FakeTable()
        with patch.object(config, "PROXYCHECK_API_KEY", "abc123-secret"):
            pq.note(table, "denied", "Key abc123-secret has been disabled. Queries exhausted.", NOW)
        assert "abc123-secret" not in str(table.rows)

    def test_from_a_lookup_answer(self):
        import ip_checker
        table = FakeTable()
        resp = MagicMock(status_code=200)
        resp.json.return_value = {"status": "warning", "message": LOW_MSG,
                                  "203.0.113.9": {"proxy": "no", "type": "Business", "risk": 0}}
        with patch("config.http") as http:
            http.post.return_value = resp
            out = ip_checker._proxycheck_batch(["203.0.113.9"], table)
        assert "203.0.113.9" in out
        assert pq.status(table)["level"] == "low"

    def test_denied_with_an_http_error(self):
        import ip_checker
        table = FakeTable()
        resp = MagicMock(status_code=429)
        resp.json.return_value = {"status": "denied", "message": FREE_OUT}
        with patch("config.http") as http:
            http.post.return_value = resp
            assert ip_checker._proxycheck_batch(["203.0.113.9"], table) == {}
        assert pq.status(table)["level"] == "exhausted"


class TestStatus:

    def test_a_level_from_an_earlier_day_is_unknown(self):
        table = FakeTable()
        pq.note(table, "denied", FREE_OUT, NOW - timedelta(days=1))
        assert pq.status(table, NOW)["level"] == "unknown"
        assert pq.status(table, NOW - timedelta(days=1))["level"] == "exhausted"

    def test_old_message_is_not_shown_with_a_new_count(self):
        table = FakeTable()
        pq.note(table, "denied", FREE_OUT, NOW - timedelta(days=1))
        with patch.object(config, "PROXYCHECK_API_KEY", "k"), patch("config.http") as http:
            http.get.return_value = _usage(850)
            pq.refresh_usage(table, NOW)
            s = pq.status(table, NOW)
        assert s["level"] == "low" and s["message"] == ""

    def test_without_a_key_the_limit_is_100(self):
        s = pq.status(FakeTable(), NOW)
        assert s["limit"] == 100 and s["used"] is None and s["key"] is False

    def test_usage_count_sets_the_level(self):
        table = FakeTable()
        pq.note(table, "ok", "", NOW)
        with patch.object(config, "PROXYCHECK_API_KEY", "k"), patch("config.http") as http:
            http.get.return_value = _usage(850)
            pq.refresh_usage(table, NOW)
            s = pq.status(table, NOW)
        assert (s["level"], s["used"], s["limit"], s["plan"]) == ("low", 850, 1000, "Free")


class TestUsage:

    def test_no_key_no_call(self):
        with patch("config.http") as http:
            pq.refresh_usage(FakeTable(), NOW)
            http.get.assert_not_called()

    def test_read_at_most_every_30_minutes(self):
        table = FakeTable()
        with patch.object(config, "PROXYCHECK_API_KEY", "k"), patch("config.http") as http:
            http.get.return_value = _usage(10)
            pq.refresh_usage(table, NOW)
            pq.refresh_usage(table, NOW + timedelta(minutes=10))
            assert http.get.call_count == 1
            pq.refresh_usage(table, NOW + timedelta(minutes=31))
            assert http.get.call_count == 2
            assert http.get.call_args.args[0] == pq.USAGE_URL
            assert http.get.call_args.kwargs["params"] == {"key": "k"}

    def test_dashboard_api_off(self):
        table = FakeTable()
        r = MagicMock(status_code=200)
        r.json.return_value = {"status": "denied", "message": "Dashboard API access is not enabled."}
        with patch.object(config, "PROXYCHECK_API_KEY", "k"), patch("config.http") as http:
            http.get.return_value = r
            pq.refresh_usage(table, NOW)
            s = pq.status(table, NOW)
        assert s["used"] is None and "not enabled" in s["usage_error"]


class TestWarning:

    def test_one_email_per_level_per_day(self):
        table = FakeTable()
        with patch("alerting.send_quota_warning", return_value=True) as send:
            pq.note(table, "warning", LOW_MSG, NOW)
            assert pq.check(table, NOW) == "low"
            assert pq.check(table, NOW + timedelta(minutes=2)) is None
            pq.note(table, "denied", FREE_OUT, NOW + timedelta(hours=1))
            assert pq.check(table, NOW + timedelta(hours=1)) == "exhausted"
            assert pq.check(table, NOW + timedelta(hours=2)) is None
            pq.note(table, "denied", FREE_OUT, NOW + timedelta(days=1))
            assert pq.check(table, NOW + timedelta(days=1)) == "exhausted"
        assert send.call_count == 3

    def test_ok_sends_nothing(self):
        table = FakeTable()
        pq.note(table, "ok", "", NOW)
        with patch("alerting.send_quota_warning") as send:
            assert pq.check(table, NOW) is None
            send.assert_not_called()

    def test_failed_email_is_tried_again(self):
        table = FakeTable()
        pq.note(table, "denied", FREE_OUT, NOW)
        with patch("alerting.send_quota_warning", return_value=False):
            assert pq.check(table, NOW) is None
        with patch("alerting.send_quota_warning", return_value=True):
            assert pq.check(table, NOW) == "exhausted"

    def test_failed_state_write_does_not_repeat_the_email(self):
        table = FakeTable()
        pq.note(table, "denied", FREE_OUT, NOW)
        with patch("alerting.send_quota_warning", return_value=True) as send, \
                patch("proxycheck_quota._save"):                    # the "warned" write fails
            pq.check(table, NOW)
            pq.check(table, NOW + timedelta(minutes=2))
        assert send.call_count == 1

    def test_no_table_no_email(self):
        with patch("alerting.send_quota_warning") as send:
            assert pq.check(None, NOW) is None
            send.assert_not_called()

    def test_email_text(self):
        import alerting
        state = {"level": "exhausted", "message": NO_KEY_OUT, "key": False, "used": None, "limit": 100}
        with patch("alerting._deliver", return_value=True) as deliver:
            assert alerting.send_quota_warning(state)
        subject, body = deliver.call_args.args[0], deliver.call_args.args[1]
        assert subject.startswith(alerting.INFO_TAG) and "used up" in subject
        assert "Get a free proxycheck.io API key" in body
        assert "for up to 26 hours" in body and "are lost" in body

    def test_weekly_report_names_the_problem(self):
        import alerting
        health = {"last_content": NOW, "queues": {}, "ip_lookups": {"level": "exhausted", "used": 1000,
                                                                     "limit": 1000, "plan": "Free"}}
        with patch("alerting._deliver", return_value=True) as deliver:
            alerting.send_weekly_report(None, [], health, NOW)
        assert "proxycheck.io quota is used up: 1,000 of 1,000 queries used today (Free plan)." \
            in deliver.call_args.args[1]
