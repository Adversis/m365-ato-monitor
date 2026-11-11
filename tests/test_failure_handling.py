"""Tests for the simple failure cases: quota used, email refused, no audit
content, missing subscription, client secret near expiry."""

import logging
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from tests import mock_data
from tests.fakes import FakeTable


def _pc_response(status="ok", ips=()):
    """proxycheck.io batch response for the given IPs."""
    body = {"status": status}
    for ip in ips:
        body[ip] = mock_data.PROXYCHECK_RESPONSES[ip][ip]
    r = MagicMock(status_code=200)
    r.json.return_value = body
    return r


# ---------------------------------------------------------------------------
# proxycheck.io quota used: sign-ins wait in the pending-IP queue
# ---------------------------------------------------------------------------

class TestPendingIpQueue:

    @patch("function_app.send_suspicious_login_alert", return_value=True)
    def test_denied_then_ok_sends_alert_late(self, mock_send):
        from function_app import _run_login_check
        table, cache = FakeTable(), FakeTable()
        vpn = mock_data.EVENT_VPN_LOGIN

        with patch("config.http") as mock_http:
            mock_http.post.return_value = _pc_response("denied")
            _run_login_check(table, cache, set(), [vpn])
        assert mock_send.call_count == 0
        assert vpn["Id"] in table.partition("pendingip")
        assert vpn["Id"] in table.partition("events")  # marked: queued, not lost

        cache.rows.clear()  # negative cache expired
        with patch("config.http") as mock_http:
            mock_http.post.return_value = _pc_response("ok", ["185.220.101.42"])
            # The event left the fetch window: no new events this run.
            _run_login_check(table, cache, set(table.partition("events")), [])

        mock_send.assert_called_once()
        event_arg, ip_arg, _ = mock_send.call_args.args
        assert ip_arg == "185.220.101.42"
        assert event_arg["UserId"] == vpn["UserId"]
        assert table.partition("pendingip") == {}

    def test_old_pending_row_is_abandoned_with_error(self, caplog):
        from function_app import _run_login_check
        from ip_checker import queue_pending_ip
        table, cache = FakeTable(), FakeTable()
        queue_pending_ip("k1", mock_data.EVENT_VPN_LOGIN, "185.220.101.42", table)
        old = (datetime.now(timezone.utc) - timedelta(hours=30)).isoformat()
        table.upsert_entity({"PartitionKey": "pendingip", "RowKey": "k1", "queued_at": old})

        with patch("config.http") as mock_http, caplog.at_level(logging.ERROR):
            mock_http.post.return_value = _pc_response("denied")
            _run_login_check(table, cache, set(), [])

        assert "Sign-in IP check abandoned" in caplog.text
        assert table.partition("pendingip") == {}

    def test_queued_event_not_checked_twice_in_one_run(self):
        from function_app import _run_login_check
        from ip_checker import queue_pending_ip
        table, cache = FakeTable(), FakeTable()
        vpn = mock_data.EVENT_VPN_LOGIN
        queue_pending_ip(vpn["Id"], vpn, "185.220.101.42", table)

        with patch("config.http") as mock_http, \
             patch("function_app.send_suspicious_login_alert", return_value=True) as mock_send:
            mock_http.post.return_value = _pc_response("ok", ["185.220.101.42"])
            _run_login_check(table, cache, set(), [vpn])  # same event in the window too

        mock_send.assert_called_once()


# ---------------------------------------------------------------------------
# Email refused: alerts wait in the outbox
# ---------------------------------------------------------------------------

def _graph(status):
    r = MagicMock(status_code=status)
    r.text = "error"
    return r


FINDING = {"type": "inbox_rule", "severity": "high", "user": "victim@contoso.com",
           "description": "d", "ip": None, "event": {"Id": "x"}}


class TestOutbox:

    @patch("alerting.token_manager")
    def test_refused_email_is_queued_then_sent(self, mock_tm):
        from alerting import send_compromise_alert, flush_outbox
        mock_tm.get_graph_token.return_value = "t"
        table = FakeTable()

        with patch("config.http") as mock_http:
            mock_http.post.return_value = _graph(403)
            assert send_compromise_alert(FINDING, outbox=table) is True  # queued
        assert len(table.partition("outbox")) == 1

        with patch("config.http") as mock_http:
            mock_http.post.return_value = _graph(202)
            flush_outbox(table)
            assert mock_http.post.call_count == 1
        assert table.partition("outbox") == {}

    @patch("alerting.token_manager")
    def test_flush_stops_at_first_failure(self, mock_tm, caplog):
        from alerting import _deliver, flush_outbox
        mock_tm.get_graph_token.return_value = "t"
        table = FakeTable()
        with patch("config.http") as mock_http:
            mock_http.post.return_value = _graph(500)
            _deliver("a", "body a", table)
            _deliver("b", "body b", table)
            mock_http.post.reset_mock()
            with caplog.at_level(logging.ERROR):
                flush_outbox(table)
            assert mock_http.post.call_count == 1
        assert "2 email(s) not delivered" in caplog.text
        assert len(table.partition("outbox")) == 2

    @patch("alerting.token_manager")
    def test_graph_reason_is_kept_and_shown(self, mock_tm):
        """An unlicensed alert mailbox: the UI shows Graph's error code, not only a count."""
        import function_app as fa
        from alerting import _deliver, flush_outbox
        mock_tm.get_graph_token.return_value = "t"
        table = FakeTable()
        refused = _graph(404)
        refused.json.return_value = {"error": {"code": "MailboxNotEnabledForRESTAPI", "message": "inactive"}}
        with patch("config.http") as mock_http:
            mock_http.post.return_value = refused
            _deliver("a", "body a", table)
        row = next(iter(table.partition("outbox").values()))
        assert row["last_error"] == "HTTP 404 MailboxNotEnabledForRESTAPI"

        forbidden = _graph(403)
        forbidden.json.return_value = {"error": {"code": "ErrorAccessDenied"}}
        with patch("config.http") as mock_http:
            mock_http.post.return_value = forbidden
            flush_outbox(table)                          # a later run gets another reason
        with patch("geo_monitor.table_client", return_value=None):
            queues = fa._runtime_state(table, datetime.now(timezone.utc))["queues"]
        assert queues["outbox"] == 1 and queues["outbox_error"] == "HTTP 403 ErrorAccessDenied"

    @patch("alerting.token_manager")
    def test_old_outbox_row_is_dropped_with_error(self, mock_tm, caplog):
        from alerting import flush_outbox
        mock_tm.get_graph_token.return_value = "t"
        table = FakeTable()
        old = (datetime.now(timezone.utc) - timedelta(days=8)).isoformat()
        table.upsert_entity({"PartitionKey": "outbox", "RowKey": "r", "subject": "s",
                             "body": "b", "queued_at": old})
        with patch("config.http") as mock_http, caplog.at_level(logging.ERROR):
            flush_outbox(table)
            mock_http.post.assert_not_called()
        assert "Email dropped after 7 days" in caplog.text
        assert table.partition("outbox") == {}

    @patch("alerting.token_manager")
    def test_no_outbox_returns_false(self, mock_tm):
        from alerting import send_compromise_alert
        mock_tm.get_graph_token.return_value = "t"
        with patch("config.http") as mock_http:
            mock_http.post.return_value = _graph(403)
            assert send_compromise_alert(FINDING) is False

    @patch("alerting.token_manager")
    def test_large_event_json_is_truncated(self, mock_tm):
        from alerting import send_compromise_alert
        mock_tm.get_graph_token.return_value = "t"
        finding = dict(FINDING, event={"Id": "x", "Blob": "A" * 50_000})
        table = FakeTable()
        with patch("config.http") as mock_http:
            mock_http.post.return_value = _graph(403)
            assert send_compromise_alert(finding, outbox=table) is True
        body = next(iter(table.partition("outbox").values()))["body"]
        assert len(body) < 30_000
        assert "truncated" in body


# ---------------------------------------------------------------------------
# No audit content: unified audit logging off
# ---------------------------------------------------------------------------

class TestContentWatchdog:

    def test_no_content_since_first_run_logs_error(self, caplog):
        from function_app import _check_content_flow
        table = FakeTable()
        now = datetime.now(timezone.utc)
        _check_content_flow(table, {"Audit.AzureActiveDirectory": []}, now - timedelta(hours=49))
        with caplog.at_level(logging.ERROR):
            _check_content_flow(table, {"Audit.AzureActiveDirectory": []}, now)
        assert "No audit content for 49 hours" in caplog.text
        assert "UnifiedAuditLogIngestionEnabled" in caplog.text

    def test_content_stops_after_it_was_seen(self, caplog):
        from function_app import _check_content_flow
        table = FakeTable()
        now = datetime.now(timezone.utc)
        _check_content_flow(table, {"Audit.Exchange": [{"Id": "1"}]}, now - timedelta(hours=50))
        with caplog.at_level(logging.ERROR):
            _check_content_flow(table, {"Audit.Exchange": []}, now)
        assert "since the last content" in caplog.text

    def test_recent_content_no_error(self, caplog):
        from function_app import _check_content_flow
        table = FakeTable()
        now = datetime.now(timezone.utc)
        _check_content_flow(table, {"Audit.Exchange": [{"Id": "1"}]}, now - timedelta(hours=2))
        with caplog.at_level(logging.ERROR):
            _check_content_flow(table, {"Audit.Exchange": []}, now)
        assert "No audit content" not in caplog.text

    def test_disabled_with_zero(self, caplog):
        from function_app import _check_content_flow
        table = FakeTable()
        now = datetime.now(timezone.utc)
        with patch("config.NO_CONTENT_ALERT_HOURS", 0):
            _check_content_flow(table, {}, now - timedelta(days=9))
            with caplog.at_level(logging.ERROR):
                _check_content_flow(table, {}, now)
        assert table.rows == {}
        assert "No audit content" not in caplog.text


# ---------------------------------------------------------------------------
# Missing subscription or consent: the error names the cause
# ---------------------------------------------------------------------------

class TestManagementApiErrors:

    @patch("o365_client.token_manager")
    @patch("config.http")
    def test_missing_subscription_hint(self, mock_http, mock_tm):
        from o365_client import fetch_audit_content_urls
        mock_tm.get_o365_token.return_value = "t"
        resp = MagicMock(status_code=400, headers={})
        resp.json.return_value = {"error": {"code": "AF20022",
                                            "message": "No subscription found for the specified content type"}}
        mock_http.get.return_value = resp
        now = datetime.now(timezone.utc)
        with pytest.raises(RuntimeError) as exc:
            fetch_audit_content_urls("Audit.Exchange", now, now)
        assert "AF20022" in str(exc.value)
        assert "starts it on the next run" in str(exc.value)


# ---------------------------------------------------------------------------
# /api/status shows the queues and the content watchdog
# ---------------------------------------------------------------------------

def test_status_shows_queues_and_last_content():
    import json
    from function_app import status_check
    table = FakeTable()
    table.upsert_entity({"PartitionKey": "outbox", "RowKey": "r", "subject": "s", "body": "b",
                         "queued_at": datetime.now(timezone.utc).isoformat()})
    resp = MagicMock(status_code=200)
    resp.json.return_value = {"status": "ok"}
    req = MagicMock()
    req.params = {}
    with patch("o365_client.token_manager"), \
         patch("o365_client.fetch_audit_content_urls", return_value=[]), \
         patch("function_app._get_table_clients", return_value=(table, None)), \
         patch("config.http") as mock_http:
        mock_http.get.return_value = resp
        body = json.loads(status_check(req).get_body())
    assert body["queues"] == {"outbox": 1, "outbox_error": "", "pending_ip_checks": 0, "digest": 0}
    assert set(body["last_content_seen"]) == {"Audit.AzureActiveDirectory", "Audit.Exchange"}
