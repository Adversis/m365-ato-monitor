"""Tests for suspicious-login digest mode (LOGIN_ALERT_MODE=digest)."""

from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock

from tests import mock_data
from tests.test_end_to_end import _mock_batch_post


class TestDigestQueueing:

    @patch("config.LOGIN_ALERT_MODE", "digest")
    @patch("function_app.send_suspicious_login_alert")
    @patch("function_app.queue_login_for_digest")
    @patch("config.http")
    def test_digest_mode_queues_instead_of_emailing(self, mock_http, mock_queue, mock_send):
        from function_app import _run_login_check
        mock_http.post.side_effect = _mock_batch_post
        events_table = MagicMock()
        ip_cache_table = MagicMock()
        ip_cache_table.get_entity.side_effect = Exception("Not found")

        _run_login_check(events_table, ip_cache_table, set(), [mock_data.EVENT_VPN_LOGIN])

        mock_queue.assert_called_once()           # queued for the digest
        mock_send.assert_not_called()             # not emailed immediately
        rows = [c.args[0]["RowKey"] for c in events_table.upsert_entity.call_args_list]
        assert rows.count(mock_data.EVENT_VPN_LOGIN["Id"]) == 1   # marked processed

    @patch("config.LOGIN_ALERT_MODE", "digest")
    @patch("function_app.send_suspicious_login_alert")
    @patch("function_app.queue_login_for_digest")
    @patch("config.http")
    def test_digest_queue_failure_does_not_mark_processed(self, mock_http, mock_queue, mock_send):
        from function_app import _run_login_check
        mock_http.post.side_effect = _mock_batch_post
        mock_queue.side_effect = Exception("table down")
        events_table = MagicMock()
        ip_cache_table = MagicMock()
        ip_cache_table.get_entity.side_effect = Exception("Not found")

        _run_login_check(events_table, ip_cache_table, set(), [mock_data.EVENT_VPN_LOGIN])

        events_table.upsert_entity.assert_not_called()  # retried next run


class TestDigestFlush:

    @patch("config.LOGIN_ALERT_MODE", "digest")
    @patch("config.LOGIN_DIGEST_MINUTES", 60)
    @patch("function_app.send_login_digest")
    @patch("function_app.read_login_digest")
    @patch("function_app.delete_login_digest")
    def test_flush_sends_and_clears_when_oldest_exceeds_window(self, mock_delete, mock_read, mock_send):
        from function_app import _maybe_flush_login_digest
        old = (datetime.now(timezone.utc) - timedelta(minutes=90)).isoformat()
        entries = [{"PartitionKey": "logindigest", "RowKey": "k1", "queued_at": old, "user": "a@b.com"}]
        mock_read.return_value = entries
        mock_send.return_value = True

        table = MagicMock()
        _maybe_flush_login_digest(table)

        mock_send.assert_called_once_with(entries, outbox=table)
        mock_delete.assert_called_once()

    @patch("config.LOGIN_ALERT_MODE", "digest")
    @patch("config.LOGIN_DIGEST_MINUTES", 60)
    @patch("function_app.send_login_digest")
    @patch("function_app.read_login_digest")
    def test_flush_waits_while_window_open(self, mock_read, mock_send):
        from function_app import _maybe_flush_login_digest
        recent = (datetime.now(timezone.utc) - timedelta(minutes=5)).isoformat()
        mock_read.return_value = [{"RowKey": "k1", "queued_at": recent}]

        _maybe_flush_login_digest(MagicMock())

        mock_send.assert_not_called()

    @patch("config.LOGIN_ALERT_MODE", "immediate")
    @patch("function_app.send_login_digest")
    @patch("function_app.read_login_digest")
    def test_immediate_mode_with_empty_queue_sends_nothing(self, mock_read, mock_send):
        from function_app import _maybe_flush_login_digest
        mock_read.return_value = []
        _maybe_flush_login_digest(MagicMock())
        mock_send.assert_not_called()

    @patch("config.LOGIN_ALERT_MODE", "immediate")
    @patch("config.LOGIN_DIGEST_MINUTES", 60)
    @patch("function_app.send_login_digest")
    @patch("function_app.read_login_digest")
    @patch("function_app.delete_login_digest")
    def test_immediate_mode_sends_leftover_queue_now(self, mock_delete, mock_read, mock_send):
        """Regression: rows queued in digest mode must not stay unsent after a
        switch to immediate mode."""
        from function_app import _maybe_flush_login_digest
        recent = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
        entries = [{"PartitionKey": "logindigest", "RowKey": "k1", "queued_at": recent}]
        mock_read.return_value = entries
        mock_send.return_value = True

        table = MagicMock()
        _maybe_flush_login_digest(table)

        mock_send.assert_called_once_with(entries, outbox=table)
        mock_delete.assert_called_once()

    def test_no_table_is_noop(self):
        from function_app import _maybe_flush_login_digest
        _maybe_flush_login_digest(None)  # must not raise

    @patch("config.LOGIN_ALERT_MODE", "digest")
    @patch("config.LOGIN_DIGEST_MINUTES", 60)
    @patch("function_app.send_login_digest")
    @patch("function_app.read_login_digest")
    @patch("function_app.delete_login_digest")
    def test_one_missing_timestamp_does_not_force_premature_flush(self, mock_delete, mock_read, mock_send):
        from function_app import _maybe_flush_login_digest
        recent = (datetime.now(timezone.utc) - timedelta(minutes=2)).isoformat()
        mock_read.return_value = [
            {"RowKey": "k1", "queued_at": recent},
            {"RowKey": "k2"},  # no queued_at — must not drag the batch into a flush
        ]
        _maybe_flush_login_digest(MagicMock())
        mock_send.assert_not_called()

    @patch("config.LOGIN_ALERT_MODE", "digest")
    @patch("config.LOGIN_DIGEST_MINUTES", 60)
    @patch("function_app.send_login_digest")
    @patch("function_app.read_login_digest")
    @patch("function_app.delete_login_digest")
    def test_naive_timestamp_does_not_raise(self, mock_delete, mock_read, mock_send):
        from function_app import _maybe_flush_login_digest
        mock_read.return_value = [{"RowKey": "k1", "queued_at": "2020-01-01T00:00:00"}]  # naive, ancient
        mock_send.return_value = True
        _maybe_flush_login_digest(MagicMock())   # must not raise (TypeError on subtract)
        mock_send.assert_called_once()

    @patch("config.LOGIN_ALERT_MODE", "digest")
    @patch("config.LOGIN_DIGEST_MINUTES", 60)
    @patch("function_app.send_login_digest")
    @patch("function_app.read_login_digest")
    @patch("function_app.delete_login_digest")
    def test_all_unparseable_rows_flush_to_avoid_wedge(self, mock_delete, mock_read, mock_send):
        from function_app import _maybe_flush_login_digest
        mock_read.return_value = [{"RowKey": "k1", "queued_at": ""}, {"RowKey": "k2", "queued_at": "garbage"}]
        mock_send.return_value = True
        _maybe_flush_login_digest(MagicMock())
        mock_send.assert_called_once()  # nothing parseable -> flush so the queue can't wedge

    @patch("config.LOGIN_ALERT_MODE", "digest")
    @patch("config.LOGIN_DIGEST_MINUTES", 60)
    @patch("function_app.send_login_digest")
    @patch("function_app.read_login_digest")
    def test_flush_is_exception_safe(self, mock_read, mock_send):
        from function_app import _maybe_flush_login_digest
        mock_read.return_value = [{"RowKey": "k1", "queued_at": "2020-01-01T00:00:00"}]
        mock_send.side_effect = Exception("graph down")
        _maybe_flush_login_digest(MagicMock())   # swallows — must not abort the monitor run
