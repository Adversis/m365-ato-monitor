"""Tests for the per-content-type fetch, the fetch checkpoint, and the setup email."""

import logging
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest
from tests import mock_data
from tests.fakes import FakeTable

AAD = "Audit.AzureActiveDirectory"
EXCH = "Audit.Exchange"


def _fetch_by_type(results):
    """side_effect for fetch_content_records: results[content_type] is a tuple or an exception."""
    def _fetch(content_type, start, end):
        r = results[content_type]
        if isinstance(r, Exception):
            raise r
        return r
    return _fetch


@pytest.fixture
def table():
    return FakeTable()


@pytest.fixture
def monitor(table):
    """Patch the monitor's dependencies. Yields the mocks."""
    with patch("function_app._get_table_clients", return_value=(table, None)), \
         patch("function_app.fetch_content_records") as fetch, \
         patch("function_app.send_setup_confirmation", return_value=True) as setup, \
         patch("function_app._run_login_check") as login, \
         patch("function_app._run_compromise_check") as compromise:
        yield {"fetch": fetch, "setup": setup, "login": login, "compromise": compromise}


class TestPerTypeFetch:

    def test_exchange_failure_does_not_stop_login_check(self, monitor, table):
        from function_app import audit_log_monitor
        login = mock_data.EVENT_VPN_LOGIN
        monitor["fetch"].side_effect = _fetch_by_type({
            AAD: ([login], True),
            EXCH: RuntimeError("Listing Audit.Exchange content failed: HTTP 400"),
        })

        audit_log_monitor(None)

        assert monitor["login"].call_args.args[3] == [login]
        assert monitor["compromise"].call_args.args[3] == [login]
        assert table.checkpoint(AAD) is not None
        assert table.checkpoint(EXCH) == monitor["fetch"].call_args_list[1].args[1]

    def test_incomplete_fetch_does_not_move_checkpoint(self, monitor, table):
        from function_app import audit_log_monitor
        monitor["fetch"].side_effect = _fetch_by_type({AAD: ([], False), EXCH: ([], True)})

        audit_log_monitor(None)

        assert table.checkpoint(AAD) == monitor["fetch"].call_args_list[0].args[1]
        assert table.checkpoint(EXCH) is not None

    def test_processing_error_does_not_move_checkpoint(self, monitor, table):
        from function_app import audit_log_monitor
        monitor["fetch"].side_effect = _fetch_by_type({AAD: ([], True), EXCH: ([], True)})
        monitor["login"].side_effect = RuntimeError("bug")

        audit_log_monitor(None)

        monitor["compromise"].assert_called_once()  # still runs
        assert table.checkpoint(AAD) == monitor["fetch"].call_args_list[0].args[1]
        assert table.checkpoint(EXCH) == monitor["fetch"].call_args_list[1].args[1]

    def test_completion_trace_only_after_a_fetch(self, monitor, caplog):
        """The install.ps1 health alert fires when this trace is absent for 1 hour. Keep the text."""
        from function_app import audit_log_monitor
        monitor["fetch"].side_effect = _fetch_by_type({AAD: RuntimeError("x"), EXCH: RuntimeError("y")})
        with caplog.at_level(logging.INFO):
            audit_log_monitor(None)
        assert "audit_log_monitor run completed" not in caplog.text

        caplog.clear()
        monitor["fetch"].side_effect = _fetch_by_type({AAD: ([], True), EXCH: ([], True)})
        with caplog.at_level(logging.INFO):
            audit_log_monitor(None)
        assert "audit_log_monitor run completed" in caplog.text

    def test_all_fetches_fail_sends_no_setup_email(self, monitor):
        from function_app import audit_log_monitor
        monitor["fetch"].side_effect = _fetch_by_type({AAD: RuntimeError("x"), EXCH: RuntimeError("y")})

        audit_log_monitor(None)

        monitor["setup"].assert_not_called()
        monitor["login"].assert_not_called()


class TestFetchWindow:

    def test_no_checkpoint_uses_lookback(self, table):
        from function_app import _fetch_window
        from config import LOOKBACK_MINUTES
        now = datetime.now(timezone.utc)
        start, end = _fetch_window(table, AAD, now)
        assert end == now
        assert start == now - timedelta(minutes=LOOKBACK_MINUTES)

    def test_recent_checkpoint_uses_lookback(self, table):
        from function_app import _fetch_window, _write_checkpoint
        from config import LOOKBACK_MINUTES
        now = datetime.now(timezone.utc)
        _write_checkpoint(table, AAD, now - timedelta(minutes=2))
        start, _ = _fetch_window(table, AAD, now)
        assert start == now - timedelta(minutes=LOOKBACK_MINUTES)

    def test_old_checkpoint_catches_up(self, table):
        from function_app import _fetch_window, _write_checkpoint
        now = datetime.now(timezone.utc)
        checkpoint = now - timedelta(minutes=30)
        _write_checkpoint(table, AAD, checkpoint)
        start, _ = _fetch_window(table, AAD, now)
        assert start == checkpoint

    def test_gap_beyond_catchup_is_logged_and_clamped(self, table, caplog):
        from function_app import _fetch_window, _write_checkpoint
        from config import MAX_CATCHUP_MINUTES
        now = datetime.now(timezone.utc)
        _write_checkpoint(table, AAD, now - timedelta(hours=5))

        with caplog.at_level(logging.ERROR):
            start, _ = _fetch_window(table, AAD, now)

        floor = now - timedelta(minutes=MAX_CATCHUP_MINUTES)
        assert start == floor
        assert "Coverage gap" in caplog.text
        # The gap is reported one time: the checkpoint moves to the limit.
        assert table.checkpoint(AAD) == floor

    def test_unreadable_checkpoint_uses_lookback(self):
        from function_app import _fetch_window
        from config import LOOKBACK_MINUTES
        broken = MagicMock()
        broken.get_entity.side_effect = RuntimeError("storage down")
        now = datetime.now(timezone.utc)
        start, _ = _fetch_window(broken, AAD, now)
        assert start == now - timedelta(minutes=LOOKBACK_MINUTES)


class TestSetupConfirmation:

    @patch("function_app.send_setup_confirmation", return_value=False)
    def test_not_marked_when_send_fails(self, mock_send, table):
        from function_app import _check_setup_confirmation
        _check_setup_confirmation(table)
        mock_send.assert_called_once()
        assert ("system", "setup_confirmed") not in table.rows

    @patch("function_app.send_setup_confirmation", return_value=True)
    def test_marked_once_when_sent(self, mock_send, table):
        from function_app import _check_setup_confirmation
        _check_setup_confirmation(table)
        _check_setup_confirmation(table)
        mock_send.assert_called_once()
        assert ("system", "setup_confirmed") in table.rows

    @patch("function_app.send_setup_confirmation", return_value=True)
    def test_storage_error_does_not_send(self, mock_send):
        from function_app import _check_setup_confirmation
        broken = MagicMock()
        broken.get_entity.side_effect = RuntimeError("timeout")
        _check_setup_confirmation(broken)
        mock_send.assert_not_called()


class TestFetchContentRecords:

    @patch("o365_client.fetch_audit_events")
    @patch("o365_client.fetch_audit_content_urls")
    def test_blob_failure_returns_partial_and_incomplete(self, mock_urls, mock_events):
        from o365_client import fetch_content_records
        mock_urls.return_value = ["https://manage.office.com/a", "https://manage.office.com/b"]
        mock_events.side_effect = [[mock_data.EVENT_NORMAL_LOGIN], RuntimeError("HTTP 500")]
        now = datetime.now(timezone.utc)

        records, complete = fetch_content_records(AAD, now - timedelta(minutes=8), now)

        assert records == [mock_data.EVENT_NORMAL_LOGIN]
        assert complete is False

    @patch("o365_client.fetch_audit_content_urls")
    def test_listing_failure_raises(self, mock_urls):
        from o365_client import fetch_content_records
        mock_urls.side_effect = RuntimeError("HTTP 400")
        now = datetime.now(timezone.utc)
        with pytest.raises(RuntimeError):
            fetch_content_records(EXCH, now, now)

    @patch("o365_client.token_manager")
    @patch("config.http")
    def test_blob_non_200_raises(self, mock_http, mock_tm):
        from o365_client import fetch_audit_events
        mock_tm.get_o365_token.return_value = "t"
        mock_http.get.return_value = MagicMock(status_code=500)
        with pytest.raises(RuntimeError):
            fetch_audit_events("https://manage.office.com/api/v1.0/t/activity/feed/audit/x")

    def test_blob_non_microsoft_url_raises(self):
        from o365_client import fetch_audit_events
        with pytest.raises(RuntimeError):
            fetch_audit_events("https://evil.example/manage.office.com")


class TestTokenErrors:

    @patch("config.http")
    def test_token_error_names_aadsts_code_not_secret(self, mock_http):
        from o365_client import TokenManager
        resp = MagicMock(status_code=401)
        resp.json.return_value = {"error": "invalid_client", "error_codes": [7000222],
                                  "error_description": "AADSTS7000222: secret expired"}
        mock_http.post.return_value = resp

        with pytest.raises(RuntimeError) as exc:
            TokenManager().get_o365_token()

        assert "7000222" in str(exc.value)
        assert "invalid_client" in str(exc.value)
        assert "test-client-secret" not in str(exc.value)


class TestLoginResult:

    def test_success_and_failure(self):
        from o365_client import login_result
        assert login_result({"Operation": "UserLoggedIn"}) == "Success"
        assert login_result({"Operation": "UserLoginFailed", "ErrorNumber": "50126"}) == "Failed (50126)"
        assert login_result({}) == "Unknown"


class TestFullRunThroughHttp:
    """Two monitor runs. Only the HTTP layer and Table Storage are fakes."""

    INBOX_RULE = {
        "Id": "ex-1", "RecordType": 1, "Operation": "New-InboxRule",
        "UserId": "victim@contoso.com", "ClientIP": "10.0.0.9",
        "Parameters": [{"Name": "Name", "Value": "r"}, {"Name": "ForwardTo", "Value": "drop@evil.com"}],
    }
    FORWARDING = {
        "Id": "ex-2", "RecordType": 1, "Operation": "Set-Mailbox",
        "UserId": "victim@contoso.com", "ClientIP": "10.0.0.9",
        "Parameters": [{"Name": "ForwardingSmtpAddress", "Value": "smtp:drop@evil.com"}],
    }

    def _http(self, sent, graph_status=202, proxycheck_status="ok"):
        aad_blob = "https://manage.office.com/api/v1.0/t/activity/feed/audit/aad"
        exch_blob = "https://manage.office.com/api/v1.0/t/activity/feed/audit/exch"

        def get(url, params=None, **kwargs):
            r = MagicMock(status_code=200, headers={})
            if url.endswith("/subscriptions/content"):
                blob = aad_blob if params["contentType"] == AAD else exch_blob
                r.json.return_value = [{"contentUri": blob}]
            elif url == aad_blob:
                r.json.return_value = [mock_data.EVENT_VPN_LOGIN, mock_data.EVENT_NORMAL_LOGIN]
            elif url == exch_blob:
                r.json.return_value = [self.INBOX_RULE, self.FORWARDING]
            else:
                r.status_code = 404
            return r

        def post(url, data=None, json=None, **kwargs):
            r = MagicMock(status_code=200)
            if "login.microsoftonline.com" in url:
                r.json.return_value = {"access_token": "tok", "expires_in": 3600}
            elif "proxycheck.io" in url:
                body = {"status": proxycheck_status}
                for ip in (data["ips"].split(",") if proxycheck_status == "ok" else []):
                    body[ip] = mock_data.PROXYCHECK_RESPONSES.get(ip, {}).get(ip) or \
                        {"proxy": "no", "type": "Business", "risk": 0}
                r.json.return_value = body
            elif "graph.microsoft.com" in url:
                r.status_code = graph_status
                r.text = "error"
                if graph_status == 202:
                    sent.append(json["message"]["subject"])
            return r

        http = MagicMock()
        http.get.side_effect = get
        http.post.side_effect = post
        return http

    def test_alerts_once_across_overlapping_runs(self):
        from function_app import audit_log_monitor
        table, cache = FakeTable(), FakeTable()
        sent = []
        with patch("function_app._get_table_clients", return_value=(table, cache)), \
             patch("geo_monitor.table_client", return_value=FakeTable()), \
             patch("config.http", self._http(sent)):
            audit_log_monitor(None)
            first = list(sent)
            audit_log_monitor(None)  # same content again: the windows overlap

        assert any(s.startswith("[M365 Monitor] Setup complete") for s in first)
        assert any("Suspicious sign-in" in s and "jane.smith@contoso.com" in s for s in first)
        assert any("HIGH: Inbox rule" in s for s in first)
        assert any("HIGH: Mailbox forwarding" in s for s in first)
        assert len(first) == 4
        assert sent == first  # second run: no new email
        assert table.checkpoint(AAD) is not None and table.checkpoint(EXCH) is not None

    def test_mail_refused_and_quota_used_then_recovered(self):
        """Run 1: Graph refuses mail, proxycheck.io quota is used. Run 2: both work.
        Each alert must arrive exactly one time."""
        from function_app import audit_log_monitor
        table, cache = FakeTable(), FakeTable()
        sent = []
        with patch("function_app._get_table_clients", return_value=(table, cache)), \
             patch("geo_monitor.table_client", return_value=FakeTable()):
            with patch("config.http", self._http(sent, graph_status=403, proxycheck_status="denied")):
                audit_log_monitor(None)
            assert sent == []
            assert len(table.partition("outbox")) == 2      # inbox rule, mailbox forwarding
            assert len(table.partition("pendingip")) == 2   # both sign-ins (8.8.8.8 and the VPN IP)

            cache.rows.clear()  # the 5-minute failure cache expired
            with patch("config.http", self._http(sent)):
                audit_log_monitor(None)

        kinds = sorted(s.split(": ")[1].split(" - ")[0] for s in sent)
        assert kinds == ["Inbox rule", "Mailbox forwarding", "Suspicious sign-in", "the monitor is active"]
        assert len(sent) == len(set(sent)) == 4
        assert table.partition("outbox") == {}
        assert table.partition("pendingip") == {}
