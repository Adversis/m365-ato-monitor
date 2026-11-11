"""End-to-end tests for the login check and compromise detection pipelines.

Login check: each suspicious sign-in is logged and emailed (or queued for the digest).
Compromise check: each new finding is emailed.

audit_log_monitor fetches each content type one time per run and passes the
records to _run_login_check and _run_compromise_check. These tests pass event
lists to those functions directly. tests/test_fetch_pipeline.py tests the fetch.
"""

from unittest.mock import patch, MagicMock
from tests import mock_data


def _mock_batch_post(url, data=None, timeout=None, **kwargs):
    """Mock the outbound POSTs a login-check run makes: proxycheck batch, Graph
    token acquisition, and Graph sendMail (suspicious logins now email).

    proxycheck mirrors the real contract — addresses arrive in the POST form
    field "ips" (comma-separated); a wrong shape returns an error.
    """
    resp = MagicMock()

    if "login.microsoftonline.com" in url:  # OAuth token endpoint
        resp.status_code = 200
        resp.json.return_value = {"access_token": "fake-token", "expires_in": 3600}
        return resp

    if "graph.microsoft.com" in url:  # sendMail -> 202 Accepted on success
        resp.status_code = 202
        return resp

    if "proxycheck.io" in url:
        ips_field = data.get("ips") if isinstance(data, dict) else None
        if ips_field:
            ips = [ip.strip() for ip in ips_field.split(",") if ip.strip()]
            result = {"status": "ok"}
            for ip in ips:
                if ip in mock_data.PROXYCHECK_RESPONSES:
                    result[ip] = mock_data.PROXYCHECK_RESPONSES[ip][ip]
                else:
                    result[ip] = {"proxy": "no", "type": "Residential", "risk": 0}
            resp.status_code = 200
            resp.json.return_value = result
            return resp

    resp.status_code = 404
    resp.json.return_value = {}
    return resp


# Exchange inbox-rule record (RecordType 1) forwarding externally. Private
# ClientIP keeps it out of the proxycheck batch so no HTTP mock is needed.
INBOX_RULE_EVENT = {
    "Id": "ir-evt-1",
    "RecordType": 1,
    "CreationTime": "2024-01-15T12:00:00",
    "Operation": "New-InboxRule",
    "UserId": "victim@contoso.com",
    "ClientIP": "10.0.0.9",
    "Parameters": [
        {"Name": "Name", "Value": "exfil"},
        {"Name": "ForwardTo", "Value": "attacker@evil.com"},
    ],
}


class TestLoginCheck:

    @patch("config.http")
    def test_suspicious_login_logged(self, mock_http, caplog):
        """Suspicious logins are logged to App Insights."""
        import logging
        from function_app import _run_login_check
        mock_http.post.side_effect = _mock_batch_post

        with caplog.at_level(logging.WARNING):
            _run_login_check(None, None, set(), [mock_data.EVENT_VPN_LOGIN])

        assert "Suspicious login" in caplog.text
        assert "jane.smith@contoso.com" in caplog.text
        assert "185.220.101.42" in caplog.text

    @patch("config.http")
    @patch("function_app.send_suspicious_login_alert")
    def test_suspicious_login_emails(self, mock_alert, mock_http):
        """Every suspicious login now also sends an alert email."""
        from function_app import _run_login_check
        mock_http.post.side_effect = _mock_batch_post
        mock_alert.return_value = True

        _run_login_check(None, None, set(), [mock_data.EVENT_VPN_LOGIN])

        mock_alert.assert_called_once()
        _event, ip_arg, analysis_arg = mock_alert.call_args.args
        assert ip_arg == "185.220.101.42"
        assert analysis_arg["is_suspicious"] is True

    @patch("config.http")
    @patch("function_app.send_suspicious_login_alert")
    def test_clean_login_not_emailed(self, mock_alert, mock_http):
        """A non-suspicious login does not email."""
        from function_app import _run_login_check
        mock_http.post.side_effect = _mock_batch_post

        _run_login_check(None, None, set(), [mock_data.EVENT_NORMAL_LOGIN])

        mock_alert.assert_not_called()

    @patch("config.http")
    @patch("function_app.send_suspicious_login_alert")
    def test_failed_login_email_not_marked_processed(self, mock_alert, mock_http):
        """If the alert email fails, the event is not marked — it retries next run."""
        from function_app import _run_login_check
        mock_http.post.side_effect = _mock_batch_post
        mock_alert.return_value = False  # sendMail failed

        events_table = MagicMock()
        ip_cache_table = MagicMock()
        ip_cache_table.get_entity.side_effect = Exception("Not found")

        _run_login_check(events_table, ip_cache_table, set(), [mock_data.EVENT_VPN_LOGIN])

        events_table.upsert_entity.assert_not_called()

    @patch("config.http")
    def test_clean_login_no_warning(self, mock_http, caplog):
        import logging
        from function_app import _run_login_check
        mock_http.post.side_effect = _mock_batch_post

        with caplog.at_level(logging.WARNING):
            _run_login_check(None, None, set(), [mock_data.EVENT_NORMAL_LOGIN])

        assert "Suspicious login" not in caplog.text

    @patch("config.http")
    def test_private_ip_skipped(self, mock_http):
        from function_app import _run_login_check

        _run_login_check(None, None, set(), [mock_data.EVENT_PRIVATE_IP_LOGIN])
        mock_http.post.assert_not_called()

    @patch("config.http")
    def test_no_events(self, mock_http, caplog):
        import logging
        from function_app import _run_login_check

        with caplog.at_level(logging.INFO):
            _run_login_check(None, None, set(), [])

        assert "No login events found" in caplog.text

    @patch("config.http")
    def test_ipv4_with_port_cleaned(self, mock_http, caplog):
        import logging
        from function_app import _run_login_check
        mock_http.post.side_effect = _mock_batch_post

        with caplog.at_level(logging.WARNING):
            _run_login_check(None, None, set(), [mock_data.EVENT_VPN_LOGIN])

        assert "185.220.101.42" in caplog.text

    @patch("config.http")
    def test_batch_api_called_once(self, mock_http):
        from function_app import _run_login_check
        mock_http.post.side_effect = _mock_batch_post
        events = [
            mock_data.EVENT_VPN_LOGIN,
            mock_data.EVENT_TOR_LOGIN,
            mock_data.EVENT_NORMAL_LOGIN,
        ]

        _run_login_check(None, None, set(), events)

        # Filter on the request URL (arg 0), not str(c) — the alert email body now
        # mentions proxycheck.io, which would otherwise match the sendMail calls.
        proxycheck_calls = [
            c for c in mock_http.post.call_args_list if c.args and "proxycheck.io" in c.args[0]
        ]
        assert len(proxycheck_calls) == 1

    @patch("config.http")
    def test_proxycheck_request_uses_ips_form_field(self, mock_http):
        """Regression: the batch POST must send data={'ips': 'a,b'} — a raw body
        makes proxycheck return 'No valid IP Addresses supplied.'"""
        from function_app import _run_login_check
        mock_http.post.side_effect = _mock_batch_post

        _run_login_check(None, None, set(), [mock_data.EVENT_VPN_LOGIN])

        proxycheck_call = next(
            c for c in mock_http.post.call_args_list if c.args and "proxycheck.io" in c.args[0]
        )
        assert proxycheck_call.kwargs["data"] == {"ips": "185.220.101.42"}

    @patch("config.http")
    def test_suspicious_marked_processed(self, mock_http):
        """A suspicious login is marked processed after its email is sent."""
        from function_app import _run_login_check

        events_table = MagicMock()
        ip_cache_table = MagicMock()
        ip_cache_table.get_entity.side_effect = Exception("Not found")
        mock_http.post.side_effect = _mock_batch_post

        _run_login_check(events_table, ip_cache_table, set(), [mock_data.EVENT_VPN_LOGIN])

        rows = [c.args[0]["RowKey"] for c in events_table.upsert_entity.call_args_list]
        assert rows.count(mock_data.EVENT_VPN_LOGIN["Id"]) == 1          # the sign-in is marked processed
        assert sum(r.startswith("signinalert-") for r in rows) == 1       # one alert for this user, IP, and day

    @patch("config.TENANT_ID", None)
    def test_missing_env_vars_aborts(self, caplog):
        import logging
        from function_app import audit_log_monitor

        with caplog.at_level(logging.ERROR):
            audit_log_monitor(None)

        assert "Missing required environment variables" in caplog.text


class TestDedup:

    @patch("config.http")
    def test_dedup_skips_processed(self, mock_http, caplog):
        import logging
        from function_app import _run_login_check

        mock_http.post.side_effect = _mock_batch_post
        already_processed = {mock_data.EVENT_VPN_LOGIN["Id"]}
        events = [mock_data.EVENT_VPN_LOGIN, mock_data.EVENT_TOR_LOGIN]

        with caplog.at_level(logging.WARNING):
            _run_login_check(None, None, already_processed, events)

        # VPN was already processed, only TOR should log
        assert "bob.wilson@contoso.com" in caplog.text
        assert "jane.smith@contoso.com" not in caplog.text


class TestResilienceOnFailure:

    @patch("config.http")
    def test_proxycheck_failure_queues_sign_in_for_later_check(self, mock_http):
        """A failed lookup must not lose the sign-in when it leaves the fetch window."""
        from function_app import _run_login_check

        events_table = MagicMock()
        events_table.query_entities.return_value = []
        ip_cache_table = MagicMock()
        ip_cache_table.get_entity.side_effect = Exception("Not found")
        mock_http.post.return_value = MagicMock(status_code=500)

        _run_login_check(events_table, ip_cache_table, set(), [mock_data.EVENT_VPN_LOGIN])

        partitions = [c.args[0]["PartitionKey"] for c in events_table.upsert_entity.call_args_list]
        assert partitions == ["pendingip", "events"]

    @patch("config.http")
    def test_proxycheck_failure_without_storage_marks_nothing(self, mock_http):
        from function_app import _run_login_check
        mock_http.post.return_value = MagicMock(status_code=500)
        _run_login_check(None, None, set(), [mock_data.EVENT_VPN_LOGIN])  # must not raise

    @patch("config.http")
    def test_skipped_count_logged(self, mock_http, caplog):
        import logging
        from function_app import _run_login_check

        fail_resp = MagicMock()
        fail_resp.status_code = 500
        mock_http.post.return_value = fail_resp

        with caplog.at_level(logging.INFO):
            _run_login_check(None, None, set(), [mock_data.EVENT_VPN_LOGIN])

        assert "1 skipped" in caplog.text


class TestAllowlist:

    @patch("config.http")
    @patch("config.ALLOWED_NETWORKS")
    def test_allowed_ip_skipped(self, mock_networks, mock_http):
        import ipaddress
        from function_app import _run_login_check

        mock_networks.__iter__ = lambda self: iter([ipaddress.ip_network("185.220.101.0/24")])
        mock_networks.__bool__ = lambda self: True

        _run_login_check(None, None, set(), [mock_data.EVENT_VPN_LOGIN])
        mock_http.post.assert_not_called()

    def test_parse_allowlist(self):
        from config import _parse_allowlist
        result = _parse_allowlist("10.0.0.0/8, 1.2.3.4, 2607:f8b0::/32")
        assert len(result) == 3

    def test_parse_allowlist_empty(self):
        from config import _parse_allowlist
        assert _parse_allowlist("") == []


class TestRecordTypeFiltering:

    def test_login_filter_keeps_types_9_and_15(self):
        from o365_client import filter_login_records
        records = [
            mock_data.EVENT_FEDERATED_LOGIN,
            mock_data.EVENT_NORMAL_LOGIN,
            mock_data.EVENT_NON_LOGIN,
        ]
        ids = [e.get("Id") for e in filter_login_records(records)]
        assert mock_data.EVENT_FEDERATED_LOGIN["Id"] in ids
        assert mock_data.EVENT_NORMAL_LOGIN["Id"] in ids
        assert mock_data.EVENT_NON_LOGIN["Id"] not in ids


class TestCompromiseCheck:
    """First coverage for _run_compromise_check (previously untested)."""

    @patch("function_app.send_compromise_alert")
    def test_external_inbox_rule_alerts(self, mock_alert):
        from function_app import _run_compromise_check
        mock_alert.return_value = True

        _run_compromise_check(None, None, set(), [INBOX_RULE_EVENT])

        mock_alert.assert_called_once()
        finding = mock_alert.call_args.args[0]
        assert finding["type"] == "inbox_rule"
        assert finding["user"] == "victim@contoso.com"

    @patch("function_app.send_compromise_alert")
    def test_benign_events_do_not_alert(self, mock_alert):
        from function_app import _run_compromise_check

        # A normal sign-in carries no inbox-rule / consent / attack-tool signal.
        _run_compromise_check(None, None, set(), [mock_data.EVENT_NORMAL_LOGIN])

        mock_alert.assert_not_called()

    @patch("function_app.send_compromise_alert")
    def test_already_processed_finding_skipped(self, mock_alert):
        from function_app import _run_compromise_check
        from ip_checker import get_event_key
        mock_alert.return_value = True

        processed = {"inbox_rule_" + get_event_key(INBOX_RULE_EVENT)}
        _run_compromise_check(None, None, processed, [INBOX_RULE_EVENT])

        mock_alert.assert_not_called()

    @patch("function_app.send_compromise_alert")
    def test_login_mark_does_not_hide_compromise_finding(self, mock_alert):
        """Regression: the login check marks sign-in events with the bare event
        key. That mark must not suppress a compromise finding on the same event
        (for example a user-agent alert that failed to send in the last run)."""
        from function_app import _run_compromise_check
        from ip_checker import get_event_key
        mock_alert.return_value = True
        event = dict(mock_data.EVENT_PRIVATE_IP_LOGIN,
                     ExtendedProperties=[{"Name": "UserAgent", "Value": "AADInternals"}])

        _run_compromise_check(None, None, {get_event_key(event)}, [event])

        mock_alert.assert_called_once()

    @patch("function_app.send_compromise_alert")
    def test_failed_alert_not_marked(self, mock_alert):
        from function_app import _run_compromise_check
        mock_alert.return_value = False
        table = MagicMock()

        _run_compromise_check(table, None, set(), [INBOX_RULE_EVENT])

        table.upsert_entity.assert_not_called()

    @patch("function_app.send_compromise_alert")
    @patch("function_app.detect_suspicious_oauth_consents")
    def test_one_detector_error_does_not_stop_others(self, mock_consents, mock_alert):
        from function_app import _run_compromise_check
        mock_consents.__name__ = "detect_suspicious_oauth_consents"
        mock_consents.side_effect = RuntimeError("bug")
        mock_alert.return_value = True

        with patch("function_app._DETECTORS", (
            __import__("function_app").detect_suspicious_inbox_rules, mock_consents,
        )):
            _run_compromise_check(None, None, set(), [INBOX_RULE_EVENT])

        mock_alert.assert_called_once()


class TestHostingDetection:

    def test_hosting_type_flagged(self):
        from ip_checker import analyze_ip
        ip_data = mock_data.PROXYCHECK_DATACENTER_IP["54.239.28.85"]
        assert analyze_ip(ip_data)["is_suspicious"] is True
        assert "hosting" in analyze_ip(ip_data)["flags"]

    def test_residential_not_flagged(self):
        from ip_checker import analyze_ip
        ip_data = mock_data.PROXYCHECK_CLEAN_IP["8.8.8.8"]
        assert analyze_ip(ip_data)["is_suspicious"] is False
