"""Security regression tests.

Each test covers one weakness found in review and the fix for it. Design
limits that code cannot test are in docs/SECURITY.md.
"""

import json
import logging
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# proxycheck.io API key must not reach the logs
# ---------------------------------------------------------------------------

class TestProxycheckKeyRedaction:

    def test_request_exception_text_is_redacted(self, caplog):
        """requests puts the full URL (with ?key=) in its exception text."""
        import ip_checker
        err = ConnectionError("Max retries exceeded with url: /v2/?vpn=1&key=SECRET-KEY-123")
        with patch("config.PROXYCHECK_API_KEY", "SECRET-KEY-123"), \
             patch("config.http") as mock_http, caplog.at_level(logging.ERROR):
            mock_http.post.side_effect = err
            assert ip_checker.check_ips_batch(["185.220.101.42"]) == {}
        assert "SECRET-KEY-123" not in caplog.text
        assert "***" in caplog.text

    def test_urllib3_retry_warnings_suppressed(self):
        """urllib3 logs the request URL at WARNING on each retry."""
        import config
        assert config.http is not None  # import of config sets the level
        assert logging.getLogger("urllib3").getEffectiveLevel() >= logging.ERROR

    def test_redact_without_key_is_identity(self):
        import config
        with patch("config.PROXYCHECK_API_KEY", ""):
            assert config.redact("abc") == "abc"


# ---------------------------------------------------------------------------
# proxycheck.io response handling
# ---------------------------------------------------------------------------

class TestProxycheckResponses:

    def _resp(self, body):
        r = MagicMock(status_code=200)
        r.json.return_value = body
        return r

    def test_warning_status_results_are_used(self):
        """status=warning (for example near the quota) still has results."""
        import ip_checker
        body = {"status": "warning", "message": "within 10% of your query limit",
                "185.220.101.42": {"proxy": "yes", "type": "VPN", "risk": 70}}
        with patch("config.http") as mock_http:
            mock_http.post.return_value = self._resp(body)
            results = ip_checker.check_ips_batch(["185.220.101.42"])
        assert results["185.220.101.42"]["type"] == "VPN"

    def test_per_ip_error_entry_is_a_failed_lookup(self):
        import ip_checker
        body = {"status": "ok", "1.2.3.4": {"error": "Invalid or Internal IP Address."}}
        with patch("config.http") as mock_http:
            mock_http.post.return_value = self._resp(body)
            assert ip_checker.check_ips_batch(["1.2.3.4"]) == {}

    def test_denied_logs_error(self, caplog):
        import ip_checker
        with patch("config.http") as mock_http, caplog.at_level(logging.ERROR):
            mock_http.post.return_value = self._resp({"status": "denied", "message": "1,000 queries exhausted"})
            assert ip_checker.check_ips_batch(["1.2.3.4"]) == {}
        assert "quota or access problem" in caplog.text


# ---------------------------------------------------------------------------
# IP normalization (allowlist and cache key consistency)
# ---------------------------------------------------------------------------

class TestIPNormalization:

    @pytest.mark.parametrize("raw,expected", [
        ("::ffff:10.0.0.1", "10.0.0.1"),
        ("2001:DB8:0::1", "2001:db8::1"),
        ("[2001:0db8::1]:443", "2001:db8::1"),
        ("185.220.101.42:51763", "185.220.101.42"),
        ("1.2.3.4:443:1.2.3.4", "1.2.3.4"),
        ("10.0.0.0/8", "10.0.0.0"),
        ("no_ip", None),
        ("", None),
    ])
    def test_clean_ip_canonical(self, raw, expected):
        from ip_checker import clean_ip
        assert clean_ip(raw) == expected

    def test_mapped_and_plain_ipv4_share_a_cache_key(self):
        from ip_checker import _ip_row_key, clean_ip
        assert _ip_row_key(clean_ip("::ffff:10.0.0.1")) == _ip_row_key(clean_ip("10.0.0.1"))

    def test_ipv6_case_variants_share_allowlist_result(self):
        import ipaddress
        from ip_checker import clean_ip, is_allowed_ip
        with patch("config.ALLOWED_NETWORKS", [ipaddress.ip_network("2001:db8::/32")]):
            assert is_allowed_ip(clean_ip("2001:DB8::5"))


# ---------------------------------------------------------------------------
# Email content and delivery
# ---------------------------------------------------------------------------

class TestEmail:

    @patch("alerting.token_manager")
    def test_token_failure_returns_false_not_raise(self, mock_tm):
        """A Graph token failure must not stop the monitor run."""
        from alerting import send_compromise_alert
        mock_tm.get_graph_token.side_effect = RuntimeError("Token request failed: HTTP 401")
        finding = {"type": "inbox_rule", "severity": "high", "user": "u@contoso.com",
                   "description": "d", "ip": None, "event": {}}
        assert send_compromise_alert(finding) is False

    @patch("alerting.token_manager")
    @patch("config.http.post")
    def test_send_has_timeout(self, mock_post, mock_tm):
        from alerting import send_setup_confirmation
        mock_tm.get_graph_token.return_value = "t"
        mock_post.return_value = MagicMock(status_code=202)
        send_setup_confirmation()
        assert mock_post.call_args.kwargs.get("timeout")

    @patch("alerting.token_manager")
    @patch("config.http.post")
    def test_user_values_are_html_escaped(self, mock_post, mock_tm):
        from alerting import send_compromise_alert
        mock_tm.get_graph_token.return_value = "t"
        mock_post.return_value = MagicMock(status_code=202)
        finding = {"type": "inbox_rule", "severity": "high",
                   "user": "<script>x</script>@contoso.com",
                   "description": "<img src=x onerror=alert(1)>", "ip": "1.2.3.4",
                   "event": {"CreationTime": "<b>t</b>"}}
        send_compromise_alert(finding)
        payload = mock_post.call_args.kwargs["json"]
        body = payload["message"]["body"]["content"]
        assert "<script>" not in body and "<img" not in body and "<b>t</b>" not in body
        # The subject is plain text: no HTML entities.
        assert "<script>x</script>@contoso.com" in payload["message"]["subject"]

    def test_object_id_field_not_used_for_user_link(self):
        """In sign-in records ObjectId is the target app ID, not the user."""
        from alerting import _entra_user_link
        with patch("config.RESOLVE_USER_IDS", False):
            link = _entra_user_link({"ObjectId": "00000002-0000-0ff1-ce00-000000000000",
                                     "UserId": "u@contoso.com"})
        assert "00000002-0000-0ff1-ce00-000000000000" not in link
        assert "AllUsers" in link

    @patch("o365_client.token_manager")
    @patch("config.http")
    def test_graph_lookup_escapes_path(self, mock_http, mock_tm):
        import o365_client
        o365_client._user_id_cache.clear()
        mock_tm.get_graph_token.return_value = "t"
        mock_http.get.return_value = MagicMock(status_code=404)
        with patch("o365_client._userid_table_client", return_value=None):
            o365_client.resolve_user_object_id("../me")
        assert "/users/..%2Fme?" in mock_http.get.call_args.args[0]

    @patch("o365_client.token_manager")
    @patch("config.http")
    def test_graph_lookup_transient_failure_not_cached(self, mock_http, mock_tm):
        import o365_client
        o365_client._user_id_cache.clear()
        mock_tm.get_graph_token.return_value = "t"
        mock_http.get.return_value = MagicMock(status_code=503)
        with patch("o365_client._userid_table_client", return_value=None):
            o365_client.resolve_user_object_id("a@contoso.com")
            o365_client.resolve_user_object_id("a@contoso.com")
        assert mock_http.get.call_count == 2


# ---------------------------------------------------------------------------
# HTTP endpoints
# ---------------------------------------------------------------------------

def _req(**params):
    req = MagicMock()
    req.params = params
    return req


class TestRecentEndpoint:

    @pytest.mark.parametrize("params", [{"hours": "abc"}, {"limit": "1.5"}])
    def test_bad_params_return_400(self, params):
        from function_app import recent_activity
        assert recent_activity(_req(**params)).status_code == 400

    def test_query_error_text_not_returned(self):
        from function_app import recent_activity
        table = MagicMock()
        table.query_entities.side_effect = RuntimeError("AccountKey=SECRETSTORAGEKEY")
        with patch("function_app._get_table_clients", return_value=(table, table)):
            resp = recent_activity(_req())
        assert b"SECRETSTORAGEKEY" not in resp.get_body()

    def test_ipv6_shown_from_entity(self):
        from function_app import recent_activity
        events, cache = MagicMock(), MagicMock()
        events.query_entities.return_value = []
        cache.query_entities.return_value = [{
            "RowKey": "2001_db8__1", "ip": "2001:db8::1", "data": json.dumps({"proxy": "no"}),
            "cached_at": "2026-01-01T00:00:00+00:00", "is_negative": False,
        }]
        with patch("function_app._get_table_clients", return_value=(events, cache)):
            body = json.loads(recent_activity(_req()).get_body())
        assert body["recent_ips"][0]["ip"] == "2001:db8::1"


class TestStatusEndpoint:

    def _run(self, proxycheck_body, token_error=None):
        from function_app import status_check
        tm = MagicMock()
        if token_error:
            tm.get_o365_token.side_effect = token_error
        resp = MagicMock(status_code=200)
        resp.json.return_value = proxycheck_body
        with patch("o365_client.token_manager", tm), \
             patch("o365_client.fetch_audit_content_urls", return_value=[]), \
             patch("function_app._get_table_clients", return_value=(None, None)), \
             patch("config.http") as mock_http:
            mock_http.get.return_value = resp
            out = status_check(_req())
        return out.status_code, json.loads(out.get_body())

    def test_healthy(self):
        code, body = self._run({"status": "ok"})
        assert code == 200 and body["status"] == "healthy"
        assert "o365_api_exchange" in body["checks"]

    def test_proxycheck_denied_is_degraded(self):
        """Old code counted any string containing "ok" as healthy."""
        code, body = self._run({"status": "denied", "message": "quota"})
        assert code == 503
        assert body["checks"]["proxycheck_io"].startswith("FAILED")

    def test_exception_name_containing_ok_is_degraded(self):
        class TokenError(Exception):
            pass
        code, body = self._run({"status": "ok"}, token_error=TokenError("bad"))
        assert code == 503


class TestRetryCap:

    def test_retry_after_is_capped(self):
        from config import _CappedRetry
        resp = MagicMock()
        resp.headers = {"Retry-After": "600"}
        retry = _CappedRetry(total=3, respect_retry_after_header=True)
        with patch("urllib3.util.retry.Retry.get_retry_after", return_value=600.0):
            assert retry.get_retry_after(resp) == _CappedRetry.RETRY_AFTER_MAX_SECONDS
        # A new Retry from .increment() keeps the subclass.
        assert isinstance(retry.new(), _CappedRetry)


# ---------------------------------------------------------------------------
# Deploy scripts
# ---------------------------------------------------------------------------

class TestScripts:

    def _read(self, *parts):
        import pathlib
        return (pathlib.Path(__file__).resolve().parent.parent.joinpath(*parts)).read_text()

    def test_installer_makes_no_secret(self):
        """install.ps1 uses the managed identity as a federated credential: no client secret, no storage key."""
        text = self._read("install.ps1")
        for bad in ("addPassword", "credential reset", "client_secret", "AZURE_CLIENT_SECRET=", "keys list --account"):
            assert bad not in text
        assert "federatedIdentityCredentials" in text
        assert "Set-StorageSharedKey $false" in text      # keys off once the app uses the identity

    def test_function_key_not_in_url(self):
        """The function key goes in the x-functions-key header, never in the URL (logs, history)."""
        for parts in (("install.ps1",), ("scripts", "live-test.ps1")):
            text = self._read(*parts)
            assert "?code=" not in text and "&code=" not in text

    def test_installer_query_strings_are_parameters(self):
        """A "&" in an az argument breaks az.cmd on Windows. Graph and ARM queries use -Query."""
        import re
        text = self._read("install.ps1")
        for line in text.splitlines():
            if "-Url" in line:
                assert not re.search(r"-Url\s+\"[^\"]*\?", line), line
