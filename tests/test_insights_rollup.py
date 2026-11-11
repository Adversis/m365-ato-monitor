"""Tests for the App Insights-backed 30-day monthly roll-up (Q5)."""

from unittest.mock import patch, MagicMock


def _table_response(suspicious, unique_ips, total_events, compromise=0, country=0):
    """Shape of the App Insights /query response: tables[0].rows[0]."""
    return {
        "tables": [{
            "name": "PrimaryResult",
            "columns": [
                {"name": "suspicious"},
                {"name": "unique_ips"},
                {"name": "total_events"},
                {"name": "compromise"},
                {"name": "country"},
            ],
            "rows": [[suspicious, unique_ips, total_events, compromise, country]],
        }]
    }


class TestInsightsClient:

    @patch("insights_client.token_manager")
    @patch("config.http")
    @patch("config.APP_INSIGHTS_APP_ID", "app-guid-123")
    def test_parses_stats(self, mock_http, mock_tm):
        from insights_client import get_monthly_login_stats
        mock_tm.get_app_insights_token.return_value = "tok"
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = _table_response(3, 2, 1500, 1, 4)
        mock_http.post.return_value = resp

        stats = get_monthly_login_stats()

        assert stats == {"total_events": 1500, "suspicious": 3, "unique_ips": 2,
                         "compromise": 1, "country": 4, "runs": 0, "gaps": 0, "errors": 0}
        assert "ago(30d)" in mock_http.post.call_args.kwargs["json"]["query"]
        # Query targets the configured app id.
        assert "app-guid-123" in mock_http.post.call_args.args[0]

    @patch("config.APP_INSIGHTS_APP_ID", "")
    def test_unconfigured_returns_none(self):
        from insights_client import get_monthly_login_stats
        assert get_monthly_login_stats() is None

    @patch("insights_client.token_manager")
    @patch("config.http")
    @patch("config.APP_INSIGHTS_APP_ID", "app-guid-123")
    def test_http_error_returns_none(self, mock_http, mock_tm):
        from insights_client import get_monthly_login_stats
        mock_tm.get_app_insights_token.return_value = "tok"
        resp = MagicMock()
        resp.status_code = 403
        mock_http.post.return_value = resp
        assert get_monthly_login_stats() is None

    @patch("insights_client.token_manager")
    @patch("config.http")
    @patch("config.APP_INSIGHTS_APP_ID", "app-guid-123")
    def test_null_aggregates_default_to_zero(self, mock_http, mock_tm):
        """summarize over an empty window yields null aggregates -> coerce to 0."""
        from insights_client import get_monthly_login_stats
        mock_tm.get_app_insights_token.return_value = "tok"
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = _table_response(None, None, None, None, None)
        mock_http.post.return_value = resp
        assert get_monthly_login_stats() == {"total_events": 0, "suspicious": 0, "unique_ips": 0,
                                             "compromise": 0, "country": 0, "runs": 0, "gaps": 0,
                                             "errors": 0}


class TestMonthlyRollup:

    @patch("function_app.send_summary_email")
    @patch("function_app.get_monthly_login_stats")
    def test_rollup_emails_stats(self, mock_stats, mock_email):
        from function_app import monthly_rollup
        mock_stats.return_value = {"total_events": 1500, "suspicious": 3, "unique_ips": 2}

        monthly_rollup(None)

        mock_email.assert_called_once()
        kwargs = mock_email.call_args.kwargs
        assert kwargs["total"] == 1500
        assert kwargs["suspicious"] == 3
        assert kwargs["unique_ips"] == 2
        assert kwargs["period_label"] == "Monthly"

    @patch("function_app.send_summary_email")
    @patch("function_app.get_monthly_login_stats")
    def test_rollup_skips_when_unavailable(self, mock_stats, mock_email):
        from function_app import monthly_rollup
        mock_stats.return_value = None

        monthly_rollup(None)

        mock_email.assert_not_called()
