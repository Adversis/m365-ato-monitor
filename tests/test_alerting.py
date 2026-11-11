"""Tests for email alerting — setup confirmation, compromise alerts, monthly summary."""

from unittest.mock import patch, MagicMock


class TestSetupConfirmation:

    @patch("alerting.token_manager")
    @patch("config.http.post")
    def test_sends_setup_email(self, mock_post, mock_tm):
        from alerting import send_setup_confirmation
        mock_tm.get_graph_token.return_value = "fake_token"
        resp = MagicMock()
        resp.status_code = 202
        mock_post.return_value = resp

        result = send_setup_confirmation()

        assert result is True
        mock_post.assert_called_once()
        payload = mock_post.call_args[1]["json"]
        assert payload["message"]["subject"].startswith("[M365 Monitor] Setup complete")
        body = payload["message"]["body"]["content"]
        assert "monthly report" in body.lower()
        assert "-SendTestAlerts" in body       # next step: send a test alert


class TestCompromiseAlert:

    def _make_finding(self, **overrides):
        base = {
            "type": "inbox_rule",
            "severity": "high",
            "user": "victim@contoso.com",
            "description": "Inbox rule 'Auto-forward' forwards EXTERNALLY to attacker@evil.com",
            "ip": "185.220.101.42",
            "event": {"Id": "test-1", "CreationTime": "2024-01-15T12:00:00", "Operation": "New-InboxRule"},
        }
        base.update(overrides)
        return base

    @patch("alerting.token_manager")
    @patch("config.http.post")
    def test_sends_compromise_alert(self, mock_post, mock_tm):
        from alerting import send_compromise_alert
        mock_tm.get_graph_token.return_value = "fake_token"
        resp = MagicMock()
        resp.status_code = 202
        mock_post.return_value = resp

        result = send_compromise_alert(self._make_finding())

        assert result is True
        payload = mock_post.call_args[1]["json"]
        assert payload["message"]["subject"] == "[M365 Alert] HIGH: Inbox rule - victim@contoso.com"

    @patch("alerting.token_manager")
    @patch("config.http.post")
    def test_includes_ip_context(self, mock_post, mock_tm):
        from alerting import send_compromise_alert
        mock_tm.get_graph_token.return_value = "fake_token"
        resp = MagicMock()
        resp.status_code = 202
        mock_post.return_value = resp

        send_compromise_alert(self._make_finding(), ip_context="Source IP is VPN (NordVPN, risk 67/100)")

        body = mock_post.call_args[1]["json"]["message"]["body"]["content"]
        assert "NordVPN" in body

    @patch("alerting.token_manager")
    @patch("config.http.post")
    def test_failure_returns_false(self, mock_post, mock_tm):
        from alerting import send_compromise_alert
        mock_tm.get_graph_token.return_value = "fake_token"
        resp = MagicMock()
        resp.status_code = 403
        resp.text = "Forbidden"
        mock_post.return_value = resp

        result = send_compromise_alert(self._make_finding())
        assert result is False

    @patch("alerting.token_manager")
    @patch("config.http.post")
    def test_has_summary_and_recommended_action(self, mock_post, mock_tm):
        from alerting import send_compromise_alert
        mock_tm.get_graph_token.return_value = "fake_token"
        resp = MagicMock()
        resp.status_code = 202
        mock_post.return_value = resp

        send_compromise_alert(self._make_finding())

        body = mock_post.call_args[1]["json"]["message"]["body"]["content"]
        assert "What to do" in body
        assert "revoke" in body.lower()
        assert "Entra ID" in body          # link to the user
        # action is tailored to the inbox_rule finding type
        assert "Remove the inbox rule" in body
        assert "2024-01-15 12:00:00 UTC" in body   # readable time


class TestSuspiciousLoginAlert:

    @patch("alerting.token_manager")
    @patch("config.http.post")
    def test_login_alert_summary_action_and_asn(self, mock_post, mock_tm):
        from alerting import send_suspicious_login_alert
        mock_tm.get_graph_token.return_value = "fake_token"
        resp = MagicMock()
        resp.status_code = 202
        mock_post.return_value = resp

        event = {"UserId": "jane@contoso.com", "CreationTime": "2026-06-12T14:00:00",
                 "Operation": "UserLoggedIn"}
        analysis = {
            "is_suspicious": True, "confidence": "medium", "flags": ["vpn"],
            "risk_score": 75, "asn": "AS15169", "org": "NordVPN",
            "city": "Frankfurt", "country": "Germany",
        }

        result = send_suspicious_login_alert(event, "185.220.101.42", analysis)

        assert result is True
        payload = mock_post.call_args[1]["json"]
        assert payload["message"]["subject"] == (
            "[M365 Alert] MEDIUM: Suspicious sign-in - jane@contoso.com from 185.220.101.42, success")
        body = payload["message"]["body"]["content"]
        assert "If you do not recognize this sign-in" in body
        assert "ALLOWED_IPS" in body
        assert "revoke" in body.lower()
        assert "entra.microsoft.com" in body   # deep link to the user
        assert "AS15169" in body          # ASN enrichment in the summary
        assert "NordVPN" in body
        assert "proxycheck.io" in body    # explains why it's flagged


class TestLoginDigest:

    @patch("alerting.token_manager")
    @patch("config.http.post")
    def test_digest_email_lists_all_entries(self, mock_post, mock_tm):
        from alerting import send_login_digest
        mock_tm.get_graph_token.return_value = "fake_token"
        resp = MagicMock()
        resp.status_code = 202
        mock_post.return_value = resp

        entries = [
            {"creation_time": "2026-06-12T14:00:00", "user": "jane@contoso.com",
             "ip": "185.220.101.42", "flags": "vpn", "confidence": "medium",
             "risk": 75, "org": "NordVPN", "location": "Frankfurt, Germany"},
            {"creation_time": "2026-06-12T14:01:00", "user": "bob@contoso.com",
             "ip": "171.25.193.78", "flags": "tor", "confidence": "high",
             "risk": 100, "org": "Tor", "location": "Amsterdam, Netherlands"},
        ]

        result = send_login_digest(entries)

        assert result is True
        payload = mock_post.call_args[1]["json"]
        assert payload["message"]["subject"] == "[M365 Alert] HIGH: 2 suspicious sign-ins"
        body = payload["message"]["body"]["content"]
        assert "jane@contoso.com" in body
        assert "bob@contoso.com" in body
        assert "171.25.193.78" in body


class TestSummaryEmail:

    @patch("alerting.token_manager")
    @patch("config.http.post")
    def test_sends_monthly_summary(self, mock_post, mock_tm):
        from alerting import send_summary_email
        mock_tm.get_graph_token.return_value = "fake_token"
        resp = MagicMock()
        resp.status_code = 202
        mock_post.return_value = resp

        send_summary_email(total=500, suspicious=3, unique_ips=200, period_label="Monthly",
                           compromise=1, country=2)

        payload = mock_post.call_args[1]["json"]
        subject = payload["message"]["subject"]
        assert subject.startswith("[M365 Monitor] Monthly report, ")
        assert subject.endswith(": 6 alerts to review")
        body = payload["message"]["body"]["content"]
        assert "500" in body and "Compromise indicators" in body and "New-country sign-ins" in body


class TestEmailQuality:
    """Formatting rules that every email must follow."""

    def _all_bodies(self):
        import alerting
        sent = []
        event = {"UserId": "u@contoso.com", "CreationTime": "2026-11-07T14:02:11",
                 "Operation": "UserLoginFailed", "ErrorNumber": "50126"}
        analysis = {"confidence": "high", "flags": ["tor"], "risk_score": 100, "org": "Tor",
                    "city": "Amsterdam", "country": "Netherlands"}
        finding = {"type": "oauth_consent", "severity": "high", "user": "u@contoso.com",
                   "description": "d", "ip": "1.2.3.4", "event": {"Id": "x"}}
        anomaly = {"user": "u@contoso.com", "country": "NG", "outcome": "success", "ip": "1.2.3.4",
                   "event": {**event, "Operation": "UserLoggedIn"}, "known": ["US"], "learning": False,
                   "analysis": {"country": "Nigeria"}}
        with patch("alerting._send_email", side_effect=lambda s, b: sent.append((s, b)) or True):
            alerting.send_setup_confirmation()
            alerting.send_summary_email(10, 0, 0, "Monthly")
            alerting.send_compromise_alert(finding)
            alerting.send_suspicious_login_alert(event, "1.2.3.4", analysis)
            alerting.send_country_anomaly_alert(anomaly, "none (ANOMALY_ACTION=none)")
            alerting.send_login_digest([{"user": "u@contoso.com", "ip": "1.2.3.4", "flags": "tor"}])
        return sent

    def test_subject_prefixes(self):
        for subject, _ in self._all_bodies():
            assert subject.startswith(("[M365 Alert] ", "[M365 Monitor] ")), subject
            assert "((" not in subject and "))" not in subject, subject

    def test_layout(self):
        for subject, body in self._all_bodies():
            assert body.startswith("<!DOCTYPE html>"), subject
            assert 'role="presentation"' in body, subject       # table layout
            assert "<!--[if mso]>" in body, subject             # Outlook width fallback
            assert "max-width:640px" in body, subject
            assert "Sent from admin@contoso.com" in body, subject  # footer

    def test_readable_values(self):
        bodies = {s: b for s, b in self._all_bodies()}
        signin = next(b for s, b in bodies.items() if "Suspicious sign-in -" in s)
        assert "2026-11-07 14:02:11 UTC" in signin
        assert "50126: wrong user name or password" in signin
        assert ">Tor<" in signin or "Tor address" in signin

    def test_sentence_matches_result(self):
        from alerting import _signin_sentence
        assert "signed in from" in _signin_sentence("u", "Success", "X")
        assert "failed sign-in (50126: wrong user name or password)" in _signin_sentence("u", "Failed (50126)", "X")
        assert "correct password" in _signin_sentence("u", "Failed (50074)", "X")
        assert "failed sign-in from" in _signin_sentence("u", "Failed", "X")
        unknown = _signin_sentence("u", "Unknown", "X")
        assert "failed" not in unknown and "result: unknown" in unknown


class TestManagementUiLinks:

    def _country_body(self, **kwargs):
        import alerting
        anomaly = {"user": "jane@contoso.com", "country": "FR", "outcome": "success", "ip": "1.2.3.4",
                   "event": {"UserId": "Jane@Contoso.com", "Operation": "UserLoggedIn"}, "known": ["US"],
                   "learning": False, "analysis": {"country": "France"}}
        sent = []
        with patch("alerting._send_email", side_effect=lambda s, b: sent.append(b) or True):
            alerting.send_country_anomaly_alert(anomaly, kwargs.get("result", "none (ANOMALY_ACTION=none)"))
        return sent[0]

    def test_links_when_ui_enabled(self, monkeypatch):
        monkeypatch.setenv("ADMIN_UI_ENABLED", "true")
        monkeypatch.setenv("WEBSITE_HOSTNAME", "func.azurewebsites.net")
        body = self._country_body()
        assert "https://func.azurewebsites.net/api/manage#countries:jane@contoso.com" in body
        assert "Approve FR for this user" in body
        assert ">Management UI</a>" in body          # footer link
        assert "--account-enabled" not in body       # not blocked: no re-enable step

    def test_no_links_when_ui_disabled(self, monkeypatch):
        monkeypatch.delenv("ADMIN_UI_ENABLED", raising=False)
        body = self._country_body(result="Block sign-in: done; Revoke sessions: done")
        assert "/api/manage" not in body
        assert "--account-enabled true" in body      # blocked: re-enable step still shown
