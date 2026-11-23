"""Alerts to a webhook: formats, delivery modes, fallback to email, and URL checks."""

import json
from unittest.mock import MagicMock, patch

import pytest

import alerting
import config
import webhook

URL = "https://hooks.slack.com/services/T000/B000/XXXXXXXX"
FINDING = {"type": "inbox_rule", "severity": "high", "user": "victim@contoso.com",
           "description": "Inbox rule '..' forwards to pay@evil.example.", "ip": None, "event": {"Id": "x"}}


@pytest.fixture
def hook():
    with patch.multiple(config, WEBHOOK_URL=URL, WEBHOOK_FORMAT="slack", ALERT_DELIVERY="both"), \
            patch("webhook._public_host", return_value=True), patch("alerting.admin_store"):
        yield


class TestCheckUrl:

    @pytest.mark.parametrize("url", [URL, "https://prod-12.westus.logic.azure.com/workflows/abc/triggers/manual/paths/invoke?sig=x"])
    def test_good(self, url):
        assert webhook.check_url(url) == ""

    @pytest.mark.parametrize("url,word", [
        ("http://hooks.slack.com/x", "https"), ("https://10.0.0.5/hook", "IP address"),
        ("https://169.254.169.254/metadata", "IP address"), ("https://user:pw@example.com/x", "user name"),
        ("https://example.com:8443/x", "443"), ("https://example.com/a b", "one line"),
    ])
    def test_bad(self, url, word):
        assert word in webhook.check_url(url)

    def test_settings_validation(self):
        import settings
        s = settings.BY_NAME["WEBHOOK_URL"]
        assert settings.validate(s, URL) == URL and settings.validate(s, "") == ""
        with pytest.raises(ValueError):
            settings.validate(s, "http://example.com/x")

    def test_private_host_refused(self):
        with patch.object(config, "WEBHOOK_URL", URL), \
                patch("webhook.socket.getaddrinfo", return_value=[(2, 1, 6, "", ("10.1.2.3", 443))]), \
                patch("webhook._http") as http:
            assert webhook.post("s") == (False, "The webhook host does not resolve to a public address.")
            http.post.assert_not_called()


class TestFormats:

    def test_slack(self):
        p = webhook.payload("slack", "[M365 Alert] HIGH: Inbox rule - a@b.c", "text", "https://x/api/manage#user:a@b.c")
        assert p["text"].startswith("*[M365 Alert] HIGH") and "<https://x/api/manage#user:a@b.c|Open" in p["text"]

    def test_teams_adaptive_card(self):
        p = webhook.payload("teams", "subject", "text", "https://x")
        card = p["attachments"][0]["content"]
        assert p["type"] == "message" and card["type"] == "AdaptiveCard"
        assert card["body"][0]["inlines"][0]["text"] == "subject" and card["actions"][0]["url"] == "https://x"

    def test_attacker_text_is_not_markup(self):
        """Rule and app names come from the attacker: no Slack mention or link, no Teams markdown."""
        evil = "Rule <!channel> <https://evil.example/login|Reset your password> & [x](https://evil.example)"
        slack = webhook.payload("slack", "subject", evil, "")["text"]
        assert "<!channel>" not in slack and "<https://evil" not in slack and "&lt;!channel&gt;" in slack
        card = webhook.payload("teams", "subject", evil, "")["attachments"][0]["content"]
        assert all(b["type"] == "RichTextBlock" and b["inlines"][0]["type"] == "TextRun" for b in card["body"])
        assert card["body"][1]["inlines"][0]["text"] == evil

    def test_no_retry_and_a_short_timeout(self):
        """A receiver that does not answer gets one POST, and the run waits at most 15 seconds."""
        assert webhook._http.get_adapter("https://x").max_retries.total == 0
        assert webhook._TIMEOUT == (5, 10)

    def test_json(self):
        p = webhook.payload("json", "subject", "text", "https://x")
        assert p["subject"] == "subject" and p["source"] == "m365-ato-monitor"


class TestDelivery:

    @pytest.mark.parametrize("fmt", ["slack", "teams", "json"])
    def test_session_context_reaches_email_and_each_webhook_format(self, hook, fmt):
        from ip_checker import analyze_ip
        import session_monitor
        from tests.fakes import FakeTable
        from tests.test_session_monitor import HOME_IP, VPN_IP, NOW, Lookup, signin, mailbox
        record = mailbox(VPN_IP, 20)
        record.update(UserAgent="Outlook <test>", AppId="resource-app")
        record["AppAccessContext"].update(ClientAppId="client-app", APIId="api-app")
        finding = session_monitor.check(FakeTable(), [signin(HOME_IP, 1), record], Lookup(), NOW,
                                        analyze=analyze_ip)[0]
        related = [{"type": "mfa_change", "severity": "medium", "status": "emailed",
                    "at": "2026-11-08T11:00:00Z"}]
        with patch.object(config, "WEBHOOK_FORMAT", fmt), patch("webhook._http") as http, \
                patch("alerting._send_email", return_value=True) as email:
            http.post.return_value.status_code = 200
            assert alerting.send_compromise_alert(finding, related=related)
        payload = json.loads(http.post.call_args.kwargs["data"])
        if fmt == "teams":
            text = payload["attachments"][0]["content"]["body"][1]["inlines"][0]["text"]
        else:
            text = payload["text"]
        body = email.call_args.args[1]
        for value in ("2026-11-08 11:01:00 UTC", "2026-11-08 11:20:00 UTC", "19 minutes",
                      "Client=OWA;Action=ViaProxy", "resource-app", "client-app", "api-app",
                      "No matching sign-in from this exact IP", "7-day history"):
            assert value in text and value in body
        assert "Other alerts for this user in the last 24 hours: 1" in text
        assert alerting.short_title("mfa_change") in text
        assert "Outlook &lt;test&gt;" in body
        assert ("Outlook &lt;test&gt;" if fmt == "slack" else "Outlook <test>") in text
        assert "without a new sign-in" not in text and "Session first seen" not in text

    def test_both_sends_email_and_webhook(self, hook):
        with patch("webhook._http") as http, patch("alerting._send_email", return_value=True) as email:
            http.post.return_value = MagicMock(status_code=200)
            assert alerting.send_compromise_alert(FINDING)
        assert email.call_count == 1
        body = json.loads(http.post.call_args.kwargs["data"])
        assert "victim@contoso.com: Inbox rule '..' forwards" in body["text"]
        assert http.post.call_args.kwargs["allow_redirects"] is False

    def test_webhook_only(self, hook):
        with patch.object(config, "ALERT_DELIVERY", "webhook"), patch("webhook._http") as http, \
                patch("alerting._send_email", return_value=True) as email:
            http.post.return_value = MagicMock(status_code=204)
            assert alerting.send_compromise_alert(FINDING)
        assert email.call_count == 0

    def test_webhook_only_falls_back_to_email(self, hook):
        with patch.object(config, "ALERT_DELIVERY", "webhook"), patch("webhook._http") as http, \
                patch("alerting._send_email", return_value=True) as email:
            http.post.return_value = MagicMock(status_code=500)
            assert alerting.send_compromise_alert(FINDING)
        assert email.call_count == 1

    def test_reports_stay_in_email(self, hook):
        with patch("webhook._http") as http, patch("alerting._send_email", return_value=True):
            alerting._deliver(f"{alerting.INFO_TAG} Weekly report", "<p>x</p>", None)
            http.post.assert_not_called()

    def test_no_url_means_email(self):
        with patch.multiple(config, WEBHOOK_URL="", ALERT_DELIVERY="webhook"), patch("webhook._http") as http, \
                patch("alerting._send_email", return_value=True) as email, patch("alerting.admin_store"):
            assert alerting.send_compromise_alert(FINDING)
            http.post.assert_not_called()
        assert email.call_count == 1

    def test_url_redacted_in_logs(self):
        with patch.object(config, "WEBHOOK_URL", URL):
            assert URL not in config.redact(f"ConnectionError: {URL}")

    def test_url_path_redacted_in_requests_errors(self):
        """requests shows the host and the path apart: the secret path must go too."""
        with patch.object(config, "WEBHOOK_URL", "https://hooks.slack.com/services/T0/B0/secretpart"):
            msg = ("HTTPSConnectionPool(host='hooks.slack.com', port=443): Max retries exceeded with url: "
                   "/services/T0/B0/secretpart")
            assert "secretpart" not in config.redact(msg)


class TestNoticesAndDigest:

    def test_ui_change_notices_go_by_email_with_webhook_only(self, hook):
        """A change of ALERT_DELIVERY or WEBHOOK_URL must not hide itself in the new webhook."""
        with patch.object(config, "ALERT_DELIVERY", "webhook"), patch("webhook._http") as http, \
                patch("alerting._send_email", return_value=True) as email:
            http.post.return_value.status_code = 200
            alerting.send_settings_changed("eve@contoso.com", [{"name": "ALERT_DELIVERY", "old": "email",
                                                                "new": "webhook"}])
        assert email.call_count == 1 and http.post.call_count == 1

    def test_failed_digest_email_waits_in_the_outbox(self, hook):
        """Without the outbox, each run sent the same digest to the webhook again."""
        from tests.fakes import FakeTable
        outbox = FakeTable()
        with patch("webhook._http") as http, patch("alerting._send_email", return_value=False):
            http.post.return_value.status_code = 200
            ok = alerting.send_login_digest([{"user": "u@contoso.com", "ip": "203.0.113.9", "flags": "vpn"}],
                                            outbox=outbox)
        assert ok and len(outbox.partition("outbox")) == 1


def test_compromise_webhook_text_names_the_network():
    import alerting
    from unittest.mock import patch as _patch
    finding = {"type": "mfa_change", "severity": "medium", "user": "jane@contoso.com",
               "description": "An MFA method was added.", "ip": "2001:db8::1", "asn": "AS64500",
               "network": "Example Wireless", "event": {"Id": "x", "CreationTime": "2026-11-18T22:24:55"}}
    with _patch("alerting._deliver", return_value=True) as deliver:
        alerting.send_compromise_alert(finding, ip_context="Changed after a sign-in from 2001:db8::1")
    assert "Network: Example Wireless (AS64500)." in deliver.call_args.kwargs["summary"]
