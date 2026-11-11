"""Detector-level tests for the three post-compromise features:
inbox rules, OAuth consents, and attack-tool / automation user agents.

Each detector is tested for (a) the malicious case it must flag and (b) the
benign cases it must NOT flag (its built-in false-positive suppression).
"""

from compromise_detector import (
    detect_suspicious_inbox_rules,
    detect_suspicious_oauth_consents,
    detect_suspicious_user_agents,
)


def _params(**kv):
    return [{"Name": k, "Value": v} for k, v in kv.items()]


# ---------------------------------------------------------------------------
# Inbox rules
# ---------------------------------------------------------------------------

class TestInboxRules:

    def test_external_forward_flagged(self):
        event = {
            "Id": "ir-1",
            "Operation": "New-InboxRule",
            "UserId": "victim@contoso.com",
            "Parameters": _params(Name="Exfil", ForwardTo="attacker@evil.com"),
        }
        findings = detect_suspicious_inbox_rules([event])
        assert len(findings) == 1
        f = findings[0]
        assert f["type"] == "inbox_rule"
        assert f["severity"] == "high"
        assert f["user"] == "victim@contoso.com"
        assert f["event"] is event
        assert "evil.com" in f["description"]

    def test_internal_forward_not_flagged(self):
        # Forwarding within the tenant domain is normal user behavior.
        event = {
            "Operation": "New-InboxRule",
            "UserId": "user@contoso.com",
            "Parameters": _params(Name="Team", ForwardTo="colleague@contoso.com"),
        }
        assert detect_suspicious_inbox_rules([event]) == []

    def test_external_redirect_flagged(self):
        event = {
            "Operation": "Set-InboxRule",
            "UserId": "victim@contoso.com",
            "Parameters": _params(Name="Redir", RedirectTo="drop@attacker.io"),
        }
        findings = detect_suspicious_inbox_rules([event])
        assert len(findings) == 1
        assert "attacker.io" in findings[0]["description"]

    def test_delete_message_flagged(self):
        event = {
            "Operation": "New-InboxRule",
            "UserId": "victim@contoso.com",
            "Parameters": _params(Name="Hide", DeleteMessage="True"),
        }
        findings = detect_suspicious_inbox_rules([event])
        assert len(findings) == 1
        assert "delete" in findings[0]["description"].lower()

    def test_hidden_folder_move_flagged(self):
        event = {
            "Operation": "New-InboxRule",
            "UserId": "victim@contoso.com",
            "Parameters": _params(Name="Stash", MoveToFolder="RSS Feeds"),
        }
        findings = detect_suspicious_inbox_rules([event])
        assert len(findings) == 1
        assert "hidden folder" in findings[0]["description"].lower()

    def test_non_rule_operation_ignored(self):
        event = {"Operation": "UserLoggedIn", "UserId": "u@contoso.com", "Parameters": []}
        assert detect_suspicious_inbox_rules([event]) == []

    def test_benign_rule_no_indicators_ignored(self):
        # Moving to a normal folder with no external forward is not suspicious.
        event = {
            "Operation": "New-InboxRule",
            "UserId": "u@contoso.com",
            "Parameters": _params(Name="Sort", MoveToFolder="Projects"),
        }
        assert detect_suspicious_inbox_rules([event]) == []


# ---------------------------------------------------------------------------
# OAuth consents
# ---------------------------------------------------------------------------

class TestOAuthConsents:

    def _consent_event(self, new_value, app="Suspicious App"):
        return {
            "Id": "oc-1",
            "Operation": "Consent to application.",
            "UserId": "victim@contoso.com",
            "Target": [{"Type": 1, "ID": app}, {"Type": 2, "ID": "app-guid-123"}],
            "ModifiedProperties": [
                {"Name": "ConsentAction.Permissions", "NewValue": new_value}
            ],
        }

    def test_high_risk_scope_flagged(self):
        findings = detect_suspicious_oauth_consents([self._consent_event("Mail.Read Mail.Send")])
        assert len(findings) == 1
        f = findings[0]
        assert f["type"] == "oauth_consent"
        assert f["severity"] == "high"
        assert "Suspicious App" in f["description"]
        assert "Mail.Read" in f["description"]

    def test_benign_scope_ignored(self):
        # User.Read / openid / profile are not high-risk — no alert.
        assert detect_suspicious_oauth_consents([self._consent_event("User.Read openid profile")]) == []

    def test_non_consent_operation_ignored(self):
        assert detect_suspicious_oauth_consents([{"Operation": "UserLoggedIn", "UserId": "u@contoso.com"}]) == []


# ---------------------------------------------------------------------------
# User agents
# ---------------------------------------------------------------------------

class TestUserAgents:

    def _ua_event(self, ua):
        return {
            "Id": "ua-1",
            "Operation": "UserLoggedIn",
            "UserId": "victim@contoso.com",
            "ExtendedProperties": [{"Name": "UserAgent", "Value": ua}],
        }

    def test_attack_tool_flagged_high(self):
        findings = detect_suspicious_user_agents([self._ua_event("AADInternals/0.9.2")])
        assert len(findings) == 1
        assert findings[0]["type"] == "attack_tool"
        assert findings[0]["severity"] == "high"

    def test_automation_flagged_medium(self):
        findings = detect_suspicious_user_agents([self._ua_event("python-requests/2.31.0")])
        assert len(findings) == 1
        assert findings[0]["type"] == "suspicious_user_agent"
        assert findings[0]["severity"] == "medium"

    def test_browser_ua_ignored(self):
        ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        assert detect_suspicious_user_agents([self._ua_event(ua)]) == []

    def test_missing_ua_ignored(self):
        event = {"Operation": "UserLoggedIn", "UserId": "u@contoso.com", "ExtendedProperties": []}
        assert detect_suspicious_user_agents([event]) == []


# ---------------------------------------------------------------------------
# Regression tests for bypasses and gaps found in review
# ---------------------------------------------------------------------------

class TestInboxRuleBypasses:

    def test_external_attachment_forward_with_internal_forward(self):
        # Old code checked only ForwardTo when it was set.
        event = {
            "Operation": "New-InboxRule",
            "UserId": "victim@contoso.com",
            "Parameters": _params(Name="x", ForwardTo="colleague@contoso.com",
                                  ForwardAsAttachmentTo="drop@evil.com"),
        }
        findings = detect_suspicious_inbox_rules([event])
        assert len(findings) == 1
        assert "drop@evil.com" in findings[0]["description"]

    def test_external_recipient_before_internal_one(self):
        # Old code took only the domain after the last "@".
        event = {
            "Operation": "New-InboxRule",
            "UserId": "victim@contoso.com",
            "Parameters": _params(Name="x", ForwardTo="drop@evil.com;victim@contoso.com"),
        }
        findings = detect_suspicious_inbox_rules([event])
        assert len(findings) == 1
        assert "drop@evil.com" in findings[0]["description"]

    def test_smtp_bracket_format(self):
        event = {
            "Operation": "Set-InboxRule",
            "UserId": "victim@contoso.com",
            "Parameters": _params(Name="x", RedirectTo='"Bob" [SMTP:bob@evil.com]'),
        }
        assert len(detect_suspicious_inbox_rules([event])) == 1

    def test_internal_domains_setting(self):
        event = {
            "Operation": "New-InboxRule",
            "UserId": "user@contoso.com",
            "Parameters": _params(Name="x", ForwardTo="user@contoso.onmicrosoft.com"),
        }
        import compromise_detector
        from unittest.mock import patch
        with patch.object(compromise_detector.config, "INTERNAL_DOMAINS", {"contoso.onmicrosoft.com"}):
            assert detect_suspicious_inbox_rules([event]) == []

    def test_hidden_folder_with_path(self):
        event = {
            "Operation": "New-InboxRule",
            "UserId": "victim@contoso.com",
            "Parameters": _params(Name="x", MoveToFolder=":\\Conversation History"),
        }
        assert len(detect_suspicious_inbox_rules([event])) == 1

    def test_soft_delete_flagged(self):
        event = {
            "Operation": "New-InboxRule",
            "UserId": "victim@contoso.com",
            "Parameters": _params(Name="x", SoftDeleteMessage="True"),
        }
        assert len(detect_suspicious_inbox_rules([event])) == 1

    def test_malformed_record_does_not_stop_detector(self):
        bad = {"Operation": "New-InboxRule", "UserId": "u@contoso.com", "Parameters": "not-a-list"}
        good = {
            "Operation": "New-InboxRule",
            "UserId": "victim@contoso.com",
            "Parameters": _params(Name="x", ForwardTo="drop@evil.com"),
        }
        findings = detect_suspicious_inbox_rules([bad, None, good])
        assert len(findings) == 1


class TestUpdateInboxRules:
    """Record shapes from public samples (Red Canary for Outlook, Splunk attack_data for EWS)."""

    def _event(self, **props):
        return {
            "Operation": "UpdateInboxRules",
            "UserId": "victim@contoso.com",
            "OperationProperties": [{"Name": k, "Value": v} for k, v in props.items()],
        }

    def test_outlook_forward_external(self):
        event = self._event(
            RuleOperation="AddMailboxRule", RuleName="x",
            RuleActions='[{"ActionType":"Forward","Recipients":["drop@evil.com"],'
                        '"ForwardFlags":"PreserveSender, DoNotChangeMessage"}]',
        )
        findings = detect_suspicious_inbox_rules([event])
        assert len(findings) == 1
        assert "drop@evil.com" in findings[0]["description"]

    def test_ews_forward_external(self):
        event = self._event(
            RuleOperation="Create", Name="x", Actions="ForwardToRecipientsAction",
            ServerRule='{"Actions":[{"Recipients":[{"Values":["drop@evil.com"]}]}]}',
        )
        findings = detect_suspicious_inbox_rules([event])
        assert len(findings) == 1
        assert "'x'" in findings[0]["description"]

    def test_outlook_forward_internal_not_flagged(self):
        event = self._event(
            RuleOperation="AddMailboxRule", RuleName="x",
            RuleActions='[{"ActionType":"Forward","Recipients":["boss@contoso.com"]}]',
        )
        assert detect_suspicious_inbox_rules([event]) == []

    def test_rule_removal_not_flagged(self):
        event = self._event(
            RuleOperation="RemoveMailboxRule", RuleName="x",
            RuleActions='[{"ActionType":"Forward","Recipients":["drop@evil.com"]}]',
        )
        assert detect_suspicious_inbox_rules([event]) == []

    def test_outlook_delete_flagged(self):
        event = self._event(RuleOperation="AddMailboxRule", RuleName="x",
                            RuleActions='[{"ActionType":"Delete"}]')
        assert len(detect_suspicious_inbox_rules([event])) == 1


class TestMailboxForwarding:

    def _event(self, **params):
        return {
            "Id": "mf-1",
            "Operation": "Set-Mailbox",
            "UserId": "victim@contoso.com",
            "Parameters": _params(Identity="victim", **params),
        }

    def test_external_smtp_forwarding_high(self):
        from compromise_detector import detect_mailbox_forwarding
        findings = detect_mailbox_forwarding([self._event(
            ForwardingSmtpAddress="smtp:drop@evil.com", DeliverToMailboxAndForward="False")])
        assert len(findings) == 1
        assert findings[0]["type"] == "mailbox_forwarding"
        assert findings[0]["severity"] == "high"
        assert "copy" in findings[0]["description"]

    def test_internal_recipient_medium(self):
        from compromise_detector import detect_mailbox_forwarding
        findings = detect_mailbox_forwarding([self._event(ForwardingAddress="boss@contoso.com")])
        assert len(findings) == 1
        assert findings[0]["severity"] == "medium"

    def test_forwarding_removed_not_flagged(self):
        from compromise_detector import detect_mailbox_forwarding
        assert detect_mailbox_forwarding([self._event(ForwardingSmtpAddress="")]) == []

    def test_other_set_mailbox_change_not_flagged(self):
        from compromise_detector import detect_mailbox_forwarding
        assert detect_mailbox_forwarding([self._event(ProhibitSendQuota="50GB")]) == []


class TestConsentGaps:

    def test_app_role_assignment_flagged(self):
        # Application permission grant. Old code did not read AppRole.Value.
        event = {
            "Operation": "Add app role assignment to service principal.",
            "UserId": "admin@contoso.com",
            "ModifiedProperties": [
                {"Name": "AppRole.Value", "NewValue": "full_access_as_app", "OldValue": ""},
                {"Name": "ServicePrincipal.DisplayName", "NewValue": "Evil Mailer", "OldValue": ""},
            ],
        }
        findings = detect_suspicious_oauth_consents([event])
        assert len(findings) == 1
        assert "full_access_as_app" in findings[0]["description"]
        assert "Evil Mailer" in findings[0]["description"]

    def test_real_consent_format(self):
        value = ("[] => [[Id: abc, ClientId: def, PrincipalId: ghi, ResourceId: jkl, "
                 "ConsentType: Principal, Scope: EWS.AccessAsUser.All User.Read offline_access, "
                 "CreatedDateTime: , LastModifiedDateTime ]]; ")
        event = {
            "Operation": "Consent to application.",
            "UserId": "victim@contoso.com",
            "ModifiedProperties": [{"Name": "ConsentAction.Permissions", "NewValue": value}],
        }
        findings = detect_suspicious_oauth_consents([event])
        assert len(findings) == 1
        assert findings[0]["description"].endswith("risky scopes: EWS.AccessAsUser.All")
