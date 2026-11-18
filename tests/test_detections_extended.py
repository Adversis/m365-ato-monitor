"""Detections added after a comparison with public rule sets (Elastic, Splunk, Sigma).

Record shapes follow the fields those rules read from the Management
Activity API: Exchange admin cmdlets put arguments in Parameters; Entra ID
audit records put changes in ModifiedProperties; sign-ins put the user agent
and request type in ExtendedProperties.
"""

import json
from unittest.mock import MagicMock, patch

import pytest

import compromise_detector as cd
import config


def _params(**kv):
    return [{"Name": k, "Value": v} for k, v in kv.items()]


def _cmdlet(operation, actor="admin@contoso.com", **params):
    return {"Id": f"id-{operation}", "RecordType": 1, "Operation": operation, "UserId": actor,
            "UserType": 2, "ClientIP": "198.51.100.7", "Parameters": _params(**params)}


def _aad(operation, actor="admin@contoso.com", props=None, target="user@contoso.com", **extra):
    event = {"Id": f"id-{operation}", "RecordType": 8, "Operation": operation, "UserId": actor,
             "ObjectId": target, "Target": [{"Type": 5, "ID": target}],
             "ModifiedProperties": [{"Name": n, "OldValue": o, "NewValue": v} for n, o, v in (props or [])]}
    event.update(extra)
    return event


def _one(findings, ftype, severity):
    assert len(findings) == 1, findings
    assert findings[0]["type"] == ftype
    assert findings[0]["severity"] == severity
    return findings[0]


# ---------------------------------------------------------------------------
# Inbox rules: name and keyword heuristics
# ---------------------------------------------------------------------------

class TestInboxRuleHeuristics:

    def _rule(self, op="New-InboxRule", **params):
        return {"Id": "r1", "Operation": op, "UserId": "victim@contoso.com", "Parameters": _params(**params)}

    def test_symbols_only_name_flagged(self):
        f = _one(cd.detect_suspicious_inbox_rules([self._rule(Name=".", MoveToFolder="Archive")]),
                 "inbox_rule", "medium")
        assert "no letters or digits" in f["description"]

    def test_symbols_only_name_without_action_flagged(self):
        _one(cd.detect_suspicious_inbox_rules([self._rule(Name="..", StopProcessingRules="True")]),
             "inbox_rule", "medium")

    def test_short_name_needs_hiding_action(self):
        assert cd.detect_suspicious_inbox_rules([self._rule(Name="ab", ForwardTo="boss@contoso.com")]) == []
        f = _one(cd.detect_suspicious_inbox_rules([self._rule(Name="ab", MarkAsRead="True")]),
                 "inbox_rule", "medium")
        assert "very short name" in f["description"]

    def test_set_inbox_rule_name_from_identity(self):
        event = self._rule(op="Set-InboxRule", Identity="victim@contoso.com\\.", MarkAsRead="True")
        _one(cd.detect_suspicious_inbox_rules([event]), "inbox_rule", "medium")

    def test_keyword_with_mark_as_read_and_move(self):
        event = self._rule(Name="Sort vendors", SubjectOrBodyContainsWords="invoice;wire",
                           MarkAsRead="True", MoveToFolder="Archive")
        f = _one(cd.detect_suspicious_inbox_rules([event]), "inbox_rule", "medium")
        assert "'invoice'" in f["description"] and "marks it as read" in f["description"]

    def test_keyword_without_hiding_action_not_flagged(self):
        event = self._rule(Name="Flag invoices", SubjectContainsWords="invoice", ApplyCategory="Finance")
        assert cd.detect_suspicious_inbox_rules([event]) == []

    def test_keyword_with_hidden_folder_is_high(self):
        event = self._rule(Name="Clean", SubjectContainsWords="password reset", MoveToFolder="RSS Feeds")
        f = _one(cd.detect_suspicious_inbox_rules([event]), "inbox_rule", "high")
        assert "hidden folder" in f["description"] and "'password'" in f["description"]

    def test_calendar_folder_is_hidden(self):
        _one(cd.detect_suspicious_inbox_rules([self._rule(Name="Tidy", MoveToFolder="Calendar")]),
             "inbox_rule", "high")

    def test_keywords_setting_is_used(self):
        event = self._rule(Name="Sort", SubjectContainsWords="quarterly", MarkAsRead="True")
        assert cd.detect_suspicious_inbox_rules([event]) == []
        with patch.object(cd.config, "INBOX_RULE_KEYWORDS", ["quarterly"]):
            _one(cd.detect_suspicious_inbox_rules([event]), "inbox_rule", "medium")


# ---------------------------------------------------------------------------
# Sign-in methods
# ---------------------------------------------------------------------------

class TestSignInMethods:

    def _signin(self, operation="UserLoggedIn", ua="Mozilla/5.0", request_type="OAuth2:Authorize"):
        return {"Id": "s1", "RecordType": 15, "Operation": operation, "UserId": "u@contoso.com",
                "ClientIP": "203.0.113.9",
                "ExtendedProperties": [{"Name": "UserAgent", "Value": ua},
                                       {"Name": "RequestType", "Value": request_type}]}

    def test_legacy_auth_success_is_high(self):
        f = _one(cd.detect_sign_in_methods([self._signin(ua="BAV2ROPC")]), "legacy_auth", "high")
        assert f["ip"] == "203.0.113.9"

    def test_legacy_auth_failure_ignored(self):
        assert cd.detect_sign_in_methods([self._signin("UserLoginFailed", ua="BAV2ROPC")]) == []

    def test_device_code_success_is_medium(self):
        _one(cd.detect_sign_in_methods([self._signin(request_type="Cmsi:Cmsi")]), "device_code", "medium")

    def test_normal_sign_in_ignored(self):
        assert cd.detect_sign_in_methods([self._signin()]) == []

    def test_undici_is_an_automation_user_agent(self):
        findings = cd.detect_suspicious_user_agents([self._signin(ua="undici")])
        _one(findings, "suspicious_user_agent", "medium")


# ---------------------------------------------------------------------------
# Mail flow rules
# ---------------------------------------------------------------------------

class TestMailFlowRules:

    def test_external_blind_copy_is_high(self):
        f = _one(cd.detect_mail_flow_rules([_cmdlet("New-TransportRule", Name="Journal",
                                                     BlindCopyTo="drop@evil.com")]),
                 "mail_flow_rule", "high")
        assert "evil.com" in f["description"] and f["user"] == "admin@contoso.com"

    def test_redirect_and_delete_are_high(self):
        event = _cmdlet("Set-TransportRule", Identity="R", RedirectMessageTo="x@evil.com", DeleteMessage="True")
        f = _one(cd.detect_mail_flow_rules([event]), "mail_flow_rule", "high")
        assert "redirects mail" in f["description"] and "deletes" in f["description"]

    def test_new_rule_without_risky_action(self):
        event = _cmdlet("New-TransportRule", Name="Disclaimer", ApplyHtmlDisclaimerText="Confidential")
        assert cd.detect_mail_flow_rules([event]) == []          # default: only risky rules
        with patch.object(cd.config, "MAIL_FLOW_RULE_ANY", True):
            f = _one(cd.detect_mail_flow_rules([event]), "mail_flow_rule", "medium")
        assert "was created" in f["description"]

    def test_benign_change_ignored(self):
        assert cd.detect_mail_flow_rules([_cmdlet("Set-TransportRule", Identity="Disclaimer",
                                                  Priority="1")]) == []

    def test_spam_bypass_is_medium(self):
        f = _one(cd.detect_mail_flow_rules([_cmdlet("Set-TransportRule", Identity="R",
                                                    SenderDomainIs="evil.com", SetSCL="-1")]),
                 "mail_flow_rule", "medium")
        assert "SCL -1" in f["description"]


# ---------------------------------------------------------------------------
# Mailbox delegation
# ---------------------------------------------------------------------------

class TestMailboxDelegation:

    def test_full_access(self):
        f = _one(cd.detect_mailbox_delegation([_cmdlet("Add-MailboxPermission", Identity="ceo@contoso.com",
                                                       User="intern@contoso.com", AccessRights="FullAccess")]),
                 "mailbox_delegation", "medium")
        assert "ceo@contoso.com" in f["description"] and "intern@contoso.com" in f["description"]

    def test_read_permission_ignored(self):
        assert cd.detect_mailbox_delegation([_cmdlet("Add-MailboxPermission", Identity="a",
                                                     User="b", AccessRights="ReadPermission")]) == []

    def test_system_actor_ignored(self):
        event = _cmdlet("Add-MailboxPermission", actor="NT AUTHORITY\\SYSTEM (Microsoft.Exchange.ServiceHost)",
                        Identity="a", User="b", AccessRights="FullAccess")
        assert cd.detect_mailbox_delegation([event]) == []

    @pytest.mark.parametrize("prefix", ["NT SERVICE", "SERVICE"])
    def test_exchange_service_account_ignored(self, prefix):
        # Seen in a new tenant: Exchange grants Discovery Management FullAccess on the
        # DiscoverySearchMailbox again every few weeks. Records name the account with or without "NT".
        event = _cmdlet("Add-MailboxPermission",
                        actor=f"{prefix}\\MSExchangeAdminApiNetCore (Microsoft.Exchange.AdminApi.NetCore)",
                        Identity="DiscoverySearchMailbox{D919BA05-46A6-415f-80AD-7E09334BB852}",
                        User="Discovery Management", AccessRights="FullAccess")
        assert cd.detect_mailbox_delegation([event]) == []
        event["UserId"] = "admin@contoso.com"
        _one(cd.detect_mailbox_delegation([event]), "mailbox_delegation", "medium")

    @staticmethod
    def _group_folder_share(user_id, member):
        # The shape of a real record (made-up values): Exchange sets up a Microsoft 365 group mailbox.
        return {"Operation": "ModifyFolderPermissions", "RecordType": 2, "Workload": "Exchange",
                "ResultStatus": "Succeeded", "UserType": 2, "UserId": user_id, "LogonUserSid": user_id,
                "ClientIP": "::1", "ClientInfoString": "Client=WebServices;Action=ConfigureGroupMailbox",
                "MailboxOwnerUPN": "projects@contoso.com", "CreationTime": "2026-11-17T14:34:51",
                "Item": {"ParentFolder": {"Name": "Team Chat", "Path": "\\Conversation History\\Team Chat",
                                          "MemberUpn": member, "MemberSid": "S-1-8-1-2-3-4-0",
                                          "MemberRights": "ReadAny, Create, EditOwned, Visible"}}}

    def test_group_mailbox_setup_ignored(self):
        # Regression: "Folder '\Conversation History\Team Chat' was shared with Owner@local".
        service = "S-1-5-80-1111111111-2222222222-3333333333-4444444444-5555555555"
        assert cd.detect_mailbox_delegation([self._group_folder_share(service, "Owner@local")]) == []
        # Owner@local and Member@local are the group's owners and members, not outside addresses.
        assert cd.detect_mailbox_delegation([self._group_folder_share("admin@contoso.com", "Member@local")]) == []
        # A person who shares the folder outside still alerts, and so does a service SID's look-alike
        # that is a user SID.
        _one(cd.detect_mailbox_delegation([self._group_folder_share("admin@contoso.com", "x@fabrikam.com")]),
             "mailbox_delegation", "medium")
        _one(cd.detect_mailbox_delegation([self._group_folder_share("S-1-5-21-1-2-3-500", "x@fabrikam.com")]),
             "mailbox_delegation", "medium")

    def test_send_as(self):
        _one(cd.detect_mailbox_delegation([_cmdlet("Add-RecipientPermission", Identity="cfo@contoso.com",
                                                   Trustee="x@contoso.com", AccessRights="SendAs")]),
             "mailbox_delegation", "medium")

    def test_send_on_behalf(self):
        _one(cd.detect_mailbox_delegation([_cmdlet("Set-Mailbox", Identity="cfo@contoso.com",
                                                   GrantSendOnBehalfTo="x@contoso.com")]),
             "mailbox_delegation", "medium")
        assert cd.detect_mailbox_delegation([_cmdlet("Set-Mailbox", Identity="cfo", Office="HQ")]) == []

    def test_inbox_shared_with_everyone(self):
        f = _one(cd.detect_mailbox_delegation([_cmdlet("Add-MailboxFolderPermission",
                                                       Identity="cfo@contoso.com:\\Inbox",
                                                       User="Default", AccessRights="Reviewer")]),
                 "mailbox_delegation", "medium")
        assert "everyone in the organization" in f["description"]

    @pytest.mark.parametrize("identity,user,rights", [
        ("cfo@contoso.com:\\Calendar", "Default", "Reviewer"),     # calendar sharing is normal
        ("cfo@contoso.com:\\Inbox", "Default", "None"),            # no access
        ("cfo@contoso.com:\\Inbox", "pa@contoso.com", "Reviewer"),  # one internal person
    ])
    def test_normal_folder_sharing_ignored(self, identity, user, rights):
        event = _cmdlet("Set-MailboxFolderPermission", Identity=identity, User=user, AccessRights=rights)
        assert cd.detect_mailbox_delegation([event]) == []

    def test_inbox_shared_externally(self):
        _one(cd.detect_mailbox_delegation([_cmdlet("Add-MailboxFolderPermission",
                                                   Identity="cfo@contoso.com:\\Inbox",
                                                   User="spy@evil.com", AccessRights="Reviewer")]),
             "mailbox_delegation", "medium")


# ---------------------------------------------------------------------------
# Audit
# ---------------------------------------------------------------------------

class TestAuditDisabled:

    @pytest.mark.parametrize("operation,params", [
        ("Set-AdminAuditLogConfig", {"UnifiedAuditLogIngestionEnabled": "False"}),
        ("Set-OrganizationConfig", {"AuditDisabled": "True"}),
        ("Set-MailboxAuditBypassAssociation", {"Identity": "svc@contoso.com", "AuditBypassEnabled": "True"}),
        ("Set-Mailbox", {"Identity": "ceo@contoso.com", "AuditEnabled": "False"}),
    ])
    def test_audit_off_is_high(self, operation, params):
        _one(cd.detect_audit_disabled([_cmdlet(operation, **params)]), "audit_disabled", "high")

    def test_audit_on_ignored(self):
        assert cd.detect_audit_disabled([_cmdlet("Set-Mailbox", Identity="a", AuditEnabled="True")]) == []
        assert cd.detect_audit_disabled([_cmdlet("Set-AdminAuditLogConfig",
                                                 UnifiedAuditLogIngestionEnabled="True")]) == []


# ---------------------------------------------------------------------------
# Mail protection
# ---------------------------------------------------------------------------

class TestMailProtection:

    @pytest.mark.parametrize("operation", ["Remove-AntiPhishPolicy", "Disable-SafeLinksRule",
                                           "Remove-MalwareFilterRule", "Disable-HostedContentFilterRule"])
    def test_removed_or_disabled_is_medium(self, operation):
        _one(cd.detect_mail_protection_weakened([_cmdlet(operation, Identity="Default")]),
             "mail_protection_weakened", "medium")

    def test_dkim_off(self):
        _one(cd.detect_mail_protection_weakened([_cmdlet("Set-DkimSigningConfig", Identity="contoso.com",
                                                         Enabled="False")]),
             "mail_protection_weakened", "medium")

    def test_external_auto_forwarding_allowed_is_high(self):
        _one(cd.detect_mail_protection_weakened([_cmdlet("Set-HostedOutboundSpamFilterPolicy",
                                                         Identity="Default", AutoForwardingMode="On")]),
             "mail_protection_weakened", "high")
        assert cd.detect_mail_protection_weakened([_cmdlet("Set-HostedOutboundSpamFilterPolicy",
                                                           Identity="Default",
                                                           AutoForwardingMode="Automatic")]) == []

    def test_allowed_sender_domain(self):
        f = _one(cd.detect_mail_protection_weakened([_cmdlet("Set-HostedContentFilterPolicy", Identity="Default",
                                                             AllowedSenderDomains="evil.com")]),
                 "mail_protection_weakened", "medium")
        assert "evil.com" in f["description"]

    def test_new_policy_ignored(self):
        assert cd.detect_mail_protection_weakened([_cmdlet("New-AntiPhishPolicy", Name="Strict")]) == []


# ---------------------------------------------------------------------------
# MFA
# ---------------------------------------------------------------------------

def _methods(*types):
    return json.dumps([{"MethodType": t, "Default": i == 0} for i, t in enumerate(types)])


class TestMfaChanges:

    def test_method_added_to_account_with_mfa(self):
        event = _aad("Update user.", actor="victim@contoso.com", target="victim@contoso.com",
                     props=[("StrongAuthenticationMethod", _methods(6), _methods(6, 7))])
        f = _one(cd.detect_mfa_changes([event]), "mfa_change", "medium")
        assert f["user"] == "victim@contoso.com" and "Added: code from an authenticator app" in f["description"]

    def test_first_registration_ignored(self):
        event = _aad("Update user.", props=[("StrongAuthenticationMethod", "", _methods(6))])
        assert cd.detect_mfa_changes([event]) == []

    def test_authenticator_device_added(self):
        old = json.dumps([{"DeviceName": "iPhone", "DeviceToken": "a"}])
        new = json.dumps([{"DeviceName": "iPhone", "DeviceToken": "a"}, {"DeviceName": "Pixel", "DeviceToken": "b"}])
        event = _aad("Update user.", props=[("StrongAuthenticationPhoneAppDetail", old, new)])
        f = _one(cd.detect_mfa_changes([event]), "mfa_change", "medium")
        assert "Authenticator app device added: Pixel." in f["description"]

    def test_method_removed_ignored(self):
        event = _aad("Update user.", props=[("StrongAuthenticationMethod", _methods(6, 7), _methods(6))])
        assert cd.detect_mfa_changes([event]) == []

    def test_double_encoded_value(self):
        event = _aad("Update user.", props=[("StrongAuthenticationMethod",
                                             json.dumps(_methods(6)), json.dumps(_methods(6, 7)))])
        _one(cd.detect_mfa_changes([event]), "mfa_change", "medium")

    def test_per_user_mfa_disabled_is_high(self):
        f = _one(cd.detect_mfa_changes([_aad("Disable Strong Authentication.", target="cfo@contoso.com")]),
                 "mfa_change", "high")
        assert f["user"] == "cfo@contoso.com"

    def test_tenant_mfa_settings(self):
        event = _aad("Set Company Information.", props=[("StrongAuthenticationPolicy", "", "{...}")])
        _one(cd.detect_mfa_changes([event]), "mfa_change", "medium")
        assert cd.detect_mfa_changes([_aad("Set Company Information.",
                                           props=[("DisplayName", "", "Contoso")])]) == []


# ---------------------------------------------------------------------------
# Admin roles, app credentials, federation
# ---------------------------------------------------------------------------

class TestTenantChanges:

    def test_global_admin_is_high(self):
        event = _aad("Add member to role.", target="new@contoso.com",
                     props=[("Role.DisplayName", "", '"Global Administrator"')])
        f = _one(cd.detect_admin_roles([event]), "admin_role", "high")
        assert "new@contoso.com" in f["description"] and "Global Administrator" in f["description"]

    def test_microsoft_provisioning_of_a_first_party_app_ignored(self):
        spns = ("00000014-0000-0000-c000-000000000000/SyncFabric-int.windowsazure.net;"
                "00000014-0000-0000-c000-000000000000;https://syncfabric.windowsazure.com")
        event = _aad("Add member to role.", actor="Certificate", target=spns,
                     props=[("Role.DisplayName", "", "Directory Readers")])
        event["Target"] = [{"Type": 2, "ID": "ServicePrincipal_5a0e1c2d-0000-4000-8000-000000000001"}]
        assert cd.detect_admin_roles([event]) == []
        # A person adds the same app: alert, with a readable name.
        event["UserId"] = "admin@contoso.com"
        f = _one(cd.detect_admin_roles([event]), "admin_role", "medium")
        assert "the service principal of app 00000014-0000-0000-c000-000000000000" in f["description"]
        # "Certificate" and an app that is not a Microsoft first-party app: alert.
        event["UserId"] = "Certificate"
        event["ObjectId"] = "8b7a1f2e-1111-4222-8333-123456789abc;https://attacker.example"
        _one(cd.detect_admin_roles([event]), "admin_role", "medium")

    def test_other_role_is_medium(self):
        event = _aad("Add member to role.", props=[("Role.DisplayName", "", "Reports Reader")])
        _one(cd.detect_admin_roles([event]), "admin_role", "medium")

    def test_exchange_role_assignment(self):
        _one(cd.detect_admin_roles([_cmdlet("New-ManagementRoleAssignment", Role="ApplicationImpersonation",
                                            User="svc@contoso.com")]), "admin_role", "high")
        _one(cd.detect_admin_roles([_cmdlet("New-ManagementRoleAssignment", Role="Mail Recipients",
                                            User="helpdesk@contoso.com")]), "admin_role", "medium")

    def test_app_secret_added(self):
        event = _aad("Update application – Certificates and secrets management ", target="App",
                     Target=[{"Type": 1, "ID": "Payroll Sync"}])
        f = _one(cd.detect_app_credentials([event]), "app_credential", "medium")
        assert "Payroll Sync" in f["description"]

    def test_service_principal_credential_added(self):
        _one(cd.detect_app_credentials([_aad("Add service principal credentials.")]), "app_credential", "medium")
        assert cd.detect_app_credentials([_aad("Update application.")]) == []

    def test_federation_is_high(self):
        event = _aad("Set domain authentication.", target="contoso.com")
        f = _one(cd.detect_domain_federation([event]), "domain_federation", "high")
        assert "contoso.com" in f["description"]

    def test_domain_added_is_medium(self):
        _one(cd.detect_domain_federation([_aad("Add verified domain.", target="evil.com")]),
             "domain_federation", "medium")


# ---------------------------------------------------------------------------
# Pipeline and alert text
# ---------------------------------------------------------------------------

class TestPipeline:

    def test_all_detectors_registered(self):
        import function_app
        names = {d.__name__ for d in function_app._DETECTORS}
        public = {n for n in dir(cd) if n.startswith("detect_")}
        assert names == public

    def test_one_record_two_findings_have_different_keys(self):
        import function_app
        event = _cmdlet("Set-Mailbox", Identity="cfo@contoso.com", GrantSendOnBehalfTo="x@contoso.com",
                        AuditEnabled="False")
        findings = []
        for detector in function_app._DETECTORS:
            findings.extend(detector([event]))
        assert {f["type"] for f in findings} == {"mailbox_delegation", "audit_disabled"}
        assert len({function_app.finding_key(f) for f in findings}) == 2

    def test_detector_skips_bad_record(self):
        bad = {"Operation": "Update user.", "ModifiedProperties": "not a list"}
        good = _aad("Disable Strong Authentication.")
        assert len(cd.detect_mfa_changes([bad, good])) == 1


class TestAlertText:

    @patch("alerting.token_manager")
    @patch("config.http.post")
    def test_admin_change_email(self, mock_post, mock_tm):
        from alerting import send_compromise_alert
        mock_tm.get_graph_token.return_value = "t"
        mock_post.return_value = MagicMock(status_code=202)
        finding = cd.detect_mail_flow_rules([_cmdlet("New-TransportRule", Name="J", BlindCopyTo="d@evil.com")])[0]
        assert send_compromise_alert(finding) is True
        message = mock_post.call_args[1]["json"]["message"]
        assert message["subject"] == "[M365 Alert] HIGH: Mail flow rule - admin@contoso.com"
        body = message["body"]["content"]
        assert "Mail flow rule changed" in body
        assert "If no one on your team made this change" in body
        assert "Mail flow &gt; Rules" in body

    def test_every_type_has_title_and_steps(self):
        import alerting
        types = {"inbox_rule", "mailbox_forwarding", "oauth_consent", "attack_tool", "suspicious_user_agent",
                 "legacy_auth", "device_code", "mail_flow_rule", "mailbox_delegation", "audit_disabled",
                 "mail_protection_weakened", "mfa_change", "admin_role", "app_credential", "domain_federation"}
        assert types <= set(alerting._FINDING_TITLES)
        assert types <= set(alerting._FINDING_SHORT)
        assert types <= set(alerting._COMPROMISE_STEPS)


class TestDirectSend:

    def test_protection_turned_off_is_high(self):
        f = _one(cd.detect_mail_protection_weakened([_cmdlet("Set-OrganizationConfig", RejectDirectSend="False")]),
                 "mail_protection_weakened", "high")
        assert "Direct Send" in f["description"]

    def test_protection_turned_on_ignored(self):
        assert cd.detect_mail_protection_weakened([_cmdlet("Set-OrganizationConfig", RejectDirectSend="True")]) == []
        assert cd.detect_mail_protection_weakened([_cmdlet("Set-OrganizationConfig", AuditDisabled="False")]) == []


# ---------------------------------------------------------------------------
# False positives from service actors and the tenant's own domains
# ---------------------------------------------------------------------------

class TestTenantDomainsAndServiceActors:
    """A second verified domain is internal; Exchange service accounts are skipped in every detector."""

    def test_second_tenant_domain_is_internal(self, monkeypatch):
        event = _cmdlet("Set-Mailbox", actor="admin@contoso.com", Identity="sam@contoso.com",
                        ForwardingSmtpAddress="smtp:sam@contoso-brand.com")
        assert _one(cd.detect_mailbox_forwarding([event]), "mailbox_forwarding", "high")
        monkeypatch.setattr(config, "TENANT_DOMAINS", {"contoso.com", "contoso-brand.com"})
        _one(cd.detect_mailbox_forwarding([event]), "mailbox_forwarding", "medium")    # still a forwarding change
        rule = _cmdlet("New-InboxRule", actor="sam@contoso.com", Name="copy", ForwardTo="sam@contoso-brand.com")
        assert cd.detect_suspicious_inbox_rules([rule]) == []

    def test_sid_actor_uses_the_mailbox_owner_domain(self):
        # A mailbox audit record whose actor is a user SID: the owner's domain decides what is internal.
        rule = {"Operation": "UpdateInboxRules", "RecordType": 2, "Workload": "Exchange",
                "UserId": "S-1-5-21-1-2-3-1001", "MailboxOwnerUPN": "sam@contoso.com", "ClientIP": "198.51.100.7",
                "OperationProperties": [{"Name": "RuleName", "Value": "team"},
                                        {"Name": "RuleActions", "Value": json.dumps(
                                            [{"ActionType": "Forward", "Recipients": ["lee@contoso.com"]}])}]}
        assert cd.detect_suspicious_inbox_rules([rule]) == []
        rule["OperationProperties"][1]["Value"] = json.dumps([{"ActionType": "Forward",
                                                               "Recipients": ["x@fabrikam.com"]}])
        _one(cd.detect_suspicious_inbox_rules([rule]), "inbox_rule", "high")

    @pytest.mark.parametrize("actor", ["NT AUTHORITY\\SYSTEM (w3wp)", "S-1-5-80-1-2-3-4-5", "S-1-5-18"])
    def test_exchange_service_skipped_in_all_detectors(self, actor):
        events = [_cmdlet("Set-Mailbox", actor=actor, Identity="sam@contoso.com",
                          ForwardingSmtpAddress="smtp:x@fabrikam.com"),
                  _cmdlet("New-TransportRule", actor=actor, Name="r", BlindCopyTo="x@fabrikam.com"),
                  _cmdlet("Set-Mailbox", actor=actor, Identity="sam@contoso.com", AuditEnabled="False")]
        for detect in (cd.detect_mailbox_forwarding, cd.detect_mail_flow_rules, cd.detect_audit_disabled):
            assert detect(events) == []

    def test_entra_service_principal_is_not_skipped(self):
        # In Entra ID records UserType 4 is a service principal (the MFA service): not an Exchange service.
        event = _aad("Disable Strong Authentication.", actor="ServicePrincipal_1", UserType=4)
        _one(cd.detect_mfa_changes([event]), "mfa_change", "high")
