"""Record shapes seen in real Management Activity API data.

Each test reproduces a format detail found in public sample records (Elastic
integration test data, Microsoft Sentinel samples, Panther tests) or in the
Microsoft schema and Learn pages. The records here are written for these tests;
they copy the shape, not the data.
"""

import json
import os

import pytest

import compromise_detector as cd
import config
import geo_monitor
import o365_client
from ip_checker import extract_ip


# ---------------------------------------------------------------------------
# Types: RecordType, UserType, and IdentityType can be strings
# ---------------------------------------------------------------------------

class TestStringTypes:

    @pytest.mark.parametrize("value", [15, "15", 9, "9"])
    def test_login_filter_accepts_int_and_string(self, value):
        assert o365_client.filter_login_records([{"RecordType": value, "Operation": "UserLoggedIn"}])

    @pytest.mark.parametrize("value", [8, "8", None, "", "x"])
    def test_login_filter_rejects_other_types(self, value):
        assert o365_client.filter_login_records([{"RecordType": value}]) == []

    def test_target_type_as_string(self):
        event = {"Operation": "Add member to role.", "UserId": "admin@contoso.com", "ObjectId": "Not Available",
                 "Target": [{"ID": "User_1", "Type": "2"}, {"ID": "new@contoso.com", "Type": "5"}],
                 "ModifiedProperties": [{"Name": "Role.DisplayName", "OldValue": "", "NewValue": "Global Administrator"}]}
        f = cd.detect_admin_roles([event])[0]
        assert "new@contoso.com" in f["description"]

    def test_app_name_from_string_type_target(self):
        # Entra ID records put the app display name in Target type 1 (Name).
        event = {"Operation": "Update application – Certificates and secrets management ",
                 "UserId": "admin@contoso.com", "ObjectId": "Not Available",
                 "Target": [{"ID": "Application_1", "Type": "2"}, {"ID": "Payroll", "Type": "1"}]}
        assert "'Payroll'" in cd.detect_app_credentials([event])[0]["description"]

    def test_app_name_from_target_name_property(self):
        event = {"Operation": "Add service principal credentials.", "UserId": "admin@contoso.com",
                 "ObjectId": "Not Available", "ExtendedProperties": [{"Name": "targetName", "Value": "Sync"}]}
        assert "'Sync'" in cd.detect_app_credentials([event])[0]["description"]


# ---------------------------------------------------------------------------
# Operation names
# ---------------------------------------------------------------------------

class TestOperationNames:

    def test_case_insensitive(self):
        # Learn writes "Set company information."; Splunk and Sigma use "Set Company Information.".
        event = {"Operation": "Set company information.", "UserId": "admin@contoso.com",
                 "ModifiedProperties": [{"Name": "StrongAuthenticationPolicy", "OldValue": "", "NewValue": "x"}]}
        assert cd.detect_mfa_changes([event])[0]["type"] == "mfa_change"

    @pytest.mark.parametrize("operation", [
        "Update application – Certificates and secrets management ",   # en dash, trailing space (real)
        "Update application - Certificates and secrets management",    # hyphen
        "update application – certificates and secrets management",
    ])
    def test_app_credential_operation_variants(self, operation):
        assert cd.detect_app_credentials([{"Operation": operation, "UserId": "a@contoso.com"}])

    @pytest.mark.parametrize("operation", ["Add domain to company.", "Verify domain."])
    def test_domain_operations_from_purview_list(self, operation):
        f = cd.detect_domain_federation([{"Operation": operation, "UserId": "a@contoso.com", "ObjectId": "evil.com"}])
        assert f and f[0]["severity"] == "medium"


# ---------------------------------------------------------------------------
# IP fields
# ---------------------------------------------------------------------------

class TestIpFields:

    @pytest.mark.parametrize("event,expected", [
        ({"ClientIP": "198.51.100.20:54321"}, "198.51.100.20"),           # Exchange admin: port
        ({"ClientIP": "[2001:db8::5]:443"}, "2001:db8::5"),               # IPv6 with port
        ({"ClientIP": None, "ActorIpAddress": "203.0.113.7"}, "203.0.113.7"),   # Entra admin: ClientIP null
        ({"ClientIP": "", "ActorIpAddress": ""}, None),
        ({"ClientIPAddress": "203.0.113.8"}, "203.0.113.8"),              # Exchange mailbox schema
        ({"ActorIP": "203.0.113.9"}, "203.0.113.9"),
        ({"ClientIP": "::1", "ClientIPAddress": "52.96.1.10"}, "52.96.1.10"),  # prefer public
        ({"ClientIP": "::1"}, "::1"),
        ({"ClientIP": "52.96.1.11, 10.0.0.1"}, "52.96.1.11"),
        ({"ClientIP": "10.0.0.1", "ActorIpAddress": "52.96.1.12"}, "52.96.1.12"),
        # Documentation ranges count as private in Python; they are still returned if alone.
        ({"ExtendedProperties": [{"Name": "ClientIPAddress", "Value": "203.0.113.12"}]}, "203.0.113.12"),
    ])
    def test_extract_ip(self, event, expected):
        assert extract_ip(event) == expected


# ---------------------------------------------------------------------------
# Sign-in errors: ErrorNumber or only LogonError
# ---------------------------------------------------------------------------

class TestSignInErrors:

    @pytest.mark.parametrize("record,code", [
        ({"ErrorNumber": "50126"}, "50126"),
        ({"ErrorNumber": 50074}, "50074"),
        ({"ErrorCode": "50076"}, "50076"),
        ({"LogonError": "UserStrongAuthClientAuthNRequiredInterrupt"}, "50074"),
        ({"LogonError": "InvalidUserNameOrPassword"}, "50126"),
        ({"LogonError": "SomethingNew"}, ""),
        ({}, ""),
    ])
    def test_error_code(self, record, code):
        assert config.sign_in_error_code(record) == code

    def test_mfa_interrupt_with_name_only_is_password_ok(self):
        record = {"Operation": "UserLoginFailed", "LogonError": "UserStrongAuthClientAuthNRequiredInterrupt"}
        assert geo_monitor.sign_in_outcome(record) == "password_ok"
        assert o365_client.login_result(record) == "Failed (50074)"

    def test_unknown_name_is_shown(self):
        record = {"Operation": "UserLoginFailed", "LogonError": "SomethingNew"}
        assert o365_client.login_result(record) == "Failed (SomethingNew)"
        assert geo_monitor.sign_in_outcome(record) == "failed"

    def test_every_mapped_name_has_an_alert_label(self):
        import alerting
        assert set(config.LOGON_ERROR_CODES.values()) <= set(alerting._SIGNIN_ERRORS)


# ---------------------------------------------------------------------------
# Failed operations and system actors
# ---------------------------------------------------------------------------

class TestFailedAndSystem:

    @pytest.mark.parametrize("status", ["False", "Failed", "Failure"])
    def test_failed_cmdlet_ignored(self, status):
        event = {"Operation": "New-TransportRule", "UserId": "a@contoso.com", "ResultStatus": status,
                 "Parameters": [{"Name": "BlindCopyTo", "Value": "x@evil.com"}]}
        assert cd.detect_mail_flow_rules([event]) == []

    @pytest.mark.parametrize("status", ["True", "Succeeded", "Success", "", None])
    def test_succeeded_cmdlet_flagged(self, status):
        event = {"Operation": "New-TransportRule", "UserId": "a@contoso.com", "ResultStatus": status,
                 "Parameters": [{"Name": "BlindCopyTo", "Value": "x@evil.com"}]}
        assert cd.detect_mail_flow_rules([event])

    def test_failed_sign_in_with_attack_tool_still_flagged(self):
        event = {"Operation": "UserLoginFailed", "ResultStatus": "Failed", "UserId": "u@contoso.com",
                 "ExtendedProperties": [{"Name": "UserAgent", "Value": "AADInternals"}]}
        assert cd.detect_suspicious_user_agents([event])

    @pytest.mark.parametrize("actor,user_type", [
        ("NT AUTHORITY\\SYSTEM (Microsoft.Exchange.ServiceHost)", "3"),
        ("S-1-5-18", "2"),
        ("svc@contoso.com", 4),
    ])
    def test_system_actor_permission_ignored(self, actor, user_type):
        event = {"Operation": "Add-MailboxPermission", "UserId": actor, "UserType": user_type,
                 "Parameters": [{"Name": "Identity", "Value": "a"}, {"Name": "User", "Value": "b"},
                                {"Name": "AccessRights", "Value": "FullAccess"}]}
        assert cd.detect_mailbox_delegation([event]) == []


# ---------------------------------------------------------------------------
# Exchange values
# ---------------------------------------------------------------------------

class TestExchangeValues:

    def test_hosted_organization_identity_is_shortened(self):
        dn = "NAMPR01A001.prod.outlook.com/Microsoft Exchange Hosted Organizations/contoso.onmicrosoft.com/CEO"
        event = {"Operation": "Add-MailboxPermission", "UserId": "admin@contoso.com", "UserType": "2",
                 "Parameters": [{"Name": "Identity", "Value": dn}, {"Name": "User", "Value": "intern@contoso.com"},
                                {"Name": "AccessRights", "Value": "FullAccess"}]}
        desc = cd.detect_mailbox_delegation([event])[0]["description"]
        assert "'CEO'" in desc and "Hosted Organizations" not in desc

    @pytest.mark.parametrize("rights", ["ChangePermission", "ChangeOwner", "FullAccess, ReadPermission"])
    def test_elevated_mailbox_rights(self, rights):
        event = {"Operation": "Add-MailboxPermission", "UserId": "admin@contoso.com", "UserType": "2",
                 "Parameters": [{"Name": "Identity", "Value": "ceo"}, {"Name": "User", "Value": "x"},
                                {"Name": "AccessRights", "Value": rights}]}
        assert cd.detect_mailbox_delegation([event])

    def test_inbox_rule_name_from_object_id_path(self):
        event = {"Operation": "Set-InboxRule", "UserId": "victim@contoso.com",
                 "ObjectId": "NAMPR01A001.prod.outlook.com/Microsoft Exchange Hosted Organizations/contoso/victim/.",
                 "Parameters": [{"Name": "MarkAsRead", "Value": "True"}]}
        f = cd.detect_suspicious_inbox_rules([event])[0]
        assert "no letters or digits" in f["description"]


# ---------------------------------------------------------------------------
# Folder sharing from Outlook (mailbox audit record)
# ---------------------------------------------------------------------------

def _folder_event(operation="UpdateFolderPermissions", name="Inbox", member="Everyone",
                  rights="ReadAny, Visible", actor="victim@contoso.com"):
    return {"Operation": operation, "RecordType": 2, "UserId": actor, "UserType": 0,
            "MailboxOwnerUPN": "victim@contoso.com", "ClientIPAddress": "203.0.113.4",
            "Item": {"ParentFolder": {"Name": name, "Path": f"\\{name}", "MemberUpn": member, "MemberRights": rights}}}


class TestOutlookFolderSharing:

    @pytest.mark.parametrize("operation", ["UpdateFolderPermissions", "ModifyFolderPermissions", "AddFolderPermissions"])
    def test_inbox_shared_with_everyone(self, operation):
        f = cd.detect_mailbox_delegation([_folder_event(operation)])[0]
        assert f["type"] == "mailbox_delegation" and "everyone in the organization" in f["description"]
        assert f["ip"] == "203.0.113.4" and f["user"] == "victim@contoso.com"

    def test_shared_externally(self):
        f = cd.detect_mailbox_delegation([_folder_event(member="spy@evil.com")])[0]
        assert "spy@evil.com" in f["description"]

    @pytest.mark.parametrize("kwargs", [
        {"name": "Calendar"},                                   # calendar sharing is normal
        {"member": "pa@contoso.com"},                           # one internal person
        {"rights": "FreeBusySimple"},                           # no read right
        {"actor": "S-1-5-18"},                                  # service
    ])
    def test_normal_sharing_ignored(self, kwargs):
        assert cd.detect_mailbox_delegation([_folder_event(**kwargs)]) == []

    def test_sid_actor_uses_mailbox_owner(self):
        event = _folder_event(actor="S-1-5-21-1-2-3-1001")
        event["UserType"] = 2
        f = cd.detect_mailbox_delegation([event])
        assert f and f[0]["user"] == "victim@contoso.com"


# ---------------------------------------------------------------------------
# MFA records written by the MFA service
# ---------------------------------------------------------------------------

class TestMfaServiceActor:

    def test_service_principal_actor_name(self):
        new = json.dumps([{"MethodType": 6, "Default": True}, {"MethodType": 7, "Default": False}])
        old = json.dumps([{"MethodType": 6, "Default": True}])
        event = {"Operation": "Update user.", "RecordType": 8, "UserId": "ServicePrincipal_1a2b", "UserType": 4,
                 "ObjectId": "victim@contoso.com",
                 "Actor": [{"ID": "Azure MFA StrongAuthenticationService", "Type": 1},
                           {"ID": "ServicePrincipal_1a2b", "Type": 2}],
                 "Target": [{"ID": "User_1", "Type": 2}, {"ID": "victim@contoso.com", "Type": 5}],
                 "ModifiedProperties": [{"Name": "StrongAuthenticationMethod", "OldValue": old, "NewValue": new}]}
        f = cd.detect_mfa_changes([event])[0]
        assert f["user"] == "victim@contoso.com"
        assert "record written by Azure MFA StrongAuthenticationService" in f["description"]

    def test_pretty_printed_json_with_crlf(self):
        old = "[\r\n  {\r\n    \"DeviceName\": \"iPhone\",\r\n    \"DeviceToken\": \"a\"\r\n  }\r\n]"
        new = ("[\r\n  {\r\n    \"DeviceName\": \"iPhone\",\r\n    \"DeviceToken\": \"a\"\r\n  },\r\n"
               "  {\r\n    \"DeviceName\": \"Pixel\",\r\n    \"DeviceToken\": \"b\"\r\n  }\r\n]")
        event = {"Operation": "Update user.", "UserId": "u@contoso.com", "ObjectId": "u@contoso.com",
                 "ModifiedProperties": [{"Name": "StrongAuthenticationPhoneAppDetail", "OldValue": old, "NewValue": new}]}
        assert cd.detect_mfa_changes([event])

    def test_same_count_with_changed_details_ignored(self):
        old = json.dumps([{"DeviceName": "NO_DEVICE", "OathTokenTimeDrift": 0}])
        new = json.dumps([{"DeviceName": "NO_DEVICE", "OathTokenTimeDrift": -1}])
        event = {"Operation": "Update user.", "UserId": "svc@contoso.com", "ObjectId": "u@contoso.com",
                 "ModifiedProperties": [{"Name": "StrongAuthenticationPhoneAppDetail", "OldValue": old, "NewValue": new}]}
        assert cd.detect_mfa_changes([event]) == []


# ---------------------------------------------------------------------------
# Consent records
# ---------------------------------------------------------------------------

class TestConsentFormat:

    def test_old_and_new_permission_lists(self):
        # ConsentAction.Permissions is "[[... Scope: a b]] => [[... Scope: a b c]]; ".
        value = ("[[Id: x, ClientId: y, PrincipalId: , ResourceId: z, ConsentType: AllPrincipals, Scope: User.Read]] => "
                 "[[Id: x, ClientId: y, PrincipalId: , ResourceId: z, ConsentType: AllPrincipals, "
                 "Scope: User.Read Mail.Read]]; ")
        event = {"Operation": "Consent to application.", "UserId": "u@contoso.com", "ClientIP": "",
                 "ActorIpAddress": "203.0.113.30",
                 "Target": [{"ID": "ServicePrincipal_1", "Type": "2"}, {"ID": "Evil App", "Type": "1"}],
                 "ModifiedProperties": [{"Name": "ConsentAction.Permissions", "OldValue": "", "NewValue": value}]}
        f = cd.detect_suspicious_oauth_consents([event])[0]
        assert "Mail.Read" in f["description"] and "Evil App" in f["description"]
        assert f["ip"] == "203.0.113.30"


def test_sample_file_names_documented():
    """API Compatibility lists the record fields that these tests cover."""
    doc = open(os.path.join(os.path.dirname(__file__), "..", "docs", "API_COMPATIBILITY.md")).read()
    for term in ("UpdateFolderPermissions", "LogonError", "ClientIPAddress", "IdentityType"):
        assert term in doc, term


# ---------------------------------------------------------------------------
# UpdateInboxRules (Outlook desktop and EWS). Shapes from real records:
# Splunk attack_data, SEKOIA intake-format tests, Red Canary.
# ---------------------------------------------------------------------------

def _uir(client="Client=MSExchangeRPC", user="victim@contoso.com", **props):
    ops = []
    for name, value in props.items():
        ops.append({"Name": name} if value is None else {"Name": name, "Value": value})
    return {"Operation": "UpdateInboxRules", "RecordType": 2, "UserId": user, "ResultStatus": "Succeeded",
            "ClientInfoString": client, "ClientIP": "52.96.1.20", "ClientIPAddress": "52.96.1.20",
            "OperationProperties": ops}


class TestUpdateInboxRulesFormats:

    def test_outlook_forward(self):
        event = _uir(RuleOperation="AddMailboxRule", RuleId="-123", RuleState="Enabled",
                     RuleCondition="{(SenderSearchKey Equal SMTP:vendor@partner.com)}", RuleName=None,
                     RuleProvider="RuleOrganizer",
                     RuleActions='[{"ActionType":"Forward","Recipients":["drop@evil.com"],'
                                 '"ForwardFlags":"PreserveSender, DoNotChangeMessage"}]')
        f = cd.detect_suspicious_inbox_rules([event])[0]
        assert f["severity"] == "high" and "drop@evil.com" in f["description"]
        assert "partner.com" not in f["description"]   # condition address is not a target
        assert f["ip"] == "52.96.1.20"

    def test_ews_rule_by_script(self):
        server_rule = json.dumps({
            "ID": 0, "Condition": {"PropValue": {"Value": "vendor@partner.com"}},
            "Actions": [{"ActionType": 7, "Recipients": [{"Values": [
                {"PropType": 31, "Value": "haag@evil.com"}, {"PropType": 258, "Value": "AAAAgUt6hA=="}]}]}]})
        event = _uir(client="Client=WebServices;python-requests/2.25.1;",
                     Actions="ForwardToRecipientsAction", Conditions="ContainsBodyStringCondition",
                     Provider="RuleOrganizer", RemoveOutlookRuleBlob=None, Name="haags rule",
                     IsNew="True", IsDirty="True", RuleOperation="Create", ServerRule=server_rule)
        f = cd.detect_suspicious_inbox_rules([event])[0]
        assert f["severity"] == "high"
        assert "haag@evil.com" in f["description"] and "partner.com" not in f["description"]
        assert "python-requests" in f["description"]

    def test_script_made_rule_without_forward_is_high(self):
        event = _uir(client="Client=WebServices;python-requests/2.31.0;", Actions="MarkAsReadAction",
                     Name="Sort", RuleOperation="Create", ServerRule="{}")
        assert cd.detect_suspicious_inbox_rules([event])[0]["severity"] == "high"

    def test_client_side_rule_ignored(self):
        event = _uir(RuleOperation="ModifyMailboxRule", RuleName="MyRule",
                     RuleActions='[{"ActionType":"DeferAction","LengthOfDeferData":"1453"}]')
        assert cd.detect_suspicious_inbox_rules([event]) == []

    def test_removal_ignored(self):
        event = _uir(RuleOperation="RemoveMailboxRule", RuleName="Exfil", RuleActions="[]")
        assert cd.detect_suspicious_inbox_rules([event]) == []

    def test_internal_forward_ignored(self):
        event = _uir(RuleOperation="AddMailboxRule", RuleName="To boss",
                     RuleActions='[{"ActionType":"Forward","Recipients":["boss@contoso.com"],"ForwardFlags":"None"}]')
        assert cd.detect_suspicious_inbox_rules([event]) == []

    def test_forward_to_x500_only(self):
        event = _uir(RuleOperation="AddMailboxRule", RuleName="Fwd",
                     RuleActions='[{"ActionType":"Forward","Recipients":["/o=ExchangeLabs/ou=Exchange/cn=Recipients/cn=x"]}]')
        f = cd.detect_suspicious_inbox_rules([event])[0]
        assert "no SMTP address" in f["description"]

    def test_outlook_delete(self):
        event = _uir(RuleOperation="AddMailboxRule", RuleName="Clean", RuleActions='[{"ActionType":"Delete"}]')
        assert "deletes" in cd.detect_suspicious_inbox_rules([event])[0]["description"]


# ---------------------------------------------------------------------------
# Management API requests carry PublisherIdentifier (dedicated quota)
# ---------------------------------------------------------------------------

def test_publisher_identifier_on_listing_and_content():
    from datetime import datetime, timezone
    from unittest.mock import MagicMock, patch
    listing = MagicMock(status_code=200, headers={})
    listing.json.return_value = [{"contentUri": "https://manage.office.com/api/v1.0/t/activity/feed/audit/1"}]
    blob = MagicMock(status_code=200)
    blob.json.return_value = []
    with patch.object(o365_client.token_manager, "get_o365_token", return_value="tok"), \
            patch.object(config.http, "get", side_effect=[listing, blob]) as get:
        now = datetime.now(timezone.utc)
        urls = o365_client.fetch_audit_content_urls("Audit.Exchange", now, now)
        o365_client.fetch_audit_events(urls[0])
    assert get.call_args_list[0].kwargs["params"]["PublisherIdentifier"] == config.TENANT_ID
    assert get.call_args_list[1].kwargs["params"] == {"PublisherIdentifier": config.TENANT_ID}



# ---------------------------------------------------------------------------
# MFA phone numbers (StrongAuthenticationUserDetails), shape from Splunk
# attack_data and Microsoft's September 2026 MFA-manipulation guidance.
# ---------------------------------------------------------------------------

def _details(phone):
    return json.dumps([{"PhoneNumber": phone, "AlternativePhoneNumber": None, "Email": None,
                        "VoiceOnlyPhoneNumber": None}]) if phone else "[]"


def _user_update(old, new):
    return {"Operation": "Update user.", "RecordType": 8, "UserId": "ServicePrincipal_1", "UserType": 4,
            "ObjectId": "victim@contoso.com",
            "Actor": [{"ID": "Azure Credential Configuration Endpoint Service", "Type": 1}],
            "ModifiedProperties": [{"Name": "StrongAuthenticationUserDetails", "OldValue": old, "NewValue": new}]}


class TestMfaPhoneNumbers:

    def test_phone_replaced(self):
        f = cd.detect_mfa_changes([_user_update(_details("+1 5550100"), _details("+44 7700900123"))])[0]
        assert "+44 7700900123" in f["description"] and f["user"] == "victim@contoso.com"
        assert "Azure Credential Configuration Endpoint Service" in f["description"]

    def test_first_phone_ignored(self):
        assert cd.detect_mfa_changes([_user_update("[]", _details("+1 5550100"))]) == []

    def test_unchanged_or_removed_ignored(self):
        assert cd.detect_mfa_changes([_user_update(_details("+1 5550100"), _details("+1 5550100"))]) == []
        assert cd.detect_mfa_changes([_user_update(_details("+1 5550100"), "[]")]) == []
