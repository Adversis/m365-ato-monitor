"""Alert switches, allowed networks (ASNs), and the automatic response to compromise alerts."""

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

import alerting
import config
import responder
import settings
from ip_checker import analyze_ip
from tests.fakes import FakeTable

NOW = datetime(2026, 11, 8, 12, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

class TestSettings:

    def test_alert_types_match_alert_titles(self):
        assert {t for t, _ in settings.ALERT_TYPES} == set(alerting._FINDING_TITLES)

    def test_alerts_off_validation(self):
        s = settings.BY_NAME["ALERTS_OFF"]
        assert settings.validate(s, ["mail_flow_rule", "device_code"]) == ["mail_flow_rule", "device_code"]
        assert settings.validate(s, []) == []
        with pytest.raises(ValueError):
            settings.validate(s, ["not_a_type"])

    @pytest.mark.parametrize("raw,expected", [
        (["AS21928", "as6167", "22394"], ["AS21928", "AS6167", "AS22394"]),
        ("AS21928\nAS21928", ["AS21928"]),
    ])
    def test_asn_validation(self, raw, expected):
        assert settings.validate(settings.BY_NAME["ALLOWED_ASNS"], raw) == expected

    @pytest.mark.parametrize("bad", [["T-Mobile"], ["AS"], ["AS-1"], ["99999999999"]])
    def test_asn_invalid(self, bad):
        with pytest.raises(ValueError):
            settings.validate(settings.BY_NAME["ALLOWED_ASNS"], bad)

    def test_apply_sets_config(self):
        try:
            settings.apply({"ALERTS_OFF": ["mail_flow_rule"], "ALLOWED_ASNS": ["AS21928"],
                            "COMPROMISE_ACTION": "revoke"})
            assert config.ALERTS_OFF == {"mail_flow_rule"}
            assert config.ALLOWED_ASNS == {"AS21928"}
            assert config.COMPROMISE_ACTION == "revoke"
            assert settings.current(settings.BY_NAME["ALERTS_OFF"]) == ["mail_flow_rule"]
        finally:
            settings.apply({})

    def test_response_options_need_permissions(self):
        s = settings.BY_NAME["COMPROMISE_ACTION"]
        assert settings.missing_roles(s, "revoke", ["Mail.Send"]) == ("User.RevokeSessions.All",)
        s = settings.BY_NAME["AUTO_DISABLE_INBOX_RULES"]
        assert settings.missing_roles(s, True, ["Mail.Send"]) == ("MailboxSettings.ReadWrite",)
        assert settings.missing_roles(s, True, ["MailboxSettings.ReadWrite"]) == ()


# ---------------------------------------------------------------------------
# Allowed networks
# ---------------------------------------------------------------------------

class TestAllowedAsns:

    VPN = {"proxy": "yes", "type": "VPN", "risk": 70, "asn": "AS21928", "organisation": "T-Mobile USA"}

    def test_flagged_without_allowlist(self):
        assert analyze_ip(self.VPN)["is_suspicious"] is True

    def test_allowed_asn_is_not_flagged(self):
        with patch.object(config, "ALLOWED_ASNS", {"AS21928"}):
            result = analyze_ip(self.VPN)
        assert result["is_suspicious"] is False and result["allowed_asn"] is True
        assert result["confidence"] == "none"

    def test_other_asn_still_flagged(self):
        with patch.object(config, "ALLOWED_ASNS", {"AS7018"}):
            assert analyze_ip(self.VPN)["is_suspicious"] is True

    @pytest.mark.parametrize("value,expected", [("AS21928", "AS21928"), ("21928", "AS21928"),
                                                (21928, "AS21928"), ("", ""), (None, ""), ("ASX", "")])
    def test_normalize(self, value, expected):
        assert config.normalize_asn(value) == expected


# ---------------------------------------------------------------------------
# Alert switches in the pipeline
# ---------------------------------------------------------------------------

def _rule_event(**params):
    return {"Id": "e1", "RecordType": 1, "Operation": "New-InboxRule", "UserId": "victim@contoso.com",
            "ClientIP": "198.51.100.5", "Parameters": [{"Name": k, "Value": v} for k, v in params.items()]}


class TestAlertSwitches:

    def _run(self, events, **cfg):
        import function_app as fa
        table = FakeTable()
        with patch.multiple(config, **cfg), \
                patch("function_app.check_ips_batch", return_value={}), \
                patch("function_app.send_compromise_alert", return_value=True) as send, \
                patch("responder.respond_to_finding", return_value="") as respond:
            fa._run_compromise_check(table, FakeTable(), set(), events)
        return send, respond, table

    def test_alert_type_off(self):
        send, respond, table = self._run([_rule_event(Name="x1", ForwardTo="a@evil.com")],
                                         ALERTS_OFF={"inbox_rule"})
        assert send.call_count == 0 and respond.call_count == 0
        assert any("inbox_rule_" in r["RowKey"] for r in table.rows.values())   # marked processed

    def test_other_types_still_sent(self):
        send, _, _ = self._run([_rule_event(Name="x1", ForwardTo="a@evil.com")], ALERTS_OFF={"mail_flow_rule"})
        assert send.call_count == 1


# ---------------------------------------------------------------------------
# Automatic response to compromise alerts
# ---------------------------------------------------------------------------

def _finding(ftype="inbox_rule", severity="high", user="victim@contoso.com", **extra):
    """A finding as the detectors make it: by default the user changed their own account."""
    f = {"type": ftype, "severity": severity, "user": user, "description": "d", "ip": None,
         "event": {"Id": "e1", "Operation": "New-InboxRule"}, "actor": user, "target": user}
    f.update(extra)
    return f


def _resp(status, body=None):
    r = MagicMock(status_code=status)
    r.json.return_value = body or {}
    return r


class TestCompromiseResponse:

    def test_nothing_configured(self):
        with patch.object(config, "COMPROMISE_ACTION", "none"), patch.object(config, "AUTO_DISABLE_INBOX_RULES", False):
            assert responder.respond_to_finding(FakeTable(), _finding(), NOW) == ""

    @pytest.mark.parametrize("finding", [
        _finding(severity="medium"),
        _finding(ftype="oauth_consent"),
        _finding(ftype="mail_flow_rule", user="admin@contoso.com"),
        _finding(ftype="admin_role", user="admin@contoso.com"),
    ])
    def test_not_applied(self, finding):
        with patch.object(config, "COMPROMISE_ACTION", "disable"), patch("responder._graph") as graph:
            assert responder.respond_to_finding(FakeTable(), finding, NOW) == ""
        graph.assert_not_called()

    def test_revoke_on_session_reuse(self):
        with patch.object(config, "COMPROMISE_ACTION", "revoke"), \
                patch("responder._graph", return_value=_resp(204)) as graph:
            result = responder.respond_to_finding(FakeTable(), _finding(ftype="session_reuse"), NOW)
        assert result == "Revoke sessions: done"
        assert graph.call_args[0][:2] == ("POST", "/users/victim@contoso.com/revokeSignInSessions")

    def test_block_and_revoke(self):
        with patch.object(config, "COMPROMISE_ACTION", "disable"), \
                patch("responder._graph", return_value=_resp(204)) as graph:
            result = responder.respond_to_finding(FakeTable(), _finding(ftype="legacy_auth"), NOW)
        assert result == "Block sign-in: done; Revoke sessions: done"
        assert graph.call_args_list[0][0][2] == {"accountEnabled": False}

    def test_exempt_and_daily_limit(self):
        table = FakeTable()
        with patch.object(config, "COMPROMISE_ACTION", "revoke"), \
                patch.object(config, "ANOMALY_ACTION_EXEMPT", {"ceo@contoso.com"}), \
                patch.object(config, "ANOMALY_ACTION_MAX_PER_DAY", 1), \
                patch("responder._graph", return_value=_resp(204)):
            assert responder.respond_to_finding(table, _finding(user="ceo@contoso.com"), NOW) == "none (account is exempt)"
            assert responder.respond_to_finding(table, _finding(), NOW) == "Revoke sessions: done"
            assert "daily limit" in responder.respond_to_finding(table, _finding(user="b@contoso.com"), NOW)


class TestResponseTarget:
    """COMPROMISE_ACTION acts on the changed account, and only when that account made the change."""

    def _respond(self, finding, lookup=None):
        def graph(method, path, json_body=None):
            if method == "GET":
                return _resp(200, {"userPrincipalName": lookup}) if lookup else _resp(404)
            return _resp(204)
        with patch.object(config, "COMPROMISE_ACTION", "disable"), \
                patch("responder._graph", side_effect=graph) as g:
            result = responder.respond_to_finding(FakeTable(), finding, NOW)
        return result, [c[0][:2] for c in g.call_args_list if c[0][0] != "GET"]

    @staticmethod
    def _forwarding(actor, identity):
        import compromise_detector as cd
        event = {"Id": "f1", "Operation": "Set-Mailbox", "UserId": actor,
                 "Parameters": [{"Name": "Identity", "Value": identity},
                                {"Name": "ForwardingSmtpAddress", "Value": "smtp:drop@evil.com"}]}
        return cd.detect_mailbox_forwarding([event])[0]

    def test_admin_forwarding_on_other_mailbox_acts_on_no_one(self):
        finding = self._forwarding("admin@contoso.com", "victim@contoso.com")
        assert finding["actor"] == "admin@contoso.com" and finding["target"] == "victim@contoso.com"
        result, calls = self._respond(finding)
        assert calls == []
        assert result == "none (admin@contoso.com changed victim@contoso.com: check both accounts)"

    @pytest.mark.parametrize("identity", [
        "victim", "victim@contoso.com", "VICTIM",
        "NAMPR01.prod.outlook.com/Microsoft Exchange Hosted Organizations/contoso.onmicrosoft.com/victim",
    ])
    def test_own_forwarding_acts_on_the_mailbox(self, identity):
        result, calls = self._respond(self._forwarding("victim@contoso.com", identity))
        assert result == "Block sign-in: done; Revoke sessions: done"
        assert calls == [("PATCH", "/users/victim@contoso.com"),
                         ("POST", "/users/victim@contoso.com/revokeSignInSessions")]

    def test_object_id_is_looked_up(self):
        oid = "0f1e2d3c-4b5a-4978-8a6b-5c4d3e2f1a0b"
        result, calls = self._respond(self._forwarding("victim@contoso.com", oid), lookup="victim@contoso.com")
        assert calls[-1] == ("POST", "/users/victim@contoso.com/revokeSignInSessions")
        result, calls = self._respond(self._forwarding("victim@contoso.com", oid), lookup="other@contoso.com")
        assert calls == [] and "victim@contoso.com changed other@contoso.com" in result

    def test_name_that_is_not_an_address_gets_no_action(self):
        result, calls = self._respond(self._forwarding("admin@contoso.com", "Victim User"))
        assert calls == [] and result == "none (the record names the account as 'Victim User', not by its address)"

    def test_app_change_gets_no_action(self):
        result, calls = self._respond(self._forwarding("0a1b2c3d-app", "victim@contoso.com"))
        assert calls == [] and result.startswith("none (an app or service (0a1b2c3d-app) changed")

    def test_mfa_method_added_through_microsoft_service(self):
        import compromise_detector as cd
        event = {"Id": "m1", "Operation": "Disable Strong Authentication.", "UserId": "ServicePrincipal_abc",
                 "Target": [{"Type": 5, "ID": "victim@contoso.com"}]}
        finding = cd.detect_mfa_changes([event])[0]
        assert finding["user"] == finding["target"] == "victim@contoso.com"
        assert finding["actor"] == "ServicePrincipal_abc"
        _, calls = self._respond(finding)
        assert calls[-1] == ("POST", "/users/victim@contoso.com/revokeSignInSessions")

    def test_mfa_turned_off_by_admin_gets_no_action(self):
        import compromise_detector as cd
        event = {"Id": "m2", "Operation": "Disable Strong Authentication.", "UserId": "admin@contoso.com",
                 "Target": [{"Type": 5, "ID": "victim@contoso.com"}]}
        result, calls = self._respond(cd.detect_mfa_changes([event])[0])
        assert calls == [] and "admin@contoso.com changed victim@contoso.com" in result

    def test_sign_in_alert_acts_on_the_account_that_signed_in(self):
        result, calls = self._respond(_finding(ftype="attack_tool", actor="x", target="y"))
        assert calls[-1] == ("POST", "/users/victim@contoso.com/revokeSignInSessions")

    @pytest.mark.parametrize("params,owner,expected", [
        ({}, "", "victim@contoso.com"),                                          # own mailbox
        ({"Mailbox": "ceo@contoso.com"}, "", "ceo@contoso.com"),                # -Mailbox
        ({"Identity": "ceo@contoso.com\\Exfil"}, "", "ceo@contoso.com"),        # Set-InboxRule identity
    ])
    def test_inbox_rule_mailbox(self, params, owner, expected):
        import compromise_detector as cd
        f = cd.detect_suspicious_inbox_rules([_rule_event(Name="Exfil", ForwardTo="drop@evil.com", **params)])[0]
        assert f["target"] == f["mailbox"] == expected and f["actor"] == "victim@contoso.com"

    def test_update_inbox_rules_by_delegate(self):
        import compromise_detector as cd
        event = {"Id": "u1", "Operation": "UpdateInboxRules", "UserId": "delegate@contoso.com",
                 "MailboxOwnerUPN": "ceo@contoso.com",
                 "OperationProperties": [{"Name": "RuleName", "Value": "x"},
                                         {"Name": "RuleActions", "Value": '[{"ActionType":"Forward",'
                                          '"Recipients":["drop@evil.com"]}]'}]}
        findings = cd.detect_suspicious_inbox_rules([event])
        assert findings and findings[0]["target"] == "ceo@contoso.com"
        _, calls = self._respond(findings[0] | {"severity": "high"})
        assert calls == []

    def test_email_shows_both_accounts(self):
        finding = self._forwarding("admin@contoso.com", "victim@contoso.com")
        with patch("alerting._deliver", return_value=True) as deliver:
            alerting.send_compromise_alert(finding)
        body = deliver.call_args[0][1]
        assert "Changed account" in body and "victim@contoso.com" in body
        assert "Changed by" not in body                     # the actor is the user of this alert


class TestDisableInboxRule:

    RULES = {"value": [
        {"id": "AQAAAJ5dZp8=", "displayName": "Exfil", "isEnabled": True,
         "actions": {"forwardTo": [{"emailAddress": {"address": "drop@evil.com"}}]}},
        {"id": "AQAAAJ5dZp9=", "displayName": "Newsletters", "isEnabled": True,
         "actions": {"moveToFolder": "AAMk..."}},
    ]}

    def _run(self, finding, get_status=200, patch_status=200, body=None):
        calls = []

        def graph(method, path, json_body=None):
            calls.append((method, path, json_body))
            return _resp(get_status, body if body is not None else self.RULES) if method == "GET" else _resp(patch_status)

        with patch.object(config, "COMPROMISE_ACTION", "none"), patch.object(config, "AUTO_DISABLE_INBOX_RULES", True), \
                patch("responder._graph", side_effect=graph):
            result = responder.respond_to_finding(FakeTable(), finding, NOW)
        return result, calls

    def test_by_name(self):
        result, calls = self._run(_finding(rule_name="Exfil", mailbox="victim@contoso.com", targets=["drop@evil.com"]))
        assert result == "Disable inbox rule: done"
        assert calls[1] == ("PATCH", "/users/victim@contoso.com/mailFolders/inbox/messageRules/AQAAAJ5dZp8%3D",
                            {"isEnabled": False})

    def test_by_target_when_name_unknown(self):
        result, calls = self._run(_finding(rule_name="", mailbox="victim@contoso.com", targets=["DROP@evil.com"]))
        assert result == "Disable inbox rule: done" and len(calls) == 2

    def test_admin_created_rule_uses_mailbox(self):
        _, calls = self._run(_finding(user="admin@contoso.com", rule_name="Exfil", mailbox="victim@contoso.com"))
        assert calls[0][1].startswith("/users/victim@contoso.com/")

    def test_not_found(self):
        result, calls = self._run(_finding(rule_name="Gone", mailbox="victim@contoso.com", targets=["x@evil.com"]))
        assert "no enabled rule found" in result and len(calls) == 1

    def test_no_permission(self):
        result, _ = self._run(_finding(rule_name="Exfil", mailbox="victim@contoso.com"), get_status=403)
        assert "MailboxSettings.ReadWrite" in result

    def test_medium_rule_not_touched(self):
        result, calls = self._run(_finding(severity="medium", rule_name=".", mailbox="victim@contoso.com"))
        assert result == "" and calls == []

    def test_detector_carries_rule_details(self):
        import compromise_detector as cd
        f = cd.detect_suspicious_inbox_rules([_rule_event(Name="Exfil", ForwardTo="drop@evil.com; boss@contoso.com")])[0]
        assert f["rule_name"] == "Exfil" and f["targets"] == ["drop@evil.com"] and f["mailbox"] == "victim@contoso.com"


# ---------------------------------------------------------------------------
# Email
# ---------------------------------------------------------------------------

class TestEmail:

    @pytest.mark.parametrize("text,expect", [
        ("Revoke sessions: done; Disable inbox rule: done", ["sessions revoked", "inbox rule turned off"]),
        ("none (account is exempt); Disable inbox rule: done", ["inbox rule turned off", "Not done: account is exempt"]),
        ("Revoke sessions failed: HTTP 403 (no admin consent for the permission, or an admin account)", ["Failed:"]),
        ("none (daily limit of 3 actions reached)", ["No automatic response", "daily limit"]),
    ])
    def test_response_notice(self, text, expect):
        html = alerting._response_notice(text)
        for e in expect:
            assert e in html

    @patch("alerting.token_manager")
    @patch("config.http.post")
    def test_compromise_email_shows_response(self, post, tm):
        tm.get_graph_token.return_value = "t"
        post.return_value = MagicMock(status_code=202)
        alerting.send_compromise_alert(_finding(event={"Id": "e1", "Operation": "New-InboxRule"}),
                                       action_result="Revoke sessions: done")
        body = post.call_args[1]["json"]["message"]["body"]["content"]
        assert "Automatic response:" in body and "sessions revoked" in body

    def test_response_runs_once(self):
        import function_app as fa
        finding = _finding(event={"Id": "e9", "Operation": "New-InboxRule"})
        key = fa.finding_key(finding)
        with patch("responder.respond_to_finding", return_value="Revoke sessions: done") as respond, \
                patch("function_app.send_compromise_alert", return_value=False):
            fa._deliver_finding(dict(finding), "", FakeTable(), {f"response_{key}"}, None, NOW)
        respond.assert_not_called()


@pytest.mark.parametrize("reason,expected", [
    ("HTTP 404 MailboxNotEnabledForRESTAPI", "no Exchange Online mailbox"),
    ("HTTP 404 ErrorInvalidUser", "No such mailbox in this tenant"),
    ("HTTP 403 ErrorAccessDenied", "admin consent"),
])
def test_mailbox_refusal_hint(reason, expected):
    with patch.dict("os.environ", {"MAIL_SEND_SCOPE": "tenant"}):
        hint = alerting.mailbox_refusal_hint(reason)
    assert expected in hint
    if "MailboxNotEnabledForRESTAPI" in reason:
        assert "shared mailbox" in hint
