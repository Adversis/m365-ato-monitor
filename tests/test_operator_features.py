"""Operator features: recipients and tenant label, findings journal and incident
context, targeted mutes, manual response, inbox rule reading, onboarding scan,
weekly report and posture."""

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

import admin_store
import alerting
import config
import journal
from tests.fakes import FakeTable
from tests.test_admin_ui import MUTATE, _req

NOW = datetime(2026, 11, 8, 12, 0, tzinfo=timezone.utc)


def _resp(status, body=None):
    r = MagicMock(status_code=status)
    r.json.return_value = body if body is not None else {}
    return r


def _finding(ftype="inbox_rule", severity="medium", user="jane@contoso.com", event_id="e1",
             when="2026-11-08T11:00:00", **extra):
    f = {"type": ftype, "severity": severity, "user": user, "description": f"{ftype} finding", "ip": None,
         "event": {"Id": event_id, "Operation": "New-InboxRule", "CreationTime": when}}
    f.update(extra)
    return f


@pytest.fixture
def jt():
    table = FakeTable()
    with patch("journal.table_client", return_value=table):
        yield table


# ---------------------------------------------------------------------------
# 1. Recipients and tenant label
# ---------------------------------------------------------------------------

class TestRecipientsAndLabel:

    def test_address_list_parsing(self, monkeypatch):
        monkeypatch.setenv("ALERT_RECIPIENTS", "Tickets@PSA.example, bad-entry; ADMIN@contoso.com,x@y.io")
        assert config._address_list("ALERT_RECIPIENTS") == ["tickets@psa.example", "x@y.io"]

    @pytest.mark.parametrize("raw,expected", [
        ("Contoso", "Contoso"), (" [Contoso]  Ltd\n", "Contoso Ltd"), ("x" * 60, "x" * 40), ("", "")])
    def test_label(self, raw, expected):
        assert config._label(raw) == expected

    def test_subject_label(self):
        with patch.object(config, "TENANT_LABEL", "Contoso"):
            assert alerting.labeled("[M365 Alert] HIGH: x") == "[M365 Alert][Contoso] HIGH: x"
            assert alerting.labeled("[M365 Monitor] Weekly") == "[M365 Monitor][Contoso] Weekly"
            assert alerting.labeled("[M365 Alert][Contoso] HIGH: x") == "[M365 Alert][Contoso] HIGH: x"
        assert alerting.labeled("[M365 Alert] HIGH: x") == "[M365 Alert] HIGH: x"

    @pytest.mark.parametrize("raw,expected", [("  Contoso   Ltd ", "Contoso Ltd"), ("", ""), (None, "")])
    def test_label_setting_valid(self, raw, expected):
        import settings
        assert settings.validate(settings.BY_NAME["TENANT_LABEL"], raw) == expected

    @pytest.mark.parametrize("raw", ["[Contoso]", "x" * 41, "a\nb", 5])
    def test_label_setting_invalid(self, raw):
        import settings
        with pytest.raises(ValueError):
            settings.validate(settings.BY_NAME["TENANT_LABEL"], raw)

    def test_console_settings_apply(self):
        import settings
        settings.apply({"TENANT_LABEL": "Fabrikam", "ALERT_RECIPIENTS": ["Tickets@PSA.example"],
                        "REPORT_RECIPIENTS": ["vciso@firm.example"]})
        assert config.TENANT_LABEL == "Fabrikam"
        assert config.ALERT_RECIPIENTS == ["tickets@psa.example"]
        assert alerting.labeled("[M365 Alert] HIGH: x") == "[M365 Alert][Fabrikam] HIGH: x"
        assert alerting.recipients("[M365 Monitor] Weekly") == ["admin@contoso.com", "vciso@firm.example"]
        settings.apply({})
        assert config.TENANT_LABEL == "" and config.ALERT_RECIPIENTS == []

    def test_console_save_is_recorded_and_emailed(self, ui_on):
        import admin_api
        r = admin_api.put_settings(_req("PUT", "/api/manage/api/settings", {
            "version": 0, "changes": {"TENANT_LABEL": "Contoso", "ALERT_RECIPIENTS": "tickets@psa.example"}},
            headers=MUTATE))
        assert r.status_code == 200, r.get_body()
        names = {c["name"] for c in json.loads(r.get_body())["changes"]}
        assert names == {"TENANT_LABEL", "ALERT_RECIPIENTS"} and ui_on["email"].called
        r = admin_api.put_settings(_req("PUT", "/api/manage/api/settings", {
            "version": 1, "changes": {"TENANT_LABEL": "[bad]"}}, headers=MUTATE))
        assert r.status_code == 400 and "TENANT_LABEL" in json.loads(r.get_body())["errors"]

    @patch("alerting.token_manager")
    @patch("config.http.post")
    def test_recipients_by_tag(self, post, tm):
        tm.get_graph_token.return_value = "t"
        post.return_value = MagicMock(status_code=202)
        with patch.multiple(config, ALERT_RECIPIENTS=["tickets@psa.example"], REPORT_RECIPIENTS=["vciso@firm.example"],
                            TENANT_LABEL="Contoso"):
            alerting._deliver("[M365 Alert] HIGH: x", "<p>x</p>", None)
            alert = post.call_args[1]["json"]["message"]
            alerting._deliver("[M365 Monitor] Weekly report", "<p>x</p>", None)
            report = post.call_args[1]["json"]["message"]
        assert [r["emailAddress"]["address"] for r in alert["toRecipients"]] == ["admin@contoso.com",
                                                                                 "tickets@psa.example"]
        assert [r["emailAddress"]["address"] for r in report["toRecipients"]] == ["admin@contoso.com",
                                                                                  "vciso@firm.example"]
        assert alert["subject"].startswith("[M365 Alert][Contoso] HIGH")


# ---------------------------------------------------------------------------
# 5. Findings journal and incident context
# ---------------------------------------------------------------------------

class TestJournal:

    def test_record_and_read(self, jt):
        journal.record(jt, _finding(event_id="a"), "inbox_rule_a", "emailed", now=NOW)
        journal.record(jt, _finding("mfa_change", "high", event_id="b", when="2026-11-08T11:30:00"),
                       "mfa_change_b", "emailed", now=NOW)
        journal.record(jt, _finding(user="other@contoso.com", event_id="c"), "inbox_rule_c", "muted", now=NOW)
        rows = journal.for_user(jt, "JANE@contoso.com", NOW - timedelta(days=1))
        assert [r["type"] for r in rows] == ["mfa_change", "inbox_rule"]      # newest first
        assert journal.summary(journal.recent(jt, NOW - timedelta(days=1)))["by_status"] == {
            "emailed": 2, "muted": 1}

    def test_same_finding_same_row(self, jt):
        journal.record(jt, _finding(), "k1", "email failed", now=NOW)
        journal.record(jt, _finding(), "k1", "emailed", now=NOW)
        assert [r["status"] for r in journal.recent(jt, NOW - timedelta(days=1))] == ["emailed"]

    def test_only_new_keeps_existing(self, jt):
        journal.record(jt, _finding(), "k1", "emailed", now=NOW)
        journal.record(jt, _finding(), "k1", "onboarding", now=NOW, only_new=True)
        assert journal.recent(jt, NOW - timedelta(days=1))[0]["status"] == "emailed"

    def test_related_excludes_itself_and_old(self, jt):
        journal.record(jt, _finding(event_id="old", when="2026-11-06T11:00:00"), "k_old", "emailed", now=NOW)
        journal.record(jt, _finding(event_id="near", when="2026-11-08T09:00:00"), "k_near", "emailed", now=NOW)
        me = _finding(event_id="me")
        journal.record(jt, me, "k_me", "emailed", now=NOW)
        assert [r["key"] for r in journal.related(jt, me, "k_me", NOW)] == ["k_near"]

    def test_purge(self, jt):
        journal.record(jt, _finding(), "k1", "emailed", now=NOW - timedelta(days=100))
        journal.record(jt, _finding(event_id="e2"), "k2", "emailed", now=NOW)
        assert journal.purge(jt, NOW) == 1

    def test_no_storage(self):
        journal.record(None, _finding(), "k", "emailed")
        assert journal.for_user(None, "a@b.com", NOW) == [] and journal.recent(None, NOW) == []

    def test_related_section_in_email(self):
        rows = [{"at": "2026-11-08T10:00:00Z", "type": "mfa_change", "severity": "high", "status": "emailed",
                 "description": "Phone added"}]
        html = alerting._related(rows)
        assert "1 other alert" in html and "MFA change" in html and "one incident" in html
        assert alerting._related([]) == ""

    def test_pipeline_records_and_passes_context(self, jt):
        import function_app as fa
        events = FakeTable()
        first = _finding(event_id="f1", severity="medium")
        second = _finding("mailbox_forwarding", "high", event_id="f2")
        with patch("function_app.send_compromise_alert", return_value=True) as send, \
                patch("responder.respond_to_finding", return_value=""):
            fa._deliver_finding(first, "", events, set(), None, NOW)
            fa._deliver_finding(second, "", events, set(), None, NOW)
        assert send.call_args_list[0].kwargs["related"] == []
        related = send.call_args_list[1].kwargs["related"]
        assert [r["type"] for r in related] == ["inbox_rule"]
        assert {r["status"] for r in journal.recent(jt, NOW - timedelta(days=1))} == {"emailed"}

    def test_alert_off_is_journaled(self, jt):
        import function_app as fa
        with patch.object(config, "ALERTS_OFF", {"inbox_rule"}), \
                patch("function_app.send_compromise_alert") as send:
            fa._deliver_finding(_finding(), "", FakeTable(), set(), None, NOW)
        send.assert_not_called()
        assert journal.recent(jt, NOW - timedelta(days=1))[0]["status"] == "alert off"


# ---------------------------------------------------------------------------
# 7. Targeted mutes
# ---------------------------------------------------------------------------

def _mute(**over):
    body = {"type": "inbox_rule", "user": "jane@contoso.com", "rule_name": "", "days": 7,
            "reason": "Known newsletter rule"}
    body.update(over)
    return body


class TestMutes:

    @pytest.mark.parametrize("over,field", [
        ({"type": "*", "user": "*"}, "user"),
        ({"type": "audit_disabled"}, "type"),
        ({"type": "nope"}, "type"),
        ({"user": "not-an-address"}, "user"),
        ({"type": "mfa_change", "rule_name": "x"}, "rule_name"),
        ({"days": 0}, "days"), ({"days": 3651}, "days"), ({"days": True}, "days"),
        ({"asn": "GTHost"}, "asn"),
        ({"reason": ""}, "reason"),
    ])
    def test_validation(self, over, field):
        with pytest.raises(admin_store.ValidationError) as e:
            admin_store.validate_mute(_mute(**over))
        assert field in e.value.errors

    def test_add_match_end(self):
        table = FakeTable()
        mute = admin_store.add_mute(table, _mute(rule_name="News"), "admin@contoso.com", NOW)
        match = admin_store.matching_mute
        assert match("inbox_rule", "JANE@contoso.com", "news", "medium", NOW)["id"] == mute["id"]
        assert match("inbox_rule", "jane@contoso.com", "Other", "medium", NOW) is None
        assert match("inbox_rule", "bob@contoso.com", "News", "medium", NOW) is None
        assert match("inbox_rule", "jane@contoso.com", "News", "high", NOW) is None    # high is never muted
        assert match("inbox_rule", "jane@contoso.com", "News", "medium", NOW + timedelta(days=8)) is None
        assert admin_store.end_mute(table, mute["id"], "admin@contoso.com", NOW + timedelta(hours=1))
        assert match("inbox_rule", "jane@contoso.com", "News", "medium", NOW + timedelta(hours=2)) is None
        rows = admin_store.list_mutes(table, NOW + timedelta(hours=2), include_expired=True)
        assert rows[0]["ended_by"] == "admin@contoso.com" and not rows[0]["active"]

    def test_refresh_loads_mutes(self):
        table = FakeTable()
        admin_store.add_mute(table, _mute(type="*"), "a@contoso.com")
        admin_store._active_mutes.clear()
        admin_store.refresh(table)
        assert admin_store.matching_mute("mfa_change", "jane@contoso.com", "", "medium")

    def test_pipeline_muted(self, jt):
        import function_app as fa
        admin_store.add_mute(FakeTable(), _mute(), "admin@contoso.com", NOW - timedelta(hours=1))
        events = FakeTable()
        with patch("function_app.send_compromise_alert") as send, \
                patch("responder.respond_to_finding", return_value=""):
            fa._deliver_finding(_finding(), "", events, set(), None, NOW)
            fa._deliver_finding(_finding(severity="high", event_id="e2"), "", events, set(), None, NOW)
        assert send.call_count == 1                                  # only the high one
        statuses = {r["key"]: r["status"] for r in journal.recent(jt, NOW - timedelta(days=1))}
        assert statuses == {"inbox_rule_e1": "muted", "inbox_rule_e2": "emailed"}
        assert ("events", "inbox_rule_e1") in events.rows             # muted is marked processed

    def test_signin_muted(self, jt):
        import function_app as fa
        # _alert_signin checks the mute at the real time, not NOW.
        admin_store.add_mute(FakeTable(), _mute(type="suspicious_signin"), "a@contoso.com",
                             datetime.now(timezone.utc) - timedelta(hours=1))
        event = {"Id": "s1", "UserId": "jane@contoso.com", "Operation": "UserLoggedIn",
                 "CreationTime": "2026-11-08T11:00:00"}
        analysis = {"confidence": "medium", "flags": ["vpn"], "org": "VPN Co"}
        with patch("function_app.send_suspicious_login_alert") as send:
            assert fa._alert_signin(FakeTable(), event, "s1", "198.51.100.9", analysis) is True
            analysis_high = dict(analysis, confidence="high")
            fa._alert_signin(FakeTable(), dict(event, Id="s2"), "s2", "198.51.100.9", analysis_high)
        assert send.call_count == 1

    def test_api_add_and_end(self, ui_on):
        import admin_api
        r = admin_api.mutes(_req("POST", "/api/manage/api/mutes", dict(_mute(), action="add"), headers=MUTATE))
        assert r.status_code == 200, r.get_body()
        mute = json.loads(r.get_body())["mutes"][0]
        assert ui_on["email"].call_args.kwargs["title"] == "Alerts muted"
        history = admin_store.history(ui_on["table"])
        assert history[0]["changes"][0]["label"] == "Mute added"
        r = admin_api.mutes(_req("POST", "/api/manage/api/mutes", {"action": "end", "id": mute["id"]},
                                 headers=MUTATE))
        assert r.status_code == 200 and not json.loads(r.get_body())["mutes"][0]["active"]
        r = admin_api.mutes(_req("POST", "/api/manage/api/mutes", {"action": "end", "id": mute["id"]},
                                 headers=MUTATE))
        assert r.status_code == 404

    def test_api_needs_csrf_header(self, ui_on):
        import admin_api
        r = admin_api.mutes(_req("POST", "/api/manage/api/mutes", dict(_mute(), action="add")))
        assert r.status_code == 403


# ---------------------------------------------------------------------------
# 4. Manual response
# ---------------------------------------------------------------------------

class TestManualResponse:

    def test_refused_accounts(self):
        import responder
        with pytest.raises(ValueError, match="alert mailbox"):
            responder.manual_action("admin@contoso.com", "block", "someone@contoso.com")
        with pytest.raises(ValueError, match="own account"):
            responder.manual_action("me@contoso.com", "block", "ME@contoso.com")

    @patch("responder._graph")
    def test_actions_call_graph(self, graph):
        import responder
        graph.side_effect = [_resp(204), _resp(204)]
        assert responder.manual_action("jane@contoso.com", "block", "a@contoso.com") == \
            "Block sign-in: done; Revoke sessions: done"
        assert graph.call_args_list[0].args == ("PATCH", "/users/jane@contoso.com", {"accountEnabled": False})
        graph.side_effect = [_resp(204)]
        assert responder.manual_action("jane@contoso.com", "unblock", "a@contoso.com") == "Unblock sign-in: done"
        graph.side_effect = [_resp(403)]
        assert "failed: HTTP 403" in responder.manual_action("jane@contoso.com", "revoke", "a@contoso.com")

    def test_missing_roles(self):
        import responder
        assert responder.manual_missing_roles("revoke", ["Mail.Send"]) == ("User.RevokeSessions.All",)
        assert responder.manual_missing_roles("revoke", None) == ()

    def test_api_refuses_without_permission(self, ui_on):
        import admin_api
        r = admin_api.respond(_req("POST", "/api/manage/api/respond",
                                   {"user": "jane@contoso.com", "action": "revoke"}, headers=MUTATE))
        assert r.status_code == 403 and "User.RevokeSessions.All" in json.loads(r.get_body())["error"]

    def test_api_revoke_records_and_emails(self, ui_on):
        import admin_api
        with patch("o365_client.token_manager.granted_graph_roles", return_value=["User.RevokeSessions.All"]), \
                patch("responder._graph", return_value=_resp(204)):
            r = admin_api.respond(_req("POST", "/api/manage/api/respond",
                                       {"user": "Jane@contoso.com", "action": "revoke"}, headers=MUTATE))
        assert r.status_code == 200 and json.loads(r.get_body())["result"] == "Revoke sessions: done"
        assert ui_on["email"].call_args.kwargs["title"] == "Response action"
        assert "jane@contoso.com" in admin_store.history(ui_on["table"])[0]["changes"][0]["label"]

    def test_api_rule_off(self, ui_on):
        import admin_api
        with patch("o365_client.token_manager.granted_graph_roles", return_value=["MailboxSettings.ReadWrite"]), \
                patch("config.http.request", return_value=_resp(200)) as req, \
                patch("mailbox_rules.token_manager"):
            r = admin_api.respond(_req("POST", "/api/manage/api/respond",
                                       {"user": "jane@contoso.com", "action": "rule_off", "rule_id": "AQAB=",
                                        "rule_name": "x"}, headers=MUTATE))
        assert r.status_code == 200
        assert req.call_args.kwargs["json"] == {"isEnabled": False}
        assert req.call_args.args[1].endswith("/users/jane@contoso.com/mailFolders/inbox/messageRules/AQAB%3D")

    def test_user_page(self, ui_on, jt):
        import admin_api
        journal.record(jt, _finding(), "k1", "emailed", now=datetime.now(timezone.utc))
        r = admin_api.user_page(_req(params={"user": "jane@contoso.com"}))
        data = json.loads(r.get_body())
        assert r.status_code == 200 and data["findings"][0]["type"] == "inbox_rule"
        assert data["permissions"]["revoke"] is False and data["missing"]["revoke"] == ["User.RevokeSessions.All"]
        assert admin_api.user_page(_req(params={"user": "nobody"})).status_code == 400


# ---------------------------------------------------------------------------
# Inbox rules through Graph
# ---------------------------------------------------------------------------

def _rule(**actions):
    conditions = actions.pop("conditions", {})
    return {"id": "r1", "displayName": actions.pop("name", "Rule"), "isEnabled": True, "sequence": 1,
            "conditions": conditions, "actions": actions}


class TestMailboxRules:

    @pytest.mark.parametrize("rule,folder,severity", [
        (_rule(forwardTo=[{"emailAddress": {"address": "x@evil.example"}}]), "", "high"),
        (_rule(forwardTo=[{"emailAddress": {"address": "boss@contoso.com"}}]), "", ""),
        (_rule(delete=True, conditions={"senderContains": ["news"]}), "", ""),          # only deletes: no sign
        (_rule(delete=True, conditions={"subjectContains": ["invoice"]}), "", "high"),  # deletes payment mail
        (_rule(moveToFolder="f1", conditions={"subjectContains": ["x"]}), "RSS Feeds", "high"),
        (_rule(markAsRead=True, conditions={"subjectContains": ["Invoice"]}), "", "medium"),
        (_rule(name="..", moveToFolder="f1"), "Projects", "medium"),
        (_rule(moveToFolder="f1", conditions={"senderContains": ["github"]}), "GitHub", ""),
    ])
    def test_assess(self, rule, folder, severity):
        import mailbox_rules
        assert mailbox_rules.assess(rule, "jane@contoso.com", folder)[0] == severity

    @patch("mailbox_rules.token_manager")
    @patch("config.http.get")
    def test_list_errors(self, get, tm):
        import mailbox_rules
        get.return_value = _resp(404)
        assert mailbox_rules.list_rules("jane@contoso.com") == (None, "no mailbox")
        get.return_value = _resp(403, {"error": {"code": "ErrorAccessDenied"}})
        assert "HTTP 403" in mailbox_rules.list_rules("jane@contoso.com")[1]

    @patch("mailbox_rules.token_manager")
    @patch("config.http.get")
    def test_list_users_pages_and_skips_guests(self, get, tm):
        import mailbox_rules
        get.side_effect = [
            _resp(200, {"value": [{"userPrincipalName": "B@contoso.com", "mail": "b@contoso.com"},
                                  {"userPrincipalName": "g_x.com#EXT#@contoso.com", "mail": "g@x.com"}],
                        "@odata.nextLink": "https://graph.microsoft.com/v1.0/users?$skiptoken=1"}),
            _resp(200, {"value": [{"userPrincipalName": "a@contoso.com", "mail": "a@contoso.com"},
                                  {"userPrincipalName": "nomail@contoso.com", "mail": None}]}),
        ]
        assert mailbox_rules.list_mailbox_users() == (["a@contoso.com", "b@contoso.com"], "")

    @patch("mailbox_rules.token_manager")
    @patch("config.http.get")
    def test_next_link_must_be_graph(self, get, tm):
        import mailbox_rules
        get.return_value = _resp(200, {"value": [], "@odata.nextLink": "https://evil.example/users"})
        assert mailbox_rules.list_mailbox_users() == (None, "unexpected next page link")


# ---------------------------------------------------------------------------
# 2. Onboarding scan
# ---------------------------------------------------------------------------

def _forward_rule_event(i):
    return {"Id": f"h{i}", "RecordType": 1, "Operation": "New-InboxRule", "UserId": "jane@contoso.com",
            "CreationTime": "2026-11-05T10:00:00", "ClientIP": "198.51.100.5",
            "Parameters": [{"Name": "Name", "Value": "x1"}, {"Name": "ForwardTo", "Value": "a@evil.example"}]}


class TestOnboarding:

    def _run(self, events, jt, records, granted=("Mail.Send",), rules=None, **kw):
        import function_app as fa
        import onboarding

        def fetch(content_type, start, end):
            return (records if content_type == "Audit.Exchange" and start == onboarding._parse(
                onboarding.load(events)["history"]["from"]) else []), True

        sent = MagicMock(return_value=True)
        with patch("onboarding.fetch_content_records", side_effect=fetch), \
                patch("onboarding.token_manager.granted_graph_roles", return_value=list(granted)), \
                patch("mailbox_rules.list_mailbox_users", return_value=(["jane@contoso.com"], "")), \
                patch("mailbox_rules.read", return_value=(rules or [], "")), \
                patch("geo_monitor.table_client", return_value=None):
            state = onboarding.run(events, FakeTable(), fa._DETECTORS, NOW, send_report=sent, **kw)
        return state, sent

    def test_first_run_starts_once(self):
        import onboarding
        events = FakeTable()
        onboarding.ensure_started(events, NOW - timedelta(minutes=8), NOW)
        first = onboarding.load(events)
        onboarding.ensure_started(events, NOW, NOW)
        assert onboarding.load(events)["run_id"] == first["run_id"]
        assert first["history"]["to"] == "2026-11-08T11:52:00Z" and first["step"] == "history"

    def test_full_scan(self, jt):
        import onboarding
        events = FakeTable()
        onboarding.start(events, NOW, "full")
        state, sent = self._run(events, jt, [_forward_rule_event(1)])
        assert state["step"] == "done" and state["history"]["findings"] == 1
        assert state["history"]["records"] == 1
        assert state["rules"]["skipped"].startswith("needs the Graph permission")
        findings = sent.call_args.args[1]
        assert findings[0]["status"] == "onboarding" and findings[0]["type"] == "inbox_rule"
        assert ("events", "inbox_rule_h1") in events.rows        # the monitor does not alert it again

    def test_already_alerted_is_skipped(self, jt):
        import onboarding
        events = FakeTable()
        events.upsert_entity({"PartitionKey": "events", "RowKey": "inbox_rule_h1", "processed_at": "x"})
        onboarding.start(events, NOW, "full")
        state, _ = self._run(events, jt, [_forward_rule_event(1)])
        assert state["history"]["findings"] == 0

    def test_rule_sweep(self, jt):
        import onboarding
        events = FakeTable()
        onboarding.start(events, NOW, "rules")
        rule = {"id": "r1", "name": "x", "enabled": True, "severity": "high", "reasons": ["forwards externally"],
                "actions": "forward to a@evil.example", "targets": ["a@evil.example"]}
        state, sent = self._run(events, jt, [], granted=("User.ReadBasic.All", "MailboxSettings.Read"),
                                rules=[rule, dict(rule, id="r2", severity="")])
        assert state["rules"]["checked"] == 1 and state["rules"]["flagged_count"] == 1
        assert state["rules"]["flagged"][0]["mailbox"] == "jane@contoso.com"
        assert sent.call_args.args[1] == []          # the report lists sweep rules from the state
        assert journal.recent(jt, NOW - timedelta(days=1))[0]["description"].startswith("Existing inbox rule")

    def test_budget_stops_and_resumes(self, jt):
        import onboarding
        events = FakeTable()
        onboarding.start(events, NOW, "full")
        state, sent = self._run(events, jt, [], budget=0)
        assert state["step"] == "history" and not sent.called
        state, sent = self._run(events, jt, [])
        assert state["step"] == "done" and sent.called

    def test_new_start_replaces_running_scan(self, jt):
        import onboarding
        events = FakeTable()
        old = onboarding.start(events, NOW, "full")
        new = onboarding.start(events, NOW, "rules")
        assert not onboarding._save(events, old)
        assert onboarding.load(events)["run_id"] == new["run_id"]

    def test_history_start_is_clamped_to_seven_days(self, jt):
        import onboarding
        events = FakeTable()
        onboarding.start(events, NOW - timedelta(hours=2), "full")     # the scan waited 2 hours
        seen = []

        def fetch(content_type, start, end):
            seen.append(start)
            return [], True
        with patch("onboarding.fetch_content_records", side_effect=fetch), \
                patch("onboarding.token_manager.granted_graph_roles", return_value=[]), \
                patch("geo_monitor.table_client", return_value=None):
            onboarding.run(events, FakeTable(), [], NOW, send_report=MagicMock(return_value=True))
        assert min(seen) >= NOW - timedelta(days=7)

    def test_report_lists_only_scan_findings(self, jt):
        import onboarding
        events = FakeTable()
        journal.record(jt, _finding(event_id="old"), "inbox_rule_old", "emailed", now=NOW - timedelta(days=1))
        onboarding.start(events, NOW, "full")
        _, sent = self._run(events, jt, [_forward_rule_event(2)])
        assert [f["key"] for f in sent.call_args.args[1]] == ["inbox_rule_h2"]
        onboarding.start(events, NOW, "rules")
        _, sent = self._run(events, jt, [])
        assert sent.call_args.args[1] == []

    def test_background_timer_idle_when_done(self):
        import function_app as fa
        import onboarding
        events = FakeTable()
        state = onboarding.start(events, NOW, "rules")
        state["step"] = "done"
        onboarding._save(events, state)
        with patch("function_app._get_table_clients", return_value=(events, FakeTable())), \
                patch("onboarding.run") as run:
            fa.background_jobs(None)
        run.assert_not_called()

    def test_report_renders(self):
        import onboarding
        events = FakeTable()
        state = onboarding.start(events, NOW, "full")
        state["rules"].update(checked=3, mailboxes=4, no_mailbox=1, flagged_count=1,
                              flagged=[{"mailbox": "jane@contoso.com", "name": "x", "severity": "high",
                                        "reasons": ["forwards externally to a@evil.example"]}])
        with patch("alerting._deliver", return_value=True) as deliver:
            alerting.send_onboarding_report(state, [], None)
        subject, body = deliver.call_args.args[:2]
        assert subject == "[M365 Monitor] Starting state: 1 item to review"
        assert "no audit content was available" in body and "forwards externally" in body
        assert "the audit search read <strong>0</strong> records" in body
        assert "Get-Mailbox" in body and "Settings that affect protection" in body

    def test_api_scan_conflict(self, ui_on):
        import admin_api
        events = FakeTable()
        with patch("function_app._get_table_clients", return_value=(events, FakeTable())):
            r = admin_api.scan(_req("POST", "/api/manage/api/scan", {"kind": "rules"}, headers=MUTATE))
            assert r.status_code == 200
            r = admin_api.scan(_req("POST", "/api/manage/api/scan", {"kind": "full"}, headers=MUTATE))
            assert r.status_code == 409
            r = admin_api.scan(_req("POST", "/api/manage/api/scan", {"kind": "full", "restart": True},
                                    headers=MUTATE))
            assert r.status_code == 200 and json.loads(r.get_body())["onboarding"]["kind"] == "full"


# ---------------------------------------------------------------------------
# 3. Weekly report and posture
# ---------------------------------------------------------------------------

class TestWeeklyReport:

    def _send(self, stats, findings, health):
        with patch("alerting._deliver", return_value=True) as deliver:
            alerting.send_weekly_report(stats, findings, health, NOW)
        return deliver.call_args.args[:2]

    def test_all_clear(self):
        stats = {"runs": 5040, "total_events": 1234, "gaps": 0, "errors": 0}
        subject, body = self._send(stats, [], {"last_content": NOW - timedelta(hours=1), "queues": {}})
        assert subject == "[M365 Monitor] Weekly report, 1 Nov to 8 Nov 2026: all clear"
        assert "The monitor works" in body and "1,234" in body

    def test_problems_and_alerts(self):
        stats = {"runs": 3000, "total_events": 10, "gaps": 2, "errors": 5}
        findings = [{"type": "inbox_rule", "severity": "high", "status": "emailed", "user": "a@contoso.com",
                     "at": "2026-11-07T10:00:00Z", "description": "d"},
                    {"type": "mfa_change", "severity": "medium", "status": "muted", "user": "b@contoso.com",
                     "at": "2026-11-07T11:00:00Z", "description": "d"}]
        subject, body = self._send(stats, findings, {"last_content": NOW - timedelta(days=2),
                                                     "queues": {"outbox": 1}})
        assert subject.endswith("1 high alert, 5 health items")
        assert "coverage gap" in body and "outbox" in body and "High alerts" in body

    def test_stats_unavailable(self):
        subject, body = self._send(None, [], {"last_content": None, "queues": {}})
        assert "not available" in body and "No audit content" in body

    def test_posture_flags(self):
        with patch.multiple(config, ALERTS_OFF={"mail_flow_rule"}, LOGIN_ALERT_CONFIDENCE="off"):
            rows = {label: review for label, _, review in alerting.posture(NOW)}
        assert rows["Mail.Send permission"] and rows["Alert types off"] and rows["Suspicious sign-in emails"]
        assert not rows["Active mutes"] and not rows["Automatic response"]

    def test_timer_respects_setting(self):
        import function_app as fa
        with patch.object(config, "WEEKLY_REPORT", False), patch("function_app.send_weekly_report") as send, \
                patch("admin_store.refresh"):
            fa.weekly_report(None)
        send.assert_not_called()


# ---------------------------------------------------------------------------
# Alert mailbox in the console
# ---------------------------------------------------------------------------

class TestAlertMailbox:

    @pytest.mark.parametrize("raw,ok", [("Sec@Contoso.com ", True), ("not-an-address", False), ("", False),
                                        (["a@b.com"], False)])
    def test_validation(self, raw, ok):
        import settings
        setting = settings.BY_NAME["ADMIN_EMAIL"]
        if ok:
            assert settings.validate(setting, raw) == "sec@contoso.com"
        else:
            with pytest.raises(ValueError):
                settings.validate(setting, raw)

    def _put(self, changes, version=0):
        import admin_api
        return admin_api.put_settings(_req("PUT", "/api/manage/api/settings",
                                           {"version": version, "changes": changes}, headers=MUTATE))

    def test_change_sends_test_then_notice_and_moves_health_alerts(self, ui_on):
        with patch("admin_api.send_mailbox_test", return_value=(True, "")) as test, \
                patch("admin_api.send_mailbox_changed_notice", return_value=True) as notice, \
                patch("health_alerts.set_email", return_value="Azure Monitor health alerts now go to new@contoso.com.") as ag:
            r = self._put({"ADMIN_EMAIL": "New@contoso.com"})
            body = json.loads(r.get_body())
            assert r.status_code == 200 and config.ADMIN_EMAIL == "new@contoso.com"
            assert test.call_args.args[0] == "new@contoso.com"
            assert notice.call_args.args[:2] == ("admin@contoso.com", "new@contoso.com")
            ag.assert_called_once_with("new@contoso.com", "admin@contoso.com")
            assert "health alerts now go to" in body["notes"][0]
            # The UI's dry run sends nothing.
            import admin_api
            admin_api.put_settings(_req("PUT", "/api/manage/api/settings", {
                "version": 1, "changes": {"ADMIN_EMAIL": "other@contoso.com"}, "dry_run": True}, headers=MUTATE))
            assert test.call_count == 1

    def test_refused_mailbox_is_not_saved(self, ui_on):
        with patch("admin_api.send_mailbox_test", return_value=(False, "Microsoft Graph refused (HTTP 404).")), \
                patch("health_alerts.set_email") as ag:
            r = self._put({"ADMIN_EMAIL": "nobody@contoso.com"})
        assert r.status_code == 400 and "HTTP 404" in json.loads(r.get_body())["errors"]["ADMIN_EMAIL"]
        assert config.ADMIN_EMAIL == "admin@contoso.com" and not ag.called

    def test_same_mailbox_sends_no_test(self, ui_on):
        with patch("admin_api.send_mailbox_test") as test:
            r = self._put({"ADMIN_EMAIL": "admin@contoso.com"})
        assert r.status_code == 200 and not test.called

    @patch("alerting.token_manager")
    @patch("config.http.post")
    def test_mailbox_test_reason(self, post, tm):
        tm.get_graph_token.return_value = "t"
        post.return_value = _resp(403, {"error": {"code": "ErrorAccessDenied"}})
        ok, reason = alerting.send_mailbox_test("new@contoso.com", "a@contoso.com")
        assert not ok and "HTTP 403 ErrorAccessDenied" in reason and "install.ps1 -Update" in reason
        assert post.call_args.args[0].endswith("/users/new@contoso.com/sendMail")

    @patch("alerting.token_manager")
    @patch("config.http.post")
    def test_mailbox_test_reason_names_the_exchange_group(self, post, tm):
        import os
        tm.get_graph_token.return_value = "t"
        post.return_value = _resp(403, {"error": {"code": "ErrorAccessDenied"}})
        with patch.dict(os.environ, {"MAIL_SEND_SCOPE": "mailbox", "MAIL_SEND_GROUP": "m365-ato-monitor-senders"}):
            ok, reason = alerting.send_mailbox_test("new@contoso.com", "a@contoso.com")
        assert not ok and "Add this mailbox to the Exchange group m365-ato-monitor-senders" in reason

    @patch("health_alerts.token_manager")
    def test_action_group_update(self, tm):
        import health_alerts
        tm.get_arm_token.return_value = "t"
        group = "/subscriptions/s/resourceGroups/rg/providers/microsoft.insights/actionGroups/ag-x"
        current = {"location": "Global", "tags": {"a": "b"}, "properties": {
            "groupShortName": "auditmon", "enabled": True,
            "emailReceivers": [{"name": "admin", "emailAddress": "old@contoso.com", "status": "Enabled",
                                "useCommonAlertSchema": True}]}}
        with patch.object(config, "ACTION_GROUP_ID", group), \
                patch("config.http.get", return_value=_resp(200, current)), \
                patch("config.http.request", return_value=_resp(200)) as put:
            assert health_alerts.set_email("new@contoso.com").endswith("now go to new@contoso.com.")
        sent = put.call_args.kwargs["json"]["properties"]["emailReceivers"][0]
        assert sent == {"name": "admin", "emailAddress": "new@contoso.com", "useCommonAlertSchema": True}
        with patch.object(config, "ACTION_GROUP_ID", group), patch("config.http.get", return_value=_resp(403)):
            assert "Monitoring Contributor" in health_alerts.set_email("new@contoso.com")
        assert "not configured" in health_alerts.set_email("x@contoso.com")


# ---------------------------------------------------------------------------
# Managed identity: federated credential, Table Storage, audit subscriptions
# ---------------------------------------------------------------------------

class TestManagedIdentity:

    @pytest.fixture
    def mi_env(self, monkeypatch):
        import identity
        identity._cache.clear()
        monkeypatch.setenv("IDENTITY_ENDPOINT", "http://localhost:8081/msi/token")
        monkeypatch.setenv("IDENTITY_HEADER", "hdr")
        with patch.multiple(config, CLIENT_SECRET=None, MANAGED_IDENTITY_CLIENT_ID="uami-client-id"):
            yield
        identity._cache.clear()

    def test_identity_token_request_and_cache(self, mi_env):
        import identity
        with patch("config.http.get", return_value=_resp(200, {"access_token": "mi-tok", "expires_on": "9999999999"})) as get:
            assert identity.client_assertion() == "mi-tok"
            assert identity.client_assertion() == "mi-tok"
        assert get.call_count == 1
        kwargs = get.call_args.kwargs
        assert kwargs["headers"] == {"X-IDENTITY-HEADER": "hdr"}
        assert kwargs["params"]["resource"] == "api://AzureADTokenExchange"
        assert kwargs["params"]["client_id"] == "uami-client-id"

    def test_app_token_uses_client_assertion(self, mi_env):
        import o365_client
        with patch("config.http.get", return_value=_resp(200, {"access_token": "mi-tok", "expires_on": "9999999999"})), \
                patch("config.http.post", return_value=_resp(200, {"access_token": "app-tok", "expires_in": 3599})) as post:
            assert o365_client.TokenManager().get_graph_token() == "app-tok"
        data = post.call_args.kwargs["data"]
        assert data["client_assertion"] == "mi-tok" and "client_secret" not in data
        assert data["client_assertion_type"] == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

    def test_secret_still_works(self):
        import o365_client
        with patch.multiple(config, CLIENT_SECRET="s3cret", MANAGED_IDENTITY_CLIENT_ID=""), \
                patch("config.http.post", return_value=_resp(200, {"access_token": "app-tok", "expires_in": 3599})) as post:
            o365_client.TokenManager().get_o365_token()
        assert post.call_args.kwargs["data"]["client_secret"] == "s3cret"

    def test_no_credential(self):
        import o365_client
        with patch.multiple(config, CLIENT_SECRET=None, MANAGED_IDENTITY_CLIENT_ID=""):
            assert not config.has_credential()
            with pytest.raises(RuntimeError, match="not configured"):
                o365_client.TokenManager().get_graph_token()

    def test_table_service_with_identity(self, mi_env):
        with patch.multiple(config, STORAGE_CONNECTION_STRING=None, STORAGE_ACCOUNT_NAME="stauditmon1"):
            assert config.storage_configured()
            svc = config.table_service()
        assert svc.url.startswith("https://stauditmon1.table.core.windows.net")
        with patch("config.http.get", return_value=_resp(200, {"access_token": "st-tok", "expires_on": "9999999999"})):
            assert svc.credential.get_token("https://storage.azure.com/.default").token == "st-tok"

    def test_ensure_subscriptions_starts_missing(self):
        import o365_client
        listing = _resp(200, [{"contentType": "Audit.AzureActiveDirectory", "status": "enabled"}])
        started = _resp(200, {})
        started.text = "{}"
        with patch("o365_client.token_manager") as tm, \
                patch("config.http.get", return_value=listing), \
                patch("config.http.post", return_value=started) as post:
            tm.get_o365_token.return_value = "t"
            result = o365_client.ensure_subscriptions(force=True)
        assert result == {"Audit.AzureActiveDirectory": "enabled", "Audit.Exchange": "started"}
        assert post.call_args.kwargs["params"]["contentType"] == "Audit.Exchange"
        assert post.call_args.kwargs["params"]["PublisherIdentifier"] == config.TENANT_ID

    def test_ensure_subscriptions_rate_limited(self):
        import o365_client
        with patch("config.http.get") as get:
            assert o365_client.ensure_subscriptions() == {}       # checked recently (conftest)
        get.assert_not_called()


class TestSecretSetting:

    KEY = "111111-222222-333333-444444"

    def test_validation(self):
        import settings
        s = settings.BY_NAME["PROXYCHECK_API_KEY"]
        assert settings.validate(s, f"  {self.KEY} ") == self.KEY
        assert settings.validate(s, "") == ""
        for bad in ("short", "has space in it", "x" * 101, 5):
            with pytest.raises(ValueError):
                settings.validate(s, bad)

    def test_never_leaves_the_server(self, ui_on):
        import admin_api
        r = admin_api.put_settings(_req("PUT", "/api/manage/api/settings",
                                        {"version": 0, "changes": {"PROXYCHECK_API_KEY": self.KEY}}, headers=MUTATE))
        assert r.status_code == 200 and self.KEY not in r.get_body().decode()
        assert config.PROXYCHECK_API_KEY == self.KEY
        change = json.loads(r.get_body())["changes"][0]
        assert (change["old"], change["new"]) == ("(not set)", "(set)")
        state = admin_api.get_state(_req()).get_body().decode()
        assert self.KEY not in state
        item = next(i for i in json.loads(state)["settings"]["items"] if i["name"] == "PROXYCHECK_API_KEY")
        assert item["value"] == "" and item["is_set"] is True and item["default"] == ""
        assert self.KEY not in json.dumps(admin_store.history(ui_on["table"]))
        assert self.KEY not in json.dumps(ui_on["email"].call_args.args[1])
        assert config.redact(f"url?key={self.KEY}") == "url?key=***"

    def test_replace_and_remove(self, ui_on):
        import admin_api
        put = lambda v, changes: admin_api.put_settings(_req(  # noqa: E731
            "PUT", "/api/manage/api/settings", {"version": v, "changes": changes}, headers=MUTATE))
        put(0, {"PROXYCHECK_API_KEY": self.KEY})
        r = put(1, {"PROXYCHECK_API_KEY": "999999-888888"})
        assert json.loads(r.get_body())["changes"][0]["new"] == "(replaced)"
        r = put(2, {"PROXYCHECK_API_KEY": ""})
        assert json.loads(r.get_body())["changes"][0]["new"] == "(not set)" and config.PROXYCHECK_API_KEY == ""
