"""Account-action guards and detection at unverified trust boundaries."""

import json
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

import alerting
import compromise_detector as cd
import function_app as fa
import mail_access
import mailbox_rules
import responder
import session_monitor as sm
from ip_checker import analyze_ip
from tests.fakes import FakeTable
from tests.test_failed_signin_tools import sign_in
from tests.test_mail_access_check import graph_read, owa_read
from tests.test_rule_text import JANE, SAM
from tests.test_session_monitor import HOME_IP, SID, Lookup, mailbox, signin

NOW = datetime(2026, 11, 12, 12, tzinfo=timezone.utc)
HOST_IP = "20.50.10.20"
GRAPH_ID = "00000003-0000-0000-c000-000000000000"


@pytest.mark.parametrize("email_failures", [False, True])
@pytest.mark.parametrize("action", ["revoke", "disable"])
@pytest.mark.parametrize("ua", ["AADInternals", "Go-http-client/1.1"])
def test_wrong_password_never_changes_accounts(email_failures, action, ua):
    event = sign_in(ua=ua)
    event["ClientIP"] = HOST_IP
    country_table = FakeTable()
    with patch("config.LOGIN_ALERT_FAILED", email_failures), patch("config.COMPROMISE_ACTION", action), \
            patch("geo_monitor.table_client", return_value=country_table), \
            patch("journal.table_client", return_value=FakeTable()), \
            patch("function_app.check_ips_batch", return_value={
                HOST_IP: {"proxy": "yes", "type": "TOR", "risk": 99}}), \
            patch("function_app.send_compromise_alert", return_value=True) as send, \
            patch("responder._graph") as graph:
        fa._run_compromise_check(FakeTable(), FakeTable(), set(), [event])
    graph.assert_not_called()
    assert send.call_count == int(email_failures)  # email policy still works
    assert country_table.partition("actions") == {}  # no daily response slot consumed


@pytest.mark.parametrize("error", ["50126", "50053", "50057", "99999", ""])
def test_responder_refuses_unproven_failed_signins_directly(error):
    event = sign_in(error=error, ua="AADInternals")
    finding = cd.detect_suspicious_user_agents([event])[0]
    with patch("config.COMPROMISE_ACTION", "disable"), patch("responder._graph") as graph:
        result = responder.respond_to_finding(FakeTable(), finding, NOW)
    assert "did not prove the password" in result
    graph.assert_not_called()


@pytest.mark.parametrize("error", ["50076", "53003", "500121", "success"])
def test_password_proven_signins_still_allow_configured_response(error):
    event = sign_in(error=error, ua="AADInternals")
    if error == "success":
        event.update(Operation="UserLoggedIn", ErrorNumber="0", ResultStatus="Success")
    finding = cd.detect_suspicious_user_agents([event])[0]
    with patch("config.COMPROMISE_ACTION", "disable"), \
            patch("responder._graph", return_value=MagicMock(status_code=204)) as graph:
        result = responder.respond_to_finding(FakeTable(), finding, NOW)
    assert "Block sign-in: done" in result and graph.call_count == 2


@pytest.mark.parametrize("asn,organisation", [
    ("AS8075", "Microsoft Corporation"), ("AS12076", "Microsoft"),
    ("AS9009", "Example Microsoft Consulting"),
])
@pytest.mark.parametrize("country", ["US", "NL"])
def test_network_ownership_cannot_hide_token_replay(asn, organisation, country):
    data = {HOME_IP: {"proxy": "no", "risk": 0, "isocode": "US", "organisation": "ISP"},
            HOST_IP: {"proxy": "no", "type": "Hosting", "risk": 99, "isocode": country,
                      "asn": asn, "organisation": organisation}}
    records = [signin(HOME_IP, 1), mailbox(HOST_IP, 5)]
    findings = sm.check(FakeTable(), records, Lookup(data), NOW, analyze=analyze_ip)
    assert len(findings) == 1 and findings[0]["ip"] == HOST_IP
    findings = mail_access.check([owa_read(ip=HOST_IP)], lambda ips: data, analyze_ip, NOW)
    assert len(findings) == 1 and findings[0]["ip"] == HOST_IP


def test_previous_microsoft_exclusion_is_rechecked_on_update():
    table = FakeTable()
    sm.check(table, [signin(HOME_IP, 1)], Lookup(), NOW)
    row = table.get_entity("session", SID)
    ips = json.loads(row["ips"])
    ips[HOST_IP] = "MS"  # persisted by an earlier version
    table.upsert_entity({"PartitionKey": "session", "RowKey": SID, "ips": json.dumps(ips), "ip_schema": 1})
    record = mailbox(HOST_IP, 5)
    assert sm.check(table, [record], Lookup({}), NOW, analyze=analyze_ip) == []
    data = {HOST_IP: {"proxy": "no", "type": "Hosting", "risk": 99, "isocode": "US", "asn": "AS8075"}}
    findings = sm.check(table, [record], Lookup(data), NOW, analyze=analyze_ip)
    assert len(findings) == 1
    assert json.loads(table.get_entity("session", SID)["ips"])[HOST_IP] == "US"


def test_country_ms_is_kept_as_a_country_after_network_exemptions_are_removed():
    table = FakeTable()
    data = {HOME_IP: {"proxy": "no", "risk": 0, "isocode": "MS", "organisation": "ISP"},
            HOST_IP: {"proxy": "no", "type": "Hosting", "risk": 99, "isocode": "MS", "asn": "AS8075"}}
    sm.check(table, [signin(HOME_IP, 1)], Lookup(data), NOW, analyze=analyze_ip)
    lookup = Lookup(data)
    findings = sm.check(table, [signin(HOME_IP, 1), mailbox(HOST_IP, 5)], lookup, NOW, analyze=analyze_ip)
    assert lookup.calls == [[HOST_IP]]
    assert len(findings) == 1 and findings[0]["mark"] == sm.NETWORK_MARK


def test_graph_service_ip_is_not_a_client_observation():
    record = graph_read()
    record["SessionId"] = SID
    lookup = Lookup()
    assert mail_access.service_ip_client(record)
    assert sm.check(FakeTable(), [signin(HOME_IP, 1), record], lookup, NOW, analyze=analyze_ip) == []
    assert all(record["ClientIPAddress"] not in batch for batch in lookup.calls)
    assert mail_access.check([record], lookup, analyze_ip, NOW) == []


@pytest.mark.parametrize("change", [
    {"ClientInfoString": "Client=OWA"},
    {"ClientInfoString": "Client=RESTOther"},
    {"AppId": "unrelated", "AppAccessContext": {}},
    {"Operation": "UserLoggedIn"},
])
def test_service_exclusion_needs_client_and_resource_evidence(change):
    record = graph_read() | change
    assert not mail_access.service_ip_client(record)
    # A new-country record is still an observation when that evidence is absent.
    record["SessionId"] = SID
    assert sm.observations([record])


def test_graph_resource_in_access_context_is_enough_with_rest_client():
    record = graph_read()
    record.pop("AppId")
    assert record["AppAccessContext"]["APIId"] == GRAPH_ID
    assert mail_access.service_ip_client(record)


@pytest.mark.parametrize("field,key", [
    ("ForwardTo", "forwardTo"), ("ForwardAsAttachmentTo", "forwardAsAttachmentTo"),
    ("RedirectTo", "redirectTo"),
])
@pytest.mark.parametrize("with_internal", [False, True])
def test_unresolved_directory_recipient_warns_in_audit_and_sweep(field, key, with_internal):
    recipient = f"colleague@contoso.com;{JANE}" if with_internal else f"EX:{JANE};{SAM}"
    event = {"Id": "forward-1", "Operation": "New-InboxRule", "UserId": "victim@contoso.com",
             "Parameters": [{"Name": "Name", "Value": "Customer mail"}, {"Name": field, "Value": recipient}]}
    finding, = cd.detect_suspicious_inbox_rules([event])
    assert finding["severity"] == "medium" and "unverified directory recipients" in finding["description"]
    rule = {"displayName": "Customer mail", "actions": {key: [{"emailAddress": {"address": JANE}}]}}
    severity, reasons = mailbox_rules.assess(rule, "victim@contoso.com")
    assert severity == "medium" and "final addresses can be external" in reasons[0]
    with patch("config.COMPROMISE_ACTION", "disable"), patch("config.AUTO_DISABLE_INBOX_RULES", True), \
            patch("responder._graph") as graph:
        assert responder.respond_to_finding(FakeTable(), finding, NOW) == ""
    graph.assert_not_called()  # an unverified destination alone must not block its user


def test_external_smtp_destination_is_still_high_with_a_directory_recipient():
    event = {"Id": "forward-2", "Operation": "New-InboxRule", "UserId": "victim@contoso.com",
             "Parameters": [{"Name": "Name", "Value": "Customer mail"},
                            {"Name": "ForwardTo", "Value": f"{JANE};outside@evil.example"}]}
    finding, = cd.detect_suspicious_inbox_rules([event])
    assert finding["severity"] == "high" and "outside@evil.example" in finding["targets"]


def test_unverified_directory_alert_asks_for_confirmation_first():
    event = {"Id": "forward-3", "Operation": "New-InboxRule", "UserId": "victim@contoso.com",
             "Parameters": [{"Name": "Name", "Value": "Customer mail"}, {"Name": "ForwardTo", "Value": JANE}]}
    finding, = cd.detect_suspicious_inbox_rules([event])
    with patch("alerting._deliver", return_value=True) as deliver:
        assert alerting.send_compromise_alert(finding)
    body = deliver.call_args.args[1]
    assert "If no one on your team made this change" in body
    assert "Revoke the user's sessions and reset the password." not in body
