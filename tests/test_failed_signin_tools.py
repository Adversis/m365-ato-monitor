"""A failed sign-in (wrong password) by an automation client or an attack tool sends no
email unless LOGIN_ALERT_FAILED is on. A correct password stopped by MFA still alerts."""

from unittest.mock import patch

import pytest

import function_app as fa
import journal
import onboarding
from compromise_detector import detect_suspicious_user_agents
from tests.fakes import FakeTable


def sign_in(error="50126", ua="Go-http-client/1.1", record_id="5e55a0e1-0000-4000-8000-00000000b001"):
    """The shape of a real alert record (values made up): UserLoginFailed, InvalidUserNameOrPassword, Go-http-client."""
    return {
        "CreationTime": "2026-11-11T15:49:59", "Id": record_id, "Operation": "UserLoginFailed",
        "RecordType": 15, "ResultStatus": "Failed", "UserType": 0, "Workload": "AzureActiveDirectory",
        "ClientIP": "2001:db8:27:7c63::6fb4", "UserId": "alex@contoso.com",
        "ExtendedProperties": [{"Name": "ResultStatusDetail", "Value": "UserError"},
                               {"Name": "UserAgent", "Value": ua},
                               {"Name": "RequestType", "Value": "OAuth2:Token"}],
        "ErrorNumber": error, "LogonError": "InvalidUserNameOrPassword" if error == "50126" else "",
    }


def run(event, jt):
    with patch("journal.table_client", return_value=jt), \
            patch("function_app.send_compromise_alert", return_value=True) as send, \
            patch("function_app.check_ips_batch", return_value={}) as lookup:
        fa._run_compromise_check(FakeTable(), FakeTable(), set(), [event])
    rows, _ = journal.window(jt, journal.ANY_TIME)
    return send, lookup, rows


def test_wrong_password_from_an_automation_client_sends_no_email():
    send, lookup, rows = run(sign_in(), FakeTable())
    assert send.call_count == 0
    assert lookup.call_count == 0                                    # no IP lookup spent on it
    assert [(r["type"], r["status"], r["action"]) for r in rows] == [
        ("suspicious_user_agent", "alert off", "failed sign-in, email off")]


def test_wrong_password_from_an_attack_tool_sends_no_email():
    send, _, rows = run(sign_in(ua="AADInternals"), FakeTable())
    assert send.call_count == 0
    assert [(r["type"], r["status"]) for r in rows] == [("attack_tool", "alert off")]


@pytest.mark.parametrize("error", ["50076", "50074", "53003", "500121"])
def test_correct_password_stopped_by_mfa_or_conditional_access_alerts(error):
    send, _, rows = run(sign_in(error=error), FakeTable())
    assert send.call_count == 1
    assert [r["status"] for r in rows] != ["alert off"]


def test_email_failed_sign_ins_setting_turns_the_email_on():
    with patch("config.LOGIN_ALERT_FAILED", True):
        send, _, _ = run(sign_in(), FakeTable())
    assert send.call_count == 1


def test_successful_sign_in_from_an_automation_client_alerts():
    event = sign_in()
    event.update(Operation="UserLoggedIn", ResultStatus="Success", ErrorNumber="0", LogonError="")
    send, _, _ = run(event, FakeTable())
    assert send.call_count == 1


def test_onboarding_scan_does_not_list_a_failed_sign_in():
    jt, events = FakeTable(), FakeTable()
    counts = {"findings": 0, "high": 0, "by_type": {}}
    onboarding._detect([detect_suspicious_user_agents], [sign_in(), sign_in(error="50076", record_id="r2")],
                       events, jt, {"run_id": "run-1"}, counts, fa.datetime.now(fa.timezone.utc))
    rows, _ = journal.window(jt, journal.ANY_TIME)
    assert sorted(r["status"] for r in rows) == ["alert off", "onboarding"]
    assert counts["findings"] == 1                                   # only the correct-password one
