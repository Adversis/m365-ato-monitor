"""Tests for the EICAR-style self-test: a synthetic event must be detected by
the real detector, and (when requested) produce a clearly-labeled alert."""

from unittest.mock import patch


def test_selftest_detects_without_alert():
    from function_app import _run_self_test
    result = _run_self_test(send_alert=False)
    assert result["detected"] is True
    assert result["alert_requested"] is False
    assert result["alert_email_sent"] is False
    assert result["findings"][0]["type"] == "inbox_rule"
    assert result["findings"][0]["severity"] == "high"


@patch("selftest.send_compromise_alert")
def test_selftest_sends_labeled_alert(mock_send):
    from function_app import _run_self_test
    mock_send.return_value = True
    result = _run_self_test(send_alert=True)
    assert result["detected"] is True
    assert result["alert_email_sent"] is True
    mock_send.assert_called_once()
    # The alerted finding must be unmistakably labeled as a self-test.
    finding_arg = mock_send.call_args[0][0]
    assert "SELF-TEST" in finding_arg["description"]


@patch("selftest.send_compromise_alert")
def test_selftest_reports_alert_failure(mock_send):
    from function_app import _run_self_test
    mock_send.return_value = False
    result = _run_self_test(send_alert=True)
    assert result["detected"] is True
    assert result["alert_email_sent"] is False


# ---------------------------------------------------------------------------
# Every alert type
# ---------------------------------------------------------------------------

import pytest

import selftest


def _all_findings(event):
    from function_app import _DETECTORS
    out = []
    for d in _DETECTORS:
        out.extend(d([event]))
    return out


@pytest.mark.parametrize("ftype", list(selftest.COMPROMISE))
def test_each_record_triggers_its_type_only(ftype):
    findings = _all_findings(selftest.record(ftype))
    assert [f["type"] for f in findings] == [ftype]


def test_every_finding_type_has_a_selftest():
    import alerting
    assert set(alerting._FINDING_TITLES) == set(selftest.COMPROMISE) | set(selftest.STATEFUL)


def test_all_types_without_email():
    from function_app import _run_self_test
    result = _run_self_test(send_alert=False, types="all")
    assert result["passed"] is True
    assert [r["type"] for r in result["results"]] == selftest.ALL
    assert all(r["detected"] for r in result["results"] if r["type"] in selftest.COMPROMISE)


@patch("selftest.send_country_anomaly_alert", return_value=True)
@patch("selftest.send_suspicious_login_alert", return_value=True)
@patch("selftest.send_compromise_alert", return_value=True)
def test_all_types_send_labeled_emails(mock_comp, mock_login, mock_country):
    from function_app import _run_self_test
    result = _run_self_test(send_alert=True, types="all")
    assert result["passed"] is True and result["alert_email_sent"] is True
    assert mock_comp.call_count == len(selftest.COMPROMISE) + len(selftest.STATEFUL)
    assert all(c.kwargs["subject_prefix"] == "[SELF-TEST] " for c in mock_comp.call_args_list)
    assert mock_login.call_count == 1 and mock_country.call_count == 1
    assert "SELF-TEST" in mock_login.call_args[0][0]["UserId"]


@patch("selftest.send_compromise_alert", return_value=False)
def test_failed_email_fails_the_test(mock_comp):
    from function_app import _run_self_test
    result = _run_self_test(send_alert=True, types="mfa_change,admin_role")
    assert result["passed"] is False
    assert [r["type"] for r in result["results"]] == ["mfa_change", "admin_role"]


@pytest.mark.parametrize("value,expected", [
    (None, ["inbox_rule"]), ("", ["inbox_rule"]), ("all", selftest.ALL),
    ("mfa_change, admin_role", ["mfa_change", "admin_role"]), (["device_code", "device_code"], ["device_code"]),
])
def test_parse_types(value, expected):
    assert selftest.parse_types(value) == expected


def test_parse_types_unknown():
    with pytest.raises(ValueError):
        selftest.parse_types("inbox_rule,nope")


def test_http_endpoint_types():
    import azure.functions as func
    import json
    import function_app
    req = func.HttpRequest("GET", "/api/selftest", params={"type": "all"}, body=b"")
    resp = function_app.self_test.build().get_user_function()(req)
    body = json.loads(resp.get_body())
    assert resp.status_code == 200 and len(body["results"]) == len(selftest.ALL)
    req = func.HttpRequest("GET", "/api/selftest", params={"type": "bogus"}, body=b"")
    assert function_app.self_test.build().get_user_function()(req).status_code == 400
