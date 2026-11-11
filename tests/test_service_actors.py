"""Changes made by Microsoft's own services: journal "microsoft", no email."""

from unittest.mock import MagicMock, patch

import pytest

import journal
import service_actors as sa
from compromise_detector import detect_suspicious_oauth_consents
from tests.fakes import FakeTable

MS_SP = "a11ce000-0000-4000-8000-000000000001"
OWN_SP = "11111111-2222-4333-8444-555555555555"


def grant(actor=f"ServicePrincipal_{MS_SP}"):
    """"Add delegated permission grant." by a service principal (seen in a new tenant)."""
    return {"Id": f"g-{actor}", "CreationTime": "2026-06-11T11:08:47", "RecordType": 8,
            "Operation": "Add delegated permission grant.", "UserId": actor, "UserType": 5,
            "Actor": [{"ID": actor, "Type": 2}],
            "ModifiedProperties": [{"Name": "DelegatedPermissionGrant.Scope", "NewValue": "Files.ReadWrite.All",
                                    "OldValue": ""}],
            "Target": [{"ID": "Microsoft Graph", "Type": 1}]}


def _graph(owners):
    def get(url, params=None, headers=None, timeout=None):
        sp = url.rsplit("/", 1)[-1]
        if sp not in owners:
            return MagicMock(status_code=404)
        r = MagicMock(status_code=200)
        r.json.return_value = {"appOwnerOrganizationId": owners[sp]}
        return r
    return get


@pytest.fixture(autouse=True)
def clean():
    sa.clear_cache()
    with patch("service_actors.token_manager") as tm:
        tm.get_graph_token.return_value = "t"
        yield
    sa.clear_cache()


def finding(event):
    found = detect_suspicious_oauth_consents([event])
    assert len(found) == 1
    return found[0]


def test_microsoft_owned_service_principal():
    with patch("config.http") as http:
        http.get.side_effect = _graph({MS_SP: "F8CDEF31-A31E-4B4A-93E4-5F571E91255A"})
        assert sa.is_microsoft_service(finding(grant()))
        assert sa.is_microsoft_service(finding(grant()))
        assert http.get.call_count == 1                                      # cached


def test_tenant_owned_app_still_alerts():
    with patch("config.http") as http:
        http.get.side_effect = _graph({OWN_SP: "0e1f0000-0000-4000-8000-0000000000aa"})
        assert not sa.is_microsoft_service(finding(grant(f"ServicePrincipal_{OWN_SP}")))


def test_a_person_never_counts_as_microsoft():
    event = grant()
    event["UserId"] = "admin@contoso.com"
    with patch("config.http") as http:
        assert not sa.is_microsoft_service({"type": "oauth_consent", "event": event})
        http.get.assert_not_called()


def test_without_the_permission_everything_alerts():
    with patch("config.http") as http:
        http.get.return_value = MagicMock(status_code=403)
        assert not sa.is_microsoft_service(finding(grant()))
        assert not sa.is_microsoft_service(finding(grant()))
        assert http.get.call_count == 1                                      # no new request for an hour


def test_monitor_run_journals_without_email():
    import function_app as fa
    jt = FakeTable()
    with patch("config.http") as http, patch("journal.table_client", return_value=jt), \
            patch("function_app.send_compromise_alert", return_value=True) as send, \
            patch("function_app.check_ips_batch", return_value={}):
        http.get.side_effect = _graph({MS_SP: "f8cdef31-a31e-4b4a-93e4-5f571e91255a"})
        fa._run_compromise_check(FakeTable(), FakeTable(), set(), [grant()])
    assert send.call_count == 0
    rows, _ = journal.window(jt, journal.ANY_TIME)
    assert [r["status"] for r in rows] == ["microsoft"]


@pytest.mark.parametrize("ftype", ["mfa_change", "admin_role", "inbox_rule", "app_credential"])
def test_only_consents_can_be_microsoft_noise(ftype):
    """The MFA service writes the record when an attacker adds an MFA method; PIM writes role activations."""
    event = {"UserId": f"ServicePrincipal_{MS_SP}", "Actor": [{"ID": f"ServicePrincipal_{MS_SP}", "Type": 2}]}
    with patch("config.http") as http:
        http.get.side_effect = _graph({MS_SP: "f8cdef31-a31e-4b4a-93e4-5f571e91255a"})
        assert not sa.is_microsoft_service({"type": ftype, "event": event})
        http.get.assert_not_called()


def test_failed_lookup_is_not_repeated_for_15_minutes():
    with patch("config.http") as http, patch("service_actors.time.monotonic", return_value=1000.0) as clock:
        http.get.side_effect = ConnectionError("slow Graph")
        assert sa.owner_tenant(MS_SP) is None
        assert sa.owner_tenant(MS_SP) is None
        assert http.get.call_count == 1
        clock.return_value = 1000.0 + 901
        http.get.side_effect = _graph({MS_SP: "f8cdef31-a31e-4b4a-93e4-5f571e91255a"})
        assert sa.owner_tenant(MS_SP) == "f8cdef31-a31e-4b4a-93e4-5f571e91255a"


def test_an_answer_that_is_not_json_does_not_raise():
    bad = MagicMock(status_code=200)
    bad.json.side_effect = ValueError("not JSON")
    with patch("config.http") as http:
        http.get.return_value = bad
        assert sa.owner_tenant(MS_SP) is None
