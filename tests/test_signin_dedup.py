"""One interactive sign-in writes many records seconds apart: one alert, and a user for every record."""

from unittest.mock import MagicMock, patch

import pytest

import function_app as fa
from tests.fakes import FakeTable

IP = "2a01:4f8:c014:8d4e::1"
SID = "5e55a0e1-1111-4222-8333-000000000104"
USER = "root@contoso.onmicrosoft.com"
OID = "e4c722ac-3b83-478d-8f52-c388885dc30f"
HETZNER_VPN = {IP: {"proxy": "yes", "type": "VPN", "risk": 66, "isocode": "DE", "city": "Falkenstein",
                    "asn": "AS24940", "organisation": "Hetzner Online GmbH", "provider": "Hetzner Online GmbH"}}


def signin(n, user=USER, sid=SID, result="Success", actor=None):
    r = {"Id": f"rec-{n}", "RecordType": 15, "CreationTime": f"2026-11-09T17:25:{19 + n:02d}",
         "Operation": "UserLoggedIn" if result == "Success" else "UserLoginFailed", "UserId": user,
         "ClientIP": IP, "ResultStatus": result, "ApplicationId": "c44b4083-3bb0-49c1-b47d-974e53cbdf3c",
         "ObjectId": "797f4846-ba00-4fd7-ba43-dac1f8f63013",
         "DeviceProperties": [{"Name": "SessionId", "Value": sid}]}
    if actor is not None:
        r["Actor"] = actor
    if result != "Success":
        r["LogonError"] = "InvalidUserNameOrPassword"
    return r


def _run(records, table=None):
    table = table if table is not None else FakeTable()
    with patch("function_app.check_ips_batch", return_value=HETZNER_VPN), \
            patch("function_app.send_suspicious_login_alert", return_value=True) as send, \
            patch("journal.table_client", return_value=FakeTable()), \
            patch("geo_monitor.table_client", return_value=None):
        fa._run_login_check(table, FakeTable(), set(), records)
    return send, table


class TestDedup:

    def test_fifteen_records_one_email(self):
        records = [signin(i) for i in range(15)]
        send, table = _run(records)
        assert send.call_count == 1
        assert all(table.get_entity("events", r["Id"]) for r in records)        # every record processed

    def test_next_run_and_next_day(self):
        send, table = _run([signin(0)])
        assert send.call_count == 1
        send, _ = _run([signin(1)], table)                                       # same day, later run
        assert send.call_count == 0
        tomorrow = signin(2)
        tomorrow["CreationTime"] = "2026-11-10T08:00:00"
        send, _ = _run([tomorrow], table)
        assert send.call_count == 1

    def test_repeats_counted_on_the_first_alert(self):
        import journal
        jt = FakeTable()
        table = FakeTable()
        with patch("function_app.check_ips_batch", return_value=HETZNER_VPN), \
                patch("function_app.send_suspicious_login_alert", return_value=True), \
                patch("journal.table_client", return_value=jt), \
                patch("geo_monitor.table_client", return_value=None):
            fa._run_login_check(table, FakeTable(), set(), [signin(i) for i in range(5)])
            fa._run_login_check(table, FakeTable(), set(), [signin(i) for i in range(5, 8)])   # a later run
        rows, _ = journal.window(jt, journal.ANY_TIME)
        assert len(rows) == 1
        assert rows[0]["repeats"] == 7 and rows[0]["last_repeat"] == "2026-11-09T17:25:26Z"

    def test_failure_then_success_alerts_again(self):
        with patch("config.LOGIN_ALERT_FAILED", True):
            send, _ = _run([signin(0, result="Failed"), signin(1, result="Failed"), signin(2)])
        assert send.call_count == 2

    def test_failed_signins_no_email_by_default(self):
        import journal
        jt = FakeTable()
        table = FakeTable()
        with patch("function_app.check_ips_batch", return_value=HETZNER_VPN), \
                patch("function_app.send_suspicious_login_alert", return_value=True) as send, \
                patch("journal.table_client", return_value=jt), \
                patch("geo_monitor.table_client", return_value=None):
            fa._run_login_check(table, FakeTable(), set(), [signin(i, result="Failed") for i in range(4)])
        assert send.call_count == 0
        rows, _ = journal.window(jt, journal.ANY_TIME)
        assert len(rows) == 1 and rows[0]["status"] == "alert off" and rows[0]["repeats"] == 3

    @pytest.mark.parametrize("code", ["500121", "53000", "53003", "50055", "50097"])
    def test_correct_password_then_blocked_still_emails(self, code):
        """MFA denied (MFA fatigue), a Conditional Access block, an expired password: the password was right."""
        r = signin(0, result="Failed")
        r["ErrorNumber"] = code
        send, _ = _run([r])
        assert send.call_count == 1

    def test_correct_password_stopped_at_mfa_still_emails(self):
        r = signin(0, result="Failed")
        r["LogonError"] = "UserStrongAuthClientAuthNRequiredInterrupt"
        r["ErrorNumber"] = "50074"
        send, _ = _run([r])
        assert send.call_count == 1

    def test_unresolved_users_are_not_one_person(self):
        """Two accounts that stay "Not Available" from one IP: two alerts."""
        send, _ = _run([signin(0, user="Not Available", sid="aaaaaaaa-1111-4222-8333-000000000001"),
                        signin(1, user="Not Available", sid="aaaaaaaa-1111-4222-8333-000000000002")])
        assert send.call_count == 2

    def test_alerts_after_the_mute_is_removed(self):
        mute = {"id": "m1", "type": "suspicious_signin", "user": USER}
        table = FakeTable()
        with patch("admin_store.matching_mute", return_value=mute), patch("admin_store.describe_mute", return_value="m"):
            send, _ = _run([signin(0)], table)
        assert send.call_count == 0
        send, _ = _run([signin(1)], table)                                          # same day, mute gone
        assert send.call_count == 1
        send, _ = _run([signin(2)], table)                                          # now a repeat
        assert send.call_count == 0

    def test_failed_signins_alert_after_the_setting_is_turned_on(self):
        table = FakeTable()
        send, _ = _run([signin(0, result="Failed")], table)
        assert send.call_count == 0
        with patch("config.LOGIN_ALERT_FAILED", True):
            send, _ = _run([signin(1, result="Failed")], table)
        assert send.call_count == 1

    def test_other_user_same_ip_alerts(self):
        send, _ = _run([signin(0), signin(1, user="sam@contoso.onmicrosoft.com", sid="aaaaaaaa-1111-4222-8333-000000000000")])
        assert send.call_count == 2


class TestResolveUsers:

    def test_from_the_same_session(self):
        records = [signin(0), signin(1, user="Not Available"), signin(2, user="Not Available")]
        assert fa.resolve_signin_users(records) == 2
        assert {r["UserId"] for r in records} == {USER}
        assert records[1]["UserIdInRecord"] == "Not Available"

    def test_from_actor_upn(self):
        r = signin(0, user="Not Available", sid="", actor=[{"ID": OID, "Type": 0}, {"ID": USER, "Type": 5}])
        fa.resolve_signin_users([r])
        assert r["UserId"] == USER

    def test_from_actor_object_id_through_graph(self):
        import o365_client
        o365_client._upn_cache.clear()
        o365_client._upn_failed.clear()
        r = signin(0, user="Not Available", sid="",
                   actor=[{"ID": OID, "Type": 0}, {"ID": "Not Available", "Type": 5}])
        resp = MagicMock(status_code=200)
        resp.json.return_value = {"userPrincipalName": USER}
        with patch("o365_client.token_manager") as tm, patch("config.http") as http:
            tm.get_graph_token.return_value = "t"
            http.get.return_value = resp
            fa.resolve_signin_users([r])
            assert http.get.call_args.args[0].endswith(f"/users/{OID}")
        assert r["UserId"] == USER

    def test_slow_graph_stops_after_the_time_budget(self):
        import o365_client
        o365_client._upn_cache.clear()
        o365_client._upn_failed.clear()
        records = [signin(i, user="Not Available", sid="",
                          actor=[{"ID": f"e4c722ac-3b83-478d-8f52-c388885dc3{i:02d}", "Type": 0}]) for i in range(5)]
        now = [0.0]

        def slow_get(*args, **kwargs):
            now[0] += 11.0                          # each lookup takes 11 seconds
            return MagicMock(status_code=503)

        with patch("o365_client.token_manager") as tm, patch("config.http") as http, \
                patch("time.monotonic", side_effect=lambda: now[0]):
            tm.get_graph_token.return_value = "t"
            http.get.side_effect = slow_get
            fa.resolve_signin_users(records)
            assert http.get.call_count == 1

    def test_failed_lookup_is_not_repeated_on_the_next_run(self):
        import o365_client
        o365_client._upn_cache.clear()
        o365_client._upn_failed.clear()
        with patch("o365_client.token_manager") as tm, patch("config.http") as http:
            tm.get_graph_token.return_value = "t"
            http.get.return_value = MagicMock(status_code=503)
            for _ in range(3):
                fa.resolve_signin_users([signin(0, user="Not Available", sid="", actor=[{"ID": OID, "Type": 0}])])
            assert http.get.call_count == 1

    def test_unknown_stays(self):
        import o365_client
        o365_client._upn_cache.clear()
        o365_client._upn_failed.clear()
        r = signin(0, user="Not Available", sid="", actor=[{"ID": "Not Available", "Type": 5}])
        assert fa.resolve_signin_users([r]) == 0 and r["UserId"] == "Not Available"

    def test_one_email_after_resolution(self):
        records = [signin(0)] + [signin(i, user="Not Available") for i in range(1, 12)]
        fa.resolve_signin_users(records)
        send, _ = _run(records)
        assert send.call_count == 1
        assert send.call_args.args[0]["UserId"] == USER
