"""Tests for the per-user country baseline, the anomaly alert, and the optional response."""

import json
import logging
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from tests.fakes import FakeTable

NOW = datetime(2026, 11, 7, 12, 0, tzinfo=timezone.utc)


def _obs(user="a@contoso.com", cc="US", outcome="success", day=None, error=None):
    day = day or NOW
    event = {"Id": f"{user}-{cc}-{day:%Y%m%d%H%M%S}", "UserId": user,
             "CreationTime": day.strftime("%Y-%m-%dT%H:%M:%S"),
             "Operation": "UserLoggedIn" if outcome == "success" else "UserLoginFailed"}
    if error:
        event["ErrorNumber"] = error
    return {"user": user, "country": cc, "outcome": outcome, "ip": "198.51.100.7",
            "event": event, "analysis": {"country": cc, "org": "ISP"}}


def _table_after_learning(started_days_ago=30):
    table = FakeTable()
    table.upsert_entity({"PartitionKey": "tenant", "RowKey": "tenant",
                         "started": (NOW - timedelta(days=started_days_ago)).isoformat(),
                         "countries": "{}"})
    return table


def _learn(table, user, cc, days_ago=(20, 19, 18)):
    """Put ``cc`` into the user's baseline with sign-ins on several past days (during learning)."""
    from geo_monitor import evaluate
    for d in days_ago:
        evaluate(table, [_obs(user, cc, day=NOW - timedelta(days=d))], NOW - timedelta(days=d))


@pytest.fixture(autouse=True)
def _defaults():
    with patch("config.GEO_ANOMALY_ENABLED", True), \
         patch("config.HOME_COUNTRIES", set()), \
         patch("config.GEO_LEARNING_DAYS", 14), \
         patch("config.GEO_BASELINE_DAYS", 90), \
         patch("config.GEO_PROMOTE_DAYS", 3):
        yield


class TestBaseline:

    def test_learning_period_learns_and_does_not_alert(self):
        from geo_monitor import evaluate
        table = FakeTable()
        assert evaluate(table, [_obs(cc="US"), _obs(cc="NG")], NOW) == []
        assert evaluate(table, [_obs(cc="FR")], NOW + timedelta(days=1)) == []

    def test_new_country_after_learning_alerts_once(self):
        from geo_monitor import evaluate
        table = _table_after_learning(30)
        _learn(table, "a@contoso.com", "US", days_ago=(25, 24))  # learned in the learning period

        assert evaluate(table, [_obs(cc="US")], NOW) == []
        anomalies = evaluate(table, [_obs(cc="NG")], NOW)
        assert len(anomalies) == 1
        assert anomalies[0]["known"] == ["US"]
        # Same user and country again within 24 h: no second alert.
        assert evaluate(table, [_obs(cc="NG", day=NOW + timedelta(hours=1))], NOW + timedelta(hours=1)) == []

    def test_country_promoted_after_sign_ins_on_three_days(self):
        from geo_monitor import evaluate
        table = _table_after_learning(30)
        _learn(table, "a@contoso.com", "US", days_ago=(25,))
        for d in range(3):
            when = NOW + timedelta(days=d)
            evaluate(table, [_obs(cc="FR", day=when)], when)
        when = NOW + timedelta(days=4)
        assert evaluate(table, [_obs(cc="FR", day=when)], when) == []

    def test_home_countries_never_anomalous_and_enable_alerts_during_learning(self):
        from geo_monitor import evaluate
        with patch("config.HOME_COUNTRIES", {"US"}):
            table = FakeTable()  # learning just started
            assert evaluate(table, [_obs(cc="US")], NOW) == []
            assert len(evaluate(table, [_obs(cc="NG")], NOW)) == 1

    def test_new_user_uses_tenant_baseline(self):
        from geo_monitor import evaluate
        table = _table_after_learning(30)
        _learn(table, "a@contoso.com", "US", days_ago=(25,))
        assert evaluate(table, [_obs(user="new@contoso.com", cc="US")], NOW) == []
        assert len(evaluate(table, [_obs(user="new2@contoso.com", cc="NG")], NOW)) == 1

    def test_correct_password_failure_alerts_and_is_not_learned(self):
        from geo_monitor import evaluate, sign_in_outcome
        table = _table_after_learning(30)
        _learn(table, "a@contoso.com", "US", days_ago=(25,))
        obs = _obs(cc="NG", outcome="password_ok", error="50074")
        assert sign_in_outcome(obs["event"]) == "password_ok"
        assert len(evaluate(table, [obs], NOW)) == 1
        countries = json.loads(next(iter(table.partition("user").values()))["countries"])
        assert countries["NG"]["days"] == []

    def test_plain_failure_ignored(self):
        from geo_monitor import evaluate, sign_in_outcome
        table = _table_after_learning(30)
        _learn(table, "a@contoso.com", "US", days_ago=(25,))
        obs = _obs(cc="NG", outcome="failed", error="50126")
        assert sign_in_outcome(obs["event"]) == "failed"
        assert evaluate(table, [obs], NOW) == []

    def test_old_country_leaves_baseline(self):
        from geo_monitor import evaluate
        table = _table_after_learning(200)
        _learn(table, "a@contoso.com", "US", days_ago=(150,))
        _learn(table, "a@contoso.com", "CA", days_ago=(10, 9, 8))  # promoted, recent
        assert len(evaluate(table, [_obs(cc="US")], NOW)) == 1

    def test_no_reference_learns_instead_of_alerting(self):
        from geo_monitor import evaluate
        table = _table_after_learning(30)  # learning over, but nothing learned
        assert evaluate(table, [_obs(cc="US")], NOW) == []
        assert len(evaluate(table, [_obs(cc="NG")], NOW)) == 1  # now US is the reference

    def test_disabled(self):
        from geo_monitor import evaluate
        with patch("config.GEO_ANOMALY_ENABLED", False):
            assert evaluate(_table_after_learning(30), [_obs(cc="NG")], NOW) == []

    def test_storage_error_does_not_raise(self):
        from geo_monitor import evaluate
        broken = MagicMock()
        broken.get_entity.side_effect = RuntimeError("down")
        assert evaluate(broken, [_obs()], NOW) == []

    def test_country_code_parsing(self):
        from geo_monitor import country_of
        assert country_of({"isocode": "ng"}) == "NG"
        assert country_of({"isocode": "N/A"}) == ""
        assert country_of({}) == ""


# ---------------------------------------------------------------------------
# Response actions
# ---------------------------------------------------------------------------

def _graph_ok():
    def request(method, url, **kwargs):
        r = MagicMock()
        r.status_code = 204 if method == "PATCH" else 200
        return r
    http = MagicMock()
    http.request.side_effect = request
    return http


class TestResponder:

    def _respond(self, action, upn="victim@contoso.com", outcome="success", learning=False,
                 table=None, http=None, exempt=()):
        from responder import respond
        http = http or _graph_ok()
        with patch("config.ANOMALY_ACTION", action), \
             patch("config.ANOMALY_ACTION_EXEMPT", set(exempt)), \
             patch("config.ANOMALY_ACTION_MAX_PER_DAY", 3), \
             patch("config.http", http), patch("responder.token_manager"):
            result = respond(table if table is not None else FakeTable(), upn, outcome, learning, NOW)
        return result, http

    def test_none_makes_no_call(self):
        result, http = self._respond("none")
        http.request.assert_not_called()
        assert result.startswith("none")

    def test_revoke(self):
        result, http = self._respond("revoke")
        (method, url), = [c.args for c in http.request.call_args_list]
        assert method == "POST" and url.endswith("/users/victim@contoso.com/revokeSignInSessions")
        assert "Revoke sessions: done" in result

    def test_disable_blocks_then_revokes(self):
        result, http = self._respond("disable")
        calls = http.request.call_args_list
        assert [c.args[0] for c in calls] == ["PATCH", "POST"]
        assert calls[0].kwargs["json"] == {"accountEnabled": False}
        assert "Block sign-in: done" in result and "Revoke sessions: done" in result

    @pytest.mark.parametrize("upn,exempt", [
        ("admin@contoso.com", ()),                       # ADMIN_EMAIL (conftest)
        ("breakglass@contoso.com", ("breakglass@contoso.com",)),
    ])
    def test_exempt_accounts_unchanged(self, upn, exempt):
        result, http = self._respond("disable", upn=upn, exempt=exempt)
        http.request.assert_not_called()
        assert "exempt" in result

    def test_no_action_for_incomplete_sign_in_or_learning(self):
        for kwargs in ({"outcome": "password_ok"}, {"learning": True}):
            result, http = self._respond("disable", **kwargs)
            http.request.assert_not_called()

    def test_daily_limit(self):
        table = FakeTable()
        for _ in range(3):
            self._respond("revoke", table=table)
        result, http = self._respond("revoke", table=table)
        http.request.assert_not_called()
        assert "daily limit" in result

    def test_admin_account_refused(self, caplog):
        http = MagicMock()
        http.request.return_value = MagicMock(status_code=403)
        with caplog.at_level(logging.ERROR):
            result, _ = self._respond("disable", http=http)
        assert "HTTP 403 (no admin consent for the permission, or an admin account)" in result
        assert "Response action" in caplog.text


# ---------------------------------------------------------------------------
# Pipeline integration
# ---------------------------------------------------------------------------

def _pc(ip, isocode, proxy="no", ptype="Residential"):
    r = MagicMock(status_code=200)
    r.json.return_value = {"status": "ok", ip: {"proxy": proxy, "type": ptype, "risk": 0,
                                                 "isocode": isocode, "country": isocode,
                                                 "organisation": "Home ISP"}}
    return r


class TestPipeline:

    def _login(self, ip, user="victim@contoso.com"):
        return {"Id": f"login-{ip}", "RecordType": 15, "Operation": "UserLoggedIn",
                "UserId": user, "ClientIP": ip, "CreationTime": NOW.strftime("%Y-%m-%dT%H:%M:%S")}

    def test_foreign_residential_sign_in_alerts_and_responds(self):
        from function_app import _run_login_check
        geo = _table_after_learning(30)
        _learn(geo, "victim@contoso.com", "US", days_ago=(25,))
        with patch("geo_monitor.table_client", return_value=geo), \
             patch("config.http") as mock_http, \
             patch("function_app.send_country_anomaly_alert", return_value=True) as mock_alert, \
             patch("responder.respond", return_value="Revoke sessions: done") as mock_respond:
            mock_http.post.return_value = _pc("203.0.114.9", "NG")
            _run_login_check(FakeTable(), FakeTable(), set(), [self._login("203.0.114.9")])

        mock_alert.assert_called_once()
        anomaly, result = mock_alert.call_args.args[:2]
        assert anomaly["country"] == "NG" and result == "Revoke sessions: done"
        assert mock_respond.call_args.args[1:4] == ("victim@contoso.com", "success", False)

    def test_vpn_sign_in_not_used_for_country(self):
        from function_app import _run_login_check
        geo = _table_after_learning(30)
        _learn(geo, "victim@contoso.com", "US", days_ago=(25,))
        with patch("geo_monitor.table_client", return_value=geo), \
             patch("config.http") as mock_http, \
             patch("function_app.send_suspicious_login_alert", return_value=True), \
             patch("function_app.send_country_anomaly_alert") as mock_alert:
            mock_http.post.return_value = _pc("203.0.114.9", "NG", proxy="yes", ptype="VPN")
            _run_login_check(FakeTable(), FakeTable(), set(), [self._login("203.0.114.9")])
        mock_alert.assert_not_called()

    def test_compromise_finding_from_new_country_is_high(self):
        from function_app import _run_compromise_check
        geo = _table_after_learning(30)
        _learn(geo, "victim@contoso.com", "US", days_ago=(25,))
        rule = {"Id": "r1", "Operation": "New-InboxRule", "UserId": "victim@contoso.com",
                "ClientIP": "203.0.114.9",
                "Parameters": [{"Name": "Name", "Value": "x"}, {"Name": "DeleteMessage", "Value": "True"}]}
        with patch("geo_monitor.table_client", return_value=geo), \
             patch("config.http") as mock_http, \
             patch("function_app.send_compromise_alert", return_value=True) as mock_alert:
            mock_http.post.return_value = _pc("203.0.114.9", "NG")
            _run_compromise_check(FakeTable(), FakeTable(), set(), [rule])
        finding, ip_context = mock_alert.call_args.args[:2]
        assert finding["severity"] == "high"
        assert "NG is new for this user" in ip_context


class TestEmail:

    @patch("alerting.token_manager")
    def test_country_alert_content(self, mock_tm):
        from alerting import send_country_anomaly_alert
        mock_tm.get_graph_token.return_value = "t"
        anomaly = {**_obs(cc="NG"), "known": ["US"], "learning": False}
        anomaly["analysis"] = {"country": "Nigeria", "org": "Home ISP", "asn": "AS1"}
        with patch("config.http") as mock_http:
            mock_http.post.return_value = MagicMock(status_code=202)
            assert send_country_anomaly_alert(anomaly, "Block sign-in: done; Revoke sessions: done")
            payload = mock_http.post.call_args.kwargs["json"]
        assert payload["message"]["subject"] == (
            "[M365 Alert] HIGH: Sign-in from new country NG - a@contoso.com, success")
        body = payload["message"]["body"]["content"]
        assert "Nigeria (NG)" in body and "Usual countries" in body and "US" in body
        assert "sign-in blocked, sessions revoked" in body
        assert "--account-enabled true" in body       # undo step, shown because sign-in was blocked

    @patch("alerting.token_manager")
    def test_correct_password_and_failed_response(self, mock_tm):
        from alerting import send_country_anomaly_alert
        mock_tm.get_graph_token.return_value = "t"
        anomaly = {**_obs(cc="NG", outcome="password_ok", error="50074"), "known": ["US"], "learning": False}
        with patch("config.http") as mock_http:
            mock_http.post.return_value = MagicMock(status_code=202)
            send_country_anomaly_alert(anomaly, "Revoke sessions failed: HTTP 403 (x)")
            payload = mock_http.post.call_args.kwargs["json"]
        assert payload["message"]["subject"].endswith(", correct password")
        body = payload["message"]["body"]["content"]
        assert "correct password" in body and "Reset the password now" in body
        assert "Failed:" in body and "--account-enabled" not in body
