"""Tests for the management UI: settings layer, store, and API security checks."""

import base64
import json
from unittest.mock import patch

import azure.functions as func
import pytest

import config
from tests.fakes import FakeTable


# ---------------------------------------------------------------------------
# Settings schema and validation
# ---------------------------------------------------------------------------

class TestValidate:

    @pytest.mark.parametrize("name,raw,expected", [
        ("RISK_SCORE_THRESHOLD", "50", 50),
        ("GEO_ANOMALY_ENABLED", "false", False),
        ("LOGIN_ALERT_MODE", "digest", "digest"),
        ("ALLOWED_IPS", "203.0.113.7\n10.0.0.0/8, 2001:DB8::/32", ["203.0.113.7", "10.0.0.0/8", "2001:db8::/32"]),
        ("HOME_COUNTRIES", ["us", " ca "], ["US", "CA"]),
        ("INTERNAL_DOMAINS", "Contoso.OnMicrosoft.com.", ["contoso.onmicrosoft.com"]),
        ("ANOMALY_ACTION_EXEMPT", ["BreakGlass@Contoso.com"], ["breakglass@contoso.com"]),
        ("ATTACK_TOOL_USER_AGENTS", "AADInternals\nAADInternals\nTeamFiltration", ["AADInternals", "TeamFiltration"]),
    ])
    def test_valid(self, name, raw, expected):
        import settings
        assert settings.validate(settings.BY_NAME[name], raw) == expected

    @pytest.mark.parametrize("name,raw", [
        ("RISK_SCORE_THRESHOLD", 101),
        ("RISK_SCORE_THRESHOLD", True),
        ("RISK_SCORE_THRESHOLD", "abc"),
        ("LOOKBACK_MINUTES", 2),
        ("LOGIN_ALERT_MODE", "batch"),
        ("GEO_ANOMALY_ENABLED", "yes"),
        ("ALLOWED_IPS", ["not-an-ip"]),
        ("ALLOWED_IPS", ["0.0.0.0/0"]),           # would allow every address
        ("HOME_COUNTRIES", ["USA"]),
        ("INTERNAL_DOMAINS", ["bad domain"]),
        ("ANOMALY_ACTION_EXEMPT", ["nobody"]),
        ("ATTACK_TOOL_USER_AGENTS", ["x" * 101]),
    ])
    def test_invalid(self, name, raw):
        import settings
        with pytest.raises(ValueError):
            settings.validate(settings.BY_NAME[name], raw)

    def test_permission_check_for_values(self):
        import settings
        action = settings.BY_NAME["ANOMALY_ACTION"]
        assert settings.missing_roles(action, "disable", ["Mail.Send", "User.RevokeSessions.All"]) == (
            "User.EnableDisableAccount.All", "User.Read.All")
        assert settings.missing_roles(action, "none", []) == ()
        assert settings.missing_roles(action, "disable", None) == ()      # unknown: do not block
        # List values are not hashable: no crash (regression).
        assert settings.missing_roles(settings.BY_NAME["ALLOWED_IPS"], ["1.2.3.4"], []) == ()


class TestApply:

    def test_overrides_and_reset(self):
        import settings
        settings.apply({"ALLOWED_IPS": ["203.0.113.0/24"], "LOOKBACK_MINUTES": 30, "HOME_COUNTRIES": ["US"]})
        assert config.ALLOWED_IPS_RAW == "203.0.113.0/24"
        assert len(config.ALLOWED_NETWORKS) == 1
        assert config.DEDUP_WINDOW_MINUTES == 90 and config.MAX_CATCHUP_MINUTES == 90
        assert config.HOME_COUNTRIES == {"US"}
        settings.apply({})
        assert config.ALLOWED_IPS_RAW == "" and config.LOOKBACK_MINUTES == 8 and config.HOME_COUNTRIES == set()

    def test_bad_stored_value_uses_default(self):
        import settings
        warnings = settings.apply({"RISK_SCORE_THRESHOLD": 500})
        assert config.RISK_SCORE_THRESHOLD == 33
        assert warnings and "RISK_SCORE_THRESHOLD" in warnings[0]

    def test_detectors_read_new_values(self):
        import settings
        from compromise_detector import detect_suspicious_inbox_rules
        event = {"Operation": "New-InboxRule", "UserId": "u@contoso.com",
                 "Parameters": [{"Name": "ForwardTo", "Value": "u@fabrikam.com"}]}
        assert len(detect_suspicious_inbox_rules([event])) == 1
        settings.apply({"INTERNAL_DOMAINS": ["fabrikam.com"]})
        assert detect_suspicious_inbox_rules([event]) == []


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------

class TestStore:

    def test_save_records_history_and_applies(self):
        import admin_store
        table = FakeTable()
        diff = admin_store.save(table, {"LOGIN_ALERT_MODE": "digest"}, 0, "a@contoso.com")
        assert diff == [{"name": "LOGIN_ALERT_MODE", "label": "Email format", "old": "immediate", "new": "digest"}]
        assert config.LOGIN_ALERT_MODE == "digest"
        assert admin_store.load(table)["version"] == 1
        history = admin_store.history(table)
        assert history[0]["by"] == "a@contoso.com" and history[0]["changes"] == diff

    def test_version_conflict(self):
        import admin_store
        table = FakeTable()
        admin_store.save(table, {"RISK_SCORE_THRESHOLD": 50}, 0, "a")
        with pytest.raises(admin_store.ConflictError):
            admin_store.save(table, {"RISK_SCORE_THRESHOLD": 60}, 0, "b")

    def test_validation_errors_write_nothing(self):
        import admin_store
        table = FakeTable()
        with pytest.raises(admin_store.ValidationError) as exc:
            admin_store.save(table, {"RISK_SCORE_THRESHOLD": 50, "ALLOWED_IPS": ["nope"], "BOGUS": 1}, 0, "a")
        assert set(exc.value.errors) == {"ALLOWED_IPS", "BOGUS"}
        assert table.rows == {}

    def test_dry_run_writes_nothing(self):
        import admin_store
        table = FakeTable()
        diff = admin_store.save(table, {"RISK_SCORE_THRESHOLD": 50}, 0, "a", dry_run=True)
        assert diff and table.rows == {} and config.RISK_SCORE_THRESHOLD == 33

    def test_reset_to_default_and_same_as_default(self):
        import admin_store
        table = FakeTable()
        admin_store.save(table, {"RISK_SCORE_THRESHOLD": 50}, 0, "a")
        admin_store.save(table, {"RISK_SCORE_THRESHOLD": None}, 1, "a")
        assert admin_store.load(table)["overrides"] == {}
        assert config.RISK_SCORE_THRESHOLD == 33
        assert admin_store.save(table, {"RISK_SCORE_THRESHOLD": 33}, 2, "a") == []

    def test_permission_missing_is_rejected(self):
        import admin_store
        with pytest.raises(admin_store.ValidationError) as exc:
            admin_store.save(FakeTable(), {"ANOMALY_ACTION": "disable"}, 0, "a", granted_roles=["Mail.Send"])
        assert "User.EnableDisableAccount.All" in exc.value.errors["ANOMALY_ACTION"]

    def test_refresh_applies_stored_overrides(self):
        import admin_store
        table = FakeTable()
        admin_store.save(table, {"LOGIN_ALERT_CONFIDENCE": "high"}, 0, "a")
        import settings
        settings.apply({})
        admin_store.refresh(table)
        assert config.LOGIN_ALERT_CONFIDENCE == "high"

    def test_refresh_without_storage_keeps_values(self):
        import admin_store, settings
        settings.apply({"RISK_SCORE_THRESHOLD": 70})
        with patch("admin_store.table_client", return_value=None):
            admin_store.refresh()
        assert config.RISK_SCORE_THRESHOLD == 70

    def test_email_journal_newest_first(self):
        import admin_store
        table = FakeTable()
        with patch("admin_store.table_client", return_value=table), \
             patch("admin_store._now") as now:
            from datetime import datetime, timezone
            now.return_value = datetime(2026, 1, 1, tzinfo=timezone.utc)
            admin_store.record_email("old", "sent")
            now.return_value = datetime(2026, 1, 2, tzinfo=timezone.utc)
            admin_store.record_email("new", "queued")
        assert [e["subject"] for e in admin_store.recent_emails(table)] == ["new", "old"]


# ---------------------------------------------------------------------------
# API security checks
# ---------------------------------------------------------------------------

def _principal(roles=("Monitor.Admin",), name="admin@contoso.com"):
    claims = [{"typ": "preferred_username", "val": name}] + [{"typ": "roles", "val": r} for r in roles]
    return base64.b64encode(json.dumps({"auth_typ": "aad", "role_typ": "roles", "claims": claims}).encode()).decode()


def _req(method="GET", url="/api/manage/api/state", body=None, roles=("Monitor.Admin",), headers=None, params=None):
    h = {"Host": "func.azurewebsites.net"}
    if roles is not None:
        h["X-MS-CLIENT-PRINCIPAL"] = _principal(roles)
        h["X-MS-CLIENT-PRINCIPAL-NAME"] = "admin@contoso.com"
    h.update(headers or {})
    return func.HttpRequest(method=method, url=f"https://func.azurewebsites.net{url}", headers=h,
                            params=params or {}, body=json.dumps(body).encode() if body is not None else b"")


MUTATE = {"X-Monitor-Admin": "1", "Origin": "https://func.azurewebsites.net"}


class TestGuard:

    def test_404_when_app_service_auth_off(self, monkeypatch):
        """Without App Service Authentication the principal header can be forged."""
        import admin_api
        monkeypatch.setenv("ADMIN_UI_ENABLED", "true")
        monkeypatch.delenv("WEBSITE_AUTH_ENABLED", raising=False)
        assert admin_api.get_state(_req()).status_code == 404

    def test_404_when_ui_disabled(self, monkeypatch):
        import admin_api
        monkeypatch.setenv("ADMIN_UI_ENABLED", "false")
        monkeypatch.setenv("WEBSITE_AUTH_ENABLED", "True")
        assert admin_api.static(_req(), "index.html").status_code == 404

    def test_401_without_principal(self, ui_on):
        import admin_api
        assert admin_api.get_state(_req(roles=None)).status_code == 401

    def test_403_without_role(self, ui_on):
        import admin_api
        resp = admin_api.get_state(_req(roles=("Other.Role",)))
        assert resp.status_code == 403
        assert "Monitor.Admin" in json.loads(resp.get_body())["error"]

    def test_200_with_role(self, ui_on):
        import admin_api
        resp = admin_api.get_state(_req())
        assert resp.status_code == 200
        body = json.loads(resp.get_body())
        assert body["user"] == "admin@contoso.com"
        assert any(i["name"] == "ALLOWED_IPS" for i in body["settings"]["items"])
        assert resp.headers["Cache-Control"] == "no-store"

    def test_account_menu_shows_the_email_from_the_token(self, ui_on):
        import admin_api
        body = json.loads(admin_api.get_state(_req()).get_body())
        assert body["me"]["upn"] == "admin@contoso.com"
        assert body["me"]["access"].startswith("The Monitor.Admin role")

    def test_account_menu_names_the_directory_role(self, ui_on):
        import admin_api
        import config
        ga = "62e90394-69f5-4237-9190-012177145e10"
        user = {"access": "directory role", "oid": "e4c722ac-3b83-478d-8f52-c388885dc30f"}
        with patch.object(config, "UI_ADMIN_ROLES", {ga}), \
                patch("ui_access.directory_roles", return_value=frozenset({ga})):
            assert admin_api.describe_access(user) == "Directory role: Global Administrator"
        assert admin_api.describe_access({"access": "listed user"}) == "Listed in Settings > Management UI access"

    def test_mutation_needs_csrf_header(self, ui_on):
        import admin_api
        req = _req("PUT", "/api/manage/api/settings", {"version": 0, "changes": {"RISK_SCORE_THRESHOLD": 50}})
        assert admin_api.put_settings(req).status_code == 403

    def test_mutation_from_other_origin_refused(self, ui_on):
        import admin_api
        req = _req("PUT", "/api/manage/api/settings", {"version": 0, "changes": {}},
                   headers={"X-Monitor-Admin": "1", "Origin": "https://evil.example"})
        assert admin_api.put_settings(req).status_code == 403

    def test_html_has_strict_csp(self, ui_on):
        import admin_api
        resp = admin_api.static(_req(), "index.html")
        csp = resp.headers["Content-Security-Policy"]
        assert "script-src 'self'" in csp and "frame-ancestors 'none'" in csp and "unsafe-inline" not in csp
        assert resp.headers["X-Frame-Options"] == "DENY"

    def test_ui_has_no_inline_script_or_html_injection(self):
        import pathlib
        ui = pathlib.Path(config.__file__).parent / "ui"
        html = (ui / "index.html").read_text()
        js = (ui / "app.js").read_text()
        assert "<script>" not in html and "onclick=" not in html
        import re
        assert not re.search(r"\.(innerHTML|outerHTML)\s*=|insertAdjacentHTML\(|document\.write\(|\beval\(", js)


class TestApi:

    def test_save_sends_change_email(self, ui_on):
        import admin_api
        req = _req("PUT", "/api/manage/api/settings",
                   {"version": 0, "changes": {"LOGIN_ALERT_CONFIDENCE": "off"}}, headers=MUTATE)
        resp = admin_api.put_settings(req)
        assert resp.status_code == 200
        ui_on["email"].assert_called_once()
        user, changes = ui_on["email"].call_args.args[:2]
        assert user == "admin@contoso.com" and changes[0]["new"] == "off"

    def test_dry_run_sends_nothing(self, ui_on):
        import admin_api
        req = _req("PUT", "/api/manage/api/settings",
                   {"version": 0, "changes": {"RISK_SCORE_THRESHOLD": 40}, "dry_run": True}, headers=MUTATE)
        resp = admin_api.put_settings(req)
        assert resp.status_code == 200 and json.loads(resp.get_body())["changes"]
        ui_on["email"].assert_not_called()
        assert ui_on["table"].rows == {}

    def test_invalid_value_400_with_field_errors(self, ui_on):
        import admin_api
        req = _req("PUT", "/api/manage/api/settings",
                   {"version": 0, "changes": {"ALLOWED_IPS": ["x"]}}, headers=MUTATE)
        resp = admin_api.put_settings(req)
        assert resp.status_code == 400
        assert "ALLOWED_IPS" in json.loads(resp.get_body())["errors"]

    def test_conflict_409(self, ui_on):
        import admin_api
        req = _req("PUT", "/api/manage/api/settings", {"version": 5, "changes": {}}, headers=MUTATE)
        assert admin_api.put_settings(req).status_code == 409

    def test_country_approve_and_lookup(self, ui_on):
        import admin_api
        geo = FakeTable()
        with patch("geo_monitor.table_client", return_value=geo):
            resp = admin_api.countries(_req("POST", "/api/manage/api/countries",
                                            {"user": "Jane@Contoso.com", "country": "fr", "action": "approve"},
                                            headers=MUTATE))
            assert resp.status_code == 200
            rows = json.loads(resp.get_body())["countries"]
            assert rows == [{"country": "FR", "status": "usual", "days_seen": 1,
                             "last_seen": rows[0]["last_seen"], "approved": True}]
            got = admin_api.countries(_req("GET", "/api/manage/api/countries", params={"user": "jane@contoso.com"}))
            assert json.loads(got.get_body())["countries"][0]["country"] == "FR"
        ui_on["email"].assert_called_once()   # an approval weakens detection: email it

    @pytest.mark.parametrize("body", [
        {"user": "nobody", "country": "FR", "action": "approve"},
        {"user": "a@contoso.com", "country": "FRA", "action": "approve"},
        {"user": "a@contoso.com", "country": "FR", "action": "delete-all"},
    ])
    def test_country_bad_input(self, ui_on, body):
        import admin_api
        resp = admin_api.countries(_req("POST", "/api/manage/api/countries", body, headers=MUTATE))
        assert resp.status_code == 400


def test_purge_old_history_and_emails():
    from datetime import datetime, timedelta, timezone
    import admin_store
    table = FakeTable()
    old = datetime.now(timezone.utc) - timedelta(days=120)
    admin_store.record_history(table, "a", [{"name": "X"}], old)
    admin_store.record_history(table, "b", [{"name": "Y"}])
    assert admin_store.purge_old(table) == 1
    assert [h["by"] for h in admin_store.history(table)] == ["b"]
