"""Alert emails: the main button opens the management UI; Entra ID is a second link."""

from unittest.mock import patch

import pytest

import alerting

EVENT = {"UserId": "alex@contoso.com", "Operation": "UserLoggedIn", "ClientIP": "203.0.113.45",
         "CreationTime": "2026-11-09T14:02:11"}
ANALYSIS = {"is_suspicious": True, "flags": ["hosting"], "confidence": "medium", "risk_score": 33,
            "proxy_type": "Hosting", "asn": "AS16509", "org": "Amazon Technologies Inc.", "city": "Ashburn",
            "country": "United States"}


def _body(**kw):
    with patch("alerting._deliver", return_value=True) as deliver:
        alerting.send_suspicious_login_alert(EVENT, "203.0.113.45", ANALYSIS, **kw)
    return deliver.call_args.args[1]


def test_button_opens_the_user_page(monkeypatch):
    monkeypatch.setenv("ADMIN_UI_ENABLED", "true")
    monkeypatch.setenv("WEBSITE_HOSTNAME", "func-x.azurewebsites.net")
    body = _body()
    assert 'href="https://func-x.azurewebsites.net/api/manage#user:alex@contoso.com"' in body
    assert ">Open in the management UI</a>" in body
    assert "Or <a href=\"https://entra.microsoft.com/" in body


def test_app_actor_opens_the_alerts_page(monkeypatch):
    monkeypatch.setenv("ADMIN_UI_ENABLED", "true")
    monkeypatch.setenv("WEBSITE_HOSTNAME", "func-x.azurewebsites.net")
    html = alerting._user_button({"UserId": "ServicePrincipal_1b2c3d4e-0000-4000-8000-000000000001"})
    assert "/api/manage#alerts" in html


@pytest.mark.parametrize("enabled", ["false", ""])
def test_without_the_ui_the_button_opens_entra(monkeypatch, enabled):
    monkeypatch.setenv("ADMIN_UI_ENABLED", enabled)
    monkeypatch.setenv("WEBSITE_HOSTNAME", "func-x.azurewebsites.net")
    body = _body()
    assert "Open in the management UI" not in body
    assert ">Open Entra ID users (search for the user)</a>" in body or ">Open the user in Entra ID</a>" in body
