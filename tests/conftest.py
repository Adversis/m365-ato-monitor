"""Pytest setup: make the function modules importable, set dummy credentials,
and block network access.

The function code lives in ``function/`` and imports its siblings as top-level
modules (``import config``, ``from o365_client import ...``). We add both the
project root (so ``from tests import mock_data`` works) and ``function/`` to
sys.path, regardless of the directory pytest is invoked from.
"""

import os
import socket
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
_FUNCTION = os.path.join(_ROOT, "function")

for _p in (_ROOT, _FUNCTION):
    if _p not in sys.path:
        sys.path.insert(0, _p)

# Dummy credentials so config's module-level reads are truthy. Tests that
# exercise the missing-env path patch these to None explicitly.
os.environ.setdefault("AZURE_TENANT_ID", "test-tenant-id")
os.environ.setdefault("AZURE_CLIENT_ID", "test-client-id")
os.environ.setdefault("AZURE_CLIENT_SECRET", "test-client-secret")
os.environ.setdefault("ADMIN_EMAIL", "admin@contoso.com")
os.environ.setdefault("PROXYCHECK_API_KEY", "")
os.environ.setdefault("ALLOWED_IPS", "")


@pytest.fixture(autouse=True)
def _no_network(monkeypatch):
    """Fail any test that opens a real network connection."""
    def _blocked(*args, **kwargs):
        raise RuntimeError("Network access is blocked in tests")
    monkeypatch.setattr(socket.socket, "connect", _blocked)
    monkeypatch.setattr(socket.socket, "connect_ex", _blocked)


@pytest.fixture(autouse=True)
def _fresh_token_cache():
    """Each test starts with an empty token cache."""
    import o365_client
    o365_client.token_manager._tokens.clear()
    yield
    o365_client.token_manager._tokens.clear()


@pytest.fixture(autouse=True)
def _reset_runtime_settings():
    """Undo settings that a test changed through the management UI layer."""
    yield
    if "settings" in sys.modules:
        sys.modules["settings"].apply({})
    if "admin_store" in sys.modules:
        sys.modules["admin_store"]._active_mutes.clear()


@pytest.fixture(autouse=True)
def _no_subscription_check():
    """The 6-hourly audit subscription check is off unless a test turns it on."""
    import time
    import o365_client
    o365_client._subscriptions_checked_at = time.time()
    yield


@pytest.fixture(autouse=True)
def _empty_private_relay_list():
    """No iCloud Private Relay download in tests: an empty, loaded list."""
    import private_relay
    private_relay._set_index({4: ([], [], []), 6: ([], [], [])})
    yield
    private_relay._set_index(None)


@pytest.fixture
def ui_on(monkeypatch):
    """Management UI on, signed-in admin, in-memory tables, Graph roles = Mail.Send, change email mocked."""
    from unittest.mock import patch
    from tests.fakes import FakeTable
    monkeypatch.setenv("ADMIN_UI_ENABLED", "true")
    monkeypatch.setenv("WEBSITE_AUTH_ENABLED", "True")
    table = FakeTable()
    with patch("admin_store.table_client", return_value=table), \
         patch("geo_monitor.table_client", return_value=FakeTable()), \
         patch("function_app._get_table_clients", return_value=(FakeTable(), FakeTable())), \
         patch("o365_client.token_manager.granted_graph_roles", return_value=["Mail.Send"]), \
         patch("admin_api.send_settings_changed", return_value=True) as mock_email:
        yield {"table": table, "email": mock_email}
