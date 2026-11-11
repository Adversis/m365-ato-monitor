"""Management UI access: the Monitor.Admin role, listed users, and listed directory roles."""

import base64
import json
from unittest.mock import MagicMock, patch

import azure.functions as func
import pytest

import config
import ui_access

GA = "62e90394-69f5-4237-9190-012177145e10"
SEC_ADMIN = "194ae4cb-b126-40b2-bd5b-6091b380977d"
OID = "e4c722ac-3b83-478d-8f52-c388885dc30f"


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    monkeypatch.setenv("ADMIN_UI_ENABLED", "true")
    monkeypatch.setenv("WEBSITE_AUTH_ENABLED", "True")
    ui_access.clear_cache()
    with patch.multiple(config, UI_ADMIN_USERS=set(), UI_ADMIN_ROLES=set()):
        yield
    ui_access.clear_cache()


def _req(name="sam@contoso.com", roles=(), oid=OID):
    claims = [{"typ": "preferred_username", "val": name},
              {"typ": "http://schemas.microsoft.com/identity/claims/objectidentifier", "val": oid}]
    claims += [{"typ": "roles", "val": r} for r in roles]
    principal = base64.b64encode(json.dumps({"auth_typ": "aad", "role_typ": "roles", "claims": claims}).encode())
    return func.HttpRequest(method="GET", url="https://func.azurewebsites.net/api/manage/api/state",
                            headers={"Host": "func.azurewebsites.net", "X-MS-CLIENT-PRINCIPAL": principal.decode(),
                                     "X-MS-CLIENT-PRINCIPAL-NAME": name}, body=b"")


def _graph(values):
    r = MagicMock(status_code=200)
    r.json.return_value = {"value": values}
    return r


class TestGuard:

    def test_no_access_by_default(self):
        import admin_api
        with patch("config.http") as http:
            resp = admin_api.guard(_req())
            http.get.assert_not_called()                      # no role listed: no Graph call
        assert resp.status_code == 403
        assert "Settings > Management UI access" in json.loads(resp.get_body())["error"]

    def test_app_role(self):
        import admin_api
        assert admin_api.guard(_req(roles=("Monitor.Admin",)))["access"] == "app role"

    def test_listed_user(self):
        import admin_api
        with patch.object(config, "UI_ADMIN_USERS", {"sam@contoso.com"}):
            assert admin_api.guard(_req(name="Sam@Contoso.com"))["access"] == "listed user"
            assert not isinstance(admin_api.guard(_req(name="eve@contoso.com")), dict)

    def test_name_header_alone_gives_no_access(self):
        """The user name that decides access comes from the signed claims, not from a plain header."""
        import admin_api
        req = _req(name="eve@contoso.com")
        forged = func.HttpRequest(method="GET", url=req.url, body=b"",
                                  headers={**dict(req.headers), "X-MS-CLIENT-PRINCIPAL-NAME": "sam@contoso.com"})
        with patch.object(config, "UI_ADMIN_USERS", {"sam@contoso.com"}):
            assert admin_api.guard(forged).status_code == 403

    def test_directory_role(self):
        import admin_api
        with patch.object(config, "UI_ADMIN_ROLES", {GA}), \
                patch("ui_access.token_manager") as tm, patch("config.http") as http:
            tm.get_graph_token.return_value = "t"
            http.get.return_value = _graph([{"roleDefinitionId": GA}])
            user = admin_api.guard(_req())
            assert user["access"] == "directory role"
            params = http.get.call_args.kwargs["params"]
            assert params["$filter"] == f"principalId eq '{OID}'"
            admin_api.guard(_req())
            assert http.get.call_count == 1                   # cached

    def test_other_directory_role_is_refused(self):
        import admin_api
        with patch.object(config, "UI_ADMIN_ROLES", {GA}), \
                patch("ui_access.token_manager") as tm, patch("config.http") as http:
            tm.get_graph_token.return_value = "t"
            http.get.return_value = _graph([{"roleDefinitionId": SEC_ADMIN}])
            assert admin_api.guard(_req()).status_code == 403

    def test_listed_user_on_a_new_instance(self):
        """The stored access list loads before the check: a new instance has only the defaults."""
        import admin_api
        import admin_store
        from tests.fakes import FakeTable
        table = FakeTable()
        with patch("admin_store.table_client", return_value=table):
            admin_store.save(table, {"UI_ADMIN_USERS": ["sam@contoso.com"]}, 0, "root@contoso.com", [])
            config.UI_ADMIN_USERS = set()                     # a new instance
            admin_api._refreshed_at = None
            assert admin_api.guard(_req(name="sam@contoso.com"))["access"] == "listed user"
            admin_store.save(table, {"UI_ADMIN_USERS": []}, 1, "root@contoso.com", [])
            admin_api._refreshed_at = None                    # 30 seconds later
            assert admin_api.guard(_req(name="sam@contoso.com")).status_code == 403
        admin_store.refresh(FakeTable())                      # back to the defaults for the other tests

    def test_scoped_role_assignment_gives_no_access(self):
        with patch.object(config, "UI_ADMIN_ROLES", {GA}), \
                patch("ui_access.token_manager") as tm, patch("config.http") as http:
            tm.get_graph_token.return_value = "t"
            http.get.return_value = _graph([{"roleDefinitionId": GA, "directoryScopeId": "/administrativeUnits/x"}])
            assert ui_access.access({"name": "sam@contoso.com", "roles": set(), "oid": OID}) == ""

    def test_graph_error_is_tried_again_soon(self):
        with patch.object(config, "UI_ADMIN_ROLES", {GA}), \
                patch("ui_access.token_manager") as tm, patch("config.http") as http, \
                patch("ui_access.time.monotonic", return_value=1000.0) as clock:
            tm.get_graph_token.return_value = "t"
            http.get.side_effect = ConnectionError("down")
            assert ui_access.directory_roles(OID) == frozenset()
            http.get.side_effect = None
            http.get.return_value = _graph([{"roleDefinitionId": GA, "directoryScopeId": "/"}])
            clock.return_value = 1031.0                       # after 30 seconds, not 5 minutes
            assert ui_access.directory_roles(OID) == frozenset({GA})

    def test_graph_refusal_means_no_access(self):
        with patch.object(config, "UI_ADMIN_ROLES", {GA}), \
                patch("ui_access.token_manager") as tm, patch("config.http") as http:
            tm.get_graph_token.return_value = "t"
            http.get.return_value = MagicMock(status_code=403)
            assert ui_access.access({"name": "sam@contoso.com", "roles": set(), "oid": OID}) == ""

    def test_object_id_must_be_a_guid(self):
        with patch.object(config, "UI_ADMIN_ROLES", {GA}), patch("config.http") as http:
            assert ui_access.directory_roles("x' or 1 eq 1 or principalId eq 'y") == frozenset()
            http.get.assert_not_called()


class TestSettings:

    def test_role_set_validation(self):
        import settings
        s = settings.BY_NAME["UI_ADMIN_ROLES"]
        assert settings.validate(s, [SEC_ADMIN.upper(), GA]) == [GA, SEC_ADMIN]
        with pytest.raises(ValueError):
            settings.validate(s, ["00000000-0000-0000-0000-000000000000"])
        with pytest.raises(ValueError):
            settings.validate(settings.BY_NAME["UI_ADMIN_USERS"], ["not an address"])

    def test_roles_need_the_graph_permission(self):
        import settings
        s = settings.BY_NAME["UI_ADMIN_ROLES"]
        assert settings.missing_roles(s, [GA], ["Mail.Send"]) == ("RoleManagement.Read.Directory",)
        assert settings.missing_roles(s, [GA], ["RoleManagement.Read.Directory"]) == ()
        assert settings.missing_roles(s, [], ["Mail.Send"]) == ()

    def test_history_names_the_roles(self):
        import settings
        s = settings.BY_NAME["UI_ADMIN_ROLES"]
        assert settings.describe_for(s, [GA, SEC_ADMIN]) == "Global Administrator, Security Administrator"
        assert settings.describe_for(s, []) == "(empty)"

    def test_apply_sets_config(self):
        import settings
        with patch.multiple(config, UI_ADMIN_USERS=set(), UI_ADMIN_ROLES=set()):
            settings.apply({"UI_ADMIN_USERS": ["Sam@Contoso.com"], "UI_ADMIN_ROLES": [GA]})
            assert config.UI_ADMIN_USERS == {"sam@contoso.com"} and config.UI_ADMIN_ROLES == {GA}
            settings.apply({})


class TestAccessInfo:

    def test_lists_role_members(self):
        import admin_api

        def graph(url, headers=None, params=None, timeout=None):
            if params and "roleDefinitionId eq" in params.get("$filter", "") and GA in params["$filter"]:
                return _graph([
                    {"roleDefinitionId": GA, "principal": {"@odata.type": "#microsoft.graph.user",
                                                           "userPrincipalName": "root@contoso.com", "displayName": "Root"}},
                    {"roleDefinitionId": GA, "principal": {"@odata.type": "#microsoft.graph.group", "displayName": "G"}},
                ])
            return _graph([])

        with patch("ui_access.token_manager") as tm, patch("config.http") as http, \
                patch("admin_api.token_manager") as atm:
            tm.get_graph_token.return_value = "t"
            atm.granted_graph_roles.return_value = ["RoleManagement.Read.Directory"]
            http.get.side_effect = graph
            resp = admin_api.access_info(_req(roles=("Monitor.Admin",)))
        body = json.loads(resp.get_body())
        ga = next(r for r in body["roles"] if r["id"] == GA)
        assert ga["members"] == [{"upn": "root@contoso.com", "name": "Root"}]
        assert body["you"]["access"] == "app role" and body["can_read_roles"] is True

    def test_without_the_permission(self):
        import admin_api
        with patch("admin_api.token_manager") as atm, patch("config.http") as http:
            atm.granted_graph_roles.return_value = ["Mail.Send"]
            body = json.loads(admin_api.access_info(_req(roles=("Monitor.Admin",))).get_body())
            http.get.assert_not_called()
        assert body["can_read_roles"] is False and all(r["members"] is None for r in body["roles"])
