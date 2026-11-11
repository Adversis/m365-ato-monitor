"""Tests for Graph UPN->objectId resolution (optional exact-user deep links)."""

from unittest.mock import patch, MagicMock


class TestResolveUserObjectId:

    def setup_method(self):
        import o365_client
        o365_client._user_id_cache.clear()

    @patch("o365_client.token_manager")
    @patch("config.http")
    def test_resolves_and_caches(self, mock_http, mock_tm):
        import o365_client
        mock_tm.get_graph_token.return_value = "tok"
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"id": "abc-123"}
        mock_http.get.return_value = resp

        assert o365_client.resolve_user_object_id("jane@contoso.com") == "abc-123"
        # second call is served from the in-process cache — no second HTTP call
        assert o365_client.resolve_user_object_id("jane@contoso.com") == "abc-123"
        assert mock_http.get.call_count == 1

    @patch("o365_client.token_manager")
    @patch("config.http")
    def test_returns_none_on_404_and_caches_miss(self, mock_http, mock_tm):
        import o365_client
        mock_tm.get_graph_token.return_value = "tok"
        resp = MagicMock()
        resp.status_code = 404
        mock_http.get.return_value = resp

        assert o365_client.resolve_user_object_id("ghost@contoso.com") is None
        assert o365_client.resolve_user_object_id("ghost@contoso.com") is None
        assert mock_http.get.call_count == 1  # miss is cached, not re-queried

    def test_empty_upn_returns_none(self):
        import o365_client
        assert o365_client.resolve_user_object_id("") is None

    @patch("o365_client.token_manager")
    @patch("config.http")
    def test_persistent_cache_survives_restart(self, mock_http, mock_tm):
        import o365_client
        o365_client._user_id_cache.clear()
        table = MagicMock()
        table.get_entity.side_effect = Exception("not found")  # first call: miss
        mock_tm.get_graph_token.return_value = "tok"
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = {"id": "oid-1"}
        mock_http.get.return_value = resp

        with patch("o365_client._userid_table_client", return_value=table):
            # Cold cache -> Graph lookup -> persisted to Table Storage.
            assert o365_client.resolve_user_object_id("jane@contoso.com") == "oid-1"
            table.upsert_entity.assert_called_once()

            # Simulate a worker restart: in-process cache empty, persistent has it.
            o365_client._user_id_cache.clear()
            table.get_entity.side_effect = None
            table.get_entity.return_value = {"object_id": "oid-1"}
            mock_http.get.reset_mock()

            assert o365_client.resolve_user_object_id("jane@contoso.com") == "oid-1"
            mock_http.get.assert_not_called()  # served from persistent cache, no Graph


class TestEntraUserLink:

    def test_uses_guid_already_in_event(self):
        from alerting import _entra_user_link
        guid = "11111111-2222-3333-4444-555555555555"
        link = _entra_user_link({"UserKey": guid})
        assert guid in link
        assert "UserProfileMenuBlade" in link

    @patch("config.RESOLVE_USER_IDS", False)
    def test_falls_back_to_user_list_when_resolution_off(self):
        from alerting import _entra_user_link
        link = _entra_user_link({"UserId": "jane@contoso.com"})
        assert "AllUsers" in link

    @patch("config.RESOLVE_USER_IDS", True)
    @patch("alerting.resolve_user_object_id")
    def test_resolves_upn_when_enabled(self, mock_resolve):
        from alerting import _entra_user_link
        mock_resolve.return_value = "99999999-0000-0000-0000-000000000000"
        link = _entra_user_link({"UserId": "jane@contoso.com"})
        assert "99999999-0000-0000-0000-000000000000" in link
        assert "UserProfileMenuBlade" in link
        mock_resolve.assert_called_once_with("jane@contoso.com")
