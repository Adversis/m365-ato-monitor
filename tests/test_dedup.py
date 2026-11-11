"""Tests for event deduplication (get_event_key, mark_event_processed)."""

import hashlib
from unittest.mock import MagicMock
from tests import mock_data


class TestGetEventKey:

    def test_uses_event_id_when_present(self):
        from ip_checker import get_event_key
        key = get_event_key(mock_data.EVENT_NORMAL_LOGIN)
        assert key == "a1b2c3d4-e5f6-7890-abcd-000000000001"

    def test_falls_back_to_hash_when_no_id(self):
        from ip_checker import get_event_key
        key = get_event_key(mock_data.EVENT_NO_ID)
        # Should be a 32-char hex hash
        assert len(key) == 32
        assert all(c in "0123456789abcdef" for c in key)

    def test_hash_is_deterministic(self):
        from ip_checker import get_event_key
        key1 = get_event_key(mock_data.EVENT_NO_ID)
        key2 = get_event_key(mock_data.EVENT_NO_ID)
        assert key1 == key2

    def test_hash_uses_correct_fields(self):
        from ip_checker import get_event_key
        event = mock_data.EVENT_NO_ID
        expected_input = f"{event['CreationTime']}{event['UserId']}{event['ClientIP']}"
        expected_hash = hashlib.sha256(expected_input.encode()).hexdigest()[:32]
        assert get_event_key(event) == expected_hash

    def test_different_events_different_keys(self):
        from ip_checker import get_event_key
        key1 = get_event_key(mock_data.EVENT_NORMAL_LOGIN)
        key2 = get_event_key(mock_data.EVENT_VPN_LOGIN)
        assert key1 != key2

    def test_empty_event_returns_hash(self):
        from ip_checker import get_event_key
        key = get_event_key({})
        assert len(key) == 32


class TestMarkEventProcessed:

    def test_upserts_entity(self):
        from ip_checker import mark_event_processed
        table_client = MagicMock()

        mark_event_processed("abc123", table_client)

        table_client.upsert_entity.assert_called_once()
        entity = table_client.upsert_entity.call_args[0][0]
        assert entity["PartitionKey"] == "events"
        assert entity["RowKey"] == "abc123"
        assert "processed_at" in entity

    def test_handles_storage_error_gracefully(self):
        """Should log warning but not raise on storage failure."""
        from ip_checker import mark_event_processed
        table_client = MagicMock()
        table_client.upsert_entity.side_effect = Exception("Storage unavailable")

        # Should not raise
        mark_event_processed("abc123", table_client)
