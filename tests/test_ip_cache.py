"""IP answers in the cache: a clean answer for IP_CACHE_DAYS (default 7), a flagged answer for 24 hours."""

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

import config
import ip_checker
from tests.fakes import FakeTable

OFFICE = {"proxy": "no", "type": "Business", "risk": 0, "isocode": "US", "asn": "AS7018"}
VPN = {"proxy": "yes", "type": "VPN", "risk": 66, "isocode": "DE", "asn": "AS24940"}


def _cached(table, ip, data, age):
    when = datetime.now(timezone.utc) - age
    table.upsert_entity({"PartitionKey": "ipcache", "RowKey": ip_checker._ip_row_key(ip), "ip": ip,
                         "data": json.dumps(data), "cached_at": when.isoformat(), "is_negative": False})


@pytest.mark.parametrize("data,age,kept", [
    (OFFICE, timedelta(days=6, hours=23), True),     # clean: 7 days
    (OFFICE, timedelta(days=7, hours=1), False),
    (VPN, timedelta(hours=23), True),                # flagged: 24 hours
    (VPN, timedelta(hours=25), False),
])
def test_how_long_an_answer_is_kept(data, age, kept):
    table = FakeTable()
    _cached(table, "203.0.113.7", data, age)
    assert (ip_checker.get_cached_ip("203.0.113.7", table) is not None) is kept


def test_the_setting_shortens_the_time_for_clean_answers():
    table = FakeTable()
    _cached(table, "203.0.113.7", OFFICE, timedelta(days=2))
    with patch.object(config, "IP_CACHE_DAYS", 1):
        assert ip_checker.get_cached_ip("203.0.113.7", table) is None


def test_setting_range():
    import settings
    s = settings.BY_NAME["IP_CACHE_DAYS"]
    assert settings.validate(s, 3) == 3
    with pytest.raises(ValueError):
        settings.validate(s, 8)            # the cleanup deletes cache rows after 7 days
