"""The one-time load of past sign-ins into the network history.

All users, IDs, and IPs are made up (documentation ranges).
"""

import json
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

import network_backfill as nb
import signin_networks as sn
from tests.fakes import FakeTable

USER = "victim@contoso.com"
HOME = "198.51.100.20"
NEW = "203.0.113.9"


def _item(ip, when, user=USER, op="UserLoggedIn"):
    data = {"Id": f"s-{ip}-{when:%H%M%S}", "Operation": op, "RecordType": 15, "UserId": user,
            "ClientIP": ip, "CreationTime": when.strftime("%Y-%m-%dT%H:%M:%S"), "ResultStatus": "Success"}
    return {"id": data["Id"], "operation": op, "auditData": json.dumps(data)}


@pytest.fixture
def graph():
    """Fake Graph audit search: one query, pages from ``pages``."""
    class G:
        pages = [[], []]
        status = "succeeded"
        limit = False
        created = []
        reads = 0
        page_error = ""
    g = G()

    def create(name, start, end, **kw):
        g.created.append((start, end, kw))
        return "q-00000001", ""

    def get(query_id):
        return {"status": g.status, "limit_exceeded": g.limit, "count": None}, ""

    def records(query_id, next_link=""):
        if g.page_error:
            return None, "", g.page_error
        i = int(next_link.rsplit("=", 1)[1]) if next_link else 0
        g.reads += 1
        link = f"https://graph.microsoft.com/v1.0/security/auditLog/queries/{query_id}/records?skip={i + 1}" \
            if i + 1 < len(g.pages) else ""
        return g.pages[i], link, ""

    with patch("audit_search.create", side_effect=create), patch("audit_search.get", side_effect=get), \
            patch("audit_search.records", side_effect=records), \
            patch("network_backfill.token_manager.granted_graph_roles", return_value={"AuditLogsQuery.Read.All"}):
        yield g


def _run_until_done(events, geo, now, runs=5):
    for _ in range(runs):
        state = nb.run(events, geo, now, time.monotonic() + 30)
        if state.get("finished_at"):
            return state
    return state


def test_backfill_ends_the_learning_period(graph):
    now = datetime.now(timezone.utc)
    events, geo = FakeTable(), FakeTable()
    # The live history started yesterday (the update that added it).
    sn.record(geo, [_item_record(HOME, now - timedelta(hours=20))], now - timedelta(hours=20))
    assert not sn.near(sn.view(geo, USER), now)["history"]
    graph.pages = [[_item(HOME, now - timedelta(days=25))], [_item(NEW, now - timedelta(days=3), op="UserLoginFailed")]]

    state = _run_until_done(events, geo, now)

    assert state["finished_at"] and not state["skipped"] and state["records"] == 2
    start, end, kw = graph.created[0]
    assert kw == {"operations": ["UserLoggedIn"]} and end - start == timedelta(days=nb.BACKFILL_DAYS)
    row = sn.view(geo, USER)
    assert row["since"] == state["from"]
    assert sn.near(row, now)["history"]
    assert sn.known(row, HOME, now) is True
    assert sn.known(row, NEW, now) is False          # a failed sign-in is not a known network
    assert not nb.pending(events)


def test_waits_for_the_search(graph):
    now = datetime.now(timezone.utc)
    events, geo = FakeTable(), FakeTable()
    graph.status = "running"
    nb.run(events, geo, now, time.monotonic() + 30)   # submit
    state = nb.run(events, geo, now, time.monotonic() + 30)
    assert state["status"] == "running" and not state["finished_at"] and graph.reads == 0
    state = nb.run(events, geo, now + timedelta(hours=nb.SEARCH_WAIT_HOURS + 1), time.monotonic() + 30)
    assert state["finished_at"] and "did not finish" in state["skipped"]


def test_page_is_read_again_when_the_history_write_fails(graph):
    now = datetime.now(timezone.utc)
    events, geo = FakeTable(), FakeTable()
    graph.pages = [[_item(HOME, now - timedelta(days=5))]]
    with patch("signin_networks.record", return_value=False):
        state = _run_until_done(events, geo, now, runs=3)
    assert not state["finished_at"] and state["records"] == 0 and state["tries"] == 2   # run 1 submits, runs 2-3 fail
    state = _run_until_done(events, geo, now)
    assert state["finished_at"] and state["records"] == 1


def test_stops_without_the_permission():
    now = datetime.now(timezone.utc)
    events = FakeTable()
    with patch("network_backfill.token_manager.granted_graph_roles", return_value={"User.ReadBasic.All"}), \
            patch("audit_search.create") as create:
        state = nb.run(events, FakeTable(), now, time.monotonic() + 30)
    assert "AuditLogsQuery.Read.All" in state["skipped"] and not create.called


def test_since_never_moves_later():
    now = datetime.now(timezone.utc)
    geo = FakeTable()
    early = now - timedelta(days=40)
    sn.record(geo, [_item_record(HOME, now - timedelta(days=35))], now, since=early)
    sn.record(geo, [_item_record(HOME, now - timedelta(days=2))], now, since=now - timedelta(days=30))
    assert sn.view(geo, USER)["since"] == early.strftime("%Y-%m-%dT%H:%M:%SZ")


def _item_record(ip, when):
    return json.loads(_item(ip, when)["auditData"])


def test_record_limit_keeps_the_learning_period(graph):
    # Microsoft's 1,000,000-record limit: the history can miss a network. Do not mark it complete.
    now = datetime.now(timezone.utc)
    events, geo = FakeTable(), FakeTable()
    graph.limit = True
    graph.pages = [[_item(HOME, now - timedelta(days=25))]]
    state = _run_until_done(events, geo, now)
    row = sn.view(geo, USER)
    assert state["finished_at"] and HOME.rsplit(".", 1)[0] + ".0/24" in row["nets"]
    assert not sn.near(row, now)["history"]
