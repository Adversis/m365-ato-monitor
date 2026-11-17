"""Load past sign-ins into the network history (signin_networks), once.

The MFA check sends no email for a change until the user's network history is
signin_networks.LEARN_DAYS old. Without past sign-ins, that takes 14 days after
an install (or after the update that adds the history). This job reads the
successful sign-ins (UserLoggedIn) of the last BACKFILL_DAYS from the audit log,
through the Graph audit search (audit_search.py), and adds them to each user's
row. The row then starts at the start of the search, so the learning period
ends when the job is done.

The background timer runs it in steps, as the onboarding scan. A search
typically takes 4 to 40 minutes, and up to 48 hours.

State: table "processedevents", partition "system", row "networkbackfill" (JSON).
No function raises.
"""

import json
import logging
import time
from datetime import datetime, timedelta
from typing import Optional

from azure.core.exceptions import ResourceNotFoundError

import audit_search
import signin_networks
from o365_client import token_manager

_PARTITION = "system"
_ROW = "networkbackfill"
BACKFILL_DAYS = 30
SEARCH_WAIT_HOURS = 48
TRIES = 10
_TS = "%Y-%m-%dT%H:%M:%SZ"


def _parse(text) -> Optional[datetime]:
    try:
        return signin_networks._time(text) if text else None
    except ValueError:
        return None


def load(events_table) -> Optional[dict]:
    if events_table is None:
        return None
    try:
        row = events_table.get_entity(partition_key=_PARTITION, row_key=_ROW)
        state = json.loads(row.get("data") or "null")
    except ResourceNotFoundError:
        return None
    except Exception as e:
        logging.warning(f"Network backfill state not read: {type(e).__name__}")
        return None
    return state if isinstance(state, dict) else None


def _save(events_table, state: dict) -> None:
    try:
        events_table.upsert_entity({"PartitionKey": _PARTITION, "RowKey": _ROW, "data": json.dumps(state)})
    except Exception as e:
        logging.warning(f"Network backfill state not written: {type(e).__name__}")


def pending(events_table) -> bool:
    """True if the job did not finish (or did not start)."""
    state = load(events_table)
    return not state or not state.get("finished_at")


def summary(events_table) -> Optional[dict]:
    """Short form for the status endpoint and the management UI."""
    state = load(events_table)
    if not state:
        return None
    return {k: state.get(k) for k in ("status", "from", "to", "records", "finished_at", "skipped", "error",
                                      "limit_exceeded")}


def run(events_table, geo_table, now: datetime, deadline: float) -> Optional[dict]:
    """Do backfill work until done or the ``deadline`` (time.monotonic()). Return the state."""
    if events_table is None or geo_table is None:
        return None
    state = load(events_table) or {"query_id": "", "status": "", "from": "", "to": "", "submitted_at": "",
                                   "next_link": "", "records": 0, "tries": 0, "error": "",
                                   "skipped": "", "finished_at": ""}
    if state.get("finished_at"):
        return state
    try:
        _step(events_table, geo_table, state, now, deadline)
    except Exception:
        logging.exception("Network backfill step failed")
    return state


def _finish(events_table, state: dict, now: datetime, reason: str = "") -> None:
    state["skipped"] = reason
    state["finished_at"] = now.strftime(_TS)
    if reason:
        logging.warning(f"Network backfill stopped: {reason}")
    else:
        logging.warning(f"Network backfill done: {state['records']} sign-in records")
    _save(events_table, state)


def _failed_try(events_table, state: dict, now: datetime, error: str) -> None:
    state["tries"] = int(state.get("tries") or 0) + 1
    state["error"] = error
    if state["tries"] >= TRIES:
        _finish(events_table, state, now, f"stopped after {TRIES} errors: {error}")
    else:
        _save(events_table, state)


def _step(events_table, geo_table, state: dict, now: datetime, deadline: float) -> None:
    if not state.get("query_id"):
        granted = token_manager.granted_graph_roles()
        if granted is None:
            return                      # no Graph token now: try again on the next run
        if not audit_search.can_search(granted):
            _finish(events_table, state, now, "needs the Graph permission AuditLogsQuery.Read.All "
                                              "(run ./install.ps1 -Update)")
            return
        begin = now - timedelta(days=BACKFILL_DAYS)
        query_id, error = audit_search.create("m365-ato-monitor sign-in networks", begin, now,
                                              operations=["UserLoggedIn"])
        if error:
            _failed_try(events_table, state, now, f"the search did not start: {error}")
            return
        state.update(query_id=query_id, status="notStarted", submitted_at=now.strftime(_TS), error="",
                     tries=0, **{"from": begin.strftime(_TS), "to": now.strftime(_TS)})
        logging.warning(f"Network backfill: audit search started for {begin:%Y-%m-%d} to {now:%Y-%m-%d}")
        _save(events_table, state)
        return
    if state.get("status") != "succeeded":
        info, error = audit_search.get(state["query_id"])
        if error:
            _failed_try(events_table, state, now, error)
            return
        state["status"], state["limit_exceeded"] = info["status"], info["limit_exceeded"]
        if state["status"] in ("failed", "cancelled"):
            _finish(events_table, state, now, f"Microsoft reported the search as {state['status']}")
            return
        if state["status"] != "succeeded":
            submitted = _parse(state.get("submitted_at"))
            if submitted and now - submitted > timedelta(hours=SEARCH_WAIT_HOURS):
                _finish(events_table, state, now, f"the search did not finish in {SEARCH_WAIT_HOURS} hours")
            else:
                _save(events_table, state)
            return
        state["tries"] = 0
    # The rows start at the start of the search: the search has all sign-ins after it. Not when
    # the search hit Microsoft's record limit: a network can then be missing. Load the networks,
    # but keep each row's own start (the learning period goes on).
    since = None if state.get("limit_exceeded") else _parse(state.get("from"))
    while time.monotonic() < deadline:
        items, link, error = audit_search.records(state["query_id"], state.get("next_link") or "")
        if error:
            _failed_try(events_table, state, now, error)
            return
        records = [r for r in (audit_search.to_record(i) for i in items) if r]
        if not signin_networks.record(geo_table, records, now, since=since) and records:
            # A write failed: read this page again on the next run (a repeated page changes nothing).
            _failed_try(events_table, state, now, "the network history was not written")
            return
        state["records"] = int(state.get("records") or 0) + len(records)
        state["next_link"] = link
        if not link:
            _finish(events_table, state, now)
            return
        _save(events_table, state)
