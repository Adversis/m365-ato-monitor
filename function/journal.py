"""Findings journal: one row for each alert-worthy finding, kept for 90 days.

Uses:
  - Alert emails show the other findings for the same user in the last 24 hours.
  - The weekly report counts findings by type and by what happened to them.
  - The management UI shows a user's findings on the user page.

Table "monitorfindings":
  PartitionKey  "u-" + sha256(lowercase UPN)[:32]   (one partition per user)
  RowKey        reverse event time + "-" + sha256(finding key)[:12]
                (newest first; the same finding always gets the same row)

``status`` says what the monitor did: emailed, email failed, alert off, muted,
or onboarding (found by the onboarding scan, listed in its report).

The audit record of a finding is in its own row: PartitionKey "r-" + the same
hash, the same RowKey, fields ``event`` (JSON, at most _MAX_EVENT characters)
and ``logged_at``. The list queries do not read these rows (they have no
``at``), so a list does not download every record. ``purge`` deletes them
with the finding rows.

No function raises. Without storage, reads return [] and writes do nothing.
"""

import hashlib
import heapq
import json
import re
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from azure.core.exceptions import ResourceNotFoundError
from azure.data.tables import UpdateMode

import config

TABLE_NAME = "monitorfindings"
KEEP_DAYS = 90
CONTEXT_HOURS = 24
_TS = "%Y-%m-%dT%H:%M:%SZ"
_MAX_TEXT = 1000
_MAX_EVENT = 30_000   # a Table Storage string holds at most 32K characters
_RECORD_PREFIX = "r-"

STATUSES = ("emailed", "email failed", "alert off", "muted", "onboarding", "install", "microsoft", "known sign-in")
# Rows that no view shows: permissions that install.ps1 granted to the monitor app (older
# versions journaled them; new ones only log them).
HIDDEN = ("install",)
# The triage state that an admin sets in the management UI. "" is open (not looked at yet).
TRIAGE_STATES = ("", "investigating", "benign", "resolved")
OPEN = ("", "investigating")
_GUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_ROW_ID = re.compile(r"^(u-[0-9a-f]{32})\|(\d{13}-[0-9a-f]{12})$")
_MAX_NOTE = 300
# Not alerts: the onboarding scan's history, the permissions that install.ps1 granted,
# changes made by Microsoft's own services (service_actors.py), and MFA methods that the user
# registered after a sign-in from a known network (function_app._mfa_review).
NOT_ALERTS = ("onboarding", "install", "microsoft", "known sign-in")
# For reads that must find every row that is still kept, whatever its event time
# (the onboarding search finds records up to 180 days old).
ANY_TIME = datetime(2000, 1, 1, tzinfo=timezone.utc)

_cache = config.CachedTable(TABLE_NAME, "Findings table")


def table_client():
    """Return the table client, or None if storage is not available."""
    return _cache.get()


def partition(upn: str) -> str:
    return "u-" + hashlib.sha256(str(upn or "").strip().lower().encode("utf-8")).hexdigest()[:32]


def event_time(event: dict, now: Optional[datetime] = None) -> datetime:
    """CreationTime of an audit record as an aware UTC datetime (``now`` if missing)."""
    raw = str((event or {}).get("CreationTime") or "").strip()
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return now or datetime.now(timezone.utc)
    return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _row_key(when: datetime, key: str) -> str:
    reverse = 10**13 - int(when.timestamp() * 1000)
    return f"{reverse:013d}-{hashlib.sha256(key.encode('utf-8')).hexdigest()[:12]}"


def row_ref(finding: dict, key: str, now: Optional[datetime] = None) -> tuple:
    """(PartitionKey, RowKey) of the row that record() writes for this finding and key."""
    now = now or datetime.now(timezone.utc)
    user = str(finding.get("user") or "").strip()
    return partition(user), _row_key(event_time(finding.get("event") or {}, now), key)


def add_repeat(table, pk: str, rk: str, when: datetime) -> None:
    """One more record of an alert that was already sent (no email): count it on the alert's row."""
    if table is None or not pk or not rk:
        return
    try:
        row = table.get_entity(partition_key=pk, row_key=rk)
        last = max(str(row.get("last_repeat") or ""), when.strftime(_TS))
        table.update_entity({"PartitionKey": pk, "RowKey": rk, "repeats": int(row.get("repeats") or 0) + 1,
                             "last_repeat": last}, mode=UpdateMode.MERGE)
    except Exception as e:
        logging.warning(f"Could not count a repeat: {type(e).__name__}")


def record(table, finding: dict, key: str, status: str, *, ip_context: str = "", action: str = "",
           now: Optional[datetime] = None, only_new: bool = False, run_id: str = "") -> bool:
    """Write one finding. ``key`` is the dedup key of the finding.

    With ``only_new``, keep a row that exists, unless an earlier onboarding
    scan wrote it (the scan must not overwrite what an alert already
    recorded). ``run_id``: the onboarding scan that found it.

    Return False only if ``only_new`` kept an alert row. Else True (also
    without storage, or if the write failed).
    """
    if table is None:
        return True
    now = now or datetime.now(timezone.utc)
    event = finding.get("event") or {}
    user = str(finding.get("user") or "").strip()
    when = event_time(event, now)
    pk, rk = partition(user), _row_key(when, key)
    try:
        if only_new:
            try:
                if table.get_entity(partition_key=pk, row_key=rk).get("status") != "onboarding":
                    return False
            except ResourceNotFoundError:
                pass
        table.upsert_entity({
            "PartitionKey": pk, "RowKey": rk,
            "at": when.strftime(_TS), "logged_at": now.strftime(_TS),
            "user": user[:300], "type": str(finding.get("type") or "")[:60],
            "severity": str(finding.get("severity") or "")[:10],
            "description": str(finding.get("description") or "")[:_MAX_TEXT],
            "ip": str(finding.get("ip") or "")[:64], "ip_context": str(ip_context or "")[:300],
            "status": status, "action": str(action or "")[:500],
            "rule_name": str(finding.get("rule_name") or "")[:255],
            "mailbox": str(finding.get("mailbox") or "")[:300],
            "targets": json.dumps(list(finding.get("targets") or [])[:20]),
            "operation": str(event.get("Operation") or "")[:100],
            "record_id": str(event.get("Id") or "")[:100],
            "client": client_of(event)[:300],
            "asn": str(finding.get("asn") or "")[:16], "network": str(finding.get("network") or "")[:200],
            "key": key[:300], "run_id": str(run_id or "")[:32],
        })
    except Exception as e:
        logging.warning(f"Could not record finding: {type(e).__name__}")
        return True
    if event:
        try:
            table.upsert_entity({"PartitionKey": _RECORD_PREFIX + pk[2:], "RowKey": rk,
                                 "event": event_text(event), "logged_at": now.strftime(_TS)})
        except Exception as e:
            logging.warning(f"Could not keep the audit record of a finding: {type(e).__name__}")
    return True


def client_of(event: dict) -> str:
    """The client of an audit record: ClientInfoString, else the user agent of a sign-in, else ""."""
    text = str(event.get("ClientInfoString") or event.get("UserAgent") or "").strip()
    if not text:
        for prop in event.get("ExtendedProperties") or []:
            if isinstance(prop, dict) and prop.get("Name") == "UserAgent":
                text = str(prop.get("Value") or "").strip()
                break
    return text


def event_text(event: dict) -> str:
    """The record as indented JSON (as in the alert email). A record longer than _MAX_EVENT is cut,
    with a note (it is then not valid JSON, but still one field per line)."""
    text = json.dumps(event, indent=2, default=str)
    if len(text) > _MAX_EVENT:
        text = text[:_MAX_EVENT] + " ... (truncated; see the unified audit log)"
    return text


def audit_record(table, row_id: str) -> Optional[dict]:
    """{"record": the stored JSON text or "", "record_id": the audit record ID or ""} for a finding row.

    None if ``row_id`` is not valid or the finding is not found. ``record`` is "" if the finding
    was recorded before this version kept records, or if that write failed.
    """
    m = _ROW_ID.match(str(row_id or ""))
    if table is None or not m:
        return None
    try:
        entity = table.get_entity(partition_key=m.group(1), row_key=m.group(2))
    except ResourceNotFoundError:
        return None
    if entity.get("status") in HIDDEN:
        return None
    try:
        text = table.get_entity(partition_key=_RECORD_PREFIX + m.group(1)[2:], row_key=m.group(2)).get("event", "")
    except ResourceNotFoundError:
        text = ""
    # Only a real audit record ID helps a search in Purview. Some findings use their own ID
    # (mail access: one ID per user, IP, and day).
    record_id = str(entity.get("record_id") or "")
    return {"record": str(text or ""), "record_id": record_id if _GUID.match(record_id) else ""}


def _row(entity: dict) -> dict:
    try:
        targets = json.loads(entity.get("targets") or "[]")
    except ValueError:
        targets = []
    return {
        "at": entity.get("at", ""), "user": entity.get("user", ""), "type": entity.get("type", ""),
        "severity": entity.get("severity", ""), "description": entity.get("description", ""),
        "ip": entity.get("ip", ""), "ip_context": entity.get("ip_context", ""),
        "status": entity.get("status", ""), "action": entity.get("action", ""),
        "rule_name": entity.get("rule_name", ""), "mailbox": entity.get("mailbox", ""),
        "targets": targets if isinstance(targets, list) else [],
        "operation": entity.get("operation", ""), "record_id": entity.get("record_id", ""),
        "client": entity.get("client", ""), "asn": entity.get("asn", ""), "network": entity.get("network", ""),
        "key": entity.get("key", ""), "logged_at": entity.get("logged_at", ""),
        "run_id": entity.get("run_id", ""),
        "repeats": int(entity.get("repeats") or 0), "last_repeat": entity.get("last_repeat", ""),
        "id": f"{entity.get('PartitionKey', '')}|{entity.get('RowKey', '')}",
        "triage": _triage(entity),
        "triage_by": entity.get("triage_by", ""), "triage_at": entity.get("triage_at", ""),
        "triage_note": entity.get("triage_note", ""),
    }


def _triage(entity: dict) -> str:
    """The triage state of a row. A muted row that no admin triaged reads as benign: the mute is the
    admin's decision. An admin can still set it to Open (triage_by is then set)."""
    state = entity.get("triage", "")
    if state not in TRIAGE_STATES:
        state = ""
    if not state and not entity.get("triage_by") and entity.get("status") == "muted":
        return "benign"
    return state


def for_user(table, upn: str, since: datetime, exclude_key: str = "", limit: int = 50) -> list:
    """Findings for ``upn`` from ``since``, newest first."""
    if table is None or not upn:
        return []
    out = []
    try:
        query = f"PartitionKey eq '{partition(upn)}' and at ge '{since.strftime(_TS)}'"
        for entity in table.query_entities(query):
            if (exclude_key and entity.get("key") == exclude_key) or entity.get("status") in HIDDEN:
                continue
            out.append(_row(entity))
            if len(out) >= limit:
                break
    except Exception as e:
        logging.warning(f"Could not read findings for a user: {type(e).__name__}")
    return out


def related(table, finding: dict, key: str, now: datetime) -> list:
    """Other findings for the finding's user in the CONTEXT_HOURS before (and at) it."""
    when = min(event_time(finding.get("event") or {}, now), now)
    return for_user(table, str(finding.get("user") or ""), when - timedelta(hours=CONTEXT_HOURS),
                    exclude_key=key, limit=20)


def _newest(row: dict):
    return row["at"]


def window(table, since: datetime, limit: int = 500, keep=None, rank=_newest, query: str = "") -> tuple:
    """Findings of all users from ``since``: (the first ``limit`` rows by ``rank``, a summary of all).

    Table Storage returns rows in partition order (one partition per user),
    not in time order. So this reads every row in the window, counts it, and
    keeps only the ``limit`` rows with the highest ``rank`` (default: newest).
    ``keep``: a function (row) -> bool that selects rows. ``query``: an extra
    OData filter (only fixed text or hex values; never user input).
    """
    tally = _Tally()
    if table is None:
        return [], tally.result()
    heap = []
    flt = f"at ge '{since.strftime(_TS)}'" + (f" and {query}" if query else "")
    try:
        for i, entity in enumerate(table.query_entities(flt)):
            row = _row(entity)
            if row["status"] in HIDDEN or (keep is not None and not keep(row)):
                continue
            tally.add(row)
            item = (rank(row), i, row)
            if len(heap) < limit:
                heapq.heappush(heap, item)
            elif item[:2] > heap[0][:2]:
                heapq.heapreplace(heap, item)
    except Exception as e:
        logging.warning(f"Could not read recent findings: {type(e).__name__}")
    return [row for _, _, row in sorted(heap, key=lambda t: t[:2], reverse=True)], tally.result()


def recent(table, since: datetime, limit: int = 2000) -> list:
    """The ``limit`` newest findings of all users from ``since``, newest first."""
    return window(table, since, limit)[0]


def high_first(row: dict):
    """Rank for ``window``: high findings first, then the newest."""
    return (row["severity"] == "high", row["at"])


class _Tally:
    def __init__(self):
        self.total = self.high = 0
        self.by_type, self.by_status, self.by_triage, self.users = {}, {}, {}, set()

    def add(self, r: dict) -> None:
        self.total += 1
        self.by_type[r["type"]] = self.by_type.get(r["type"], 0) + 1
        self.by_status[r["status"]] = self.by_status.get(r["status"], 0) + 1
        state = r.get("triage") or "open"
        self.by_triage[state] = self.by_triage.get(state, 0) + 1
        self.high += r["severity"] == "high"
        if r["user"]:
            self.users.add(r["user"].lower())

    def result(self) -> dict:
        return {"total": self.total, "by_type": self.by_type, "by_status": self.by_status,
                "by_triage": self.by_triage, "high": self.high, "users": len(self.users)}


def set_triage(table, row_id: str, state: str, note: str, by: str, now: Optional[datetime] = None) -> tuple:
    """Set the triage state of one row. Return (the row before the change, the row after), or (None, None).

    ``row_id`` is "<PartitionKey>|<RowKey>" from a row of this module. The state and the note
    change only the view: they do not mute or stop later alerts.
    """
    m = _ROW_ID.match(str(row_id or ""))
    if table is None or not m or state not in TRIAGE_STATES:
        return None, None
    try:
        entity = table.get_entity(partition_key=m.group(1), row_key=m.group(2))
    except ResourceNotFoundError:
        return None, None
    if entity.get("status") in HIDDEN:
        return None, None
    before = _row(entity)
    when = (now or datetime.now(timezone.utc)).strftime(_TS)
    note = " ".join(str(note or "").split())[:_MAX_NOTE]
    table.update_entity({"PartitionKey": m.group(1), "RowKey": m.group(2), "triage": state,
                         "triage_by": str(by or "")[:300], "triage_at": when, "triage_note": note},
                        mode=UpdateMode.MERGE)
    after = dict(before, triage=state, triage_by=str(by or "")[:300], triage_at=when, triage_note=note)
    return before, after


def summary(rows: list) -> dict:
    """{"total", "by_type": {type: n}, "by_status": {status: n}, "high", "users"}."""
    tally = _Tally()
    for r in rows:
        tally.add(r)
    return tally.result()


def purge(table, now: Optional[datetime] = None) -> int:
    """Delete rows (findings and their audit records) logged more than KEEP_DAYS ago. Return the count of findings."""
    if table is None:
        return 0
    cutoff = ((now or datetime.now(timezone.utc)) - timedelta(days=KEEP_DAYS)).strftime(_TS)
    deleted = 0
    try:
        rows = table.query_entities(f"logged_at lt '{cutoff}'", select=["PartitionKey", "RowKey"])
        for entity in list(rows):
            table.delete_entity(entity["PartitionKey"], entity["RowKey"])
            deleted += not entity["PartitionKey"].startswith(_RECORD_PREFIX)   # count findings only
    except Exception as e:
        logging.warning(f"Could not purge findings: {type(e).__name__}")
    return deleted
