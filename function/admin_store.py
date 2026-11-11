"""Table Storage for the management UI: setting overrides, change history, email journal.

Table "monitoradmin":
  settings / current    the overrides (JSON), a version number, who and when
  history  / <reverse>  one row per change (newest first)
  emails   / <reverse>  one row per alert email (newest first)
  mutes    / <id>       one row per targeted mute (see "Mutes" below)
  searches / <user hash> the last audit search for a user (user page)

All functions are safe without storage: they return empty results and log a
warning on failure. They never raise into the monitor run.
"""

import hashlib
import json
import logging
import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from azure.core import MatchConditions
from azure.data.tables import UpdateMode
from azure.core.exceptions import ResourceExistsError, ResourceModifiedError, ResourceNotFoundError

import config
import settings as settings_mod

TABLE_NAME = "monitoradmin"
_KEEP_DAYS = 90

_cache = config.CachedTable(TABLE_NAME, "Admin table")


def table_client():
    """Return the table client, or None if storage is not available."""
    return _cache.get()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _reverse_key(when: datetime) -> str:
    """Row key that sorts newest first."""
    return f"{10**13 - int(when.timestamp() * 1000):013d}"


# -----------------------------------------------------------------------------
# Settings
# -----------------------------------------------------------------------------

class ConflictError(Exception):
    """Somebody else saved the settings first."""


class ValidationError(Exception):
    def __init__(self, errors: dict):
        super().__init__("not valid")
        self.errors = errors


def load(table) -> dict:
    """Return {overrides, version, updated_by, updated_at, etag}. ``etag`` is None if no row exists."""
    empty = {"overrides": {}, "version": 0, "updated_by": "", "updated_at": "", "etag": None}
    if table is None:
        return empty
    try:
        entity = table.get_entity(partition_key="settings", row_key="current")
    except ResourceNotFoundError:
        return empty
    etag = (getattr(entity, "metadata", None) or {}).get("etag")
    try:
        overrides = json.loads(entity.get("overrides") or "{}")
    except ValueError:
        overrides = {}
    return {"overrides": overrides if isinstance(overrides, dict) else {},
            "version": int(entity.get("version", 0)),
            "updated_by": entity.get("updated_by", ""), "updated_at": entity.get("updated_at", ""),
            "etag": etag}


def refresh(table=None) -> None:
    """Apply the stored overrides to config. Call at the start of each run.

    Without storage, keep the values in use (do not drop overrides because of
    a storage outage).
    """
    table = table if table is not None else table_client()
    if table is None:
        return
    try:
        settings_mod.apply(load(table)["overrides"])
    except Exception as e:
        logging.warning(f"Settings: could not load overrides: {type(e).__name__}")
    try:
        _active_mutes[:] = list_mutes(table, _now())
    except Exception as e:
        logging.warning(f"Mutes: could not load: {type(e).__name__}")


def save(table, changes: dict, version: int, user: str, granted_roles=None, dry_run: bool = False) -> list:
    """Apply ``changes`` ({name: value, or None to reset}) and return the change list.

    With ``dry_run``, validate and return the change list, but write nothing.
    Raises ValidationError, or ConflictError if ``version`` is not current or
    another save wrote the row after this one read it (ETag check).
    """
    state = load(table)
    if int(version) != state["version"]:
        raise ConflictError()
    overrides = dict(state["overrides"])
    errors, effective_new = {}, {}
    for name, raw in changes.items():
        setting = settings_mod.BY_NAME.get(name)
        if setting is None:
            errors[name] = "Unknown setting."
            continue
        if raw is None:
            overrides.pop(name, None)
            effective_new[name] = settings_mod.DEFAULTS[name]
            continue
        try:
            value = settings_mod.validate(setting, raw)
        except ValueError as e:
            errors[name] = str(e)
            continue
        missing = settings_mod.missing_roles(setting, value, granted_roles)
        if missing:
            fix = ("./install.ps1 -Update" if setting.kind == "role_set"
                   else "./install.ps1 -ResponsePermissions yes")
            errors[name] = f"Needs the Graph permission {', '.join(missing)}. Run {fix} to grant it."
            continue
        if value == settings_mod.DEFAULTS[name]:
            overrides.pop(name, None)
        else:
            overrides[name] = value
        effective_new[name] = value
    if errors:
        raise ValidationError(errors)

    diff = []
    for name, new in effective_new.items():
        old = state["overrides"].get(name, settings_mod.DEFAULTS[name])
        if old != new:
            setting = settings_mod.BY_NAME[name]
            old_text, new_text = settings_mod.describe_for(setting, old), settings_mod.describe_for(setting, new)
            if setting.kind == "secret" and old and new:
                old_text, new_text = "(set)", "(replaced)"
            diff.append({"name": name, "label": setting.label, "old": old_text, "new": new_text})
    if not diff or dry_run:
        return diff

    now = _now()
    entity = {
        "PartitionKey": "settings", "RowKey": "current",
        "overrides": json.dumps(overrides, sort_keys=True), "version": state["version"] + 1,
        "updated_by": user, "updated_at": now.isoformat(),
    }
    try:
        if state["etag"] is None:
            table.create_entity(entity)
        else:
            table.update_entity(entity, mode=UpdateMode.REPLACE, etag=state["etag"],
                                match_condition=MatchConditions.IfNotModified)
    except (ResourceExistsError, ResourceModifiedError):
        raise ConflictError()
    record_history(table, user, diff, now)
    settings_mod.apply(overrides)
    return diff


def record_history(table, user: str, changes: list, when: datetime = None) -> None:
    when = when or _now()
    try:
        table.upsert_entity({
            "PartitionKey": "history", "RowKey": _reverse_key(when),
            "at": when.isoformat(), "by": user, "changes": json.dumps(changes),
        })
    except Exception as e:
        logging.warning(f"Could not record settings history: {type(e).__name__}")


def history(table, limit: int = 30) -> list:
    rows = _newest(table, "history", limit)
    out = []
    for r in rows:
        try:
            changes = json.loads(r.get("changes") or "[]")
        except ValueError:
            changes = []
        out.append({"at": r.get("at", ""), "by": r.get("by", ""), "changes": changes})
    return out


# -----------------------------------------------------------------------------
# Email journal
# -----------------------------------------------------------------------------

def record_email(subject: str, status: str) -> None:
    """Record one email (status: sent, queued, failed). Never raises."""
    table = table_client()
    if table is None:
        return
    now = _now()
    try:
        table.upsert_entity({
            "PartitionKey": "emails", "RowKey": _reverse_key(now) + f"-{abs(hash(subject)) % 10000:04d}",
            "at": now.isoformat(), "subject": subject[:300], "status": status,
        })
    except Exception as e:
        logging.warning(f"Could not record email: {type(e).__name__}")


def recent_emails(table, limit: int = 50) -> list:
    return [{"at": r.get("at", ""), "subject": r.get("subject", ""), "status": r.get("status", "")}
            for r in _newest(table, "emails", limit)]


# -----------------------------------------------------------------------------
# Mutes: no email for medium alerts of one type, one user, or one inbox rule,
# for 1 to 90 days. High alerts are always sent. Each change is recorded in
# History and emailed (the caller does this).
# -----------------------------------------------------------------------------

MUTE_MAX_DAYS = 90
_MUTE_PARTITION = "mutes"
_MUTE_UPN_RE = re.compile(r"^[^@\s,;]{1,64}@[a-z0-9.-]{1,253}\.[a-z]{2,63}$")
_active_mutes = []   # loaded by refresh()


def _parse_time(text) -> Optional[datetime]:
    try:
        dt = datetime.fromisoformat(str(text))
    except (TypeError, ValueError):
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _mute_row(entity: dict) -> dict:
    return {"id": entity.get("RowKey", ""), "type": entity.get("type", "*"), "user": entity.get("user", "*"),
            "rule_name": entity.get("rule_name", ""), "until": entity.get("until", ""),
            "reason": entity.get("reason", ""), "created_by": entity.get("created_by", ""),
            "created_at": entity.get("created_at", ""), "ended_by": entity.get("ended_by", ""),
            "ended_at": entity.get("ended_at", "")}


def list_mutes(table, now: datetime, include_expired: bool = False) -> list:
    """Mutes, active first. Expired and ended mutes only with ``include_expired``."""
    if table is None:
        return []
    out = []
    for entity in table.query_entities(f"PartitionKey eq '{_MUTE_PARTITION}'"):
        row = _mute_row(entity)
        until = _parse_time(row["until"])
        row["active"] = bool(until and until > now)
        if row["active"] or include_expired:
            out.append(row)
    out.sort(key=lambda r: (not r["active"], r["until"]))
    return out


def mute_type_label(ftype: str) -> str:
    if ftype == "*":
        return "All alert types that can be muted"
    return dict(settings_mod.MUTE_TYPES).get(ftype, ftype)


def describe_mute(mute: dict) -> str:
    """'Inbox rules, jane@contoso.com, rule "Invoices", until 2026-11-15 (reason)'."""
    parts = [mute_type_label(mute.get("type", "*")),
             "all users" if mute.get("user", "*") == "*" else mute.get("user", "")]
    if mute.get("rule_name"):
        parts.append(f"rule '{mute['rule_name']}'")
    until = _parse_time(mute.get("until"))
    text = ", ".join(parts) + (f", until {until:%Y-%m-%d %H:%M} UTC" if until else "")
    return text + (f" ({mute['reason']})" if mute.get("reason") else "")


def validate_mute(body: dict) -> dict:
    """Return {type, user, rule_name, days, reason} or raise ValidationError."""
    errors = {}
    ftype = str(body.get("type") or "*").strip()
    user = str(body.get("user") or "*").strip().lower()
    rule = str(body.get("rule_name") or "").strip()
    reason = str(body.get("reason") or "").strip()
    days = body.get("days")
    if ftype != "*" and ftype not in dict(settings_mod.MUTE_TYPES):
        errors["type"] = ("This alert type cannot be muted (it is always high)."
                          if ftype in settings_mod.ALWAYS_HIGH else "Unknown alert type.")
    if user != "*" and not _MUTE_UPN_RE.match(user):
        errors["user"] = "Enter a user principal name, for example jane@contoso.com, or * for all users."
    if ftype == "*" and user == "*":
        errors["user"] = "Select one alert type or one user. To stop an alert type, use Settings > Alerts."
    if rule and ftype != "inbox_rule":
        errors["rule_name"] = "A rule name applies to inbox rule alerts only."
    if len(rule) > 255 or any(ord(c) < 32 for c in rule):
        errors["rule_name"] = "At most 255 characters, no control characters."
    if not 3 <= len(reason) <= 200 or any(ord(c) < 32 for c in reason):
        errors["reason"] = "Enter a reason of 3 to 200 characters."
    if isinstance(days, bool) or not isinstance(days, int) or not 1 <= days <= MUTE_MAX_DAYS:
        errors["days"] = f"Enter a whole number of days from 1 to {MUTE_MAX_DAYS}."
    if errors:
        raise ValidationError(errors)
    return {"type": ftype, "user": user, "rule_name": rule, "days": days, "reason": reason}


def add_mute(table, body: dict, by: str, now: Optional[datetime] = None) -> dict:
    """Validate and store a mute. Return the row. Raises ValidationError."""
    now = now or _now()
    m = validate_mute(body)
    row = {"PartitionKey": _MUTE_PARTITION, "RowKey": secrets.token_hex(8),
           "type": m["type"], "user": m["user"], "rule_name": m["rule_name"],
           "until": (now + timedelta(days=m["days"])).isoformat(), "reason": m["reason"],
           "created_by": by, "created_at": now.isoformat()}
    table.upsert_entity(row)
    mute = _mute_row(row)
    mute["active"] = True
    _active_mutes.append(mute)
    return mute


def end_mute(table, mute_id: str, by: str, now: Optional[datetime] = None) -> Optional[dict]:
    """End an active mute now. Return the mute, or None if it is not found or not active."""
    now = now or _now()
    if not re.fullmatch(r"[0-9a-f]{16}", str(mute_id or "")):
        return None
    try:
        entity = table.get_entity(partition_key=_MUTE_PARTITION, row_key=mute_id)
    except ResourceNotFoundError:
        return None
    until = _parse_time(entity.get("until"))
    if not until or until <= now:
        return None
    before = _mute_row(entity)
    table.upsert_entity({"PartitionKey": _MUTE_PARTITION, "RowKey": mute_id, "until": now.isoformat(),
                         "ended_by": by, "ended_at": now.isoformat()})
    _active_mutes[:] = [m for m in _active_mutes if m["id"] != mute_id]
    return before


def active_mutes(now: Optional[datetime] = None) -> list:
    """The mutes loaded by refresh() that are still active."""
    now = now or _now()
    return [m for m in _active_mutes if (_parse_time(m.get("until")) or now) > now]


def matching_mute(ftype: str, user: str, rule_name: str = "", severity: str = "",
                  now: Optional[datetime] = None) -> Optional[dict]:
    """The active mute that hides this alert, or None. High alerts are never muted."""
    if severity == "high":
        return None
    now = now or _now()
    user = str(user or "").strip().lower()
    rule_name = str(rule_name or "").strip().lower()
    for m in _active_mutes:
        until = _parse_time(m.get("until"))
        if not until or until <= now:
            continue
        if m["type"] not in ("*", ftype) or m["user"] not in ("*", user):
            continue
        if m.get("rule_name") and m["rule_name"].lower() != rule_name:
            continue
        return m
    return None


def _newest(table, partition: str, limit: int) -> list:
    if table is None:
        return []
    rows = []
    try:
        for i, entity in enumerate(table.query_entities(f"PartitionKey eq '{partition}'")):
            if i >= limit:
                break
            rows.append(entity)
    except Exception as e:
        logging.warning(f"Could not read {partition}: {type(e).__name__}")
    return rows


def purge_old(table) -> int:
    """Delete history and email rows, and mutes that ended, older than 90 days. Return the count."""
    if table is None:
        return 0
    cutoff = _reverse_key(_now() - timedelta(days=_KEEP_DAYS))
    deleted = 0
    for partition in ("history", "emails"):
        try:
            for entity in list(table.query_entities(f"PartitionKey eq '{partition}' and RowKey gt '{cutoff}'")):
                table.delete_entity(entity["PartitionKey"], entity["RowKey"])
                deleted += 1
        except Exception as e:
            logging.warning(f"Could not purge {partition}: {type(e).__name__}")
    mute_cutoff = (_now() - timedelta(days=_KEEP_DAYS)).isoformat()
    try:
        for entity in list(table.query_entities(f"PartitionKey eq '{_MUTE_PARTITION}' and until lt '{mute_cutoff}'")):
            table.delete_entity(entity["PartitionKey"], entity["RowKey"])
            deleted += 1
    except Exception as e:
        logging.warning(f"Could not purge mutes: {type(e).__name__}")
    return deleted


# -----------------------------------------------------------------------------
# Audit searches (user page): the last search for each user
# -----------------------------------------------------------------------------

_SEARCH_PARTITION = "searches"
SEARCH_KEEP_DAYS = 30           # Microsoft keeps a finished search for 30 days


def _search_key(upn: str) -> str:
    return hashlib.sha256(str(upn or "").strip().lower().encode("utf-8")).hexdigest()[:32]


def save_search(table, upn: str, query_id: str, days: int, by: str, now: Optional[datetime] = None) -> None:
    """Keep the last audit search for ``upn``, so the user page can show it again."""
    if table is None:
        return
    now = now or _now()
    try:
        table.upsert_entity({"PartitionKey": _SEARCH_PARTITION, "RowKey": _search_key(upn), "user": upn,
                             "id": query_id, "days": int(days), "by": by, "at": now.isoformat()})
    except Exception as e:
        logging.warning(f"Could not keep the audit search: {type(e).__name__}")


def last_search(table, upn: str, now: Optional[datetime] = None) -> Optional[dict]:
    """The last audit search for ``upn`` in SEARCH_KEEP_DAYS: {id, days, by, at}, or None."""
    if table is None:
        return None
    now = now or _now()
    try:
        row = table.get_entity(partition_key=_SEARCH_PARTITION, row_key=_search_key(upn))
    except ResourceNotFoundError:
        return None
    except Exception as e:
        logging.warning(f"Could not read the audit search: {type(e).__name__}")
        return None
    at = _parse_time(row.get("at"))
    if not at or now - at > timedelta(days=SEARCH_KEEP_DAYS) or row.get("user") != upn:
        return None
    return {"id": str(row.get("id") or ""), "days": int(row.get("days") or 0), "by": row.get("by", ""),
            "at": row.get("at", "")}
