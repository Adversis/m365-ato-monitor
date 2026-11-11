"""proxycheck.io query quota: how much of the daily limit is used, and a warning email.

proxycheck.io allows 100 queries per day without a key, 1,000 with a free key,
and more with a paid plan. Each IP that the monitor looks up is one query. An
IP in the cache is not looked up again: a clean answer for IP_CACHE_DAYS
(default 7), a flagged answer for 24 hours (ip_checker.get_cached_ip).

Two sources tell the monitor how much is used:

1. Each lookup answer (ip_checker). proxycheck.io answers status "warning"
   when less than 10% of the daily limit is left, and status "denied" when the
   limit is used up. note() keeps the newest state.
2. The usage export, only with a key: "Queries Today" and "Daily Limit". It
   works only if "Dashboard API Access" is on in the proxycheck.io dashboard.
   Queries to it do not count against the limit. refresh_usage() reads it at
   most every USAGE_MINUTES.

check() runs on each monitor run. When the quota is low or used up, it sends
one email per level (low, used up) per UTC day.

The state is one row in the ipcache table (partition "quota"). The ipcache
purge deletes only rows with "cached_at", so this row stays.
"""

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

import config

_PARTITION = "quota"
_ROW = "proxycheck"
USAGE_URL = "https://proxycheck.io/dashboard/export/usage/"
USAGE_MINUTES = 30
LOW_PERCENT = 80          # warn when this much of the daily limit is used (usage export)
LEVELS = ("ok", "low", "exhausted", "refused")
_RANK = {"unknown": 0, "ok": 0, "low": 1, "refused": 2, "exhausted": 2}
_last_noted = None        # (UTC day, level, message) of the last write by this instance
_warned_here = set()      # (UTC day, level) emailed by this instance: no repeat if the "warned" write failed

# What stops or waits when lookups fail. Used in the email, the management UI, and the docs.
EFFECTS = (
    ("Suspicious sign-ins and new countries",
     "The sign-in waits in a queue. Each run checks it again, for up to 26 hours. The alert comes late."),
    ("Stolen session and mail access checks",
     "Records whose IP lookup fails are skipped after about 8 minutes. These alerts are lost, unless the "
     "session is used again after the quota is back."),
    ("Account takeover alerts (inbox rules, forwarding, MFA, app consent, and others)",
     "Still sent, but without the IP reputation. An alert from a risky IP is not raised to high."),
)


def classify(status: str, message: str) -> Optional[str]:
    """Quota level from one proxycheck.io answer, or None if the answer says nothing about the quota."""
    status = str(status or "").lower()
    msg = str(message or "").lower()
    if "per second" in msg:
        return None             # a rate limit for a burst of requests, not the daily quota
    about_quota = any(w in msg for w in ("exhausted", "query limit", "allowance", "queries"))
    if status == "ok":
        return "ok"
    if status == "denied":
        return "exhausted" if about_quota else "refused"
    if status == "warning" and about_quota:
        return "low"
    return None


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _load(table) -> dict:
    if table is None:
        return {}
    try:
        return dict(table.get_entity(partition_key=_PARTITION, row_key=_ROW))
    except Exception:
        return {}


def _save(table, fields: dict) -> None:
    if table is None:
        return
    try:
        table.upsert_entity({"PartitionKey": _PARTITION, "RowKey": _ROW, **fields})   # MERGE
    except Exception as e:
        logging.warning(f"proxycheck.io quota state not kept: {type(e).__name__}")


def note(table, status: str, message: str, now: Optional[datetime] = None) -> None:
    """Keep the quota level of a lookup answer. Writes only when the level or the day changes."""
    global _last_noted
    level = classify(status, message)
    if level is None:
        return
    now = now or _now()
    message = config.redact(str(message or ""))[:300] if level != "ok" else ""
    key = (now.strftime("%Y-%m-%d"), level, message)
    if key == _last_noted:
        return
    _last_noted = key
    _save(table, {"level": level, "message": message, "level_at": now.isoformat()})


def refresh_usage(table, now: Optional[datetime] = None, force: bool = False) -> dict:
    """Read the usage export if a key is set and the stored count is older than USAGE_MINUTES."""
    now = now or _now()
    row = _load(table)
    if not config.PROXYCHECK_API_KEY:
        return row
    try:
        last = datetime.fromisoformat(str(row.get("usage_tried_at") or row.get("usage_at") or ""))
    except ValueError:
        last = None
    if not force and last and now - last < timedelta(minutes=USAGE_MINUTES):
        return row
    fields = {"usage_tried_at": now.isoformat()}
    try:
        resp = config.http.get(USAGE_URL, params={"key": config.PROXYCHECK_API_KEY}, timeout=10)
        data = resp.json() if resp.status_code == 200 else None
    except Exception as e:
        # The exception text can contain the URL, which contains the key.
        logging.warning(f"proxycheck.io usage not read: {config.redact(e)}")
        data = None
    used = _int(data.get("Queries Today")) if isinstance(data, dict) else None
    limit = _int(data.get("Daily Limit")) if isinstance(data, dict) else None
    if used is not None and limit:
        fields.update({"used": used, "limit": limit, "plan": str(data.get("Plan Tier") or "")[:40],
                       "usage_at": now.isoformat(), "usage_error": ""})
    else:
        reason = (config.redact(str(data.get("message") or ""))[:200] if isinstance(data, dict) else "")
        fields["usage_error"] = reason or ("No usage count. Turn on Dashboard API Access in the proxycheck.io "
                                           "dashboard to see it.")
    _save(table, fields)
    return {**row, **fields}


def _int(value) -> Optional[int]:
    try:
        n = int(str(value).replace(",", "").strip())
    except (TypeError, ValueError):
        return None
    return n if n >= 0 else None


def status(table, now: Optional[datetime] = None, row: Optional[dict] = None) -> dict:
    """The quota state for the management UI, /api/status, and the weekly report. No network call."""
    now = now or _now()
    row = _load(table) if row is None else row
    level = str(row.get("level") or "unknown")
    if level not in LEVELS:
        level = "unknown"
    level_at = str(row.get("level_at") or "")
    today = now.strftime("%Y-%m-%d")
    if level in ("low", "exhausted", "refused") and level_at[:10] != today:
        level = "unknown"       # from an earlier day: the limit was reset since, or the next lookup tells
    used, limit = _int(row.get("used")), _int(row.get("limit"))
    usage_at = str(row.get("usage_at") or "")
    fresh_usage = bool(usage_at) and usage_at[:10] == today
    if fresh_usage and limit:
        by_count = "exhausted" if used >= limit else "low" if used * 100 >= limit * LOW_PERCENT else "ok"
        if level == "unknown" or _RANK[by_count] > _RANK[level]:
            level = by_count
    said_today = level_at[:10] == today
    return {
        "level": level,
        "message": str(row.get("message") or "") if said_today and level in ("low", "exhausted", "refused") else "",
        "level_at": level_at,
        "key": bool(config.PROXYCHECK_API_KEY),
        "used": used if fresh_usage else None,
        "limit": limit if fresh_usage else (None if config.PROXYCHECK_API_KEY else 100),
        "plan": str(row.get("plan") or "") if fresh_usage else "",
        "usage_at": usage_at,
        "usage_error": str(row.get("usage_error") or "") if config.PROXYCHECK_API_KEY else "",
    }


def check(table, now: Optional[datetime] = None) -> Optional[str]:
    """Refresh the usage count. Send one warning email per level per UTC day. Return the level emailed."""
    if table is None:
        return None             # no place to keep "warned": do not send on every run
    now = now or _now()
    row = refresh_usage(table, now)
    state = status(table, now, row)
    level = state["level"]
    if level not in ("low", "exhausted", "refused"):
        return None
    day = now.strftime("%Y-%m-%d")
    try:
        warned = json.loads(row.get("warned") or "{}")
    except ValueError:
        warned = {}
    if not isinstance(warned, dict) or warned.get("day") != day:
        warned = {"day": day, "levels": []}
    if level in warned.get("levels", []) or (day, level) in _warned_here:
        return None
    from alerting import send_quota_warning
    if not send_quota_warning(state):
        return None
    _warned_here.add((day, level))
    warned["levels"] = sorted(set(warned.get("levels", [])) | {level})
    _save(table, {"warned": json.dumps(warned)})
    return level


def reset() -> None:
    """Tests: forget the last write and the emails of this instance."""
    global _last_noted
    _last_noted = None
    _warned_here.clear()
