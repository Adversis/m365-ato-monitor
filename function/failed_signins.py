"""Failed sign-ins per day (wrong password, locked, unknown or disabled account), for the Overview.

Password spraying shows as many failed sign-ins: one account from many IPs, or many
accounts from one network. This module sends no alert (the sign-ins failed, and there is
no action to take), but the Overview shows the last 7 days. Flagged and clean IPs count:
a spray through residential proxies looks like home connections. Private and allowed IPs
(ALLOWED_IPS) do not count, and a sign-in whose IP lookup never succeeds does not count.

A correct password that MFA or Conditional Access stopped is not counted here. The
suspicious sign-in and new country checks handle it.

State: table "processedevents", partition "system", row "failedsignins-YYYY-MM-DD" (the UTC
day of the sign-in), one JSON property "data", kept KEEP_DAYS days. A string property can
hold 32K characters (64 KiB UTF-16). The limits (USERS, NETS, IPS, ...) keep a full row
near 26K characters, and _fit() trims a row that is still longer than MAX_CHARS. Counts
of accounts and IPs are of hashes, with "+" when a limit is reached. The login check calls
record() for the sign-ins that it marked processed, so each record counts once. No
function raises.
"""

import hashlib
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from azure.core.exceptions import ResourceNotFoundError

import config

_PARTITION = "system"
_PREFIX = "failedsignins-"
KEEP_DAYS = 8
USERS = 40          # users with details, per day
USER_HASHES = 300   # distinct user hashes per day (the account count)
NETS = 30           # networks per day
NET_USERS = 8       # user hashes per network and day
IPS = 300           # distinct IP hashes per day
USER_IPS = 10       # IP hashes per user and day
MAX_CHARS = 30000

# AADSTS codes that mean the password was wrong or the account cannot sign in.
CODES = {
    "50126": "wrong password",
    "50053": "account locked",
    "50034": "account does not exist",
    "50057": "account disabled",
}


def _hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:8]


def entry(event: dict, ip: str, analysis: Optional[dict]) -> Optional[dict]:
    """The fields of one failed sign-in to count, or None if it is not one of CODES."""
    if str(event.get("Operation", "")) != "UserLoginFailed":
        return None
    code = config.sign_in_error_code(event)
    if code not in CODES:
        return None
    a = analysis or {}
    asn = config.normalize_asn(a.get("asn"))
    name = next((str(a.get(k) or "").strip() for k in ("org", "provider")
                 if str(a.get(k) or "").strip() not in ("", "Unknown")), "")
    when = str(event.get("CreationTime") or "")[:19]
    return {"day": when[:10] if len(when) >= 10 else "", "time": when,
            "user": str(event.get("UserId") or "unknown").strip().lower()[:100],
            "code": code, "ip": _hash(ip), "asn": asn or "unknown", "net": name[:60],
            "flagged": bool(a.get("is_suspicious"))}


def _empty() -> dict:
    return {"total": 0, "flagged": 0, "codes": {}, "ips": [], "ips_full": False, "uh": [], "uh_full": False,
            "users": {}, "nets": {}}


def _add_hash(items: list, value: str, limit: int) -> bool:
    """Add ``value`` to ``items`` (at most ``limit``). False if it did not fit."""
    if value in items:
        return True
    if len(items) >= limit:
        return False
    items.append(value)
    return True


def _add(day: dict, e: dict) -> None:
    day["total"] += 1
    day["flagged"] += int(e["flagged"])
    day["codes"][e["code"]] = day["codes"].get(e["code"], 0) + 1
    if not _add_hash(day["ips"], e["ip"], IPS):
        day["ips_full"] = True
    uh = _hash(e["user"])
    if not _add_hash(day["uh"], uh, USER_HASHES):
        day["uh_full"] = True
    u = day["users"].get(e["user"])
    if u is None and len(day["users"]) < USERS:
        u = day["users"][e["user"]] = {"n": 0, "first": e["time"], "last": e["time"], "ips": [], "nets": []}
    if u is not None:
        u["n"] += 1
        u["first"], u["last"] = min(u["first"], e["time"]), max(u["last"], e["time"])
        _add_hash(u["ips"], e["ip"], USER_IPS)
        _add_hash(u["nets"], e["asn"], 5)
    n = day["nets"].get(e["asn"])
    if n is None and len(day["nets"]) < NETS:
        n = day["nets"][e["asn"]] = {"name": e["net"], "n": 0, "flagged": 0, "uh": []}
    if n is not None:
        n["n"] += 1
        n["flagged"] += int(e["flagged"])
        n["name"] = n["name"] or e["net"]
        _add_hash(n["uh"], uh, NET_USERS)


def _fit(day: dict) -> str:
    """The row as JSON, at most MAX_CHARS: drop the users with the fewest failures first."""
    text = json.dumps(day, separators=(",", ":"))
    while len(text) > MAX_CHARS and day["users"]:
        del day["users"][min(day["users"], key=lambda k: (day["users"][k]["n"], k))]
        text = json.dumps(day, separators=(",", ":"))
    return text


def record(events_table, entries: list, now: Optional[datetime] = None) -> None:
    """Add ``entries`` (from entry()) to the row of each one's UTC day."""
    entries = [e for e in entries if e]
    if events_table is None or not entries:
        return
    now = now or datetime.now(timezone.utc)
    by_day = {}
    for e in entries:
        by_day.setdefault(e["day"] or f"{now:%Y-%m-%d}", []).append(e)
    for day, items in sorted(by_day.items()):
        if day < f"{now - timedelta(days=KEEP_DAYS):%Y-%m-%d}":
            continue
        row = _PREFIX + day
        try:
            try:
                old = events_table.get_entity(partition_key=_PARTITION, row_key=row)
                data = json.loads(old.get("data") or "{}")
            except ResourceNotFoundError:
                old, data = None, {}
            data = {**_empty(), **(data if isinstance(data, dict) else {})}
            for e in items:
                _add(data, e)
            events_table.upsert_entity({"PartitionKey": _PARTITION, "RowKey": row, "data": _fit(data)})
            if old is None:
                _purge(events_table, now)
        except Exception as e:
            logging.warning(f"Failed sign-in counts not written: {type(e).__name__}")


def _purge(events_table, now: datetime) -> None:
    for d in range(KEEP_DAYS + 1, KEEP_DAYS + 8):
        try:
            events_table.delete_entity(_PARTITION, f"{_PREFIX}{now - timedelta(days=d):%Y-%m-%d}")
        except Exception:
            pass


def summary(events_table, now: Optional[datetime] = None, days: int = 7, top: int = 5) -> Optional[dict]:
    """The last ``days`` UTC days: totals, the most targeted users, the main source networks, per day."""
    if events_table is None:
        return None
    now = now or datetime.now(timezone.utc)
    total = flagged = 0
    codes, ips, uhs, users, nets, per_day = {}, set(), set(), {}, {}, []
    ips_full = users_full = False
    for d in range(days - 1, -1, -1):
        day = f"{now - timedelta(days=d):%Y-%m-%d}"
        try:
            row = events_table.get_entity(partition_key=_PARTITION, row_key=_PREFIX + day)
            data = json.loads(row.get("data") or "{}")
        except ResourceNotFoundError:
            per_day.append({"date": day, "n": 0})
            continue
        except Exception as e:
            logging.warning(f"Failed sign-in counts not read: {type(e).__name__}")
            return None
        data = {**_empty(), **(data if isinstance(data, dict) else {})}
        per_day.append({"date": day, "n": int(data["total"])})
        total += int(data["total"])
        flagged += int(data["flagged"])
        ips.update(data["ips"])
        uhs.update(data["uh"])
        ips_full = ips_full or bool(data["ips_full"])
        users_full = users_full or bool(data["uh_full"])
        for c, n in data["codes"].items():
            codes[c] = codes.get(c, 0) + int(n)
        for name, u in data["users"].items():
            t = users.setdefault(name, {"n": 0, "first": u["first"], "last": u["last"], "ips": set(), "nets": set()})
            t["n"] += int(u["n"])
            t["first"], t["last"] = min(t["first"], u["first"]), max(t["last"], u["last"])
            t["ips"].update(u["ips"])
            t["nets"].update(u["nets"])
        for asn, n in data["nets"].items():
            t = nets.setdefault(asn, {"name": n.get("name", ""), "n": 0, "flagged": 0, "users": set()})
            t["n"] += int(n["n"])
            t["flagged"] += int(n["flagged"])
            t["name"] = t["name"] or n.get("name", "")
            t["users"].update(n.get("uh") or [])
    top_users = sorted(users.items(), key=lambda kv: (-kv[1]["n"], kv[0]))[:top]
    top_nets = sorted(nets.items(), key=lambda kv: (-kv[1]["n"], kv[0]))[:top]
    return {
        "days": days, "total": total, "flagged": flagged, "ips": len(ips), "ips_more": ips_full,
        "users": len(uhs), "users_more": users_full, "codes": codes, "per_day": per_day,
        "top_users": [{"user": name, "n": u["n"], "ips": len(u["ips"]), "nets": len(u["nets"]),
                       "first": u["first"], "last": u["last"]} for name, u in top_users],
        "top_nets": [{"asn": asn, "name": n["name"], "n": n["n"], "flagged": n["flagged"], "users": len(n["users"])}
                     for asn, n in top_nets],
    }
