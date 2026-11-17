"""The networks that each user signed in from, with the first and the last time.

The MFA change check uses it. To add an MFA method, the user signs in (My Sign-ins >
Security info) shortly before. The "Update user." record of the change has no IP, so
the check looks at the user's successful sign-ins in the hour before the change. A
sign-in from a network that the user did not use before is worth an email.

A network is the /24 of an IPv4 address or the /48 of an IPv6 address: a home or
office connection keeps its network when its address changes. Mobile carriers can
move a phone between networks, so a phone can look new some times.

Storage: the country baseline table (geo_monitor), partition "networks", one row per
user:
  since   when the row was made (the history is complete only after LEARN_DAYS)
  nets    {network: [first sign-in, last sign-in]}, kept NETWORK_DAYS after the last
  recent  [[time, ip], ...]: the sign-ins of the last RECENT_HOURS, newest last

The inbox rule check reads it too: a rule that only deletes mail alerts only after a sign-in
from a new network in the 24 hours before (or another alert for the user).

No function raises. Without storage, ``record`` does nothing and ``near`` says that
there is no history.
"""

import hashlib
import ipaddress
import json
import logging
from datetime import datetime, timedelta, timezone

from azure.core.exceptions import ResourceNotFoundError

from ip_checker import extract_ip

_PARTITION = "networks"
NETWORK_DAYS = 90
LEARN_DAYS = 14
RECENT_HOURS = 48
WINDOW_BEFORE = timedelta(minutes=60)
WINDOW_AFTER = timedelta(minutes=10)    # clocks of different services differ a little
_MAX_NETS = 300
_MAX_RECENT = 100


def network_of(ip: str) -> str:
    """'203.0.113.7' -> '203.0.113.0/24'; IPv6 -> its /48. '' if not an IP."""
    try:
        addr = ipaddress.ip_address(str(ip or "").strip())
    except ValueError:
        return ""
    bits = 24 if addr.version == 4 else 48
    return str(ipaddress.ip_network(f"{addr}/{bits}", strict=False))


def _key(upn: str) -> str:
    return hashlib.sha256(upn.strip().lower().encode("utf-8")).hexdigest()


def _time(value) -> datetime:
    """An ISO time (with or without a zone) as aware UTC. Raises ValueError."""
    dt = datetime.fromisoformat(str(value).strip().replace("Z", "+00:00"))
    return dt.astimezone(timezone.utc) if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _load(table, upn: str) -> dict:
    try:
        row = table.get_entity(partition_key=_PARTITION, row_key=_key(upn))
    except ResourceNotFoundError:
        return {}
    out = {"since": str(row.get("since") or "")}
    for name, empty in (("nets", {}), ("recent", [])):
        try:
            value = json.loads(row.get(name) or "null")
        except ValueError:
            value = None
        out[name] = value if isinstance(value, type(empty)) else empty
    return out


def record(table, login_records: list, now: datetime) -> None:
    """Add the successful sign-ins (UserLoggedIn) of ``login_records`` to each user's row."""
    if table is None:
        return
    by_user = {}
    for r in login_records:
        if not isinstance(r, dict) or r.get("Operation") != "UserLoggedIn":
            continue
        user, ip = str(r.get("UserId") or "").strip().lower(), extract_ip(r) or ""
        net = network_of(ip)
        try:
            when = _time(r.get("CreationTime"))
        except ValueError:
            continue
        if "@" in user and net:
            by_user.setdefault(user, []).append((when, ip, net))
    for user, signins in by_user.items():
        try:
            _record_user(table, user, signins, now)
        except Exception as e:
            logging.warning(f"Sign-in networks not kept: {type(e).__name__}")
            return


def _record_user(table, user: str, signins: list, now: datetime) -> None:
    row = _load(table, user)
    nets = row.get("nets") or {}
    recent = row.get("recent") or []
    for when, ip, net in signins:
        first, last = (nets.get(net) or [_iso(when), _iso(when)])[:2]
        # Records can arrive out of order: keep the earliest first and the latest last.
        nets[net] = [min(first, _iso(when)), max(last, _iso(when))]
        recent.append([_iso(when), ip])
    keep_net = _iso(now - timedelta(days=NETWORK_DAYS))
    nets = {n: v for n, v in nets.items() if v[1] >= keep_net}
    if len(nets) > _MAX_NETS:
        nets = dict(sorted(nets.items(), key=lambda kv: kv[1][1])[-_MAX_NETS:])
    keep_recent = _iso(now - timedelta(hours=RECENT_HOURS))
    recent = sorted({(t, ip) for t, ip in recent if t >= keep_recent})[-_MAX_RECENT:]
    table.upsert_entity({
        "PartitionKey": _PARTITION, "RowKey": _key(user), "upn": user,
        "since": row.get("since") or _iso(now),
        "nets": json.dumps(nets, sort_keys=True),
        "recent": json.dumps([list(x) for x in recent]),
    })


def near(table, upn: str, when: datetime, before: timedelta = WINDOW_BEFORE) -> dict:
    """The user's sign-ins from ``before`` before ``when`` to WINDOW_AFTER after it.

    Returns {"history": bool, "ips": [...], "new": [...]}. ``history`` is False when the
    user's row is younger than LEARN_DAYS before the window (or storage failed): a network
    can then look new only because the monitor did not see it yet. ``new``: the IPs whose
    network the user first used in the window.
    """
    empty = {"history": False, "ips": [], "new": []}
    if table is None or not upn:
        return empty
    try:
        row = _load(table, upn)
    except Exception as e:
        logging.warning(f"Sign-in networks not read: {type(e).__name__}")
        return empty
    start, end = _iso(when - before), _iso(when + WINDOW_AFTER)
    try:
        history = bool(row.get("since")) and _time(row["since"]) <= when - before - timedelta(days=LEARN_DAYS)
    except ValueError:
        history = False
    ips, new = [], []
    for t, ip in row.get("recent") or []:
        if not (start <= str(t) <= end) or ip in ips:
            continue
        ips.append(ip)
        first = ((row.get("nets") or {}).get(network_of(ip)) or [""])[0]
        if first >= start:
            new.append(ip)
    return {"history": history, "ips": ips, "new": new}
