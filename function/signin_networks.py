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
          ("last" moves in steps of one day)
  recent  [[start, end, ip], ...]: the sign-ins of the last RECENT_HOURS, as time ranges per IP
  asns    {ASN: [first sign-in, last sign-in]}: the network providers of sign-ins from clean IPs
          (not VPN, proxy, hosting, or Tor), kept NETWORK_DAYS after the last. A mobile carrier
          gives a phone new IPv6 networks often; the provider stays the same (known_asn)
  updated the last write; the weekly clean-up deletes rows with no write in NETWORK_DAYS

network_backfill.py loads the sign-ins of the last 30 days from the audit log once, so that
the history is complete soon after an install (or the update that adds the backfill).

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

from typing import Optional

from azure.core import MatchConditions
from azure.core.exceptions import ResourceExistsError, ResourceModifiedError, ResourceNotFoundError
from azure.data.tables import UpdateMode

from ip_checker import extract_ip

_PARTITION = "networks"
NETWORK_DAYS = 90
LEARN_DAYS = 14
RECENT_HOURS = 48
WINDOW_BEFORE = timedelta(minutes=60)
WINDOW_AFTER = timedelta(minutes=10)    # clocks of different services differ a little
_MAX_NETS = 300
_MAX_RECENT = 100
_MAX_ASNS = 50


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


def _parse_row(row) -> dict:
    out = {"since": str(row.get("since") or ""), "etag": (getattr(row, "metadata", None) or {}).get("etag")}
    for name, empty in (("nets", {}), ("recent", []), ("asns", {})):
        try:
            value = json.loads(row.get(name) or "null")
        except ValueError:
            value = None
        out[name] = value if isinstance(value, type(empty)) else empty
    return out


def _load(table, upn: str) -> dict:
    try:
        row = table.get_entity(partition_key=_PARTITION, row_key=_key(upn))
    except ResourceNotFoundError:
        return {}
    return _parse_row(row)


# The rows that this instance read or wrote last, so that a run reads a user's row only when the
# sign-ins change it. Writes are conditional (etag): a row that another instance changed is read again.
_rows = {}
_MAX_CACHED = 5000
_MERGE_GAP = timedelta(minutes=10)     # sign-ins from one IP this close together form one range
_END_STEP = timedelta(minutes=5)       # a range's end moves in steps (fewer writes)
_LAST_STEP = timedelta(days=1)         # "last" only serves the NETWORK_DAYS clean-up
_MAX_FAILURES = 3                      # storage is down: stop for this run instead of N failing calls


def record(table, login_records: list, now: datetime, since: Optional[datetime] = None,
           asn_lookup=None) -> bool:
    """Add the successful sign-ins (UserLoggedIn) of ``login_records`` to each user's row.

    ``since``: the start of the period that ``login_records`` covers completely (the backfill of
    past sign-ins). A row that gets sign-ins here starts no later than it. ``asn_lookup``:
    called once with the distinct IPs; returns {ip: "AS123"} for the clean IPs (no entry for a
    flagged or unknown IP). False if a write failed.
    """
    if table is None:
        return False
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
    asns = {}
    if asn_lookup and by_user:
        try:
            asns = asn_lookup(sorted({ip for signins in by_user.values() for _, ip, _ in signins})) or {}
        except Exception as e:
            logging.warning(f"Sign-in network providers not read: {type(e).__name__}")
    by_user = {u: [(w, ip, net, str(asns.get(ip) or "")) for w, ip, net in v] for u, v in by_user.items()}
    failed, ok = 0, True
    for user, signins in by_user.items():
        try:
            _record_user(table, user, signins, now, since)
            failed = 0
        except Exception as e:
            failed += 1
            ok = False
            _rows.pop(user, None)
            logging.warning(f"Sign-in networks not kept: {type(e).__name__}")
            if failed >= _MAX_FAILURES:
                logging.warning(f"Sign-in networks: {failed} failures in a row, the rest of this batch is skipped")
                return False
    return ok


def _ranges(recent: list) -> list:
    """[[start, end, ip], ...]. An entry of an older row ([time, ip]) is a range of one time."""
    out = []
    for item in recent or []:
        if isinstance(item, list) and len(item) == 3:
            out.append([str(item[0]), str(item[1]), str(item[2])])
        elif isinstance(item, list) and len(item) == 2:
            out.append([str(item[0]), str(item[0]), str(item[1])])
    return out


def _seen(table: dict, key: str, t: str) -> bool:
    """Add a sign-in time to ``table`` ({key: [first, last]}). True if it changed."""
    old = table.get(key)
    if not old:
        table[key] = [t, t]
        return True
    # Records can arrive out of order: keep the earliest first. "last" moves in steps.
    first = min(old[0], t)
    last = t if t > old[1] and _time(t) - _time(old[1]) >= _LAST_STEP else old[1]
    if [first, last] != old[:2]:
        table[key] = [first, last]
        return True
    return False


def _keep(table: dict, now: datetime, limit: int) -> dict:
    keep = _iso(now - timedelta(days=NETWORK_DAYS))
    kept = {k: v for k, v in table.items() if v[1] >= keep}
    if len(kept) > limit:
        kept = dict(sorted(kept.items(), key=lambda kv: kv[1][1])[-limit:])
    return kept


def _merge(row: dict, signins: list, now: datetime) -> tuple:
    """(nets, recent, asns, changed) after adding ``signins`` ((when, ip, net, asn)) to ``row``."""
    nets = {n: list(v) for n, v in (row.get("nets") or {}).items()}
    asns = {a: list(v) for a, v in (row.get("asns") or {}).items()}
    recent = _ranges(row.get("recent"))
    changed = not row
    for when, ip, net, asn in sorted(signins):
        t = _iso(when)
        changed = _seen(nets, net, t) or changed
        if asn:
            changed = _seen(asns, asn, t) or changed
        for rng in recent:
            if rng[2] == ip and _time(rng[0]) - _MERGE_GAP <= when <= _time(rng[1]) + _MERGE_GAP:
                if t < rng[0]:
                    rng[0], changed = t, True
                elif t > rng[1] and when - _time(rng[1]) >= _END_STEP:
                    rng[1], changed = t, True
                break
        else:
            recent.append([t, t, ip])
            changed = True
    kept, kept_asns = _keep(nets, now, _MAX_NETS), _keep(asns, now, _MAX_ASNS)
    keep_recent = _iso(now - timedelta(hours=RECENT_HOURS))
    recent2 = sorted(r for r in recent if r[1] >= keep_recent)[-_MAX_RECENT:]
    changed = (changed or len(kept) != len(nets) or len(recent2) != len(recent)
               or len(kept_asns) != len(asns))
    return kept, recent2, kept_asns, changed


def _record_user(table, user: str, signins: list, now: datetime, since: Optional[datetime] = None) -> None:
    for attempt in range(2):
        row = _rows.get(user) if attempt == 0 else None
        if row is None:
            row = _load(table, user)
        nets, recent, asns, changed = _merge(row, signins, now)
        start = row.get("since") or _iso(now)
        if since is not None and _iso(since) < start:
            start, changed = _iso(since), True
        if not changed:
            _rows[user] = row
            return
        entity = {"PartitionKey": _PARTITION, "RowKey": _key(user), "upn": user,
                  "since": start, "updated": _iso(now),
                  "nets": json.dumps(nets, sort_keys=True), "recent": json.dumps(recent),
                  "asns": json.dumps(asns, sort_keys=True)}
        try:
            if row.get("etag"):
                table.update_entity(entity, mode=UpdateMode.REPLACE, etag=row["etag"],
                                    match_condition=MatchConditions.IfNotModified)
            elif row:
                table.upsert_entity(entity)       # a row with no etag (a fake or an old SDK)
            else:
                table.create_entity(entity)
        except (ResourceModifiedError, ResourceExistsError, ResourceNotFoundError):
            _rows.pop(user, None)                 # another instance changed it: read it again
            continue
        _rows.pop(user, None)                     # the new etag is not known: read it next time
        if len(_rows) > _MAX_CACHED:
            _rows.clear()
        return
    raise RuntimeError("the row changed twice during the update")


def purge(table, now: datetime) -> int:
    """Delete the rows of users with no sign-in in NETWORK_DAYS (weekly clean-up).

    A row with no "updated" value (written by an older version) is judged by its newest network.
    """
    if table is None:
        return 0
    cutoff = _iso(now - timedelta(days=NETWORK_DAYS))
    deleted = 0
    for row in table.query_entities(f"PartitionKey eq '{_PARTITION}'"):
        newest = str(row.get("updated") or "")
        if not newest:
            nets = _parse_row(row).get("nets") or {}
            newest = max((str(v[1]) for v in nets.values() if isinstance(v, list) and len(v) > 1), default="")
        if newest < cutoff:
            table.delete_entity(_PARTITION, row["RowKey"])
            _rows.pop(str(row.get("upn") or ""), None)
            deleted += 1
    return deleted


def view(table, upn: str) -> dict:
    """The user's row for known() and near(), read once. {} if there is none or storage failed."""
    if table is None or not upn:
        return {}
    try:
        return _load(table, upn)
    except Exception as e:
        logging.warning(f"Sign-in networks not read: {type(e).__name__}")
        return {}


def _history(row: dict, start: datetime) -> bool:
    try:
        return bool(row.get("since")) and _time(row["since"]) <= start - timedelta(days=LEARN_DAYS)
    except ValueError:
        return False


def known(row: dict, ip: str, when: datetime, before: timedelta = WINDOW_BEFORE) -> Optional[bool]:
    """True if the user signed in from ``ip``'s network before the window that ends at ``when``.

    ``row``: from view(). None when it cannot tell: no network history of LEARN_DAYS, no valid IP,
    or no network of the same IP version (a dual-stack user can sign in over IPv4 and change a
    rule over IPv6).
    """
    net = network_of(ip)
    if not net or not _history(row, when - before):
        return None
    nets = row.get("nets") or {}
    version = ipaddress.ip_network(net).version
    if not any(_version(n) == version for n in nets):
        return None
    first = (nets.get(net) or [""])[0]
    return bool(first) and first < _iso(when - before)


def known_asn(row: dict, asn: str, when: datetime, before: timedelta = WINDOW_BEFORE) -> bool:
    """True if the user signed in from a clean IP of network provider ``asn`` before the window.

    False without LEARN_DAYS of history: the provider list starts empty (it is filled from clean
    sign-ins from the update that adds it), so a False only keeps the alert.
    """
    if not asn or not _history(row, when - before):
        return False
    first = ((row.get("asns") or {}).get(asn) or [""])[0]
    return bool(first) and first < _iso(when - before)


def _version(net: str) -> int:
    try:
        return ipaddress.ip_network(net).version
    except ValueError:
        return 0


def near(row: dict, when: datetime, before: timedelta = WINDOW_BEFORE) -> dict:
    """The user's sign-ins from ``before`` before ``when`` to WINDOW_AFTER after it.

    ``row``: from view(). Returns {"history": bool, "ips": [...], "new": [...]}. ``history`` is
    False when the user's row is younger than LEARN_DAYS before the window (or storage failed):
    a network can then look new only because the monitor did not see it yet. ``new``: the IPs
    whose network the user first used in the window.
    """
    start, end = _iso(when - before), _iso(when + WINDOW_AFTER)
    ips, new = [], []
    for first_t, last_t, ip in _ranges(row.get("recent")):
        if last_t < start or first_t > end or ip in ips:
            continue
        ips.append(ip)
        first = ((row.get("nets") or {}).get(network_of(ip)) or [""])[0]
        if first >= start:
            new.append(ip)
    return {"history": _history(row, when - before), "ips": ips, "new": new}
