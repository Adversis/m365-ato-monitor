"""Mail access records (MailItemsAccessed, Send): counts per day.

Mail that an attacker reads or sends with a stolen token leaves no inbox rule
and no forwarding. Exchange can log it in the unified audit log:

- MailItemsAccessed: a client read mail. MailAccessType "Sync" means that a
  client downloaded a folder (Outlook desktop); "Bind" means that a client
  opened messages (Outlook on the web, mobile, Graph, EWS). Exchange combines
  binds in 2-minute periods (OperationCount) and removes duplicates in
  1-hour periods.
- Send: a user sent a message.

Microsoft lists these records under Audit (Standard), but does not document
for every plan whether they are logged by default. This module counts the
records that the monitor receives. The status page, the console, and the
weekly report then show if the tenant logs mail access, how many records
arrive, and which fields the records have (client IP, session ID, app ID).

The mail access check (``check``, MAIL_ACCESS_CHECK) uses the same records.
A stolen session or refresh token, replayed from the attacker's network,
reads and sends mail from an IP that never signed in as the user: a token
refresh is not in the unified audit log. The check groups the records by user
and IP, skips IPs that signed in as the user in the last SIGNIN_DAYS days
(the sign-in check covers them), looks up the rest, and reports an IP that
is a VPN, proxy, hosting, or Tor address, or that is in a new country for
the user. One finding per user, IP, and day at each severity. A later high
finding still alerts after a medium finding was sent or muted.

Only clients that show the user's own IP count: Outlook on the web, Outlook
desktop (MAPI), Outlook mobile, Exchange ActiveSync, EWS, IMAP, and POP.
Graph (Client=REST) records carry a Microsoft IP and are skipped. Records
from a Microsoft 365 server IP (microsoft_nets.py) are also skipped: Outlook
mobile syncs through a Microsoft service, and Teams, Copilot, and other
Microsoft apps read mail from Microsoft's servers. Those records show the
server's IP instead of the client's.

Storage: table "processedevents", partition "system", one row per UTC day
of the records' CreationTime ("mailaccess-YYYY-MM-DD"), kept KEEP_DAYS days;
the row "mailaccess-seen" with the record IDs counted in the last SEEN_MINUTES
(each run fetches an 8-minute window every 2 minutes, so most records arrive
more than once); partition "signinip", one row per user and sign-in IP
(removed by the weekly cleanup after 7 days). No function raises.
"""

import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional

from azure.core.exceptions import ResourceNotFoundError
from azure.data.tables import UpdateMode

from ip_checker import extract_ip, network_fields
from microsoft_nets import is_service_ip

_PARTITION = "system"
_PREFIX = "mailaccess-"
KEEP_DAYS = 15
READ, SEND = "MailItemsAccessed", "Send"
FIELDS = ("reads", "sync", "bind", "messages", "sends", "with_ip", "with_session", "with_app", "throttled")
SIGNIN_DAYS = 7
_SIGNIN_PARTITION = "signinip"
# ClientInfoString prefixes of clients whose records carry the user's own IP.
REAL_IP_CLIENTS = ("client=owa", "client=msexchangerpc", "client=outlookservice", "client=activesync",
                   "client=webservices", "client=imap4", "client=pop3")
_GRAPH_API_ID = "00000003-0000-0000-c000-000000000000"
MAX_SUBJECTS = 3


def _properties(record: dict) -> dict:
    """OperationProperties as {name: value} (a list of {"Name", "Value"} in the record)."""
    out = {}
    for p in record.get("OperationProperties") or []:
        if isinstance(p, dict) and p.get("Name"):
            out[str(p["Name"])] = str(p.get("Value", ""))
    return out


def _has_session(record: dict) -> bool:
    ctx = record.get("AppAccessContext")
    return bool(record.get("SessionId") or (isinstance(ctx, dict) and ctx.get("AADSessionId")))


def count(records: list) -> dict:
    """Counts for the mail access records in ``records`` (any Exchange records)."""
    c = dict.fromkeys(FIELDS, 0)
    for r in records:
        if not isinstance(r, dict):
            continue
        op = r.get("Operation")
        if op not in (READ, SEND):
            continue
        if op == READ:
            props = _properties(r)
            c["reads"] += 1
            kind = props.get("MailAccessType", "").lower()
            if kind == "sync":
                c["sync"] += 1
            elif kind == "bind":
                c["bind"] += 1
            try:
                c["messages"] += max(1, int(r.get("OperationCount") or 1))
            except (TypeError, ValueError):
                c["messages"] += 1
            if props.get("IsThrottled", "").lower() == "true":
                c["throttled"] += 1
        else:
            c["sends"] += 1
        if r.get("ClientIPAddress") or r.get("ClientIP"):
            c["with_ip"] += 1
        if _has_session(r):
            c["with_session"] += 1
        if r.get("AppId") or r.get("ClientAppId"):
            c["with_app"] += 1
    return c


# Record IDs counted in the last SEEN_MINUTES: longer than the fetch window (LOOKBACK_MINUTES,
# at most 60) and the catch-up limit (DEDUP_WINDOW_MINUTES, at least 60).
_SEEN_ROW = "mailaccess-seen"
SEEN_MINUTES = 200
_HASH_CHARS = 12
_CHUNK = 2500        # IDs per property: 30,000 characters (a string property holds 32K characters)
_MAX_CHUNKS = 200    # an entity holds 252 properties and 1 MB


def _id_hash(record_id: str) -> str:
    return hashlib.sha256(record_id.encode("utf-8")).hexdigest()[:_HASH_CHARS]


def new_records(events_table, records: list, now: datetime) -> Optional[list]:
    """The mail access records in ``records`` that an earlier run did not count, by record ID.

    Writes their IDs to the "mailaccess-seen" row first. None if that row cannot be read or
    written: then nothing is counted, and the next run counts the records (they are still in
    its fetch window). A record without an ID is always new.
    """
    mail = [r for r in records if isinstance(r, dict) and r.get("Operation") in (READ, SEND)]
    if not mail:
        return []
    minute = int(now.timestamp() // 60)
    try:
        try:
            row = events_table.get_entity(partition_key=_PARTITION, row_key=_SEEN_ROW)
        except ResourceNotFoundError:
            row = {}
        chunks = {}
        for name, value in row.items():
            stamp = str(name)[1:].split("_")[0]
            if str(name).startswith("s") and stamp.isdigit() and int(stamp) > minute - SEEN_MINUTES:
                chunks[str(name)] = str(value or "")
        seen = {v[i:i + _HASH_CHARS] for v in chunks.values() for i in range(0, len(v), _HASH_CHARS)}
        new, hashes = [], []
        for r in mail:
            rid = str(r.get("Id") or "")
            h = _id_hash(rid) if rid else ""
            if h and h in seen:
                continue
            if h:
                seen.add(h)
                hashes.append(h)
            new.append(r)
        if not hashes and len(chunks) == len([k for k in row if str(k).startswith("s")]):
            return new
        for i in range(0, len(hashes), _CHUNK):
            chunks[f"s{minute}_{i // _CHUNK}"] = "".join(hashes[i:i + _CHUNK])
        for name in sorted(chunks, key=lambda n: (int(n[1:].split("_")[0]), n))[:-_MAX_CHUNKS or None]:
            del chunks[name]     # very busy tenant: the oldest IDs go first (some records can count twice)
        events_table.upsert_entity({"PartitionKey": _PARTITION, "RowKey": _SEEN_ROW, **chunks},
                                   mode=UpdateMode.REPLACE)
        return new
    except Exception as e:
        logging.warning(f"Mail access record IDs not read or written: {type(e).__name__}")
        return None


def record(events_table, records: list, now: Optional[datetime] = None) -> None:
    """Add the counts of the records not counted before to the row of each record's UTC day."""
    if events_table is None:
        return
    now = now or datetime.now(timezone.utc)
    fresh = new_records(events_table, records, now)
    if not fresh:
        return
    by_day = {}
    for r in fresh:
        when = str(r.get("CreationTime") or "")[:10]
        day = when if len(when) == 10 and when[4] == "-" and when[7] == "-" else f"{now:%Y-%m-%d}"
        by_day.setdefault(day, []).append(r)
    for day, recs in sorted(by_day.items()):
        c = count(recs)
        row = f"{_PREFIX}{day}"
        try:
            try:
                old = events_table.get_entity(partition_key=_PARTITION, row_key=row)
            except ResourceNotFoundError:
                old = {}
            entity = {"PartitionKey": _PARTITION, "RowKey": row,
                      "last_seen": max(str(old.get("last_seen") or ""), now.isoformat())}
            for k in FIELDS:
                entity[k] = int(old.get(k) or 0) + c[k]
            events_table.upsert_entity(entity)
            if not old:
                _purge(events_table, now)
        except Exception as e:
            logging.warning(f"Mail access counts not written: {type(e).__name__}")


def _purge(events_table, now: datetime) -> None:
    for d in range(KEEP_DAYS, KEEP_DAYS + 7):
        try:
            events_table.delete_entity(_PARTITION, f"{_PREFIX}{now - timedelta(days=d):%Y-%m-%d}")
        except Exception:
            pass


def summary(events_table, now: Optional[datetime] = None, days: int = 7) -> Optional[dict]:
    """Totals of the last ``days`` days: {"days", "totals", "per_day", "last_seen"}. None without storage."""
    if events_table is None:
        return None
    now = now or datetime.now(timezone.utc)
    totals = dict.fromkeys(FIELDS, 0)
    per_day, last_seen = [], None
    for d in range(days):
        day = (now - timedelta(days=d)).strftime("%Y-%m-%d")
        try:
            row = events_table.get_entity(partition_key=_PARTITION, row_key=f"{_PREFIX}{day}")
        except ResourceNotFoundError:
            continue
        except Exception as e:
            logging.warning(f"Mail access counts not read: {type(e).__name__}")
            return None
        counts = {k: int(row.get(k) or 0) for k in FIELDS}
        per_day.append({"date": day, **counts})
        for k in FIELDS:
            totals[k] += counts[k]
        seen = str(row.get("last_seen") or "")
        if seen and (last_seen is None or seen > last_seen):
            last_seen = seen
    return {"days": days, "totals": totals, "per_day": per_day, "last_seen": last_seen}


def describe(s: Optional[dict]) -> str:
    """One line for reports: what the tenant logs."""
    if not s:
        return "Mail access records: not known (no storage)."
    t = s["totals"]
    if not (t["reads"] or t["sends"]):
        return (f"No mail access records (MailItemsAccessed, Send) in {s['days']} days. The tenant does not log "
                "mail reads, or the licenses do not include them. Mail read with a stolen token is not visible.")
    parts = [f"{t['reads']:,} mail read records ({t['sync']:,} sync, {t['bind']:,} bind)",
             f"{t['sends']:,} send records"]
    text = f"Mail access records in {s['days']} days: " + ", ".join(parts) + "."
    n = t["reads"] + t["sends"]
    text += (f" With client IP: {100 * t['with_ip'] // n}%. With session ID: {100 * t['with_session'] // n}%. "
             f"With app ID: {100 * t['with_app'] // n}%.")
    if t["throttled"]:
        text += f" Throttled: {t['throttled']:,} (Exchange stopped logging some reads)."
    return text


# -----------------------------------------------------------------------------
# Mail access check: mail read or sent from an IP that never signed in
# -----------------------------------------------------------------------------

def _user(record: dict) -> str:
    return str(record.get("MailboxOwnerUPN") or record.get("UserId") or "").strip().lower()


def real_ip_client(record: dict) -> bool:
    """True if the record's client IP is the user's (not a Microsoft service calling for the user)."""
    info = str(record.get("ClientInfoString") or "").strip().lower()
    return info.startswith(REAL_IP_CLIENTS)


def service_ip_client(record: dict) -> bool:
    """A record whose IP belongs to a Microsoft service, not the client.

    Network ownership alone cannot establish this: Azure hosts customer VMs.
    Two cases count: a record (any workload) from a Microsoft 365 server IP
    (microsoft_nets.py: no Azure customer space), and an Exchange Graph REST
    record (the REST client marker and the Graph resource ID). Sign-in
    records always show the sign-in source and must not be excluded here.
    """
    operation = record.get("Operation")
    if operation in ("UserLoggedIn", "UserLoginFailed"):
        return False
    if is_service_ip(extract_ip(record)):
        return True
    if record.get("Workload") != "Exchange" and operation not in (READ, SEND):
        return False
    client = str(record.get("ClientInfoString") or "").split(";")[0].strip().lower()
    ctx = record.get("AppAccessContext")
    api_id = ctx.get("APIId") if isinstance(ctx, dict) else ""
    resources = {str(v or "").lower() for v in (record.get("AppId"), api_id)}
    return client == "client=rest" and _GRAPH_API_ID in resources


def observations(records: list) -> dict:
    """Mail access records grouped by (user, IP): counts, first and last time, sent subjects."""
    groups = {}
    for r in records:
        if (not isinstance(r, dict) or r.get("Operation") not in (READ, SEND) or not real_ip_client(r)
                or service_ip_client(r)):
            continue
        user, ip = _user(r), extract_ip(r)
        if "@" not in user or not ip:
            continue
        g = groups.setdefault((user, ip), {"user": user, "ip": ip, "reads": 0, "sync": 0, "sends": 0,
                                           "subjects": [], "first": "", "last": "", "clients": [], "record": r})
        if r["Operation"] == READ:
            g["reads"] += 1
            g["sync"] += _properties(r).get("MailAccessType", "").lower() == "sync"
        else:
            g["sends"] += 1
            item = r.get("Item") if isinstance(r.get("Item"), dict) else {}
            subject = str(item.get("Subject") or "").strip()
            if subject and subject not in g["subjects"] and len(g["subjects"]) < MAX_SUBJECTS:
                g["subjects"].append(subject[:120])
        t = str(r.get("CreationTime") or "")[:19]
        if t and (not g["first"] or t < g["first"]):
            g["first"], g["record"] = t, r
        if t > g["last"]:
            g["last"] = t
        client = str(r.get("ClientInfoString") or "").split(";")[0][:40]
        if client and client not in g["clients"]:
            g["clients"].append(client)
    return groups


def _signin_key(user: str, ip: str) -> str:
    return hashlib.sha256(f"{user}|{ip}".encode("utf-8")).hexdigest()[:40]


def remember_signins(events_table, login_records: list, now: Optional[datetime] = None) -> None:
    """Keep each (user, IP) of a successful sign-in, so the check skips IPs that signed in."""
    if events_table is None:
        return
    now = now or datetime.now(timezone.utc)
    pairs = set()
    for r in login_records:
        if isinstance(r, dict) and r.get("Operation") == "UserLoggedIn":
            user, ip = str(r.get("UserId") or "").strip().lower(), extract_ip(r)
            if "@" in user and ip:
                pairs.add((user, ip))
    for user, ip in pairs:
        try:
            # "processed_at": the weekly cleanup removes the row after EVENT_RETENTION_DAYS.
            events_table.upsert_entity({"PartitionKey": _SIGNIN_PARTITION, "RowKey": _signin_key(user, ip),
                                        "processed_at": now.isoformat()})
        except Exception as e:
            logging.warning(f"Sign-in IP not kept: {type(e).__name__}")
            return


def signed_in(events_table, user: str, ip: str, now: Optional[datetime] = None) -> bool:
    """True if ``ip`` signed in as ``user`` in the last SIGNIN_DAYS days."""
    if events_table is None:
        return False
    now = now or datetime.now(timezone.utc)
    try:
        row = events_table.get_entity(partition_key=_SIGNIN_PARTITION, row_key=_signin_key(user, ip))
        seen = datetime.fromisoformat(str(row.get("processed_at") or ""))
    except ResourceNotFoundError:
        return False
    except Exception:
        return False
    seen = seen if seen.tzinfo else seen.replace(tzinfo=timezone.utc)
    return now - seen <= timedelta(days=SIGNIN_DAYS)


def dedup_id(user: str, ip: str, day: str) -> str:
    """The finding's record ID: one finding per user, IP, and UTC day."""
    return "mailaccess-" + hashlib.sha256(f"{user}|{ip}|{day}".encode("utf-8")).hexdigest()[:32]


def check(records: list, lookup: Callable[[list], dict], analyze: Callable[[dict], dict], now: datetime, *,
          known: Callable[[str, str], bool] = lambda u, ip: False,
          unusual: Callable[[str, str], bool] = lambda u, cc: False,
          done: Callable[[str], bool] = lambda key: False,
          skip_ip: Callable[[str], bool] = lambda ip: False,
          country_of: Callable[[dict], str] = lambda data: str(data.get("isocode") or ""),
          cached: Callable[[list], dict] = lambda ips: {},
          max_lookups: int = 25) -> list:
    """Findings for mail read or sent from a risky IP that did not sign in as the user.

    ``lookup(ips)`` returns {ip: proxycheck data}; ``analyze`` is
    ip_checker.analyze_ip. ``known(user, ip)``: the IP signed in as the user.
    ``unusual(user, cc)``: the country is new for the user. ``done(key)``: the
    finding key was already handled. An IP without a lookup result is skipped
    (the next run tries again).

    ``cached(ips)`` returns the answers that need no query (the IP cache). They
    do not count toward ``max_lookups``. If more IPs need a query than
    ``max_lookups``, each run starts at another place in the list, so every IP
    gets a query in a few runs (a clean answer is then cached for some days).
    """
    candidates = []
    for (user, ip), g in observations(records).items():
        day = (g["first"] or now.strftime("%Y-%m-%dT%H:%M:%S"))[:10]
        g["id"] = dedup_id(user, ip, day)
        if skip_ip(ip) or done(f"mail_access_{g['id']}-high") or known(user, ip):
            continue
        candidates.append(g)
    if not candidates:
        return []
    ips = sorted({g["ip"] for g in candidates})
    results = dict(cached(ips) or {})
    uncached = [ip for ip in ips if ip not in results]
    budget = max(0, max_lookups)
    if len(uncached) > budget:
        # One step per 2-minute run: the IPs after the budget come first on a later run.
        start = int(now.timestamp() // 120) % len(uncached)
        logging.info(f"Mail access check: {len(uncached)} IPs to look up, {budget} in this run")
        uncached = (uncached[start:] + uncached[:start])[:budget]
    if uncached:
        results.update(lookup(uncached) or {})
    findings = []
    for g in candidates:
        data = results.get(g["ip"])
        if not data:
            continue
        analysis = analyze(data)
        cc = country_of(data)
        if analysis.get("is_suspicious"):
            why = (f"a {analysis.get('proxy_type') or 'suspicious'} IP ({analysis.get('org') or 'unknown network'}, "
                   f"risk {analysis.get('risk_score', 0)}/100{', ' + cc if cc else ''})")
        elif cc and unusual(g["user"], cc):
            why = f"an IP in {cc}, a new country for this user ({analysis.get('org') or 'unknown network'})"
        else:
            continue
        finding = _finding(g, why, analysis, cc)
        finding.update(network_fields(data))
        if finding["severity"] == "high":
            # The medium key may already be muted. Give an escalation its own
            # delivery key and journal row, then suppress further daily repeats.
            finding["event"]["Id"] += "-high"
        if not done(f"mail_access_{finding['event']['Id']}"):
            findings.append(finding)
    return findings


def _finding(g: dict, why: str, analysis: dict, cc: str) -> dict:
    parts = []
    if g["reads"]:
        parts.append(f"{g['reads']} mail read record{'s' if g['reads'] != 1 else ''}"
                     + (f" ({g['sync']} folder download{'s' if g['sync'] != 1 else ''})" if g["sync"] else ""))
    if g["sends"]:
        parts.append(f"{g['sends']} sent message{'s' if g['sends'] != 1 else ''}")
    text = (f"{' and '.join(parts).capitalize()} from {why}. This IP did not sign in as the user in the last "
            f"{SIGNIN_DAYS} days: the access can come from a stolen session or token. Clients: "
            f"{', '.join(g['clients']) or 'unknown'}.")
    if g["subjects"]:
        text += " Sent: " + "; ".join(f"'{x}'" for x in g["subjects"]) + "."
    high = analysis.get("confidence") == "high" or (bool(g["sends"] or g["sync"]) and analysis.get("is_suspicious"))
    first = g["record"]
    event = {"Id": g["id"], "CreationTime": g["first"] or first.get("CreationTime"), "Operation": first.get("Operation"),
             "UserId": g["user"], "ClientIP": g["ip"], "Workload": "Exchange",
             "ClientInfoString": first.get("ClientInfoString"), "SessionId": first.get("SessionId"),
             "SourceRecordId": first.get("Id")}
    return {"type": "mail_access", "severity": "high" if high else "medium", "user": g["user"],
            "description": text, "ip": g["ip"], "event": event,
            "ip_context": f"Source IP: {why}" + (f", country {cc}" if cc and cc not in why else "")}

