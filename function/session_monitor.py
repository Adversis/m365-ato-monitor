"""Session reuse: one Microsoft Entra session used from two countries, or
moved to a risky network in the same country.

A stolen session (an AiTM phishing cookie or an infostealer token) keeps the
session ID of the original sign-in. The unified audit log carries that ID:

- Sign-ins (UserLoggedIn): DeviceProperties[SessionId].
- Exchange records: SessionId; Exchange, SharePoint, and Teams records:
  AppAccessContext.AADSessionId. Real records show the same GUID in all three.

A replayed cookie writes new UserLoggedIn records with the attacker's IP. A
replayed refresh token is a non-interactive sign-in, which the unified audit
log does not include; only the workload records (for example mail access)
show it. This module tracks the countries of each session from both kinds
of record and reports:

- a session that appears in a new country;
- a session that started on a normal network and then appears, in the same
  country, in a workload record from a VPN, proxy, hosting, or Tor IP that
  did not sign in as the user. The suspicious sign-in check already reports
  a sign-in from such an IP; this finding covers a token used without a
  sign-in. One finding per session.

Not detected: records without a session ID (about half of workload records,
for example Outlook desktop and some API access), and an attacker on a
normal network in the same country (AiTM kits often use a residential proxy
in the victim's country). Exchange Graph REST records show a service IP and
are ignored when the record identifies that API and client. Records (not
sign-ins) from a Microsoft 365 server IP (microsoft_nets.py) are ignored
too. Other Microsoft-owned
networks also host customer VMs and are checked. Allowlisted IPs are ignored.

Microsoft's AiTM hunting guidance uses the same join (SessionId, different
country).
"""

import json
import logging
import re
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional

from azure.core.exceptions import ResourceNotFoundError

import config
import geo_monitor
from mail_access import SIGNIN_DAYS, service_ip_client
from ip_checker import extract_ip, is_allowed_ip, is_private_ip, network_fields

TABLE_NAME = "signinsessions"
PARTITION = "session"
# A finding waits here until its alert is sent, queued, muted, or off (mark_alerted). The session row
# keeps the new country or risky IP, so a later run cannot make the finding again: without this row,
# an alert that fails to go out would be lost.
PENDING_PARTITION = "pending"
PENDING_DAYS = 7
PENDING_MAX = 50
_PENDING_FIELDS = ("type", "severity", "user", "description", "ip", "session_id", "country", "mark", "ip_context",
                   "asn", "network", "session_context")
_EVENT_FIELDS = ("Id", "CreationTime", "Operation", "UserId", "ClientIP", "ClientIPAddress", "Workload",
                 "RecordType", "ResultStatus", "UserAgent", "ApplicationId", "MailboxOwnerUPN", "SessionId",
                 "ClientInfoString", "AppId", "ClientAppId", "AppAccessContext")
RETENTION_DAYS = 30
MAX_IPS = 25
NETWORK_MARK = "risky-network"  # in "alerted": the session already had a same-country risky-IP finding
_GUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

_cache = config.CachedTable(TABLE_NAME, "Session table")


def table_client():
    """Return the session table client, or None if storage is not available."""
    return _cache.get()


def session_id(record: dict) -> str:
    """The Entra session ID of a record, lowercase, or ""."""
    candidates = []
    for prop in record.get("DeviceProperties") or []:
        if isinstance(prop, dict) and prop.get("Name") == "SessionId":
            candidates.append(prop.get("Value"))
    candidates.append(record.get("SessionId"))
    ctx = record.get("AppAccessContext")
    if isinstance(ctx, dict):
        candidates.append(ctx.get("AADSessionId"))
    for value in candidates:
        text = str(value or "").strip()
        if _GUID_RE.match(text):
            return text.lower()
    return ""


def _user(record: dict) -> str:
    for value in (record.get("UserId"), record.get("MailboxOwnerUPN")):
        if "@" in str(value or ""):
            return str(value).strip().lower()
    return ""


def _time(record: dict) -> str:
    return str(record.get("CreationTime") or "")


def observations(records: list) -> list:
    """(session ID, user, IP, record) for records that show a session in use.

    Sign-ins count only when successful. Private and allowlisted IPs are skipped.
    """
    out = []
    for record in records:
        if (not isinstance(record, dict) or record.get("Operation") == "UserLoginFailed"
                or service_ip_client(record)):
            continue
        sid = session_id(record)
        user = _user(record)
        ip = extract_ip(record)
        if not sid or not user or not ip or is_private_ip(ip) or is_allowed_ip(ip):
            continue
        out.append((sid, user, ip, record))
    out.sort(key=lambda o: _time(o[3]))
    return out


def _load(table, sid: str) -> dict:
    try:
        entity = table.get_entity(PARTITION, sid)
    except ResourceNotFoundError:
        return {}
    ips = json.loads(entity.get("ips") or "{}")
    if int(entity.get("ip_schema") or 1) < 2:
        # Version 1 used "MS" as a network exemption. Version 2 stores only
        # country codes (including MS, the ISO code for Montserrat).
        ips = {ip: cc for ip, cc in ips.items() if cc != "MS"}
    return {
        "user": entity.get("user", ""),
        "ips": ips,
        "ip_times": json.loads(entity.get("ip_times") or "{}"),
        "countries": json.loads(entity.get("countries") or "{}"),
        "alerted": json.loads(entity.get("alerted") or "[]"),
        "risky": json.loads(entity.get("risky") or "[]"),
        "first_seen": entity.get("first_seen", ""),
    }


def _save(table, sid: str, row: dict, now: datetime) -> None:
    ips = row["ips"]
    if len(ips) > MAX_IPS:
        ips = dict(list(ips.items())[-MAX_IPS:])
    risky = [ip for ip in row.get("risky", []) if ip in ips]
    table.upsert_entity({
        "PartitionKey": PARTITION, "RowKey": sid, "user": row["user"],
        "ip_schema": 2,
        "ips": json.dumps(ips), "countries": json.dumps(row["countries"]),
        "ip_times": json.dumps({ip: t for ip, t in row.get("ip_times", {}).items() if ip in ips}),
        "alerted": json.dumps(row["alerted"]), "risky": json.dumps(risky),
        "first_seen": row.get("first_seen") or now.isoformat(),
        "last_seen": now.isoformat(),
    })


def _usual(geo_table, user: str, cc: str, now: datetime) -> bool:
    """True if ``cc`` is a home country or a learned country of the user."""
    if cc in config.HOME_COUNTRIES:
        return True
    try:
        rows = geo_monitor.user_countries(geo_table, user, now)
    except Exception:
        return False
    return any(r["country"] == cc and r["status"] == "usual" for r in rows)


def check(table, records: list, lookup: Callable[[list], dict], now: datetime, geo_table=None, *,
          analyze: Optional[Callable[[dict], dict]] = None,
          known: Callable[[str, str], bool] = lambda user, ip: False,
          skip: Callable[[dict], bool] = lambda record: False) -> list:
    """Track session countries. Return one finding for each session seen in a new country,
    and one for each session that moves to a risky network in the same country.

    ``lookup`` takes a list of IPs and returns {ip: proxycheck.io data}.
    ``analyze`` classifies that data (ip_checker.analyze_ip); without it, the
    same-country check is off. ``known(user, ip)`` is True if the IP signed in
    as the user. ``skip(record)`` is True for records that another check reports
    (mail reads and sends). The caller sends the alert and then calls
    ``mark_alerted`` with the finding's ``mark``.
    """
    obs = observations(records)
    if not obs:
        return []
    rows = {sid: _load(table, sid) for sid in {o[0] for o in obs}}
    to_lookup = sorted({ip for sid, _, ip, _ in obs if ip not in rows[sid].get("ips", {})})
    results = lookup(to_lookup) if to_lookup else {}

    findings = []
    changed = set()
    moved_sessions = set()
    for sid, user, ip, record in obs:
        row = rows[sid]
        if not row.get("user"):
            row["user"] = user
        row.setdefault("ips", {})
        row.setdefault("ip_times", {})
        row.setdefault("countries", {})
        row.setdefault("alerted", [])
        row.setdefault("risky", [])
        when = _time(record) or now.isoformat()

        cc = row["ips"].get(ip)
        moved = None  # (normal IP seen before, analysis) when the session moves to a risky IP
        if cc is None:
            data = results.get(ip)
            if not data:
                continue  # lookup failed; the record comes back in the next window
            cc = geo_monitor.country_of(data)
            if not cc:
                continue
            normal = _normal_ip(row)
            row["ips"][ip] = cc
            changed.add(sid)
            analysis = analyze(data) if analyze else {}
            if analysis.get("is_suspicious"):
                row["risky"].append(ip)
                if normal:
                    moved = (normal, analysis)
        # Presentation only: keep the actual event time for each IP. Older rows have no
        # per-IP time; do not substitute the processing time or another IP's country time.
        observed = _utc_time(_time(record))
        previous_time = _utc_time(row["ip_times"].get(ip, ""))
        if observed and (not previous_time or observed > previous_time):
            row["ip_times"][ip] = observed.isoformat()
            changed.add(sid)
        countries = row["countries"]
        if cc in countries:
            if when > countries[cc]["last"]:
                countries[cc]["last"] = when
                changed.add(sid)
            if (moved and NETWORK_MARK not in row["alerted"] and sid not in moved_sessions
                    and record.get("Operation") != "UserLoggedIn" and not skip(record)
                    and not known(row["user"] or user, ip)):
                moved_sessions.add(sid)
                findings.append(_network_finding(sid, row["user"] or user, ip, cc, moved[0], moved[1],
                                                 results.get(ip) or {}, record, row["ip_times"]))
            continue
        others = sorted(countries.items(), key=lambda kv: kv[1]["last"])
        countries[cc] = {"first": when, "last": when, "ip": ip}
        changed.add(sid)
        if not others or cc in row["alerted"]:
            continue

        prev_cc, prev = others[-1]
        data = results.get(ip) or {}
        usual = _usual(geo_table, row["user"] or user, cc, now)
        gap = _minutes_between(row["ip_times"].get(prev["ip"], ""), _time(record))
        gap_text = f" {gap} minutes later" if gap is not None and gap >= 0 else ""
        org = _network_text(data)
        findings.append({
            "type": "session_reuse",
            "severity": "medium" if usual else "high",
            "user": row["user"] or user,
            "description": (
                f"Session {sid[:8]} was used from {prev_cc} (IP {prev['ip']}) and then from {cc} "
                f"(IP {ip}, {org}){gap_text}. A network change, a service acting for the user, or a stolen "
                f"session cookie or token can cause this. "
                f"Operation: {record.get('Operation', 'unknown')}."
            ),
            "ip": ip,
            "event": record,
            "session_id": sid,
            "country": cc,
            "mark": cc,
            "ip_context": "This country is usual for the user" if usual else "",
            "session_context": _session_context(prev["ip"], ip, row["ip_times"], record),
            **network_fields(data),
        })

    # First the pending findings, then the session state. If a pending write fails, the error stops
    # the run: the checkpoint does not move, and the next run makes the finding again.
    for finding in findings:
        save_pending(table, finding, now)
    for sid in changed:
        try:
            _save(table, sid, rows[sid], now)
        except Exception as e:
            logging.warning(f"Session table write failed: {type(e).__name__}")
    return findings


def pending_key(finding: dict) -> str:
    return f"{finding['session_id']}|{finding.get('mark') or finding['country']}"


def save_pending(table, finding: dict, now: datetime) -> None:
    """Keep ``finding`` until mark_alerted. Raises if Table Storage refuses."""
    event = finding.get("event") or {}
    event_json = json.dumps(event, default=str)
    if len(event_json) > 30000:     # a Table Storage string holds at most 32K characters
        event_json = json.dumps({k: event[k] for k in _EVENT_FIELDS if k in event}, default=str)
    table.upsert_entity({
        "PartitionKey": PENDING_PARTITION, "RowKey": pending_key(finding),
        "finding": json.dumps({k: finding[k] for k in _PENDING_FIELDS if k in finding}, default=str),
        "event": event_json, "created": now.isoformat(),
    })


def pending_findings(table, now: datetime, exclude=()) -> list:
    """Findings whose alert did not go out on an earlier run (oldest first). Drops them after PENDING_DAYS."""
    try:
        rows = sorted(table.query_entities(f"PartitionKey eq '{PENDING_PARTITION}'"),
                      key=lambda r: str(r.get("created") or ""))
    except Exception as e:
        logging.warning(f"Pending session alerts not read: {type(e).__name__}")
        return []
    out = []
    for row in rows:
        if row["RowKey"] in exclude:
            continue
        try:
            created = datetime.fromisoformat(str(row.get("created")))
            finding = json.loads(row["finding"])
            finding["event"] = json.loads(row.get("event") or "{}")
        except (ValueError, KeyError, TypeError):
            _delete_pending(table, row["RowKey"])
            continue
        if now - created > timedelta(days=PENDING_DAYS):
            logging.error(f"Session alert not sent for {PENDING_DAYS} days, dropped: user={finding.get('user')}, "
                          f"session={str(finding.get('session_id'))[:8]}, mark={finding.get('mark')}")
            _delete_pending(table, row["RowKey"])
            continue
        out.append(finding)
        if len(out) >= PENDING_MAX:
            break
    return out


def _delete_pending(table, key: str) -> None:
    try:
        table.delete_entity(PENDING_PARTITION, key)
    except Exception as e:
        logging.warning(f"Pending session alert not deleted: {type(e).__name__}")


def _normal_ip(row: dict) -> str:
    """The latest IP of the session that is not risky, or ""."""
    for ip in reversed(row["ips"]):
        if ip not in row["risky"]:
            return ip
    return ""


def _network_finding(sid: str, user: str, ip: str, cc: str, normal: str, analysis: dict, data: dict,
                     record: dict, ip_times: dict) -> dict:
    """A session that started on a normal network and moved to a risky IP in the same country."""
    kind = analysis.get("proxy_type") or ", ".join(analysis.get("flags") or []) or "suspicious"
    org = _network_text(data)
    return {
        "type": "session_reuse",
        "severity": "high" if analysis.get("confidence") == "high" else "medium",
        "user": user,
        "description": (
            f"Session {sid[:8]} appeared from IP {normal} and then from {ip} in the same country ({cc}). "
            f"proxycheck.io classifies the later IP as {kind} ({org}). "
            f"A network change, a service acting for the user, or a stolen token can cause this. "
            f"Operation: {record.get('Operation', 'unknown')}."
        ),
        "ip": ip,
        "event": record,
        "session_id": sid,
        "country": cc,
        "mark": NETWORK_MARK,
        "ip_context": f"No matching sign-in from this exact IP was found in the monitor's {SIGNIN_DAYS}-day "
                      "history. This does not prove that no sign-in occurred",
        "session_context": _session_context(normal, ip, ip_times, record),
        **network_fields(data),
    }


def _network_text(data: dict) -> str:
    """Keep the provider as well as the organisation (which can be an old allocation name)."""
    parts = list(dict.fromkeys(str(data[k])[:100] for k in ("provider", "organisation", "asn")
                               if data.get(k) and data[k] != "Unknown")) or ["unknown network"]
    risk = data.get("risk")
    if risk not in (None, ""):
        parts.append(f"score {risk}/100")
    place = ", ".join(str(data[k])[:100] for k in ("city", "region") if data.get(k) and data[k] != "Unknown")
    if place:
        parts.append(f"estimated location: {place}")
    return ", ".join(parts)


def _utc_time(value: str) -> Optional[datetime]:
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).astimezone(timezone.utc)
    except ValueError:
        return None


def _session_context(previous_ip: str, ip: str, ip_times: dict, record: dict) -> list:
    """Bounded, plain-text facts shared by email and webhook; no extra API calls."""
    facts = []
    for label, address, value in (("Previous observation", previous_ip, ip_times.get(previous_ip, "")),
                                  ("Current observation", ip, _time(record))):
        dt = _utc_time(value)
        stamp = dt.strftime("%Y-%m-%d %H:%M:%S UTC") if dt else "time unavailable"
        facts.append((label, f"{address} at {stamp}"))
    gap = _minutes_between(ip_times.get(previous_ip, ""), _time(record))
    if gap is not None and gap >= 0:
        facts.append(("Elapsed", f"{gap} minutes"))
    ctx = record.get("AppAccessContext")
    ctx = ctx if isinstance(ctx, dict) else {}
    for label, value in (("Client / protocol", record.get("ClientInfoString")),
                         ("User agent", record.get("UserAgent")),
                         ("App ID", record.get("AppId") or record.get("ApplicationId")),
                         ("Client app ID", record.get("ClientAppId") or ctx.get("ClientAppId")),
                         ("API ID", ctx.get("APIId"))):
        if value:
            facts.append((label, str(value)[:160]))
    return facts


def mark_alerted(table, sid: str, cc: str, now: datetime) -> None:
    """Record that an alert went out for ``cc`` (a country, or NETWORK_MARK) in this session.

    Also deletes the pending finding.
    """
    row = _load(table, sid)
    if row and cc not in row["alerted"]:
        row["alerted"].append(cc)
        _save(table, sid, row, now)
    _delete_pending(table, f"{sid}|{cc}")


def _minutes_between(a: str, b: str) -> Optional[int]:
    try:
        ta = datetime.fromisoformat(str(a).replace("Z", "+00:00"))
        tb = datetime.fromisoformat(str(b).replace("Z", "+00:00"))
    except ValueError:
        return None
    if ta.tzinfo is None:
        ta = ta.replace(tzinfo=timezone.utc)
    if tb.tzinfo is None:
        tb = tb.replace(tzinfo=timezone.utc)
    return int((tb - ta) / timedelta(minutes=1))

