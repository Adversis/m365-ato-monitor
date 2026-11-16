"""M365 ATO Monitor: Azure Function triggers and pipeline.

Emails:
  - Setup confirmation: one time, after the first successful audit fetch.
  - Compromise indicator: one email per finding.
  - Suspicious login: one email per login, or one digest (LOGIN_ALERT_MODE).
  - Roll-up: 1st of each month, 08:00 UTC, for the last 30 days.
"""

import hashlib
import json
import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

import azure.functions as func
from azure.core.exceptions import ResourceNotFoundError
from azure.data.tables import TableServiceClient

import admin_api
import admin_store
import config
import geo_monitor
import journal
import mail_access
import responder
# Fixed at deployment (environment). Tunable settings are read as config.X at
# call time, because the management UI can change them between runs.
from config import (
    TENANT_ID, EVENT_RETENTION_DAYS, RUN_DURATION_WARN_SECONDS, should_email_login,
)
from o365_client import (
    AAD_CONTENT_TYPE, EXCHANGE_CONTENT_TYPE, CONTENT_TYPES,
    ensure_subscriptions, fetch_content_records, filter_login_records, login_result, resolve_user_upn,
)
from ip_checker import (
    extract_ip, is_private_ip, is_allowed_ip,
    get_event_key, get_processed_keys, mark_event_processed,
    check_ips_batch, analyze_ip, network_fields,
    queue_login_for_digest, read_login_digest, delete_login_digest,
    queue_pending_ip, read_pending_ips, delete_pending_ip,
)
from alerting import (
    send_summary_email, send_compromise_alert, send_setup_confirmation,
    send_suspicious_login_alert, send_login_digest,
    send_country_anomaly_alert, send_weekly_report, flush_outbox,
)
from compromise_detector import (
    install_grant,
    detect_suspicious_inbox_rules,
    detect_mailbox_forwarding,
    detect_suspicious_oauth_consents,
    detect_suspicious_user_agents,
    detect_sign_in_methods,
    detect_mail_flow_rules,
    detect_mailbox_delegation,
    detect_audit_disabled,
    detect_mail_protection_weakened,
    detect_mfa_changes,
    detect_admin_roles,
    detect_app_credentials,
    detect_domain_federation,
)
from insights_client import get_monthly_login_stats, get_stats
import onboarding
import selftest
import private_relay
import proxycheck_quota
import session_monitor
from service_actors import is_microsoft_service

app = func.FunctionApp()

_SYSTEM_PARTITION = "system"
_TS_FMT = "%Y-%m-%dT%H:%M:%SZ"


def _get_table_clients():
    """Return (events_table, ip_cache_table). Both are None if storage is not available."""
    if not config.storage_configured():
        logging.warning(
            "Table Storage is not configured (STORAGE_ACCOUNT_NAME). No event dedup, IP cache, or "
            "checkpoint. Expect duplicate alerts."
        )
        return None, None

    try:
        svc = config.table_service()
        return (
            svc.create_table_if_not_exists("processedevents"),
            svc.create_table_if_not_exists("ipcache"),
        )
    except Exception as e:
        logging.warning(f"Could not connect to table storage: {type(e).__name__}: {e}")
        return None, None


def _check_setup_confirmation(events_table):
    """Send the one-time setup email. Mark it sent only after Graph accepts it."""
    if not events_table:
        return
    try:
        events_table.get_entity(partition_key=_SYSTEM_PARTITION, row_key="setup_confirmed")
        return
    except ResourceNotFoundError:
        pass
    except Exception as e:
        # State is unknown. Do not risk a duplicate email; try on the next run.
        logging.warning(f"Setup confirmation check failed: {type(e).__name__}")
        return

    if not send_setup_confirmation():
        return  # try again on the next run
    try:
        events_table.upsert_entity({
            "PartitionKey": _SYSTEM_PARTITION,
            "RowKey": "setup_confirmed",
            "confirmed_at": datetime.now(timezone.utc).isoformat(),
        })
    except Exception as e:
        logging.warning(f"Could not record setup confirmation: {type(e).__name__}")


# -----------------------------------------------------------------------------
# Fetch checkpoint (one per content type)
# -----------------------------------------------------------------------------
# The Management API selects content blobs by the time each blob became
# available. Each run normally fetches the last LOOKBACK_MINUTES. After a
# complete fetch, the run stores the window end as the checkpoint. If the
# monitor did not run, or a fetch failed, the next window starts at the
# checkpoint, but not more than MAX_CATCHUP_MINUTES back. An older checkpoint
# is a coverage gap: the run logs an error.

def _checkpoint_row(content_type: str) -> str:
    return f"checkpoint-{content_type}"


def _read_checkpoint(events_table, content_type: str) -> Optional[datetime]:
    if not events_table:
        return None
    try:
        entity = events_table.get_entity(partition_key=_SYSTEM_PARTITION,
                                          row_key=_checkpoint_row(content_type))
        dt = datetime.fromisoformat(str(entity.get("end", "")))
    except ResourceNotFoundError:
        return None
    except Exception as e:
        logging.warning(f"Could not read {content_type} checkpoint: {type(e).__name__}")
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _write_checkpoint(events_table, content_type: str, end: datetime) -> None:
    if not events_table:
        return
    try:
        events_table.upsert_entity({
            "PartitionKey": _SYSTEM_PARTITION,
            "RowKey": _checkpoint_row(content_type),
            "end": end.isoformat(),
        })
    except Exception as e:
        logging.warning(f"Could not write {content_type} checkpoint: {type(e).__name__}")


def _fetch_window(events_table, content_type: str, now: datetime) -> tuple:
    """Return (start, end) for this run's fetch of ``content_type``."""
    start = now - timedelta(minutes=config.LOOKBACK_MINUTES)
    checkpoint = _read_checkpoint(events_table, content_type)
    if checkpoint is None:
        # Keep the first attempted window too, if processing or delivery fails.
        _write_checkpoint(events_table, content_type, start)
        return start, now
    if checkpoint >= start:
        return start, now

    floor = now - timedelta(minutes=config.MAX_CATCHUP_MINUTES)
    if checkpoint < floor:
        logging.error(
            f"Coverage gap: {content_type} content from {checkpoint:{_TS_FMT}} to "
            f"{floor:{_TS_FMT}} is not fully processed. The monitor did not run, or "
            f"the fetch failed, for more than {config.MAX_CATCHUP_MINUTES} minutes."
        )
        # Report each gap one time: move the checkpoint to the catch-up limit.
        _write_checkpoint(events_table, content_type, floor)
        return floor, now

    logging.warning(f"Catch-up: {content_type} from checkpoint {checkpoint:{_TS_FMT}}")
    return checkpoint, now


# -----------------------------------------------------------------------------
# Content-flow watchdog
# -----------------------------------------------------------------------------

def _read_time(events_table, row_key: str) -> Optional[datetime]:
    try:
        entity = events_table.get_entity(partition_key=_SYSTEM_PARTITION, row_key=row_key)
        dt = datetime.fromisoformat(str(entity.get("at", "")))
    except ResourceNotFoundError:
        return None
    except Exception:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _write_time(events_table, row_key: str, when: datetime) -> None:
    try:
        events_table.upsert_entity({"PartitionKey": _SYSTEM_PARTITION, "RowKey": row_key,
                                    "at": when.isoformat()})
    except Exception as e:
        logging.warning(f"Could not write {row_key}: {type(e).__name__}")


def _check_content_flow(events_table, records: dict, now: datetime) -> None:
    """Log an error if no audit content arrived for NO_CONTENT_ALERT_HOURS.

    The usual cause is that unified audit logging is off. The runs still
    complete, so the no-runs alert does not fire. The errors alert does.
    """
    if not events_table or config.NO_CONTENT_ALERT_HOURS <= 0:
        return
    seen_now = False
    for content_type, recs in records.items():
        if recs:
            _write_time(events_table, f"content-{content_type}", now)
            seen_now = True
    if seen_now:
        return

    seen = [t for t in (_read_time(events_table, f"content-{ct}") for ct in CONTENT_TYPES) if t]
    reference = max(seen) if seen else _read_time(events_table, "first_run")
    if reference is None:
        _write_time(events_table, "first_run", now)
        return
    hours = (now - reference).total_seconds() / 3600
    if hours > config.NO_CONTENT_ALERT_HOURS:
        since = "since the first run" if not seen else "since the last content"
        logging.error(
            f"No audit content for {hours:.0f} hours ({since}, {reference:{_TS_FMT}}). "
            "Check that unified audit logging is on: Get-AdminAuditLogConfig | "
            "Format-List UnifiedAuditLogIngestionEnabled"
        )


# -----------------------------------------------------------------------------
# Main monitor (every 2 minutes)
# -----------------------------------------------------------------------------

@app.timer_trigger(schedule="0 */2 * * * *", arg_name="timer", run_on_startup=False)
def audit_log_monitor(timer: func.TimerRequest) -> None:
    """Fetch audit content, check sign-in IPs, and detect compromise indicators."""
    if not (config.has_credential() and config.ADMIN_EMAIL):
        logging.error("Missing required environment variables")
        return

    started = datetime.now(timezone.utc)
    admin_store.refresh()  # settings changed in the management UI

    events_table, ip_cache_table = _get_table_clients()
    processed_keys = (
        get_processed_keys(events_table, since_minutes=config.DEDUP_WINDOW_MINUTES)
        if events_table else set()
    )
    ensure_subscriptions()  # at most every 6 hours; starts a missing subscription

    # Fetch each content type on its own. A failure of one type (for example,
    # no Audit.Exchange subscription) does not stop the other.
    records = {}
    complete_until = {}
    window_starts = []
    for content_type in CONTENT_TYPES:
        start, end = _fetch_window(events_table, content_type, started)
        window_starts.append(start)
        try:
            recs, complete = fetch_content_records(content_type, start, end)
        except Exception as e:
            logging.error(f"Error fetching {content_type} audit content: {config.redact(e)}")
            if "AF20022" in str(e) or "AF20023" in str(e):
                ensure_subscriptions(force=True)
            continue
        records[content_type] = recs
        if complete:
            complete_until[content_type] = end

    if not records:
        return

    _check_setup_confirmation(events_table)
    onboarding.ensure_started(events_table, min(window_starts), started)
    _check_content_flow(events_table, records, started)
    flush_outbox(events_table)

    aad = records.get(AAD_CONTENT_TYPE, [])
    exchange = records.get(EXCHANGE_CONTENT_TYPE, [])
    mail_access.record(events_table, exchange, started)

    failed = False
    try:
        resolve_signin_users(aad)
    except Exception:
        logging.exception("Sign-in users not resolved")
    try:
        _run_login_check(events_table, ip_cache_table, processed_keys, filter_login_records(aad))
    except Exception:
        failed = True
        logging.exception("Login check failed")
    try:
        _run_compromise_check(events_table, ip_cache_table, processed_keys, aad + exchange)
    except Exception:
        failed = True
        logging.exception("Compromise check failed")
    try:
        # Before the session and mail access checks: both skip an IP that signed in as the user.
        mail_access.remember_signins(events_table, aad, started)
    except Exception:
        logging.exception("Sign-in IPs not kept")
    try:
        _run_session_check(events_table, ip_cache_table, processed_keys, aad + exchange, started)
    except Exception:
        failed = True
        logging.exception("Session check failed")
    try:
        _run_mail_access_check(events_table, ip_cache_table, processed_keys, exchange, started)
    except Exception:
        failed = True
        logging.exception("Mail access check failed")
    _maybe_flush_login_digest(events_table)
    try:
        proxycheck_quota.check(ip_cache_table, started)
    except Exception:
        logging.exception("proxycheck.io quota check failed")

    # Move the checkpoint only when processing finished. Else the next run
    # fetches the same window again; dedup prevents duplicate alerts.
    if not failed:
        for content_type, end in complete_until.items():
            _write_checkpoint(events_table, content_type, end)

    elapsed = (datetime.now(timezone.utc) - started).total_seconds()
    logging.info(f"audit_log_monitor run completed in {elapsed:.1f}s")
    if elapsed > RUN_DURATION_WARN_SECONDS:
        logging.warning(
            f"Run duration {elapsed:.1f}s is near the 2-minute interval. "
            "The timer does not start a run while the previous run continues."
        )


def _actor_ids(record: dict) -> list:
    return [str(a.get("ID") or "").strip() for a in record.get("Actor") or [] if isinstance(a, dict)]


def resolve_signin_users(records: list, max_lookups: int = 20, budget_seconds: float = 10.0) -> int:
    """Fill in the user of sign-in records whose UserId is not a UPN (for example "Not Available").

    One interactive sign-in writes several records, seconds apart. Some carry
    "Not Available" as UserId. In order, the user comes from: another record
    of the same session (DeviceProperties SessionId) in this batch, a UPN in
    Actor, or a user object ID in Actor (Graph). The record keeps the original
    value in UserIdInRecord. Returns the number of records changed. The Graph
    lookups stop after ``max_lookups`` or ``budget_seconds``: a slow Graph must
    not use the run time that detection needs.
    """
    deadline = time.monotonic() + budget_seconds
    logins = [r for r in records if isinstance(r, dict) and r.get("Operation") in ("UserLoggedIn", "UserLoginFailed")]
    by_session = {}
    for r in logins:
        sid = session_monitor.session_id(r)
        if sid and "@" in str(r.get("UserId") or ""):
            by_session[sid] = str(r["UserId"])
    changed, lookups = 0, 0
    for r in logins:
        original = str(r.get("UserId") or "")
        if "@" in original:
            continue
        upn = by_session.get(session_monitor.session_id(r) or "-")
        if not upn:
            upn = next((a for a in _actor_ids(r) if "@" in a), "")
        if not upn:
            for oid in _actor_ids(r):
                if lookups >= max_lookups or time.monotonic() > deadline:
                    break
                if oid.lower() in (str(r.get("ApplicationId") or "").lower(), str(r.get("ObjectId") or "").lower()):
                    continue  # an app, not the user
                if len(oid) == 36 and oid.count("-") == 4:
                    lookups += 1
                    upn = resolve_user_upn(oid) or ""
                    if upn:
                        break
        if upn:
            r["UserIdInRecord"] = original
            r["UserId"] = upn
            changed += 1
    if changed:
        logging.info(f"Sign-in users resolved: {changed} record(s) without a UPN")
    return changed


def _run_login_check(events_table, ip_cache_table, processed_keys: set, login_events: list) -> None:
    """Check sign-in IPs. Log and alert each suspicious sign-in.

    Mark a suspicious sign-in processed only after its email is sent or queued
    (outbox or digest). A sign-in whose IP lookup fails goes to the pending-IP
    queue and is checked again on later runs, for up to PENDING_IP_MAX_HOURS.
    """
    logging.info("Login IP check triggered")

    queued = read_pending_ips(events_table, config.PENDING_IP_MAX_ROWS) if events_table else []
    if not login_events and not queued:
        logging.info("No login events found in the specified time range")
        _handle_country_anomalies(events_table, [])
        return

    # (event, event_key, ip, queued_at). queued_at is None for a new sign-in.
    pending = [(row["event"], row["key"], row["ip"], row["queued_at"]) for row in queued if row["ip"]]
    queued_keys = {row["key"] for row in queued}
    ips_to_check = {row["ip"] for row in queued if row["ip"]}

    for event in login_events:
        event_key = get_event_key(event)
        if event_key in processed_keys or event_key in queued_keys:
            continue

        ip = extract_ip(event)
        if not ip or is_private_ip(ip) or is_allowed_ip(ip):
            if events_table:
                mark_event_processed(event_key, events_table)
            continue

        pending.append((event, event_key, ip, None))
        ips_to_check.add(ip)

    if not pending:
        logging.info(f"Processed {len(login_events)} login events, 0 required IP checks")
        _handle_country_anomalies(events_table, [])
        return

    ip_results = check_ips_batch(sorted(ips_to_check), ip_cache_table)

    suspicious_count = 0
    skipped_count = 0
    alerted = {}         # suspicious sign-in alerts of this run (user, IP, outcome, day) -> journal row
    observations = []  # country baseline input: sign-ins from IPs that are not flagged
    clean_events = []
    failed = False

    for event, event_key, ip, queued_at in pending:
        ip_data = ip_results.get(ip)
        if not ip_data:
            skipped_count += 1
            if not _defer_ip_check(events_table, event, event_key, ip, queued_at):
                failed = True
            continue

        analysis = analyze_ip(ip_data)
        if not analysis["is_suspicious"]:
            observations.append({
                "user": event.get("UserId", ""), "country": geo_monitor.country_of(ip_data),
                "outcome": geo_monitor.sign_in_outcome(event), "ip": ip,
                "event": event, "analysis": analysis,
            })
            clean_events.append((event_key, queued_at))
            continue  # acknowledge only after the country baseline and pending alerts are saved

        suspicious_count += 1
        logging.warning(
            f"Suspicious login: User={event.get('UserId')}, "
            f"IP={ip}, Flags={','.join(analysis['flags'])}, Confidence={analysis['confidence']}, "
            f"Result={login_result(event)}, "
            f"Org={analysis['org']}, Location={analysis['city']},{analysis['country']}"
        )
        done = _alert_signin(events_table, event, event_key, ip, analysis, alerted)
        if not done:
            failed = True

        if done and events_table:
            mark_event_processed(event_key, events_table)
            if queued_at is not None:
                delete_pending_ip(events_table, event_key)

    logging.info(
        f"Login check: {len(login_events)} events, "
        f"{len(ips_to_check)} IPs checked, "
        f"{suspicious_count} suspicious, "
        f"{skipped_count} skipped"
    )
    if queued:
        logging.info(f"Pending IP checks: {len(queued)} read from the queue")

    _handle_country_anomalies(events_table, observations)
    for event_key, queued_at in clean_events:
        if events_table:
            mark_event_processed(event_key, events_table)
            if queued_at is not None:
                delete_pending_ip(events_table, event_key)
    if failed:
        raise RuntimeError("Sign-in checks remain neither delivered nor queued")


def _signin_finding(event: dict, ip: str, analysis: dict) -> dict:
    """A suspicious sign-in in the shape of a finding (journal, mutes)."""
    location = ", ".join(str(p) for p in (analysis.get("city"), analysis.get("country"))
                         if p and p != "Unknown")
    return {
        "type": "suspicious_signin",
        "severity": "high" if analysis.get("confidence") == "high" else "medium",
        "user": str(event.get("UserId", "")),
        "description": (f"Sign-in ({login_result(event)}) from {ip}: {', '.join(analysis.get('flags', []))}, "
                        f"{analysis.get('org', '')}" + (f", {location}" if location else "")),
        "ip": ip, "event": event,
        **network_fields(analysis),
    }


def _alert_ref(events_table, key: str) -> Optional[tuple]:
    """(PartitionKey, RowKey, decision) of the journal row of the first sign-in for ``key``, or None.

    ("", "", ...) if the row is not known. decision: "emailed" (also digest), "muted", or "alert off".
    """
    if events_table is None:
        return None
    try:
        row = events_table.get_entity(partition_key="events", row_key=key)
    except Exception:
        return None
    if not (isinstance(row.get("processed_at"), str) and row.get("processed_at")):
        return None
    return str(row.get("journal_pk") or ""), str(row.get("journal_rk") or ""), str(row.get("decision") or "emailed")


def signin_alert_key(user: str, ip: str, outcome: str, day: str) -> str:
    """One suspicious sign-in alert per user, IP, outcome (success or failure), and UTC day."""
    raw = f"{user.strip().lower()}|{ip}|{outcome}|{day}"
    return "signinalert-" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def _alert_signin(events_table, event: dict, event_key: str, ip: str, analysis: dict,
                  alerted: Optional[dict] = None) -> bool:
    """Mute check, then email or digest. Record the result in the journal. True when done.

    One sign-in writes several records, seconds apart, from the same IP. Only
    the first record of a user, IP, outcome, and UTC day sends an alert. Each
    other record adds one to "repeats" on the journal row of that alert, so the
    management UI shows continued use. ``alerted`` maps the keys of this run to
    their journal rows.
    """
    if not should_email_login(analysis["confidence"]):
        return True
    finding = _signin_finding(event, ip, analysis)
    key = f"signin_{event_key}"
    now = datetime.now(timezone.utc)
    when = journal.event_time(event, now)
    # A user that is not resolved ("Not Available") is not one person: no dedup across records.
    user_key = finding["user"] if "@" in finding["user"] else f"{finding['user']}#{event_key}"
    dedup = signin_alert_key(user_key, ip, geo_monitor.sign_in_outcome(event), when.strftime("%Y-%m-%d"))
    suppressed, action = _signin_suppression(event, finding, now)
    ref = alerted.get(dedup) if alerted is not None else None
    if ref is None:
        ref = _alert_ref(events_table, dedup)
    # A repeat of a muted or "alert off" sign-in alerts after the mute or the setting is gone.
    if ref is not None and not (ref[2] in ("muted", "alert off") and not suppressed):
        logging.info(f"Suspicious sign-in: already handled today for {finding['user']} from {ip} ({ref[2]})")
        journal.add_repeat(journal.table_client(), ref[0], ref[1], when)
        return True
    done = _alert_signin_once(events_table, event, event_key, ip, analysis, finding, key, now, suppressed, action)
    if done:
        decision = suppressed or "emailed"
        ref = (*journal.row_ref(finding, key, now), decision)
        if alerted is not None:
            alerted[dedup] = ref
        if events_table is not None:
            try:
                events_table.upsert_entity({"PartitionKey": "events", "RowKey": dedup, "processed_at": now.isoformat(),
                                            "journal_pk": ref[0], "journal_rk": ref[1], "decision": decision})
            except Exception as e:
                logging.warning(f"Sign-in alert key not kept: {type(e).__name__}")
    return done


FAILED_SIGN_IN_OFF = "failed sign-in, email off"


def failed_sign_in_off(finding: dict) -> bool:
    """True if the finding is a failed sign-in (wrong password, locked, disabled) and
    LOGIN_ALERT_FAILED is off. A correct password stopped by MFA or Conditional Access
    is not "failed" here: it still alerts."""
    event = finding.get("event") or {}
    if config.LOGIN_ALERT_FAILED or str(event.get("Operation", "")) not in ("UserLoggedIn", "UserLoginFailed"):
        return False
    return geo_monitor.sign_in_outcome(event) == "failed"


def _signin_suppression(event: dict, finding: dict, now: datetime) -> tuple:
    """("alert off" or "muted", the action text) if this sign-in sends no email now, else ("", "")."""
    if not config.LOGIN_ALERT_FAILED and geo_monitor.sign_in_outcome(event) == "failed":
        return "alert off", FAILED_SIGN_IN_OFF
    mute = admin_store.matching_mute("suspicious_signin", finding["user"], "", finding["severity"], now,
                                     asn=finding.get("asn", ""))
    if mute:
        return "muted", admin_store.describe_mute(mute)
    return "", ""


def _alert_signin_once(events_table, event: dict, event_key: str, ip: str, analysis: dict, finding: dict,
                       key: str, now: datetime, suppressed: str = "", action: str = "") -> bool:
    jt = journal.table_client()
    if suppressed:
        logging.info(f"Suspicious sign-in, no email ({suppressed}: {action}): User={finding['user']}, IP={ip}")
        journal.record(jt, finding, key, suppressed, action=action, now=now)
        return True
    if config.LOGIN_ALERT_MODE == "digest" and events_table is not None:
        try:
            queue_login_for_digest(event_key, _digest_entry(event, ip, analysis), events_table)
        except Exception as e:
            logging.warning(f"Failed to queue login for digest: {type(e).__name__}")
            return False  # retry on the next run
        journal.record(jt, finding, key, "emailed", action="digest", now=now)
        return True
    sent = send_suspicious_login_alert(event, ip, analysis, outbox=events_table,
                                       related=journal.related(jt, finding, key, now))
    journal.record(jt, finding, key, "emailed" if sent else "email failed", now=now)
    return sent


def _handle_country_anomalies(events_table, observations: list) -> None:
    """Find sign-ins from countries outside each user's baseline. Alert and respond."""
    if not events_table:
        return
    geo_table = geo_monitor.table_client()
    if geo_table is None:
        if observations and config.GEO_ANOMALY_ENABLED:
            raise RuntimeError("Country baseline storage is unavailable")
        return
    now = datetime.now(timezone.utc)
    anomalies = geo_monitor.evaluate(geo_table, observations, now, durable=True)
    anomalies += geo_monitor.pending_anomalies(
        geo_table, now, exclude={geo_monitor.pending_key(a) for a in anomalies})
    for anomaly in anomalies:
        event = anomaly["event"]
        key = f"country_{get_event_key(event)}"
        if _was_processed(events_table, key):
            geo_monitor.mark_delivered(geo_table, anomaly)
            continue
        logging.warning(
            f"Country anomaly: User={event.get('UserId')}, Country={anomaly['country']}, "
            f"IP={anomaly['ip']}, Result={login_result(event)}, "
            f"Known={','.join(anomaly['known']) or 'none'}"
        )
        response_key = f"response_{key}"
        result = _response_result(events_table, response_key)
        if not result:
            result = responder.respond(geo_table, str(event.get("UserId", "")), anomaly["outcome"],
                                       anomaly["learning"], now)
            if result:
                _mark_response(events_table, response_key, result)
        finding = {"type": "new_country", "severity": "high", "user": str(event.get("UserId", "")),
                   "description": (f"Sign-in ({login_result(event)}) from {anomaly['country']}, "
                                   f"IP {anomaly['ip']}. Usual: {', '.join(anomaly['known']) or 'none'}."),
                   "ip": anomaly["ip"], "event": event}
        jt = journal.table_client()
        sent = send_country_anomaly_alert(anomaly, result, outbox=events_table,
                                          related=journal.related(jt, finding, key, now))
        journal.record(jt, finding, key, "emailed" if sent else "email failed", action=result, now=now)
        if sent:
            mark_event_processed(key, events_table)
            geo_monitor.mark_delivered(geo_table, anomaly)


def _defer_ip_check(events_table, event: dict, event_key: str, ip: str, queued_at) -> bool:
    """Keep a sign-in whose IP lookup failed. True if queued or its retry period ended."""
    if not events_table:
        return False
    if queued_at is None:
        if queue_pending_ip(event_key, event, ip, events_table):
            mark_event_processed(event_key, events_table)
            return True
        return False
    if datetime.now(timezone.utc) - queued_at > timedelta(hours=config.PENDING_IP_MAX_HOURS):
        logging.error(
            f"Sign-in IP check abandoned after {config.PENDING_IP_MAX_HOURS} hours: "
            f"User={event.get('UserId')}, IP={ip}, Time={event.get('CreationTime')}. "
            "Check the proxycheck.io key and quota."
        )
        delete_pending_ip(events_table, event_key)
    return True


_DETECTORS = (
    detect_suspicious_inbox_rules,
    detect_mailbox_forwarding,
    detect_suspicious_oauth_consents,
    detect_suspicious_user_agents,
    detect_sign_in_methods,
    detect_mail_flow_rules,
    detect_mailbox_delegation,
    detect_audit_disabled,
    detect_mail_protection_weakened,
    detect_mfa_changes,
    detect_admin_roles,
    detect_app_credentials,
    detect_domain_federation,
)


def finding_key(finding: dict) -> str:
    """Dedup key for one finding.

    The finding type is part of the key. The login check marks sign-in events
    with the bare event key. Without the prefix, a sign-in check could hide a
    compromise alert that failed to send for the same event.
    """
    return f"{finding['type']}_{get_event_key(finding['event'])}"


def _run_compromise_check(events_table, ip_cache_table, processed_keys: set, events: list) -> None:
    """Detect compromise indicators and send one alert for each new finding."""
    logging.info("Compromise check triggered")

    if not events:
        return

    findings = []
    for detector in _DETECTORS:
        try:
            findings.extend(detector(events))
        except Exception:
            logging.exception(f"Detector {detector.__name__} failed")

    new_findings = [f for f in findings if finding_key(f) not in processed_keys]
    now = datetime.now(timezone.utc)
    for finding in [f for f in new_findings if install_grant(f)]:
        _record_install_grant(finding, events_table, processed_keys, now)
    for finding in [f for f in new_findings if finding_key(f) not in processed_keys and is_microsoft_service(f)]:
        _record_not_alert(finding, events_table, processed_keys, now, "microsoft",
                          "A Microsoft service made this change (its app belongs to Microsoft). No alert email.")
    # A failed sign-in (wrong password) by an automation client or an attack tool: logged, no email
    # (LOGIN_ALERT_FAILED), as for a suspicious sign-in IP. No IP lookup is spent on it.
    for finding in [f for f in new_findings if finding_key(f) not in processed_keys and failed_sign_in_off(f)]:
        _record_not_alert(finding, events_table, processed_keys, now, "alert off", FAILED_SIGN_IN_OFF)
    new_findings = [f for f in new_findings if finding_key(f) not in processed_keys]
    if not new_findings:
        return

    # A record that a Microsoft service wrote (for example a rule changed in Outlook mobile, through
    # Microsoft's servers) shows the service's IP, not the client's. Its IP says nothing about the
    # actor: no lookup, and it does not raise the severity. The content of the finding still decides.
    service_ip = {id(f) for f in new_findings if f.get("ip") and mail_access.service_ip_client(f.get("event") or {})}
    finding_ips = {
        f["ip"] for f in new_findings
        if f.get("ip") and id(f) not in service_ip and not is_private_ip(f["ip"]) and not is_allowed_ip(f["ip"])
    }
    ip_results = check_ips_batch(sorted(finding_ips), ip_cache_table) if finding_ips else {}

    geo_table = geo_monitor.table_client() if events_table else None
    now = datetime.now(timezone.utc)
    sent_count = 0
    failed = False
    for finding in new_findings:
        ip_context = ""
        ip = finding.get("ip")
        # A failed lookup (quota, timeout) leaves the finding medium. A mute must not hide it.
        ip_unchecked = bool(ip) and ip in finding_ips and ip not in ip_results
        if id(finding) in service_ip:
            ip_context = f"{ip} is a Microsoft service IP: the record does not show the client's IP"
        elif ip and ip in ip_results:
            finding.update(network_fields(ip_results[ip]))
            analysis = analyze_ip(ip_results[ip])
            cc = geo_monitor.country_of(ip_results[ip])
            if analysis["is_suspicious"]:
                ip_context = (
                    f"Source IP is {analysis['proxy_type'] or 'suspicious'} "
                    f"({analysis['org']}, risk {analysis['risk_score']}/100)"
                )
                finding["severity"] = "high"
            elif geo_monitor.is_unusual(geo_table, str(finding.get("user", "")), cc, now):
                ip_context = f"Source IP country {cc} is new for this user ({analysis['org']})"
                finding["severity"] = "high"

        if _deliver_finding(finding, ip_context, events_table, processed_keys, geo_table, now,
                            ip_unchecked=ip_unchecked):
            sent_count += 1
        elif finding_key(finding) not in processed_keys:
            failed = True

    logging.info(
        f"Compromise check: {len(new_findings)} new findings, {sent_count} alerts sent or queued, "
        f"{len(events)} events"
    )
    if failed:
        raise RuntimeError("Compromise alerts remain neither delivered nor queued")


def _record_install_grant(finding: dict, events_table, processed_keys: set, now: datetime) -> None:
    """A permission that install.ps1 granted to the monitor app: no email, not in the journal.

    Only the log keeps it ("Install grant"), so that the views show what needs a look.
    """
    key = finding_key(finding)
    logging.info(f"Install grant (no alert): {finding.get('description')} "
                 f"(by {finding.get('user')}, record {(finding.get('event') or {}).get('Id', '')})")
    processed_keys.add(key)
    if events_table:
        mark_event_processed(key, events_table)


def _record_not_alert(finding: dict, events_table, processed_keys: set, now: datetime, status: str,
                      action: str) -> None:
    """Journal a finding with ``status`` (not an alert), send no email, and mark it processed."""
    key = finding_key(finding)
    logging.info(f"Finding not alerted ({status}): {finding.get('type')}: {finding.get('description')}")
    journal.record(journal.table_client(), finding, key, status, now=now, action=action)
    processed_keys.add(key)
    if events_table:
        mark_event_processed(key, events_table)


def _deliver_finding(finding: dict, ip_context: str, events_table, processed_keys: set,
                     geo_table, now: datetime, ip_unchecked: bool = False) -> bool:
    """Log a finding, apply the automatic response, send the alert. True if sent or queued.

    A type in ALERTS_OFF is logged and marked processed, and nothing else happens.
    A mute applies only when the source IP was checked (``ip_unchecked`` False):
    a VPN, Tor, or new-country IP makes the finding high, and mutes never hide
    high findings.
    The response runs one time per finding (its own dedup key), before the email,
    so the email can say what was done.
    """
    key = finding_key(finding)
    jt = journal.table_client()
    if finding["type"] in config.ALERTS_OFF:
        logging.info(
            f"Compromise indicator (alert turned off): type={finding['type']}, "
            f"user={finding['user']}, severity={finding['severity']}"
        )
        journal.record(jt, finding, key, "alert off", ip_context=ip_context, now=now)
        processed_keys.add(key)
        if events_table:
            mark_event_processed(key, events_table)
        return False
    mute = admin_store.matching_mute(finding["type"], finding["user"], finding.get("rule_name", ""),
                                     finding["severity"], now, asn=finding.get("asn", ""))
    if mute and ip_unchecked:
        logging.warning(f"Mute {mute['id']} not applied: the source IP was not checked (IP lookup failed)")
        ip_context = ip_context or ("The source IP was not checked (the IP lookup failed). A mute matches "
                                    "this alert, but a mute applies only after the IP check.")
        mute = None
    if mute:
        logging.info(
            f"Compromise indicator (muted): type={finding['type']}, user={finding['user']}, "
            f"severity={finding['severity']}, mute={mute['id']}"
        )
        journal.record(jt, finding, key, "muted", ip_context=ip_context,
                       action=admin_store.describe_mute(mute), now=now)
        processed_keys.add(key)
        if events_table:
            mark_event_processed(key, events_table)
        return False
    logging.warning(
        f"Compromise indicator: type={finding['type']}, "
        f"user={finding['user']}, severity={finding['severity']}"
    )
    action_result = ""
    response_key = f"response_{key}"
    if response_key not in processed_keys:
        try:
            action_result = responder.respond_to_finding(geo_table, finding, now)
        except Exception:
            logging.exception("Automatic response failed")
            action_result = "Automatic response failed: see the log"
        if action_result and events_table:
            _mark_response(events_table, response_key, action_result)
    elif events_table:
        # The response ran on an earlier run, and the email was not sent then. Say what was done.
        action_result = _response_result(events_table, response_key)
    sent = send_compromise_alert(finding, ip_context, outbox=events_table, action_result=action_result,
                                 related=journal.related(jt, finding, key, now))
    journal.record(jt, finding, key, "emailed" if sent else "email failed", ip_context=ip_context,
                   action=action_result, now=now)
    if sent:
        processed_keys.add(key)
        if events_table:
            mark_event_processed(key, events_table)
    return sent


def _mark_response(events_table, response_key: str, result: str) -> None:
    """Mark the response done, with its result (an email sent later can then show it)."""
    try:
        events_table.upsert_entity({"PartitionKey": "events", "RowKey": response_key,
                                    "processed_at": datetime.now(timezone.utc).isoformat(),
                                    "result": str(result)[:500]})
    except Exception as e:
        logging.warning(f"Failed to mark the response as done: {type(e).__name__}")


def _response_result(events_table, response_key: str) -> str:
    try:
        return str(events_table.get_entity(partition_key="events", row_key=response_key).get("result") or "")
    except Exception:
        return ""


def _run_session_check(events_table, ip_cache_table, processed_keys: set, records: list,
                       now: datetime) -> None:
    """Alert when one Entra session appears in a second country, or moves to a risky IP (session_monitor)."""
    if not config.SESSION_CHECK_ENABLED:
        return
    table = session_monitor.table_client()
    if table is None:
        return
    # The mail access check reports mail reads and sends from a risky IP. Skip them here, unless it is off.
    mail_checked = config.MAIL_ACCESS_CHECK and "mail_access" not in config.ALERTS_OFF and events_table is not None
    findings = session_monitor.check(
        table, records, lambda ips: check_ips_batch(ips, ip_cache_table), now, geo_monitor.table_client(),
        analyze=analyze_ip,
        known=lambda user, ip: mail_access.signed_in(events_table, user, ip, now),
        skip=lambda r: mail_checked and r.get("Operation") in (mail_access.READ, mail_access.SEND))
    # Findings of earlier runs whose alert did not go out (send and outbox failed, or the run stopped).
    findings += session_monitor.pending_findings(table, now, exclude={session_monitor.pending_key(f) for f in findings})
    geo_table = geo_monitor.table_client()
    for finding in findings:
        mark = finding.get("mark") or finding["country"]
        key = finding_key(finding)
        if key in processed_keys or (events_table is not None and _was_processed(events_table, key)):
            session_monitor.mark_alerted(table, finding["session_id"], mark, now)   # sent on an earlier run
            continue
        sent = _deliver_finding(finding, finding.get("ip_context", ""), events_table, processed_keys,
                                geo_table, now)
        if sent or finding["type"] in config.ALERTS_OFF or admin_store.matching_mute(
                finding["type"], finding["user"], "", finding["severity"], now, asn=finding.get("asn", "")):
            session_monitor.mark_alerted(table, finding["session_id"], mark, now)


# -----------------------------------------------------------------------------
# Suspicious-login digest (LOGIN_ALERT_MODE=digest)
# -----------------------------------------------------------------------------

def _was_processed(events_table, key: str) -> bool:
    try:
        events_table.get_entity(partition_key="events", row_key=key)
        return True
    except Exception:
        return False


def _run_mail_access_check(events_table, ip_cache_table, processed_keys: set, exchange: list,
                           now: datetime) -> None:
    """Alert when mail is read or sent from a risky IP that did not sign in as the user (mail_access.py)."""
    if not (config.MAIL_ACCESS_CHECK and events_table):
        return
    geo_table = geo_monitor.table_client()
    findings = mail_access.check(
        exchange, lambda ips: check_ips_batch(ips, ip_cache_table), analyze_ip, now,
        known=lambda user, ip: mail_access.signed_in(events_table, user, ip, now),
        unusual=lambda user, cc: geo_monitor.is_unusual(geo_table, user, cc, now),
        done=lambda key: key in processed_keys or _was_processed(events_table, key),
        skip_ip=lambda ip: is_private_ip(ip) or is_allowed_ip(ip),
        country_of=geo_monitor.country_of,
        cached=lambda ips: check_ips_batch(ips, ip_cache_table, cache_only=True),
        max_lookups=config.MAIL_ACCESS_MAX_LOOKUPS)
    failed = False
    for finding in findings:
        sent = _deliver_finding(finding, finding.get("ip_context", ""), events_table, processed_keys, geo_table, now)
        if not sent and finding_key(finding) not in processed_keys:
            failed = True
    if failed:
        raise RuntimeError("Mail access alerts remain neither delivered nor queued")


def _digest_entry(event: dict, ip: str, analysis: dict) -> dict:
    """Flat record of one suspicious login for the digest queue (Table Storage)."""
    city, country = analysis.get("city", ""), analysis.get("country", "")
    return {
        "user": str(event.get("UserId", "Unknown")),
        "ip": ip,
        "result": login_result(event),
        "flags": ", ".join(analysis.get("flags", [])),
        "confidence": analysis.get("confidence", ""),
        "risk": analysis.get("risk_score", 0),
        "org": str(analysis.get("org", "")),
        "location": ", ".join(p for p in (city, country) if p and p != "Unknown"),
        "creation_time": str(event.get("CreationTime", "")),
    }


def _maybe_flush_login_digest(events_table) -> None:
    """Send the digest email and clear the queue.

    Digest mode: send when the oldest queued login is LOGIN_DIGEST_MINUTES old.
    Other mode: send queued logins now (they remain from an earlier digest mode).
    This function must not raise: a bad queue row must not stop the run.
    """
    if not events_table:
        return

    try:
        entries = read_login_digest(events_table)
        if not entries:
            return

        if config.LOGIN_ALERT_MODE == "digest":
            now = datetime.now(timezone.utc)
            ages = []
            for e in entries:
                try:
                    dt = datetime.fromisoformat(str(e.get("queued_at", "")))
                except (ValueError, TypeError):
                    continue  # no valid time: the row goes with the batch
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                ages.append(now - dt)

            # Wait only if a valid time exists and the oldest row is not old
            # enough. If no row has a valid time, send now, so the queue cannot stop.
            oldest = max(ages, default=None)
            if oldest is not None and oldest < timedelta(minutes=config.LOGIN_DIGEST_MINUTES):
                return

        if send_login_digest(entries, outbox=events_table):
            delete_login_digest(events_table, entries)
            logging.info(f"Login digest sent: {len(entries)} suspicious logins")
    except Exception as e:
        logging.warning(f"Login digest flush failed: {type(e).__name__}: {e}")


# -----------------------------------------------------------------------------
# Monthly roll-up (1st of each month at 08:00 UTC)
# -----------------------------------------------------------------------------

@app.timer_trigger(schedule="0 0 8 1 * *", arg_name="timer", run_on_startup=False)
def monthly_rollup(timer: func.TimerRequest) -> None:
    """Email a summary of the last 30 days. Runs on the 1st at 08:00 UTC.

    The Management Activity API keeps content for 7 days only. The roll-up
    counts the monitor's own traces in Application Insights instead.
    """
    if not (config.has_credential() and config.ADMIN_EMAIL):
        logging.error("Missing required environment variables for monthly roll-up")
        return

    admin_store.refresh()
    stats = get_monthly_login_stats()
    if stats is None:
        logging.error("Monthly roll-up skipped: App Insights query unavailable")
        return

    events_table, _ = _get_table_clients()
    if not send_summary_email(
        total=stats["total_events"],
        suspicious=stats["suspicious"],
        unique_ips=stats["unique_ips"],
        period_label="Monthly",
        outbox=events_table,
        compromise=stats.get("compromise", 0),
        country=stats.get("country", 0),
    ):
        logging.error("Monthly roll-up email not sent")


# -----------------------------------------------------------------------------
# Weekly report (Mondays 07:17 UTC)
# -----------------------------------------------------------------------------

@app.timer_trigger(schedule="0 17 7 * * 1", arg_name="timer", run_on_startup=False)
def weekly_report(timer: func.TimerRequest) -> None:
    """Email the weekly health report (WEEKLY_REPORT)."""
    if not (config.has_credential() and config.ADMIN_EMAIL):
        return
    admin_store.refresh()
    if not config.WEEKLY_REPORT:
        return
    now = datetime.now(timezone.utc)
    events_table, _ = _get_table_clients()
    findings, totals = journal.window(journal.table_client(), now - timedelta(days=7), limit=50,
                                      keep=lambda r: r["status"] not in journal.NOT_ALERTS, rank=journal.high_first)
    if not send_weekly_report(get_stats(7), findings, _weekly_health(events_table, now), now, outbox=events_table,
                              totals=totals):
        logging.error("Weekly report email not sent")


def _weekly_health(events_table, now: datetime) -> dict:
    state = _runtime_state(events_table, now, _get_table_clients()[1] if events_table else None)
    seen = [t for t in (_read_time(events_table, f"content-{ct}") for ct in CONTENT_TYPES) if t] \
        if events_table else []
    return {"last_content": max(seen) if seen else None, "queues": state["queues"],
            "onboarding": onboarding.summary(onboarding.load(events_table)),
            "mail_access": state["mail_access"], "ip_lookups": state["ip_lookups"]}


# -----------------------------------------------------------------------------
# Background jobs (every 5 minutes): the onboarding scan, in steps
# -----------------------------------------------------------------------------

@app.timer_trigger(schedule="0 1-59/5 * * * *", arg_name="timer", run_on_startup=False)
def background_jobs(timer: func.TimerRequest) -> None:
    """Continue the onboarding scan, if one runs. Each run stops after onboarding.BUDGET_SECONDS."""
    if not (config.has_credential() and config.ADMIN_EMAIL):
        return
    events_table, ip_cache_table = _get_table_clients()
    state = onboarding.load(events_table)
    if not state or state.get("step") == "done":
        return
    admin_store.refresh()
    onboarding.run(events_table, ip_cache_table, _DETECTORS)


# -----------------------------------------------------------------------------
# Weekly cleanup (03:00 UTC Sundays)
# -----------------------------------------------------------------------------

@app.timer_trigger(schedule="0 0 3 * * 0", arg_name="timer", run_on_startup=False)
def weekly_cleanup(timer: func.TimerRequest) -> None:
    """Delete dedup and IP cache rows older than EVENT_RETENTION_DAYS."""
    if not config.storage_configured():
        return

    try:
        svc = config.table_service()
    except Exception as e:
        logging.error(f"Cleanup: could not connect to storage: {type(e).__name__}")
        return

    cutoff = (datetime.now(timezone.utc) - timedelta(days=EVENT_RETENTION_DAYS)).isoformat()

    deleted = _purge_old_entities(svc, "processedevents", "processed_at", cutoff)
    cache_deleted = _purge_old_entities(svc, "ipcache", "cached_at", cutoff)
    admin_deleted = admin_store.purge_old(admin_store.table_client())
    findings_deleted = journal.purge(journal.table_client())
    session_cutoff = (datetime.now(timezone.utc) - timedelta(days=session_monitor.RETENTION_DAYS)).isoformat()
    session_deleted = _purge_old_entities(svc, session_monitor.TABLE_NAME, "last_seen", session_cutoff)

    logging.info(f"Cleanup complete: deleted {deleted} processed events, {cache_deleted} cached IPs, "
                 f"{admin_deleted} old history, email, and mute rows, {session_deleted} old sessions, "
                 f"{findings_deleted} old findings")


BATCH_DELETE_SIZE = 100  # Table Storage limit for one transaction


def _purge_old_entities(svc: TableServiceClient, table_name: str, time_field: str, cutoff: str) -> int:
    """Delete rows whose ``time_field`` is before ``cutoff``.

    Only "events" rows have processed_at, and only "ipcache" rows have
    cached_at, so each batch has one partition (a transaction requirement).
    """
    deleted = 0
    try:
        table = svc.create_table_if_not_exists(table_name)
        batch = []
        for entity in table.query_entities(f"{time_field} lt '{cutoff}'"):
            batch.append(("delete", entity))
            if len(batch) >= BATCH_DELETE_SIZE:
                deleted += _submit_delete_batch(table, batch)
                batch = []
        if batch:
            deleted += _submit_delete_batch(table, batch)
    except Exception as e:
        logging.warning(f"Cleanup: error purging {table_name}: {type(e).__name__}")
    return deleted


def _submit_delete_batch(table, batch: list) -> int:
    try:
        table.submit_transaction(batch)
        return len(batch)
    except Exception:
        count = 0
        for _, entity in batch:
            try:
                table.delete_entity(entity["PartitionKey"], entity["RowKey"])
                count += 1
            except Exception:
                pass
        return count


# -----------------------------------------------------------------------------
# HTTP triggers (all need a function key)
# -----------------------------------------------------------------------------

def _json_response(body: dict, status_code: int = 200) -> func.HttpResponse:
    return func.HttpResponse(json.dumps(body, indent=2), mimetype="application/json",
                             status_code=status_code)


@app.route(route="test", methods=["GET"], auth_level=func.AuthLevel.FUNCTION)
def test_trigger(req: func.HttpRequest) -> func.HttpResponse:
    """Run one monitor pass now."""
    logging.info("Manual test triggered")
    try:
        audit_log_monitor(None)
        return func.HttpResponse("Run complete. See Application Insights for results.", status_code=200)
    except Exception as e:
        logging.error(f"Manual run failed: {type(e).__name__}: {config.redact(e)}")
        return func.HttpResponse("Run failed. See Application Insights for details.", status_code=500)


@app.route(route="health", methods=["GET"], auth_level=func.AuthLevel.FUNCTION)
def health_check(req: func.HttpRequest) -> func.HttpResponse:
    """Liveness only. Use /api/status to check dependencies."""
    return _json_response({"status": "healthy", "timestamp": datetime.now(timezone.utc).isoformat()})


@app.route(route="recent", methods=["GET"], auth_level=func.AuthLevel.FUNCTION)
def recent_activity(req: func.HttpRequest) -> func.HttpResponse:
    """Show recently processed events and cached IPs."""
    try:
        hours = max(1, min(168, int(req.params.get("hours", "24"))))
        limit = max(1, min(500, int(req.params.get("limit", "50"))))
    except (ValueError, TypeError):
        return _json_response({"error": "hours and limit must be integers"}, 400)

    events_table, ip_cache_table = _get_table_clients()
    if not events_table or not ip_cache_table:
        return _json_response({"error": "Table Storage not configured"}, 503)

    cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()

    recent_events = []
    try:
        for i, entity in enumerate(events_table.query_entities(
            f"PartitionKey eq 'events' and processed_at ge '{cutoff}'"
        )):
            if i >= limit:
                break
            recent_events.append({
                "event_id": entity["RowKey"],
                "processed_at": entity.get("processed_at", ""),
            })
    except Exception as e:
        logging.warning(f"/recent: events query failed: {type(e).__name__}")
        recent_events = [{"error": "query failed"}]

    recent_ips = []
    try:
        for i, entity in enumerate(ip_cache_table.query_entities(
            f"PartitionKey eq 'ipcache' and cached_at ge '{cutoff}'"
        )):
            if i >= limit:
                break
            if entity.get("is_negative", False):
                continue
            try:
                data = json.loads(entity.get("data") or "{}")
            except ValueError:
                data = {}
            recent_ips.append({
                "ip": entity.get("ip") or entity["RowKey"],
                "proxy": data.get("proxy", "unknown"),
                "type": data.get("type", ""),
                "risk": data.get("risk", 0),
                "cached_at": entity.get("cached_at", ""),
            })
    except Exception as e:
        logging.warning(f"/recent: IP cache query failed: {type(e).__name__}")
        recent_ips = [{"error": "query failed"}]

    return _json_response({
        "period": f"last {hours} hours",
        "events_processed": len(recent_events),
        "ips_cached": len(recent_ips),
        "recent_events": recent_events,
        "recent_ips": recent_ips,
    })


def _failed(e: Exception) -> str:
    return f"FAILED: {type(e).__name__}: {config.redact(e)[:200]}"


def _dependency_checks() -> dict:
    """Test each external dependency. Return {"status", "checks"}."""
    from o365_client import token_manager, fetch_audit_content_urls

    checks = {}
    try:
        token_manager.get_o365_token()
        checks["azure_ad_token"] = "ok"
    except Exception as e:
        checks["azure_ad_token"] = _failed(e)

    now = datetime.now(timezone.utc)
    for name, content_type in (("o365_api_aad", AAD_CONTENT_TYPE), ("o365_api_exchange", EXCHANGE_CONTENT_TYPE)):
        try:
            urls = fetch_audit_content_urls(content_type, now - timedelta(minutes=60), now)
            checks[name] = f"ok ({len(urls)} content blobs in last 60 min)"
        except Exception as e:
            checks[name] = _failed(e)

    try:
        token_manager.get_graph_token()
        checks["graph_api_token"] = "ok"
    except Exception as e:
        checks["graph_api_token"] = _failed(e)

    events_table, _ = _get_table_clients()
    if events_table:
        try:
            processed = get_processed_keys(events_table, since_minutes=1440)
            checks["table_storage"] = f"ok ({len(processed)} events processed in last 24h)"
        except Exception as e:
            checks["table_storage"] = _failed(e)
    else:
        checks["table_storage"] = "SKIPPED (no connection string)"

    try:
        url = "https://proxycheck.io/v2/8.8.8.8?vpn=1"
        if config.PROXYCHECK_API_KEY:
            url += f"&key={config.PROXYCHECK_API_KEY}"
        resp = config.http.get(url, timeout=10)
        pc_status = resp.json().get("status") if resp.status_code == 200 else None
        if pc_status in ("ok", "warning"):
            msg = config.redact(resp.json().get("message", ""))[:200] if pc_status == "warning" else ""
            checks["proxycheck_io"] = f"ok (status={pc_status}{': ' + msg if msg else ''})"
        elif resp.status_code == 200:
            msg = config.redact(resp.json().get("message", ""))[:200]
            checks["proxycheck_io"] = f"FAILED: status={pc_status}: {msg}"
        else:
            checks["proxycheck_io"] = f"FAILED: HTTP {resp.status_code}"
    except Exception as e:
        checks["proxycheck_io"] = _failed(e)

    all_ok = all(v.startswith("ok") or v.startswith("SKIPPED") for v in checks.values())
    return {"status": "healthy" if all_ok else "degraded", "checks": checks}


def _runtime_state(events_table, now: datetime, ip_cache_table=None) -> dict:
    """Checkpoints, last content, queues, country baseline, IP lookup quota, credential."""
    checkpoints, last_content, queues = {}, {}, {}
    if events_table:
        for content_type in CONTENT_TYPES:
            cp = _read_checkpoint(events_table, content_type)
            checkpoints[content_type] = cp.strftime(_TS_FMT) if cp else None
            seen = _read_time(events_table, f"content-{content_type}")
            last_content[content_type] = seen.strftime(_TS_FMT) if seen else None
        for name, partition in (("outbox", "outbox"), ("pending_ip_checks", "pendingip"),
                                ("digest", "logindigest")):
            try:
                rows = list(events_table.query_entities(f"PartitionKey eq '{partition}'"))
                queues[name] = len(rows)
                if name == "outbox":
                    # The Graph reason of the newest refusal, for the management UI.
                    reasons = sorted((str(r.get("queued_at") or ""), str(r.get("last_error") or ""))
                                     for r in rows if r.get("last_error"))
                    queues["outbox_error"] = reasons[-1][1] if reasons else ""
            except Exception:
                queues[name] = None
    return {
        "last_complete_fetch": checkpoints,
        "last_content_seen": last_content,
        "queues": queues,
        "country_baseline": geo_monitor.status(geo_monitor.table_client(), now) if events_table else None,
        "mail_access": mail_access.summary(events_table, now),
        "ip_lookups": proxycheck_quota.status(ip_cache_table, now),
        "credential": "client secret" if config.CLIENT_SECRET else (
            "managed identity" if config.MANAGED_IDENTITY_CLIENT_ID else "none"),
    }


@app.route(route="status", methods=["GET"], auth_level=func.AuthLevel.FUNCTION)
def status_check(req: func.HttpRequest) -> func.HttpResponse:
    """Test each external dependency and show the active configuration."""
    admin_store.refresh()
    now = datetime.now(timezone.utc)
    result = _dependency_checks()
    events_table, ip_cache_table = _get_table_clients()
    state = _runtime_state(events_table, now, ip_cache_table)
    config_info = {
        "tenant_configured": bool(TENANT_ID),
        "admin_email": config.ADMIN_EMAIL or "(not set)",
        "proxycheck_key_configured": bool(config.PROXYCHECK_API_KEY),
        "allowed_ips": config.ALLOWED_IPS_RAW or "(none)",
        "risk_score_threshold": config.RISK_SCORE_THRESHOLD,
        "lookback_minutes": config.LOOKBACK_MINUTES,
        "max_catchup_minutes": config.MAX_CATCHUP_MINUTES,
        "credential": state["credential"],
        "login_alert_confidence": config.LOGIN_ALERT_CONFIDENCE,
        "login_alert_mode": config.LOGIN_ALERT_MODE,
        "attack_tool_user_agents": config.ATTACK_TOOL_USER_AGENTS,
        "automation_user_agents": config.AUTOMATION_USER_AGENTS,
        "high_risk_oauth_scopes": sorted(config.HIGH_RISK_OAUTH_SCOPES),
        "inbox_rule_keywords": config.INBOX_RULE_KEYWORDS,
        "private_relay_trusted": config.PRIVATE_RELAY_TRUSTED,
        "private_relay_list": private_relay.status(),
        "tenant_label": config.TENANT_LABEL,
        "alert_recipients": config.ALERT_RECIPIENTS,
        "report_recipients": config.REPORT_RECIPIENTS,
        "weekly_report": config.WEEKLY_REPORT,
        "active_mutes": len(admin_store.active_mutes(now)),
    }
    return _json_response({
        "status": result["status"],
        "timestamp": now.isoformat(),
        "checks": result["checks"],
        "last_complete_fetch": state["last_complete_fetch"],
        "last_content_seen": state["last_content_seen"],
        "queues": state["queues"],
        "country_baseline": state["country_baseline"],
        "ip_lookups": state["ip_lookups"],
        "onboarding_scan": onboarding.summary(onboarding.load(events_table)),
        "config": config_info,
    }, 200 if result["status"] == "healthy" else 503)


# -----------------------------------------------------------------------------
# Self-test: send a synthetic event through the real detector and alert path
# -----------------------------------------------------------------------------

def _run_self_test(send_alert: bool = False, types=None) -> dict:
    """Run synthetic records through the real detectors (see selftest.py).

    ``types``: None (inbox rule only), "all", or a list or comma list of types.
    With ``send_alert``, also send one labeled email for each type. This tests
    detection, alerting, and logging. It does not test the Management API;
    /api/status does that. Raises ValueError for an unknown type.
    """
    chosen = selftest.parse_types(types)
    out = selftest.run(chosen, send_alert, _DETECTORS)
    results = out["results"]
    out.update({
        "self_test": chosen[0] if len(chosen) == 1 else "multiple",
        "detected": all(r["detected"] is not False for r in results),
        "findings": [{"type": r["type"], "severity": r["severity"], "description": r.get("description", "")}
                     for r in results if r["detected"]],
        "alert_requested": send_alert,
        "alert_email_sent": bool(send_alert and all(r["email_sent"] for r in results)),
        "note": ("Synthetic records. ?type=all tests every alert type; ?alert=true sends labeled "
                 "[SELF-TEST] emails. Find the 'SELF-TEST' trace in Application Insights."),
    })
    return out


@app.route(route="selftest", methods=["GET"], auth_level=func.AuthLevel.FUNCTION)
def self_test(req: func.HttpRequest) -> func.HttpResponse:
    """Self-test. ?type=all (or a comma list) picks alert types; ?alert=true sends the emails."""
    send_alert = req.params.get("alert", "").lower() == "true"
    try:
        result = _run_self_test(send_alert=send_alert, types=req.params.get("type"))
    except ValueError as e:
        return _json_response({"error": str(e), "types": ["all"] + selftest.ALL}, 400)
    return _json_response(result, 200 if result["passed"] else 500)


# -----------------------------------------------------------------------------
# Management UI (App Service Authentication + Monitor.Admin role; see admin_api)
# -----------------------------------------------------------------------------

@app.route(route="manage", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def manage_page(req: func.HttpRequest) -> func.HttpResponse:
    return admin_api.static(req, "index.html")


@app.route(route="manage/app.js", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def manage_js(req: func.HttpRequest) -> func.HttpResponse:
    return admin_api.static(req, "app.js")


@app.route(route="manage/app.css", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def manage_css(req: func.HttpRequest) -> func.HttpResponse:
    return admin_api.static(req, "app.css")


@app.route(route="manage/api/state", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def manage_state(req: func.HttpRequest) -> func.HttpResponse:
    return admin_api.get_state(req)


@app.route(route="manage/api/settings", methods=["PUT"], auth_level=func.AuthLevel.ANONYMOUS)
def manage_settings(req: func.HttpRequest) -> func.HttpResponse:
    return admin_api.put_settings(req)


@app.route(route="manage/api/checks", methods=["POST"], auth_level=func.AuthLevel.ANONYMOUS)
def manage_checks(req: func.HttpRequest) -> func.HttpResponse:
    return admin_api.post_checks(req)


@app.route(route="manage/api/selftest", methods=["POST"], auth_level=func.AuthLevel.ANONYMOUS)
def manage_selftest(req: func.HttpRequest) -> func.HttpResponse:
    return admin_api.post_selftest(req)


@app.route(route="manage/api/countries", methods=["GET", "POST"], auth_level=func.AuthLevel.ANONYMOUS)
def manage_countries(req: func.HttpRequest) -> func.HttpResponse:
    return admin_api.countries(req)


@app.route(route="manage/api/user", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def manage_user(req: func.HttpRequest) -> func.HttpResponse:
    return admin_api.user_page(req)


@app.route(route="manage/api/rules", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def manage_rules(req: func.HttpRequest) -> func.HttpResponse:
    return admin_api.user_rules(req)


@app.route(route="manage/api/respond", methods=["POST"], auth_level=func.AuthLevel.ANONYMOUS)
def manage_respond(req: func.HttpRequest) -> func.HttpResponse:
    return admin_api.respond(req)


@app.route(route="manage/api/mutes", methods=["GET", "POST"], auth_level=func.AuthLevel.ANONYMOUS)
def manage_mutes(req: func.HttpRequest) -> func.HttpResponse:
    return admin_api.mutes(req)


@app.route(route="manage/api/findings", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def manage_findings(req: func.HttpRequest) -> func.HttpResponse:
    return admin_api.findings(req)


@app.route(route="manage/api/record", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def manage_record(req: func.HttpRequest) -> func.HttpResponse:
    return admin_api.finding_record(req)


@app.route(route="manage/api/ipnetwork", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def manage_ip_network(req: func.HttpRequest) -> func.HttpResponse:
    return admin_api.ip_network(req)


@app.route(route="manage/api/triage", methods=["POST"], auth_level=func.AuthLevel.ANONYMOUS)
def manage_triage(req: func.HttpRequest) -> func.HttpResponse:
    return admin_api.triage(req)


@app.route(route="manage/api/history", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def manage_history(req: func.HttpRequest) -> func.HttpResponse:
    return admin_api.history(req)


@app.route(route="manage/api/usersearch", methods=["GET", "POST"], auth_level=func.AuthLevel.ANONYMOUS)
def manage_user_search(req: func.HttpRequest) -> func.HttpResponse:
    return admin_api.user_search(req)


@app.route(route="manage/api/scan", methods=["POST"], auth_level=func.AuthLevel.ANONYMOUS)
def manage_scan(req: func.HttpRequest) -> func.HttpResponse:
    return admin_api.scan(req)


@app.route(route="manage/api/access", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def manage_access(req: func.HttpRequest) -> func.HttpResponse:
    return admin_api.access_info(req)
