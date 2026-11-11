"""Onboarding scan: the starting state of the tenant, in one report.

The scan starts by itself after the first monitor run. An admin can start it
again in the management UI (Tools). The background timer runs it in steps of
BUDGET_SECONDS, so it does not delay the 2-minute monitor runs.

Steps:
  1. history: the audit content that the Management Activity API still has.
     That is at most 7 days, and only content from after the audit
     subscription started. The detectors run on it. Each finding goes to the
     findings journal (status "onboarding"). No email is sent per finding.
     During the country learning period, successful sign-ins from IPs that are
     not VPN, proxy, or hosting go into the country baseline (at most
     IP_BUDGET IP lookups).
  2. rules: the inbox rules of every mailbox, through Microsoft Graph. This
     finds rules that existed before the monitor started. Needs
     User.ReadBasic.All and MailboxSettings.Read (or MailboxSettings.ReadWrite).
  3. search: the audit log in Microsoft Purview before the history step
     (up to SEARCH_DAYS days), through the Graph audit search
     (audit_search.py). The scan submits the search at its start, because
     Microsoft can take hours to finish it. The detectors run on the records,
     as in step 1. Sign-ins are not read here (too many). Needs
     AuditLogsQuery.Read.All.
  4. report: one email with the results and the settings that weaken protection.

State: table "processedevents", partition "system", row "onboarding" (JSON).
A new start writes a new run ID. A step that finds a different run ID stops.
"""

import json
import logging
import re
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

from azure.core import MatchConditions
from azure.core.exceptions import ResourceModifiedError, ResourceNotFoundError
from azure.data.tables import UpdateMode

import audit_search
import config
import geo_monitor
import journal
import mailbox_rules
import compromise_detector
import service_actors
from compromise_detector import history_operations
from o365_client import CONTENT_TYPES, AAD_CONTENT_TYPE, fetch_content_records, filter_login_records
from o365_client import token_manager

_PARTITION = "system"
_ROW = "onboarding"
HISTORY_DAYS = 7
WINDOW_HOURS = 1            # a small window keeps one unit of work well inside the function timeout
BUDGET_SECONDS = 75         # host.json functionTimeout is 2.5 minutes
IP_BUDGET = 300
MAX_MAILBOXES = 5000
MAX_LISTED = 50
MAX_REPORT_ROWS = 500       # journal rows that the report reads (high first); the counts are exact
SEARCH_DAYS = 180           # Audit (Standard) keeps 180 days
SEARCH_WAIT_HOURS = 48      # Microsoft: a broad search can take up to 48 hours
SEARCH_TRIES = 10           # failed submits, status reads, or page reads before the step gives up
_TS = "%Y-%m-%dT%H:%M:%SZ"

STEPS = ("history", "rules", "search", "report", "done")


def _parse(text) -> Optional[datetime]:
    try:
        dt = datetime.fromisoformat(str(text).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _load(events_table) -> tuple:
    """(the scan state or None, the row's ETag or None)."""
    if events_table is None:
        return None, None
    try:
        entity = events_table.get_entity(partition_key=_PARTITION, row_key=_ROW)
    except ResourceNotFoundError:
        return None, None
    except Exception as e:
        logging.warning(f"Onboarding state not read: {type(e).__name__}")
        return None, None
    etag = (getattr(entity, "metadata", None) or {}).get("etag")
    try:
        data = json.loads(entity.get("data") or "{}")
    except ValueError:
        return None, etag
    return (data if isinstance(data, dict) else None), etag


def load(events_table) -> Optional[dict]:
    """The scan state, or None if no scan has started."""
    return _load(events_table)[0]


def _save(events_table, state: dict) -> bool:
    """Write the state if no newer scan replaced it. False if the run ID changed.

    The ETag check stops a write when start() wrote a new scan after the read.
    """
    current, etag = _load(events_table)
    if current and current.get("run_id") != state.get("run_id"):
        logging.info("Onboarding: a new scan started; this step stops")
        return False
    entity = {"PartitionKey": _PARTITION, "RowKey": _ROW, "data": json.dumps(state, default=str)}
    try:
        if etag:
            events_table.update_entity(entity, mode=UpdateMode.REPLACE, etag=etag,
                                       match_condition=MatchConditions.IfNotModified)
        else:
            events_table.upsert_entity(entity)
    except ResourceModifiedError:
        logging.info("Onboarding: a new scan started; this step stops")
        return False
    except Exception as e:
        logging.warning(f"Onboarding state not written: {type(e).__name__}")
        return False
    return True


def start(events_table, now: datetime, kind: str = "full", by: str = "",
          end: Optional[datetime] = None) -> Optional[dict]:
    """Start a scan. ``kind``: "full" (history, rules, report) or "rules" (rules, report).

    ``end`` is where the history stops: the start of the monitor's own fetch
    window, so that the scan and the monitor do not both alert on one record.
    """
    if events_table is None or kind not in ("full", "rules"):
        return None
    end = end or now - timedelta(minutes=config.LOOKBACK_MINUTES)
    # The API refuses a start time more than 7 days back. Keep a margin.
    begin = now - timedelta(days=HISTORY_DAYS) + timedelta(minutes=30)
    state = {
        "run_id": secrets.token_hex(8), "kind": kind, "step": "history" if kind == "full" else "rules",
        "requested_by": by or "first run", "started_at": now.strftime(_TS), "finished_at": "",
        "history": {"from": begin.strftime(_TS), "to": end.strftime(_TS), "cursor": begin.strftime(_TS),
                    "records": 0, "signins": 0, "findings": 0, "high": 0, "by_type": {},
                    "flagged_signins": 0, "flagged_users": {}, "seeded_users": 0, "ip_lookups": 0,
                    "errors": [], "earliest": "", "latest": ""},
        "rules": {"mailboxes": 0, "checked": 0, "no_mailbox": 0, "errors": 0, "error_text": "",
                  "flagged": [], "flagged_count": 0, "last_upn": "", "skipped": ""},
        "search": {"query_id": "", "status": "", "from": "", "to": "", "submitted_at": "", "next_link": "",
                   "records": 0, "findings": 0, "high": 0, "by_type": {}, "earliest": "", "latest": "",
                   "limit_exceeded": False, "error": "", "tries": 0, "skipped": "" if kind == "full"
                   else "inbox rules only"},
        "report": {"sent": False, "attempts": 0},
    }
    events_table.upsert_entity({"PartitionKey": _PARTITION, "RowKey": _ROW, "data": json.dumps(state)})
    logging.warning(f"Onboarding scan started: kind={kind}, by={state['requested_by']}")
    return state


def ensure_started(events_table, window_start: datetime, now: datetime) -> None:
    """First monitor run: start the full scan if no scan ever started. Never raises."""
    if events_table is None:
        return
    try:
        if load(events_table) is None:
            start(events_table, now, "full", end=window_start)
    except Exception as e:
        logging.warning(f"Onboarding scan not started: {type(e).__name__}")


def summary(state: Optional[dict]) -> Optional[dict]:
    """Short form for the management UI."""
    if not state:
        return None
    h, r = state.get("history", {}), state.get("rules", {})
    return {"step": state.get("step"), "kind": state.get("kind"), "requested_by": state.get("requested_by"),
            "started_at": state.get("started_at"), "finished_at": state.get("finished_at"),
            "history": {k: h.get(k) for k in ("from", "to", "cursor", "records", "signins", "findings", "high",
                                              "flagged_signins", "seeded_users", "errors")},
            "rules": {k: r.get(k) for k in ("mailboxes", "checked", "no_mailbox", "errors", "error_text",
                                            "flagged_count", "skipped")},
            "search": {k: (state.get("search") or {}).get(k) for k in (
                "status", "from", "to", "records", "findings", "high", "limit_exceeded", "error", "skipped")}}


# -----------------------------------------------------------------------------
# Steps
# -----------------------------------------------------------------------------

def run(events_table, ip_cache_table, detectors, now: Optional[datetime] = None,
        budget: float = BUDGET_SECONDS, send_report=None) -> Optional[dict]:
    """Do scan work until done or ``budget`` seconds pass. Return the state.

    ``detectors``: the monitor's detector list. ``send_report``: function
    (state, findings) -> bool; the default is alerting.send_onboarding_report.
    """
    state = load(events_table)
    if not state or state.get("step") == "done":
        return state
    now = now or datetime.now(timezone.utc)
    deadline = time.monotonic() + budget
    try:
        if state["step"] in ("history", "rules"):
            _submit_search(events_table, state, now)
        if state["step"] == "history":
            if not _history(events_table, ip_cache_table, detectors, state, now, deadline):
                return state
        if state["step"] == "rules" and time.monotonic() < deadline:
            if not _rules(events_table, state, now, deadline):
                return state
        if state["step"] == "search" and time.monotonic() < deadline:
            if not _search(events_table, detectors, state, now, deadline):
                return state
        if state["step"] == "report" and time.monotonic() < deadline:
            _report(events_table, state, now, send_report)
    except Exception:
        logging.exception("Onboarding scan step failed")
    return state


def _seen(events_table, key: str) -> bool:
    """True if the monitor already processed this finding (it was alerted).

    A finding that an earlier scan marked is not "seen": a new scan lists it again.
    """
    try:
        return events_table.get_entity(partition_key="events", row_key=key).get("by") != "onboarding"
    except ResourceNotFoundError:
        return False
    except Exception:
        return False


def _mark(events_table, key: str) -> None:
    """Mark a finding processed, so that the monitor does not email it later."""
    try:
        events_table.upsert_entity({"PartitionKey": "events", "RowKey": key, "by": "onboarding",
                                    "processed_at": datetime.now(timezone.utc).isoformat()})
    except Exception as e:
        logging.warning(f"Onboarding: finding not marked processed: {type(e).__name__}")


def _detect(detectors, records: list, events_table, jt, state: dict, counts: dict, now: datetime) -> None:
    """Run the detectors on ``records``. Journal and count each new finding in ``counts``."""
    import function_app as fa
    for detector in detectors:
        try:
            found = detector(records)
        except Exception:
            logging.exception(f"Onboarding: detector {detector.__name__} failed")
            continue
        for finding in found:
            key = fa.finding_key(finding)
            if _seen(events_table, key):
                continue
            # Not items to review: a permission that install.ps1 granted to the monitor app (not
            # listed), and a change by a Microsoft service (counted in the report).
            if compromise_detector.install_grant(finding):
                _mark(events_table, key)
                continue
            status, action = "onboarding", ""
            if service_actors.is_microsoft_service(finding):
                status = "microsoft"
            elif fa.failed_sign_in_off(finding):
                # A failed sign-in (wrong password): not an item to review, as for a new record.
                status, action = "alert off", fa.FAILED_SIGN_IN_OFF
            # False: an alert for this finding is already in the journal (emailed, muted, or off).
            if not journal.record(jt, finding, key, status, action=action, now=now, only_new=True,
                                  run_id=state["run_id"]):
                continue
            _mark(events_table, key)
            if status == "microsoft":
                counts["microsoft"] = counts.get("microsoft", 0) + 1
            if status != "onboarding":
                continue
            counts["findings"] += 1
            counts["high"] += finding.get("severity") == "high"
            counts["by_type"][finding["type"]] = counts["by_type"].get(finding["type"], 0) + 1


def _history(events_table, ip_cache_table, detectors, state: dict, now: datetime, deadline: float) -> bool:
    """Process history windows until the deadline. True when the step is complete."""
    from ip_checker import analyze_ip, check_ips_batch, extract_ip, is_allowed_ip, is_private_ip

    h = state["history"]
    end = _parse(h["to"])
    cursor = _parse(h["cursor"])
    geo_table = geo_monitor.table_client()
    jt = journal.table_client()
    # The API refuses a start time more than 7 days back (a scan can wait between steps).
    floor = now - timedelta(days=HISTORY_DAYS) + timedelta(minutes=5)
    while cursor < end:
        if time.monotonic() >= deadline:
            return False
        cursor = max(cursor, floor)
        if cursor >= end:
            break
        window_end = min(cursor + timedelta(hours=WINDOW_HOURS), end)
        records = []
        for content_type in CONTENT_TYPES:
            try:
                recs, _ = fetch_content_records(content_type, cursor, window_end)
            except Exception as e:
                text = f"{content_type}: {config.redact(e)[:200]}"
                if text not in h["errors"]:
                    h["errors"] = (h["errors"] + [text])[-5:]
                continue
            records += recs
            if content_type == AAD_CONTENT_TYPE:
                logins = filter_login_records(recs)
                h["signins"] += len(logins)
                _seed(geo_table, ip_cache_table, logins, h, now,
                      (analyze_ip, check_ips_batch, extract_ip, is_allowed_ip, is_private_ip))
        h["records"] += len(records)
        for record in records:
            t = str(record.get("CreationTime") or "")[:19]
            if t and (not h["earliest"] or t < h["earliest"]):
                h["earliest"] = t
            if t and t > h["latest"]:
                h["latest"] = t

        _detect(detectors, records, events_table, jt, state, h, now)

        cursor = window_end
        h["cursor"] = cursor.strftime(_TS)
        if not _save(events_table, state):
            return False
    state["step"] = "rules"
    logging.info(f"Onboarding: history done: {h['records']} records, {h['findings']} findings")
    return _save(events_table, state)


def _seed(geo_table, ip_cache_table, logins: list, h: dict, now: datetime, fns) -> None:
    """Country baseline from past sign-ins (learning period only); count flagged sign-ins."""
    analyze_ip, check_ips_batch, extract_ip, is_allowed_ip, is_private_ip = fns
    if not logins or not config.GEO_ANOMALY_ENABLED:
        return
    pairs = []
    for event in logins:
        ip = extract_ip(event)
        if ip and not is_private_ip(ip) and not is_allowed_ip(ip):
            pairs.append((event, ip))
    budget = max(0, IP_BUDGET - h["ip_lookups"])
    ips = sorted({ip for _, ip in pairs})[:budget]
    if not ips:
        return
    h["ip_lookups"] += len(ips)
    results = check_ips_batch(ips, ip_cache_table)
    observations = []
    for event, ip in pairs:
        data = results.get(ip)
        if not data:
            continue
        analysis = analyze_ip(data)
        user = str(event.get("UserId", "")).strip().lower()
        if analysis["is_suspicious"]:
            h["flagged_signins"] += 1
            h["flagged_users"][user] = h["flagged_users"].get(user, 0) + 1
            continue
        observations.append({"user": user, "country": geo_monitor.country_of(data),
                             "outcome": geo_monitor.sign_in_outcome(event), "ip": ip,
                             "event": event, "analysis": analysis})
    if len(h["flagged_users"]) > 50:
        h["flagged_users"] = dict(sorted(h["flagged_users"].items(), key=lambda kv: -kv[1])[:50])
    h["seeded_users"] += geo_monitor.seed(geo_table, observations, now)


def _rules(events_table, state: dict, now: datetime, deadline: float) -> bool:
    """Sweep inbox rules until the deadline. True when the step is complete."""
    r = state["rules"]
    granted = token_manager.granted_graph_roles()
    if granted is None:
        # No Graph token now (a temporary error). Try again on the next run, at most 10 times.
        r["role_checks"] = int(r.get("role_checks") or 0) + 1
        if r["role_checks"] < 10:
            _save(events_table, state)
            return False
        r["skipped"] = "could not get a Microsoft Graph token (see the log)"
        state["step"] = _after_rules(state)
        return _save(events_table, state)
    if not (mailbox_rules.can_list_users(granted) and mailbox_rules.can_read(granted)):
        missing = []
        if not mailbox_rules.can_list_users(granted):
            missing.append("User.ReadBasic.All")
        if not mailbox_rules.can_read(granted):
            missing.append("MailboxSettings.Read")
        r["skipped"] = "needs the Graph permission " + " and ".join(missing)
        state["step"] = _after_rules(state)
        return _save(events_table, state)

    upns, error = mailbox_rules.list_mailbox_users(MAX_MAILBOXES)
    if upns is None:
        r["skipped"] = f"could not list users: {error}"
        state["step"] = _after_rules(state)
        return _save(events_table, state)
    r["mailboxes"] = len(upns)
    jt = journal.table_client()
    todo = [u for u in upns if u > r["last_upn"]]
    for i, upn in enumerate(todo):
        if time.monotonic() >= deadline:
            _save(events_table, state)
            return False
        rules, error = mailbox_rules.read(upn)
        if rules is None:
            if error == "no mailbox":
                r["no_mailbox"] += 1
            else:
                r["errors"] += 1
                r["error_text"] = r["error_text"] or f"{upn}: {error}"
        else:
            r["checked"] += 1
            for rule in rules:
                if not rule["severity"] or not rule["enabled"]:
                    continue
                r["flagged_count"] += 1
                if len(r["flagged"]) < MAX_LISTED:
                    r["flagged"].append({"mailbox": upn, "id": rule["id"], "name": rule["name"],
                                         "severity": rule["severity"], "reasons": rule["reasons"][:4],
                                         "actions": rule["actions"][:200]})
                finding = {"type": "inbox_rule", "severity": rule["severity"], "user": upn,
                           "description": (f"Existing inbox rule '{rule['name']}' {'; '.join(rule['reasons'][:3])}. "
                                           f"Actions: {str(rule.get('actions') or 'none')[:300]}. "
                                           f"Conditions: {str(rule.get('conditions') or 'all mail')[:300]}."),
                           "ip": "", "rule_name": rule["name"], "mailbox": upn, "targets": rule["targets"],
                           "event": {"CreationTime": now.strftime(_TS), "Operation": "Inbox rule sweep",
                                     "Id": f"sweep-{rule['id'][:60]}"}}
                journal.record(jt, finding, f"sweep_{upn}_{rule['id']}", "onboarding", now=now, only_new=True)
        r["last_upn"] = upn
        if i % 20 == 19 and not _save(events_table, state):
            return False
    state["step"] = _after_rules(state)
    logging.info(f"Onboarding: inbox rules done: {r['checked']} mailboxes, {r['flagged_count']} rules flagged")
    return _save(events_table, state)


def _after_rules(state: dict) -> str:
    return "search" if state.get("kind") == "full" and state.get("search") else "report"


# -----------------------------------------------------------------------------
# Step 3: the audit search (Graph), before the history window
# -----------------------------------------------------------------------------

def _submit_search(events_table, state: dict, now: datetime) -> None:
    """Start the audit search if it did not start. A failure is retried on the next run."""
    s = state.get("search")
    if not s or s.get("query_id") or s.get("skipped"):
        return
    granted = token_manager.granted_graph_roles()
    if granted is None:
        return                      # no Graph token now: try again on the next run
    if not audit_search.can_search(granted):
        s["skipped"] = "needs the Graph permission AuditLogsQuery.Read.All (run ./install.ps1 -Update)"
        _save(events_table, state)
        return
    end = _parse(state["history"]["from"]) or now - timedelta(days=HISTORY_DAYS)
    begin = now - timedelta(days=SEARCH_DAYS) + timedelta(hours=1)
    if end <= begin:
        s["skipped"] = "no time before the history window"
        _save(events_table, state)
        return
    query_id, error = audit_search.create(f"m365-ato-monitor onboarding {state['run_id']}", begin, end,
                                          operations=history_operations())
    if error:
        s["tries"] = int(s.get("tries") or 0) + 1
        s["error"] = error
        if s["tries"] >= SEARCH_TRIES:
            s["skipped"] = f"the search did not start: {error}"
        logging.warning(f"Onboarding: audit search not started: {error}")
        _save(events_table, state)
        return
    s.update(query_id=query_id, status="notStarted", submitted_at=now.strftime(_TS), error="", tries=0,
             **{"from": begin.strftime(_TS), "to": end.strftime(_TS)})
    logging.warning(f"Onboarding: audit search started for {begin:%Y-%m-%d} to {end:%Y-%m-%d}")
    _save(events_table, state)


def _search(events_table, detectors, state: dict, now: datetime, deadline: float) -> bool:
    """Wait for the search, then run the detectors on its records. True when the step is complete."""
    s = state["search"]

    def finish(reason: str = "") -> bool:
        if reason:
            s["skipped"] = reason
        state["step"] = "report"
        return _save(events_table, state)

    def failed_try(error: str) -> bool:
        s["tries"] = int(s.get("tries") or 0) + 1
        s["error"] = error
        if s["tries"] >= SEARCH_TRIES:
            return finish(f"stopped after {SEARCH_TRIES} errors: {error}")
        _save(events_table, state)
        return False

    if s.get("skipped"):
        return finish()
    if not s.get("query_id"):
        _submit_search(events_table, state, now)
        if s.get("skipped"):
            return finish()
        return False
    if s.get("status") != "succeeded":
        info, error = audit_search.get(s["query_id"])
        if error:
            return failed_try(error)
        s["status"], s["limit_exceeded"] = info["status"], info["limit_exceeded"]
        if s["status"] in ("failed", "cancelled"):
            return finish(f"Microsoft reported the search as {s['status']}")
        if s["status"] != "succeeded":
            submitted = _parse(s.get("submitted_at"))
            if submitted and now - submitted > timedelta(hours=SEARCH_WAIT_HOURS):
                return finish(f"the search did not finish in {SEARCH_WAIT_HOURS} hours")
            _save(events_table, state)
            return False
        s["tries"] = 0
    jt = journal.table_client()
    while time.monotonic() < deadline:
        items, link, error = audit_search.records(s["query_id"], s.get("next_link") or "")
        if error:
            return failed_try(error)
        records = [r for r in (audit_search.to_record(i) for i in items) if r]
        s["records"] += len(records)
        for record in records:
            t = str(record.get("CreationTime") or "")[:19]
            if t and (not s["earliest"] or t < s["earliest"]):
                s["earliest"] = t
            if t and t > s["latest"]:
                s["latest"] = t
        _detect(detectors, records, events_table, jt, state, s, now)
        s["next_link"] = link
        if not link:
            logging.info(f"Onboarding: audit search done: {s['records']} records, {s['findings']} findings")
            return finish()
        if not _save(events_table, state):
            return False
    _save(events_table, state)
    return False


def _report(events_table, state: dict, now: datetime, send_report) -> None:
    if send_report is None:
        from alerting import send_onboarding_report as send_report
    findings = []
    run_id = str(state.get("run_id") or "")
    if state.get("kind") == "full" and re.fullmatch(r"[0-9a-f]{1,32}", run_id):
        # Only what this scan found in the history (not alerts that were already emailed).
        # Select by run ID: an audit record can be older than the start of the history window.
        findings, _ = journal.window(
            journal.table_client(), journal.ANY_TIME, limit=MAX_REPORT_ROWS,
            keep=lambda f: f["status"] == "onboarding" and f["operation"] != "Inbox rule sweep",
            rank=journal.high_first, query=f"run_id eq '{run_id}'")
    state["report"]["attempts"] += 1
    if send_report(state, findings, events_table):
        state["report"]["sent"] = True
        state["step"] = "done"
        state["finished_at"] = now.strftime(_TS)
        logging.warning("Onboarding scan finished: report sent")
    elif state["report"]["attempts"] >= 10:
        state["step"] = "done"
        state["finished_at"] = now.strftime(_TS)
        logging.error("Onboarding report not sent after 10 attempts. The scan results are in the "
                      "findings journal (management UI).")
    _save(events_table, state)
