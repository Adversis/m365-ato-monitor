"""Management UI: static files and a JSON API.

Authentication: App Service Authentication (Entra ID sign-in) on the Function
App. The platform puts the signed-in user in the X-MS-CLIENT-PRINCIPAL header
and removes that header from client requests. The header can only be trusted
when App Service Authentication is on (WEBSITE_AUTH_ENABLED), so every route
checks that first.

Authorization (ui_access.py): the user has the "Monitor.Admin" app role, is
listed in Settings > Management UI access, or has a listed directory role. The
admin app does not require assignment, so any user of the tenant can sign in;
guard() refuses every API request of a user without access.

Requests that change data must send the header "X-Monitor-Admin: 1" and, if
the browser sends an Origin header, come from this site. A cross-site page
cannot add that header without a CORS preflight, and CORS is not enabled.
"""

import base64
import json
import logging
import os
import pathlib
import re
import time
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

import azure.functions as func

import admin_store
import audit_search
import config
import geo_monitor
import health_alerts
import journal
import mailbox_rules
import onboarding
import responder
import selftest
import settings as settings_mod
import ui_access
from alerting import send_mailbox_changed_notice, send_mailbox_test, send_settings_changed
from o365_client import token_manager

ROLE = ui_access.ROLE
_OID_CLAIMS = ("http://schemas.microsoft.com/identity/claims/objectidentifier", "oid")
_UPN_CLAIMS = ("preferred_username", "upn", "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn")
_ROLE_CLAIMS = ("roles", "http://schemas.microsoft.com/ws/2008/06/identity/claims/role")
_UI_DIR = pathlib.Path(__file__).parent / "ui"
_UPN_RE = re.compile(r"^[^@\s]{1,64}@[A-Za-z0-9.-]{1,253}$")

_HEADERS = {
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    # same-origin: the app's own requests carry a Referer (the platform can refuse a signed-in POST
    # without one); a link to another site carries none.
    "Referrer-Policy": "same-origin",
}
_CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
_STATIC = {
    "index.html": "text/html; charset=utf-8",
    "app.js": "text/javascript; charset=utf-8",
    "app.css": "text/css; charset=utf-8",
}


def enabled() -> bool:
    return (os.environ.get("ADMIN_UI_ENABLED", "").lower() == "true"
            and os.environ.get("WEBSITE_AUTH_ENABLED", "").lower() == "true")


def principal(req: func.HttpRequest):
    """The signed-in user from App Service Authentication: {"name", "roles", "upn", "oid"}, or None.

    "upn" and "oid" come only from the claims in X-MS-CLIENT-PRINCIPAL (they decide access).
    "name" can come from X-MS-CLIENT-PRINCIPAL-NAME (display only).
    """
    raw = req.headers.get("X-MS-CLIENT-PRINCIPAL")
    if not raw:
        return None
    try:
        data = json.loads(base64.b64decode(raw))
    except ValueError:
        return None
    claims = data.get("claims") or []
    role_types = set(_ROLE_CLAIMS) | {data.get("role_typ")}
    roles = {c.get("val") for c in claims if c.get("typ") in role_types}
    name = (req.headers.get("X-MS-CLIENT-PRINCIPAL-NAME")
            or next((c.get("val") for c in claims if c.get("typ") in ("preferred_username", "name")), ""))
    upn = next((c.get("val") for c in claims if c.get("typ") in _UPN_CLAIMS), "")
    oid = next((c.get("val") for c in claims if c.get("typ") in _OID_CLAIMS), "")
    display = next((c.get("val") for c in claims if c.get("typ") == "name"), "")
    return {"name": str(name)[:200], "roles": roles, "upn": str(upn or "")[:200], "oid": str(oid or "")[:64],
            "display": str(display or "")[:200]}


def describe_access(user: dict) -> str:
    """Why the signed-in user may use the management UI, for the account menu."""
    reason = user.get("access")
    if reason == "app role":
        return f"The {ROLE} role (Enterprise applications > the admin UI app)"
    if reason == "listed user":
        return "Listed in Settings > Management UI access"
    if reason == "directory role":
        names = dict(settings_mod.DIRECTORY_ROLES)
        held = sorted(names.get(r, r) for r in ui_access.directory_roles(user.get("oid", "")) & config.UI_ADMIN_ROLES)
        return "Directory role" + (f": {', '.join(held)}" if held else "")
    return ""


def _response(body: str, status: int, content_type: str) -> func.HttpResponse:
    headers = dict(_HEADERS)
    if content_type.startswith("text/html"):
        headers["Content-Security-Policy"] = _CSP
    return func.HttpResponse(body, status_code=status, headers=headers, mimetype=content_type.split(";")[0],
                             charset="utf-8")


def _json(body: dict, status: int = 200) -> func.HttpResponse:
    return _response(json.dumps(body), status, "application/json")


def _error(status: int, message: str, **extra) -> func.HttpResponse:
    return _json({"error": message, **extra}, status)


# Access settings (UI_ADMIN_USERS, UI_ADMIN_ROLES) are stored overrides. Load them before the access
# check: a new instance has only the defaults, and another instance can have changed them.
_REFRESH_SECONDS = 30
_refreshed_at = None


def _refresh_settings() -> None:
    global _refreshed_at
    now = time.monotonic()
    if _refreshed_at is None or now - _refreshed_at >= _REFRESH_SECONDS:
        admin_store.refresh()
        _refreshed_at = now


def guard(req: func.HttpRequest, mutating: bool = False):
    """Return the user dict, or an HttpResponse that refuses the request."""
    if not enabled():
        if os.environ.get("ADMIN_UI_ENABLED", "").lower() == "true":
            # Fail closed: without App Service Authentication, X-MS-CLIENT-PRINCIPAL can be forged.
            return _error(404, "The management UI is off: App Service Authentication is not detected "
                               "(WEBSITE_AUTH_ENABLED is not set). Run ./install.ps1 -Update.")
        return _error(404, "Not found.")
    user = principal(req)
    if user is None:
        return _error(401, "Sign in required. Reload the page.")
    _refresh_settings()
    reason = ui_access.access(user)
    if not reason:
        return _error(403, f"Your account ({user['name']}) has no access to the management UI. Ask an "
                           "administrator of the monitor to add you in Settings > Management UI access, "
                           f"or to assign you the {ROLE} role: Entra ID > Enterprise applications > the "
                           "admin UI app > Users and groups.")
    user["access"] = reason
    if mutating:
        if req.headers.get("X-Monitor-Admin") != "1":
            return _refused(req, user, "missing X-Monitor-Admin header")
        origin = req.headers.get("Origin")
        hosts = {h.lower() for h in (req.headers.get("Host"), req.headers.get("X-Forwarded-Host"),
                                     os.environ.get("WEBSITE_HOSTNAME")) if h}
        if origin and urlparse(origin).netloc.lower() not in hosts:
            return _refused(req, user, "wrong origin")
    return user


def _refused(req: func.HttpRequest, user: dict, reason: str) -> func.HttpResponse:
    """403 for a change request that fails the CSRF checks. Logged, so that the cause shows in Application Insights."""
    logging.warning(f"Management UI request refused ({reason}): {req.method} {urlparse(req.url).path}, "
                    f"user={user.get('name')}, Origin={req.headers.get('Origin')}, Host={req.headers.get('Host')}, "
                    f"X-Forwarded-Host={req.headers.get('X-Forwarded-Host')}")
    return _error(403, f"Request refused: {reason}.")


# -----------------------------------------------------------------------------
# Static files
# -----------------------------------------------------------------------------

def static(req: func.HttpRequest, name: str) -> func.HttpResponse:
    content_type = _STATIC[name]
    user = guard(req)
    if isinstance(user, func.HttpResponse):
        if name != "index.html":
            return user
        message = json.loads(user.get_body())["error"]
        page = ("<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>M365 Audit Log "
                "Monitor</title></head><body style=\"font-family:sans-serif;max-width:640px;margin:48px auto;"
                f"padding:0 16px;\"><h1>Access refused</h1><p>{_escape(message)}</p></body></html>")
        return _response(page, user.status_code, content_type)
    return _response((_UI_DIR / name).read_text(encoding="utf-8"), 200, content_type)


def _escape(text: str) -> str:
    return (text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;"))


# -----------------------------------------------------------------------------
# API
# -----------------------------------------------------------------------------

def _settings_payload(table, granted) -> dict:
    state = admin_store.load(table)
    items = []
    for s in settings_mod.SETTINGS:
        options = [c[0] for c in s.choices] if s.kind == "choice" else ([True, False] if s.kind == "bool" else [])
        unavailable = {}
        for option in options:
            missing = settings_mod.missing_roles(s, option, granted)
            if missing:
                unavailable[json.dumps(option)] = "Needs the Graph permission " + ", ".join(missing) + "."
        secret = s.kind == "secret"
        items.append({
            "name": s.name, "group": s.group, "label": s.label, "help": s.help, "kind": s.kind,
            "choices": [list(c) for c in s.choices], "min": s.minimum, "max": s.maximum,
            # A secret never leaves the server: only whether it is set.
            "default": "" if secret else settings_mod.DEFAULTS[s.name], "value": settings_mod.current(s),
            "is_set": bool(settings_mod.current(s, reveal=True)) if secret else None,
            "default_is_set": bool(settings_mod.DEFAULTS[s.name]) if secret else None,
            "overridden": s.name in state["overrides"], "unavailable": unavailable,
            "risky": [json.dumps(v) for v in s.risky],
        })
    return {"version": state["version"], "updated_by": state["updated_by"],
            "updated_at": state["updated_at"], "groups": [list(g) for g in settings_mod.GROUPS],
            "items": items}


def get_state(req: func.HttpRequest) -> func.HttpResponse:
    user = guard(req)
    if isinstance(user, func.HttpResponse):
        return user
    import function_app as fa
    table = admin_store.table_client()
    admin_store.refresh(table)
    events_table, ip_cache_table = fa._get_table_clients()
    now = datetime.now(timezone.utc)
    granted = token_manager.granted_graph_roles()
    health = fa._runtime_state(events_table, now, ip_cache_table)
    health["graph_roles"] = granted
    week, week_totals = journal.window(journal.table_client(), now - timedelta(days=7), limit=50,
                                       keep=lambda r: r["status"] not in NOT_ON_MAIN)
    return _json({
        "user": user["name"],
        "me": {"name": user.get("display") or user["name"], "upn": user.get("upn") or "",
               "access": describe_access(user)},
        "app": {"site": os.environ.get("WEBSITE_SITE_NAME", ""), "admin_email": config.ADMIN_EMAIL or "",
                "storage": table is not None,
                "mail_send_scope": os.environ.get("MAIL_SEND_SCOPE", "tenant"),
                "mail_send_group": os.environ.get("MAIL_SEND_GROUP", ""),
                "tenant_label": config.TENANT_LABEL,
                "alert_recipients": config.ALERT_RECIPIENTS, "report_recipients": config.REPORT_RECIPIENTS},
        "settings": _settings_payload(table, granted),
        "health": health,
        "emails": admin_store.recent_emails(table, 50),
        "history": admin_store.history(table, 30),
        "selftest_types": [{"type": t, "label": selftest.LABELS[t]} for t in selftest.ALL],
        "findings": {"days": 7, "summary": week_totals, "recent": week},
        "mutes": admin_store.list_mutes(table, now) if table is not None else [],
        "mute_types": [list(t) for t in settings_mod.MUTE_TYPES],
        "onboarding": onboarding.summary(onboarding.load(events_table)),
        "permissions": _permissions(granted),
    })


def _permissions(granted) -> dict:
    """Which manual actions the app's Graph permissions allow. Unknown roles count as allowed."""
    out = {action: not responder.manual_missing_roles(action, granted) for action in responder.MANUAL_ACTIONS}
    out["rules_read"] = granted is None or mailbox_rules.can_read(granted)
    out["rules_write"] = granted is None or mailbox_rules.can_write(granted)
    out["rule_scan"] = granted is None or (mailbox_rules.can_read(granted) and mailbox_rules.can_list_users(granted))
    out["account_state"] = granted is None or "User.Read.All" in granted
    out["audit_search"] = granted is None or audit_search.can_search(granted)
    return out


def put_settings(req: func.HttpRequest) -> func.HttpResponse:
    user = guard(req, mutating=True)
    if isinstance(user, func.HttpResponse):
        return user
    table = admin_store.table_client()
    if table is None:
        return _error(503, "Table Storage is not configured. Settings cannot be saved.")
    try:
        body = req.get_json()
    except ValueError:
        return _error(400, "The request body is not JSON.")
    changes, version = (body or {}).get("changes"), (body or {}).get("version")
    dry_run = (body or {}).get("dry_run") is True
    if not isinstance(changes, dict) or not isinstance(version, int) or isinstance(version, bool):
        return _error(400, "Send {\"version\": <int>, \"changes\": {<name>: <value or null>}}.")
    admin_store.refresh(table)          # this instance can have old values; read the stored ones
    old_mailbox = (config.ADMIN_EMAIL or "").strip().lower()
    new_mailbox = None
    if "ADMIN_EMAIL" in changes and not dry_run:
        # The alert mailbox is the sender. Prove that Graph sends from it before the save.
        raw = changes["ADMIN_EMAIL"]
        try:
            candidate = (settings_mod.DEFAULTS["ADMIN_EMAIL"] if raw is None
                         else settings_mod.validate(settings_mod.BY_NAME["ADMIN_EMAIL"], raw))
        except ValueError as e:
            return _error(400, "Some values are not valid.", errors={"ADMIN_EMAIL": str(e)})
        if candidate and candidate != old_mailbox:
            # Check the version and the other values first: send no test email for a save that fails.
            try:
                admin_store.save(table, changes, version, user["name"], token_manager.granted_graph_roles(),
                                 dry_run=True)
            except admin_store.ValidationError as e:
                return _error(400, "Some values are not valid.", errors=e.errors)
            except admin_store.ConflictError:
                return _error(409, "Somebody else saved changes after you loaded the page. Reload the page.")
            ok, reason = send_mailbox_test(candidate, user["name"])
            if not ok:
                return _error(400, "Some values are not valid.", errors={"ADMIN_EMAIL": reason})
            new_mailbox = candidate
    try:
        diff = admin_store.save(table, changes, version, user["name"], token_manager.granted_graph_roles(),
                                dry_run=dry_run)
    except admin_store.ValidationError as e:
        return _error(400, "Some values are not valid.", errors=e.errors)
    except admin_store.ConflictError:
        return _error(409, "Somebody else saved changes after you loaded the page. Reload the page.")
    notes = []
    if new_mailbox and any(c["name"] == "ADMIN_EMAIL" for c in diff):
        monitor = health_alerts.set_email(new_mailbox, old_mailbox)
        notes.append(monitor)
        if old_mailbox and not send_mailbox_changed_notice(old_mailbox, new_mailbox, user["name"], monitor):
            notes.append(f"The notice to {old_mailbox} was not sent.")
        logging.warning(f"Alert mailbox changed by {user['name']}: {old_mailbox} -> {new_mailbox}. {monitor}")
    if diff and not dry_run:
        import function_app as fa
        events_table, _ = fa._get_table_clients()
        logging.warning(f"Settings changed by {user['name']}: " +
                        "; ".join(f"{c['name']}: {c['old']} -> {c['new']}" for c in diff))
        send_settings_changed(user["name"], diff, outbox=events_table)
    return _json({"changes": diff, "notes": notes})


def post_checks(req: func.HttpRequest) -> func.HttpResponse:
    user = guard(req, mutating=True)
    if isinstance(user, func.HttpResponse):
        return user
    import function_app as fa
    return _json(fa._dependency_checks())


def post_selftest(req: func.HttpRequest) -> func.HttpResponse:
    user = guard(req, mutating=True)
    if isinstance(user, func.HttpResponse):
        return user
    import function_app as fa
    try:
        body = req.get_json() if req.get_body() else {}
    except ValueError:
        return _error(400, "The request body is not JSON.")
    body = body if isinstance(body, dict) else {}
    send = body.get("send", True) is not False
    try:
        result = fa._run_self_test(send_alert=send, types=body.get("types"))
    except ValueError as e:
        return _error(400, str(e))
    logging.warning(f"Self-test from the management UI by {user['name']}: "
                    f"{len(result['results'])} types, send={send}, passed={result['passed']}")
    return _json(result)


def countries(req: func.HttpRequest) -> func.HttpResponse:
    mutating = req.method.upper() == "POST"
    user = guard(req, mutating=mutating)
    if isinstance(user, func.HttpResponse):
        return user
    table = geo_monitor.table_client()
    if table is None:
        return _error(503, "Table Storage is not configured.")
    now = datetime.now(timezone.utc)
    if not mutating:
        upn = (req.params.get("user") or "").strip().lower()
        if not _UPN_RE.match(upn):
            return _error(400, "Enter a user principal name, for example jane@contoso.com.")
        return _json({"user": upn, "countries": geo_monitor.user_countries(table, upn, now)})

    try:
        body = req.get_json() or {}
    except ValueError:
        return _error(400, "The request body is not JSON.")
    upn = str(body.get("user", "")).strip().lower()
    cc = str(body.get("country", "")).strip().upper()
    action = body.get("action")
    if not _UPN_RE.match(upn):
        return _error(400, "Enter a user principal name, for example jane@contoso.com.")
    if not re.fullmatch(r"[A-Z]{2}", cc):
        return _error(400, "Enter a two-letter country code, for example FR.")
    if action not in ("approve", "remove"):
        return _error(400, "Action must be approve or remove.")
    if geo_monitor.set_country(table, upn, cc, action == "approve", now):
        change = {"name": "COUNTRY", "label": f"Usual countries for {upn}",
                  "old": "", "new": f"{cc} approved" if action == "approve" else f"{cc} removed"}
        admin_store.record_history(admin_store.table_client(), user["name"], [change], now)
        logging.warning(f"Country {action}: User={upn}, Country={cc}, By={user['name']}")
        import function_app as fa
        events_table, _ = fa._get_table_clients()
        send_settings_changed(user["name"], [change], outbox=events_table)
    return _json({"user": upn, "countries": geo_monitor.user_countries(table, upn, now)})


# -----------------------------------------------------------------------------
# User page: findings, countries, account state, inbox rules, manual response
# -----------------------------------------------------------------------------

def _upn(value) -> str:
    upn = str(value or "").strip().lower()
    return upn if _UPN_RE.match(upn) else ""


def _upn_error() -> func.HttpResponse:
    return _error(400, "Enter a user principal name, for example jane@contoso.com.")


def _events_table():
    import function_app as fa
    return fa._get_table_clients()[0]


def _announce(by: str, change: dict, title: str, summary: str) -> None:
    """Record a change made in the UI in History, and email it."""
    admin_store.record_history(admin_store.table_client(), by, [change])
    send_settings_changed(by, [change], outbox=_events_table(), title=title, summary=summary)


def user_page(req: func.HttpRequest) -> func.HttpResponse:
    user = guard(req)
    if isinstance(user, func.HttpResponse):
        return user
    upn = _upn(req.params.get("user"))
    if not upn:
        return _upn_error()
    admin_store.refresh(admin_store.table_client())
    now = datetime.now(timezone.utc)
    granted = token_manager.granted_graph_roles()
    mutes = [m for m in admin_store.active_mutes(now) if m["user"] in ("*", upn)]
    return _json({
        "user": upn,
        "account": responder.account_state(upn, granted),
        "findings": _fill_networks(journal.for_user(journal.table_client(), upn, journal.ANY_TIME, limit=200)),
        "countries": geo_monitor.user_countries(geo_monitor.table_client(), upn, now),
        "mutes": mutes,
        "exempt": upn in config.ANOMALY_ACTION_EXEMPT or upn == (config.ADMIN_EMAIL or "").lower(),
        "is_alert_mailbox": upn == (config.ADMIN_EMAIL or "").lower(),
        "is_you": upn == user["name"].strip().lower(),
        "permissions": _permissions(granted),
        "missing": {a: list(responder.manual_missing_roles(a, granted)) for a in responder.MANUAL_ACTIONS},
        "search": admin_store.last_search(admin_store.table_client(), upn, now),
    })


def user_rules(req: func.HttpRequest) -> func.HttpResponse:
    user = guard(req)
    if isinstance(user, func.HttpResponse):
        return user
    upn = _upn(req.params.get("user"))
    if not upn:
        return _upn_error()
    granted = token_manager.granted_graph_roles()
    if granted is not None and not mailbox_rules.can_read(granted):
        return _error(403, "Reading inbox rules needs the Graph permission MailboxSettings.Read. Run "
                           "./install.ps1 -Update to grant it.")
    rules, error = mailbox_rules.read(upn)
    if rules is None:
        if error == "no mailbox":
            return _json({"user": upn, "rules": [], "note": "This user has no Exchange Online mailbox."})
        return _error(502, f"Microsoft Graph did not return the rules: {error}.")
    return _json({"user": upn, "rules": rules})


_RESPOND_LABELS = {"revoke": "Revoke sessions", "block": "Block sign-in", "unblock": "Unblock sign-in",
                   "rule_off": "Turn off inbox rule", "rule_on": "Turn on inbox rule"}


def respond(req: func.HttpRequest) -> func.HttpResponse:
    user = guard(req, mutating=True)
    if isinstance(user, func.HttpResponse):
        return user
    try:
        body = req.get_json() or {}
    except ValueError:
        return _error(400, "The request body is not JSON.")
    upn = _upn(body.get("user"))
    action = body.get("action")
    if not upn:
        return _upn_error()
    if action not in _RESPOND_LABELS:
        return _error(400, "Action must be one of: " + ", ".join(_RESPOND_LABELS) + ".")
    granted = token_manager.granted_graph_roles()
    if action in responder.MANUAL_ACTIONS:
        missing = responder.manual_missing_roles(action, granted)
        if missing:
            return _error(403, "Needs the Graph permission " + ", ".join(missing) + ". Run "
                               "./install.ps1 -ResponsePermissions yes to grant it.")
        try:
            result = responder.manual_action(upn, action, user["name"])
        except ValueError as e:
            return _error(400, str(e))
        target = upn
    else:
        if granted is not None and not mailbox_rules.can_write(granted):
            return _error(403, "Needs the Graph permission MailboxSettings.ReadWrite. Run "
                               "./install.ps1 -ResponsePermissions yes to grant it.")
        rule_id = str(body.get("rule_id") or "")
        rule_name = str(body.get("rule_name") or "")[:255]
        if not rule_id or len(rule_id) > 512:
            return _error(400, "Select a rule.")
        result = mailbox_rules.set_enabled(upn, rule_id, action == "rule_on")
        logging.warning(f"Response action (manual): User={upn}, Action={action}, Rule={rule_name!r}, "
                        f"By={user['name']}, Result={result}")
        target = f"{upn}, rule '{rule_name or rule_id[:20]}'"
    ok = "failed" not in result
    change = {"name": "RESPONSE", "label": f"{_RESPOND_LABELS[action]}: {target}", "old": "", "new": result}
    _announce(user["name"], change, "Response action",
              f"took a response action in the management UI: {_RESPOND_LABELS[action].lower()} for {target}.")
    return _json({"ok": ok, "result": result}, 200 if ok else 502)


# -----------------------------------------------------------------------------
# Mutes, findings, onboarding scan
# -----------------------------------------------------------------------------

def mutes(req: func.HttpRequest) -> func.HttpResponse:
    mutating = req.method.upper() == "POST"
    user = guard(req, mutating=mutating)
    if isinstance(user, func.HttpResponse):
        return user
    table = admin_store.table_client()
    if table is None:
        return _error(503, "Table Storage is not configured.")
    now = datetime.now(timezone.utc)
    if mutating:
        try:
            body = req.get_json() or {}
        except ValueError:
            return _error(400, "The request body is not JSON.")
        if body.get("action") == "add":
            try:
                mute = admin_store.add_mute(table, body, user["name"], now)
            except admin_store.ValidationError as e:
                return _error(400, "Some values are not valid.", errors=e.errors)
            text = admin_store.describe_mute(mute)
            logging.warning(f"Mute added by {user['name']}: {text}")
            _announce(user["name"], {"name": "MUTE", "label": "Mute added", "old": "", "new": text},
                      "Alerts muted", f"muted alerts in the management UI: {text}.")
        elif body.get("action") == "end":
            mute = admin_store.end_mute(table, str(body.get("id") or ""), user["name"], now)
            if mute is None:
                return _error(404, "No active mute with this ID. Reload the page.")
            text = admin_store.describe_mute(mute)
            logging.warning(f"Mute ended by {user['name']}: {text}")
            _announce(user["name"], {"name": "MUTE", "label": "Mute ended", "old": text, "new": "ended"},
                      "Mute ended", f"ended a mute in the management UI: {text}.")
        else:
            return _error(400, "Action must be add or end.")
    out = {"mutes": admin_store.list_mutes(table, now, include_expired=True)[:100],
           "types": [list(t) for t in settings_mod.MUTE_TYPES], "max_days": admin_store.MUTE_MAX_DAYS}
    if mutating and body.get("action") == "add":
        out["added"] = mute
    return _json(out)


def findings(req: func.HttpRequest) -> func.HttpResponse:
    user = guard(req)
    if isinstance(user, func.HttpResponse):
        return user
    try:
        days = max(1, min(journal.KEEP_DAYS, int(req.params.get("days", "7"))))
    except (TypeError, ValueError):
        return _error(400, "days must be a whole number.")
    ftype, status = req.params.get("type"), req.params.get("status")
    triage = req.params.get("triage") or ""
    if triage not in _TRIAGE_FILTERS:
        return _error(400, "triage must be one of: " + ", ".join(t for t in _TRIAGE_FILTERS if t) + ".")
    try:
        page = max(1, int(req.params.get("page", "1")))
        size = max(10, min(PAGE_MAX, int(req.params.get("size", str(PAGE_SIZE)))))
    except (TypeError, ValueError):
        return _error(400, "page and size must be whole numbers.")
    # The journal has no time order (one partition per user): window() reads the whole period and
    # keeps the newest WINDOW_MAX rows of the type and delivery status. The triage filter and the
    # page apply to these rows; the summary counts all rows of the period.
    rows, totals = journal.window(
        journal.table_client(), datetime.now(timezone.utc) - timedelta(days=days), limit=WINDOW_MAX,
        keep=lambda r: (r["status"] not in NOT_ON_MAIN and (not ftype or r["type"] == ftype)
                        and (not status or r["status"] == status)))
    want = _TRIAGE_FILTERS[triage]
    chosen = [r for r in rows if want is None or r["triage"] in want]
    start = (page - 1) * size
    return _json({"days": days, "summary": totals, "findings": _fill_networks(chosen[start:start + size]),
                  "page": page, "size": size, "count": len(chosen), "capped": totals["total"] > len(rows)})


PAGE_SIZE = 50
PAGE_MAX = 200
# Rows that the Overview and the Alerts page do not show: the alert type is off, so no one acts on
# them (for example failed sign-ins). The user page still shows them.
NOT_ON_MAIN = ("alert off",)
WINDOW_MAX = 2000
# triage filter -> the triage states it shows (None: all).
_TRIAGE_FILTERS = {"": None, "open": journal.OPEN, "investigating": ("investigating",),
                   "benign": ("benign",), "resolved": ("resolved",)}
TRIAGE_LABELS = {"": "Open", "investigating": "Investigating", "benign": "Benign", "resolved": "Resolved"}


def _public_ip(raw) -> str:
    """The IP in canonical form if it is public and not allowed, else ""."""
    from ip_checker import clean_ip, is_allowed_ip, is_private_ip
    ip = clean_ip(str(raw or ""))
    return ip if ip and not is_private_ip(ip) and not is_allowed_ip(ip) else ""


def _fill_networks(rows: list) -> list:
    """Give rows without an ASN (alerts recorded before the journal kept it) the ASN and network
    name of their IP from the IP cache. No proxycheck.io query. The cache keeps a flagged answer
    for 24 hours and a clean one for IP_CACHE_DAYS."""
    from function_app import _get_table_clients
    from ip_checker import check_ips_batch, network_fields
    want = {}
    for r in rows:
        ip = "" if r.get("asn") else _public_ip(r.get("ip"))
        if ip:
            want.setdefault(ip, []).append(r)
    if not want:
        return rows
    try:
        _, cache = _get_table_clients()
        found = check_ips_batch(list(want), cache, cache_only=True) if cache is not None else {}
    except Exception as e:
        logging.warning(f"Alert networks not read from the IP cache: {type(e).__name__}")
        return rows
    for ip, data in found.items():
        fields = network_fields(data)
        for r in want.get(ip, []):
            if fields["asn"]:
                r.update(fields)
    return rows


def ip_network(req: func.HttpRequest) -> func.HttpResponse:
    """GET ?ip=: {"asn", "network", "note"} of one IP, for "Mute similar" on an alert without an ASN.

    The IP cache first. Else one proxycheck.io query, unless the quota is low, used up, or
    refused. ``note``: "" (found), "private", "quota", or "failed".
    """
    user = guard(req)
    if isinstance(user, func.HttpResponse):
        return user
    import proxycheck_quota
    from function_app import _get_table_clients
    from ip_checker import check_ips_batch, network_fields
    ip = _public_ip(req.params.get("ip"))
    if not ip:
        return _json({"asn": "", "network": "", "note": "private"})
    _, cache = _get_table_clients()
    found = check_ips_batch([ip], cache, cache_only=True)
    if ip not in found:
        level = proxycheck_quota.status(cache)["level"] if cache is not None else "unknown"
        if level in ("low", "exhausted", "refused"):
            return _json({"asn": "", "network": "", "note": "quota"})
        found = check_ips_batch([ip], cache)
    fields = network_fields(found.get(ip))
    return _json(dict(fields, note="" if fields["asn"] else "failed"))


def finding_record(req: func.HttpRequest) -> func.HttpResponse:
    """GET ?id=<finding row ID>: the audit record of one alert, as the alert email shows it."""
    user = guard(req)
    if isinstance(user, func.HttpResponse):
        return user
    try:
        found = journal.audit_record(journal.table_client(), req.params.get("id") or "")
    except Exception as e:
        logging.error(f"Audit record not read: {type(e).__name__}")
        return _error(503, "The audit record was not read. Try again.")
    if found is None:
        return _error(404, "No such alert. Reload the page.")
    return _json(found)


def triage(req: func.HttpRequest) -> func.HttpResponse:
    """Set the triage state of one alert. It changes only the view: later alerts still go out."""
    user = guard(req, mutating=True)
    if isinstance(user, func.HttpResponse):
        return user
    try:
        body = req.get_json() or {}
    except ValueError:
        return _error(400, "The request body is not JSON.")
    state, note = body.get("state", ""), body.get("note") or ""
    if state not in journal.TRIAGE_STATES:
        return _error(400, "state must be one of: " + ", ".join(repr(s) for s in journal.TRIAGE_STATES) + ".")
    if not isinstance(note, str) or any(not c.isprintable() for c in note):
        return _error(400, "The note must be one line of text.")
    try:
        before, after = journal.set_triage(journal.table_client(), str(body.get("id") or ""), state, note,
                                           user["name"])
    except Exception as e:
        logging.error(f"Triage not saved: {type(e).__name__}")
        return _error(503, "The change was not saved. Try again.")
    if after is None:
        return _error(404, "No such alert. Reload the page.")
    label = f"Alert triage: {before['type']} for {before['user'] or 'unknown'} ({before['at']})"
    new = TRIAGE_LABELS[state] + (f": {after['triage_note']}" if after["triage_note"] else "")
    admin_store.record_history(admin_store.table_client(), user["name"],
                               [{"label": label, "old": TRIAGE_LABELS.get(before["triage"], ""), "new": new}])
    logging.info(f"Alert triage by {user['name']}: {before['key']} -> {state or 'open'}")
    return _json({"finding": after})


def history(req: func.HttpRequest) -> func.HttpResponse:
    """One page of History, newest first."""
    user = guard(req)
    if isinstance(user, func.HttpResponse):
        return user
    try:
        page = max(1, int(req.params.get("page", "1")))
        size = max(10, min(PAGE_MAX, int(req.params.get("size", str(PAGE_SIZE)))))
    except (TypeError, ValueError):
        return _error(400, "page and size must be whole numbers.")
    rows = admin_store.history(admin_store.table_client(), page * size + 1)
    start = (page - 1) * size
    return _json({"history": rows[start:start + size], "page": page, "size": size,
                  "more": len(rows) > start + size})


def scan(req: func.HttpRequest) -> func.HttpResponse:
    user = guard(req, mutating=True)
    if isinstance(user, func.HttpResponse):
        return user
    try:
        body = req.get_json() or {}
    except ValueError:
        return _error(400, "The request body is not JSON.")
    kind = body.get("kind")
    if kind not in ("full", "rules"):
        return _error(400, "kind must be full or rules.")
    events_table = _events_table()
    if events_table is None:
        return _error(503, "Table Storage is not configured.")
    now = datetime.now(timezone.utc)
    current = onboarding.load(events_table)
    if current and current.get("step") != "done" and body.get("restart") is not True:
        return _error(409, "A scan is running. Wait for its report, or start again to replace it.",
                      onboarding=onboarding.summary(current))
    state = onboarding.start(events_table, now, kind, by=user["name"])
    admin_store.record_history(admin_store.table_client(), user["name"],
                               [{"name": "SCAN", "label": "Onboarding scan started", "old": "",
                                 "new": "inbox rules" if kind == "rules" else "audit history and inbox rules"}], now)
    return _json({"onboarding": onboarding.summary(state)})


# -----------------------------------------------------------------------------
# Audit search for one user (Microsoft Graph audit log search)
# -----------------------------------------------------------------------------

SEARCH_DAYS = (1, 7, 30, 90, 180)
SEARCH_MAX_ROWS = 1000
SEARCH_MAX_PAGES = 10
# New proxycheck.io lookups for the IPs of one search, per request. Cached answers cost no query.
# None when the daily quota is low or used up: the monitor needs it for the sign-in checks.
SEARCH_IP_LOOKUPS = 20
_MAIL_OPERATIONS = ("MailItemsAccessed", "Send")


def _ip_details(data: dict) -> dict:
    """The proxycheck.io answer for one IP, short, for the audit search table."""
    from ip_checker import analyze_ip
    a = analyze_ip(data)

    def text(value, limit=80):
        value = str(value or "").strip()
        return "" if value.lower() == "unknown" else value[:limit]
    return {"org": text(a["org"]), "asn": text(a["asn"], 20), "type": text(a["proxy_type"], 30),
            "risk": a["risk_score"], "flags": [text(f, 20) for f in a["flags"]][:4],
            "suspicious": a["is_suspicious"], "city": text(a["city"], 60), "country": text(a["country"], 60)}


def _search_ips(rows: list) -> dict:
    """IP details for the rows of a search: {"ips": {ip: details}, "pending", "failed", "quota"}.

    ``ips`` is keyed by the IP as the row shows it. A private or allowed IP gets {"note": ...}
    and no lookup. Newest IPs first: the rows are sorted newest first.
    """
    import proxycheck_quota
    from function_app import _get_table_clients
    from ip_checker import check_ips_batch, clean_ip, get_cached_ip, is_allowed_ip, is_private_ip

    details, public = {}, {}
    for raw in dict.fromkeys(r["ip"] for r in rows if r.get("ip")):
        ip = clean_ip(raw)
        if not ip:
            continue
        if is_private_ip(ip):
            details[raw] = {"note": "private"}
        elif is_allowed_ip(ip):
            details[raw] = {"note": "allowed"}
        else:
            public.setdefault(ip, []).append(raw)
    out = {"ips": details, "pending": 0, "failed": 0, "quota": "", "batch": SEARCH_IP_LOOKUPS}
    if not public:
        return out
    _, cache = _get_table_clients()
    order = list(public)
    found = check_ips_batch(order, cache, cache_only=True)
    rest = [ip for ip in order if ip not in found]
    # A lookup that failed is kept as "negative" for some minutes: no new query for it now.
    failed = {ip for ip in rest if (get_cached_ip(ip, cache) or {}).get("_negative")}
    missing = [ip for ip in rest if ip not in failed]
    level = proxycheck_quota.status(cache)["level"] if cache is not None else "unknown"
    if missing and level in ("low", "exhausted", "refused"):
        out["quota"] = level
    elif missing:
        batch = missing[:SEARCH_IP_LOOKUPS]
        found.update(check_ips_batch(batch, cache))
        failed |= {ip for ip in batch if ip not in found}
        missing = missing[SEARCH_IP_LOOKUPS:]
    for ip, data in found.items():
        for raw in public.get(ip, []):
            details[raw] = _ip_details(data)
    for ip in failed:
        for raw in public[ip]:
            details[raw] = {"note": "failed"}
    out["pending"], out["failed"] = len(missing), len(failed)
    return out


def user_search(req: func.HttpRequest) -> func.HttpResponse:
    """POST {user, days}: start a search. GET ?id=&user=: the status, then the records."""
    mutating = req.method == "POST"
    user = guard(req, mutating=mutating)
    if isinstance(user, func.HttpResponse):
        return user
    granted = token_manager.granted_graph_roles()
    if granted is not None and not audit_search.can_search(granted):
        return _error(403, "The audit search needs the Graph permission AuditLogsQuery.Read.All. Run "
                           "./install.ps1 -Update to grant it.")
    if mutating:
        try:
            body = req.get_json() or {}
        except ValueError:
            return _error(400, "The request body is not JSON.")
        upn = _upn(body.get("user"))
        if not upn:
            return _upn_error()
        days = body.get("days")
        if days not in SEARCH_DAYS:
            return _error(400, "days must be one of: " + ", ".join(str(d) for d in SEARCH_DAYS) + ".")
        now = datetime.now(timezone.utc)
        query_id, error = audit_search.create(f"m365-ato-monitor user {upn}", now - timedelta(days=days), now,
                                              users=[upn])
        if error:
            return _error(502, f"Microsoft Graph did not start the search: {error}.")
        admin_store.record_history(admin_store.table_client(), user["name"],
                                   [{"name": "AUDIT_SEARCH", "label": "Audit search", "old": "",
                                     "new": f"{upn}, last {days} days"}], now)
        admin_store.save_search(admin_store.table_client(), upn, query_id, days, user["name"], now)
        logging.warning(f"Audit search for {upn} ({days} days) started by {user['name']}")
        return _json({"id": query_id, "user": upn, "days": days, "status": "notStarted"})

    upn = _upn(req.params.get("user"))
    query_id = str(req.params.get("id") or "")
    if not upn:
        return _upn_error()
    info, error = audit_search.get(query_id)
    if error:
        return _error(502 if error != "not a query ID" else 400, f"The search status is not available: {error}.")
    if info["status"] != "succeeded":
        return _json({"id": query_id, "user": upn, "status": info["status"]})
    rows, link, pages = [], "", 0
    while pages < SEARCH_MAX_PAGES and len(rows) < SEARCH_MAX_ROWS:
        items, link, error = audit_search.records(query_id, link)
        if error:
            return _error(502, f"Microsoft Graph did not return the records: {error}.")
        pages += 1
        for item in items:
            record = audit_search.to_record(item)
            if record:
                rows.append(audit_search.summary_row(record))
        if not link:
            break
    rows.sort(key=lambda r: r["at"], reverse=True)
    by_operation = {}
    for r in rows:
        by_operation[r["operation"]] = by_operation.get(r["operation"], 0) + 1
    truncated = bool(link) or len(rows) > SEARCH_MAX_ROWS or info["limit_exceeded"]
    rows = rows[:SEARCH_MAX_ROWS]
    try:
        ip_info = _search_ips(rows)
    except Exception as e:
        logging.warning(f"Audit search: IP details not available: {type(e).__name__}")
        ip_info = {"ips": {}, "pending": 0, "failed": 0, "quota": "", "batch": SEARCH_IP_LOOKUPS, "error": True}
    return _json({"id": query_id, "user": upn, "status": "succeeded", "rows": rows,
                  "truncated": truncated,
                  "by_operation": by_operation,
                  "mail_records": sum(by_operation.get(op, 0) for op in _MAIL_OPERATIONS),
                  "ip_info": ip_info})


# -----------------------------------------------------------------------------
# Management UI access: who can open this page now
# -----------------------------------------------------------------------------

def access_info(req: func.HttpRequest) -> func.HttpResponse:
    """The listed users, and the members of each directory role that can be selected."""
    user = guard(req)
    if isinstance(user, func.HttpResponse):
        return user
    granted = token_manager.granted_graph_roles()
    can_read = granted is None or "RoleManagement.Read.Directory" in granted
    ids = [c[0] for c in settings_mod.DIRECTORY_ROLES]
    members = ui_access.role_members(ids) if can_read else {}
    return _json({
        "you": {"name": user["name"], "access": user.get("access", "")},
        "users": sorted(config.UI_ADMIN_USERS),
        "can_read_roles": can_read,
        "roles": [{"id": rid, "name": label, "selected": rid in config.UI_ADMIN_ROLES, "members": members.get(rid)}
                  for rid, label in settings_mod.DIRECTORY_ROLES],
    })
