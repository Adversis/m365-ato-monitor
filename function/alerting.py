"""Email alerts through Microsoft Graph sendMail.

No send function raises. A send function returns True when Graph accepts the
message (HTTP 202), or when it gets an ``outbox`` table and puts the message
there. ``flush_outbox`` sends queued messages again on each run. A send
function returns False if the message is neither sent nor queued; the caller
then tries again on the next run.
"""

import hashlib
import html
import json
import logging
import os
import re
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

import admin_store
import config
import webhook
import mail_access
from o365_client import token_manager, resolve_user_object_id, login_result

# Subject prefixes. A mail rule can match them: "[M365 Alert]" needs action,
# "[M365 Monitor]" is information.
ALERT_TAG = "[M365 Alert]"
INFO_TAG = "[M365 Monitor]"

# -----------------------------------------------------------------------------
# Layout (inline styles and tables only: Outlook, Gmail, and mobile clients)
# -----------------------------------------------------------------------------

_FONT = "'Segoe UI', -apple-system, Roboto, Helvetica, Arial, sans-serif"
_MONO = "Consolas, 'SF Mono', Menlo, monospace"
_TEXT, _MUTED, _BORDER, _SOFT, _LINK = "#1f2328", "#59636e", "#d1d9e0", "#f6f8fa", "#0b5cad"

# Text colors have a contrast ratio of 4.5:1 or more on white (WCAG AA).
_LEVELS = {
    "high":   ("#b42318", "#fef3f2"),
    "medium": ("#b54708", "#fffaeb"),
    "info":   ("#175cd3", "#eff8ff"),
    "ok":     ("#067647", "#ecfdf3"),
}

_FINDING_TITLES = {
    "inbox_rule": "Suspicious inbox rule",
    "mailbox_forwarding": "Mailbox forwarding set",
    "oauth_consent": "Risky OAuth consent",
    "attack_tool": "Sign-in with an attack tool",
    "suspicious_user_agent": "Sign-in with an automation client",
    "legacy_auth": "Sign-in with legacy authentication",
    "device_code": "Sign-in with a device code",
    "mail_flow_rule": "Mail flow rule changed",
    "mailbox_delegation": "Mailbox access granted",
    "audit_disabled": "Audit logging turned off",
    "mail_protection_weakened": "Mail protection weakened",
    "mfa_change": "MFA changed",
    "admin_role": "Admin role assigned",
    "app_credential": "App credential added",
    "domain_federation": "Domain or federation changed",
    "session_reuse": "Session used from a second country or a risky IP",
    "mail_access": "Mail read or sent from a risky IP",
}
_FINDING_SHORT = {
    "inbox_rule": "Inbox rule",
    "mailbox_forwarding": "Mailbox forwarding",
    "oauth_consent": "OAuth consent",
    "attack_tool": "Attack tool sign-in",
    "suspicious_user_agent": "Automation client sign-in",
    "legacy_auth": "Legacy auth sign-in",
    "device_code": "Device code sign-in",
    "mail_flow_rule": "Mail flow rule",
    "mailbox_delegation": "Mailbox access",
    "audit_disabled": "Audit off",
    "mail_protection_weakened": "Mail protection",
    "mfa_change": "MFA change",
    "admin_role": "Admin role",
    "app_credential": "App credential",
    "domain_federation": "Domain federation",
    "session_reuse": "Session reuse",
    "mail_access": "Mail access from a risky IP",
}
# Sign-in alerts in the findings journal (incident context, reports).
_SIGNIN_SHORT = {"suspicious_signin": "Suspicious sign-in", "new_country": "New-country sign-in"}


def short_title(ftype: str) -> str:
    return _FINDING_SHORT.get(ftype) or _SIGNIN_SHORT.get(ftype) or ftype.replace("_", " ").capitalize()

_FLAG_LABELS = {
    "vpn": "VPN", "tor": "Tor", "socks": "SOCKS proxy", "socks4": "SOCKS4 proxy",
    "socks5": "SOCKS5 proxy", "http": "HTTP proxy", "https": "HTTPS proxy",
    "hosting": "hosting provider", "high-risk": "high risk score",
    "compromised server": "compromised server", "inference engine": "proxy (inferred)",
    "proxy": "proxy",
}

_SIGNIN_ERRORS = {
    "50034": "user does not exist",
    "50053": "account locked",
    "50055": "correct password, but it expired",
    "50057": "account disabled",
    "50072": "correct password; MFA registration required",
    "50074": "correct password; MFA required",
    "50076": "correct password; MFA required",
    "50079": "correct password; MFA registration required",
    "50126": "wrong user name or password",
    "50133": "session not valid after a password change",
    "50140": "correct password; 'stay signed in' prompt",
    "50097": "correct password; device authentication required",
    "50158": "correct password; external challenge not completed",
    "500121": "correct password; MFA failed or denied",
    "53000": "correct password; blocked by Conditional Access (device not compliant)",
    "53001": "correct password; blocked by Conditional Access (device not joined)",
    "53002": "correct password; blocked by Conditional Access (app not approved)",
    "53003": "correct password; blocked by Conditional Access",
    "53004": "correct password; MFA registration blocked",
}


def _e(value) -> str:
    return html.escape(str(value), quote=True)


def _fmt_time(raw) -> str:
    """'2026-11-07T14:05:40' -> '2026-11-07 14:05:40 UTC'. Audit times are UTC."""
    text = str(raw or "").strip()
    try:
        dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return text or "unknown"
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def _describe_result(result: str) -> str:
    """'Failed (50126)' -> 'Failed (50126: wrong user name or password)'."""
    m = re.fullmatch(r"Failed \((\d+)\)", result)
    if m and m.group(1) in _SIGNIN_ERRORS:
        return f"Failed ({m.group(1)}: {_SIGNIN_ERRORS[m.group(1)]})"
    return result


def _flag_text(flags) -> str:
    return ", ".join(_FLAG_LABELS.get(str(f).lower(), str(f)) for f in flags) or "suspicious"


def _badge(level: str, text: str) -> str:
    color = _LEVELS[level][0]
    return (f'<span style="display:inline-block;background:{color};color:#ffffff;font-size:12px;'
            f'font-weight:700;letter-spacing:0.04em;padding:3px 8px;border-radius:3px;">{_e(text)}</span>')


def _notice(level: str, inner_html: str) -> str:
    color, tint = _LEVELS[level]
    return (f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin:0 0 20px;">'
            f'<tr><td style="background:{tint};border-left:4px solid {color};padding:12px 16px;'
            f'font-size:15px;line-height:1.5;color:{_TEXT};">{inner_html}</td></tr></table>')


def _button(href: str, text: str) -> str:
    return (f'<table role="presentation" cellpadding="0" cellspacing="0" style="margin:4px 0 24px;">'
            f'<tr><td bgcolor="{_LINK}" style="background:{_LINK};border-radius:4px;">'
            f'<a href="{_e(href)}" style="display:inline-block;padding:10px 18px;font-size:15px;'
            f'font-weight:600;color:#ffffff;text-decoration:none;">{_e(text)}</a></td></tr></table>')


def _link(href: str, text: str) -> str:
    return f'<a href="{_e(href)}" style="color:{_LINK};">{_e(text)}</a>'


def _heading(text: str) -> str:
    return (f'<h2 style="margin:28px 0 10px;font-size:16px;line-height:1.3;color:{_TEXT};">'
            f'{_e(text)}</h2>')


def _steps(items_html: list) -> str:
    lis = "".join(f'<li style="margin:0 0 8px;">{item}</li>' for item in items_html)
    return f'<ol style="margin:0 0 8px;padding-left:22px;font-size:15px;line-height:1.5;">{lis}</ol>'


def _facts(rows: list) -> str:
    """Two-column facts table. Values must already be escaped HTML."""
    trs = "".join(
        f'<tr><td style="padding:8px 12px 8px 0;border-bottom:1px solid {_BORDER};color:{_MUTED};'
        f'font-size:13px;vertical-align:top;width:34%;">{_e(label)}</td>'
        f'<td style="padding:8px 0;border-bottom:1px solid {_BORDER};font-size:14px;'
        f'vertical-align:top;word-break:break-word;">{value}</td></tr>'
        for label, value in rows if value not in (None, "")
    )
    return (f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
            f'style="border-top:1px solid {_BORDER};margin:0 0 8px;">{trs}</table>')


def _code(text: str) -> str:
    return (f'<pre style="margin:0 0 8px;background:{_SOFT};border:1px solid {_BORDER};border-radius:4px;'
            f'padding:10px 12px;font-family:{_MONO};font-size:12px;line-height:1.45;color:{_TEXT};'
            f'white-space:pre-wrap;overflow-wrap:anywhere;">{_e(text)}</pre>')


def _inline_code(text: str) -> str:
    return (f'<code style="font-family:{_MONO};font-size:13px;background:{_SOFT};'
            f'padding:1px 4px;border-radius:3px;white-space:nowrap;">{_e(text)}</code>')


def _p(inner_html: str, muted: bool = False) -> str:
    color = _MUTED if muted else _TEXT
    size = "13px" if muted else "15px"
    return f'<p style="margin:0 0 12px;font-size:{size};line-height:1.5;color:{color};">{inner_html}</p>'


def _site() -> str:
    return os.environ.get("WEBSITE_SITE_NAME", "")


def ui_url(fragment: str = "") -> str:
    """Link to the management UI, or "" if it is not enabled."""
    # WEBSITE_HOSTNAME is set by App Service. install.ps1 also sets MONITOR_HOSTNAME.
    host = os.environ.get("WEBSITE_HOSTNAME") or os.environ.get("MONITOR_HOSTNAME", "")
    if os.environ.get("ADMIN_UI_ENABLED", "").lower() != "true" or not host:
        return ""
    return f"https://{host}/api/manage" + (f"#{fragment}" if fragment else "")


def ui_link(view: str, *parts) -> str:
    """Deep link into the UI: #user:<upn> or #mute:<type>:<upn>[:<rule>]. Each part is URL-encoded."""
    if not ui_url():
        return ""
    return ui_url(":".join([view] + [quote(str(p), safe="@.") for p in parts if p not in (None, "")]))


def _document(*, preheader: str, level: str, badge: str, kicker: str, title: str,
              body: str, footer_note: str = "") -> str:
    """A complete HTML email. ``body`` and ``footer_note`` are HTML; others are text."""
    color = _LEVELS[level][0]
    site = _site()
    origin = ("M365 ATO Monitor" + (f" &middot; {_e(config.TENANT_LABEL)}" if config.TENANT_LABEL else "")
              + (f" &middot; {_e(site)}" if site else ""))
    sent_to = f"Sent from {_e(config.ADMIN_EMAIL)}." if config.ADMIN_EMAIL else ""
    manage = ui_url()
    if manage:
        sent_to += " " + _link(manage, "Management UI")
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light">
<meta name="supported-color-schemes" content="light">
<title>{_e(title)}</title>
<style>
  @media only screen and (max-width: 480px) {{
    .outer {{ padding: 8px 0 !important; }}
    .pad {{ padding-left: 16px !important; padding-right: 16px !important; }}
  }}
</style>
</head>
<body style="margin:0;padding:0;background:{_SOFT};">
<div style="display:none;max-height:0;overflow:hidden;opacity:0;color:{_SOFT};">{_e(preheader[:200])}</div>
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:{_SOFT};">
<tr><td class="outer" align="center" style="padding:24px 12px;">
<!--[if mso]><table role="presentation" width="640" cellpadding="0" cellspacing="0"><tr><td><![endif]-->
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:640px;background:#ffffff;border:1px solid {_BORDER};border-top:4px solid {color};border-radius:6px;font-family:{_FONT};color:{_TEXT};">
<tr><td class="pad" style="padding:24px 28px 8px;">
  <div style="margin:0 0 10px;">{_badge(level, badge)} <span style="font-size:13px;color:{_MUTED};padding-left:6px;">{_e(kicker)}</span></div>
  <h1 style="margin:0 0 18px;font-size:22px;line-height:1.3;color:{_TEXT};">{_e(title)}</h1>
  {body}
</td></tr>
<tr><td class="pad" style="padding:16px 28px 22px;border-top:1px solid {_BORDER};font-size:12px;line-height:1.5;color:{_MUTED};">
  {footer_note + "<br>" if footer_note else ""}{origin}. {sent_to}
</td></tr>
</table>
<!--[if mso]></td></tr></table><![endif]-->
</td></tr>
</table>
</body>
</html>
"""


# -----------------------------------------------------------------------------
# Entra links
# -----------------------------------------------------------------------------

_GUID_RE = re.compile(r"\A[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\Z")


def _object_id_from_event(event: dict) -> str:
    """Return the user's objectId if the audit record has it as a GUID.

    Do not use the ``ObjectId`` field. In sign-in records it holds the target
    application ID, not the user.
    """
    for field in ("UserKey", "UserId"):
        val = str(event.get(field, "")).strip()
        if _GUID_RE.match(val):
            return val
    return ""


def _entra_user_link(event: dict) -> str:
    """Link to the user in Entra ID.

    Order: a GUID in the record, then a Graph lookup (only if RESOLVE_USER_IDS
    is on), then the user list (the admin searches for the UPN).
    """
    base = config.PORTAL_BASE_URL
    object_id = _object_id_from_event(event)
    if not object_id and config.RESOLVE_USER_IDS:
        object_id = resolve_user_object_id(str(event.get("UserId", "")).strip())
    # Validate as a GUID again before it goes into the href.
    if object_id and _GUID_RE.match(object_id):
        return f"{base}/#view/Microsoft_AAD_UsersAndTenants/UserProfileMenuBlade/~/overview/userId/{object_id}"
    return f"{base}/#view/Microsoft_AAD_UsersAndTenants/UserManagementMenuBlade/~/AllUsers"


def _user_button(event: dict, user: str = "") -> str:
    """The user page in the management UI (button) and the user in Entra ID (link).

    ``user`` is the user of the finding (for an admin change, the account that
    was changed). Without it, the record's UserId. Without the management UI,
    the button opens Entra ID. A user that is not a UPN (an app) gets the
    Alerts page of the management UI.
    """
    link = _entra_user_link(event)
    text = "Open the user in Entra ID" if "userId/" in link else "Open Entra ID users (search for the user)"
    user = str(user or event.get("UserId") or "")
    page = ui_link("user", user) if "@" in user else ui_url("alerts")
    if not page:
        return _button(link, text)
    return (_button(page, "Open in the management UI").replace("margin:4px 0 24px;", "margin:4px 0 8px;")
            + _p(f"Or {_link(link, text[0].lower() + text[1:])}.", muted=True))


# -----------------------------------------------------------------------------
# Incident context and management UI links
# -----------------------------------------------------------------------------

_STATUS_TEXT = {"emailed": "alert sent", "email failed": "email failed", "alert off": "alert type off",
                "muted": "muted", "onboarding": "onboarding scan", "install": "made by install.ps1",
                "microsoft": "Microsoft service"}


def _repeats_text(row: dict) -> str:
    """The text " · seen 14 more times" for an alert with repeated records (no email for them), or ""."""
    n = int(row.get("repeats") or 0)
    return f" &middot; seen {n} more time{'s' if n != 1 else ''}" if n else ""


def _related(rows) -> str:
    """Other findings for the same user in the last 24 hours (journal rows), or ""."""
    rows = list(rows or [])
    if not rows:
        return ""
    high = any(r.get("severity") == "high" for r in rows)
    items = "".join(
        f'<li style="margin:0 0 4px;">{_e(_fmt_time(r.get("at")))}: <strong>{_e(short_title(r.get("type", "")))}'
        f'</strong> ({_e(r.get("severity") or "?")}, {_e(_STATUS_TEXT.get(r.get("status"), r.get("status", "")))})'
        f'{" &middot; " + _e(str(r.get("description"))[:160]) if r.get("description") else ""}'
        f'{_repeats_text(r)}</li>'
        for r in rows[:10]
    )
    more = f"<br>And {len(rows) - 10} more." if len(rows) > 10 else ""
    count = len(rows)
    head = (f"<strong>{count} other alert{'s' if count != 1 else ''} for this user in the last 24 hours."
            "</strong> Treat them as one incident." if count > 1 or high else
            "<strong>1 other alert for this user in the last 24 hours.</strong>")
    return _notice("high" if high else "medium",
                   f'{head}<ul style="margin:8px 0 0;padding-left:20px;font-size:14px;">{items}</ul>{more}')


def _respond_links(user: str, ftype: str, severity: str, rule_name: str = "") -> str:
    """Links to the user page (manual response) and, for medium alerts, to a prefilled mute."""
    page = ui_link("user", user) if "@" in str(user) else ""
    if not page:
        return ""
    text = (f"In the {_link(page, 'management UI')}, you can see the user's alerts, revoke sessions, "
            "block sign-in, and turn off inbox rules.")
    if severity != "high" and ftype:
        mute = ui_link("mute", ftype, user, rule_name)
        text += (f" If this alert is expected, {_link(mute, 'mute similar alerts')} for a set number of days.")
    return _p(text, muted=True)


# -----------------------------------------------------------------------------
# Compromise indicators
# -----------------------------------------------------------------------------

_COMPROMISE_STEPS = {
    "inbox_rule": [
        "Remove the inbox rule: Exchange admin center, or Outlook on the web &gt; Settings &gt; Mail &gt; Rules.",
        "Find out which mail the rule forwarded or deleted: Microsoft Purview &gt; Audit.",
    ],
    "mailbox_forwarding": [
        "Remove the forwarding address: Exchange admin center &gt; Mailboxes &gt; the user &gt; "
        "Mail flow settings &gt; Email forwarding.",
        "Find out which mail went to the forwarding address: Microsoft Purview &gt; Audit.",
    ],
    "oauth_consent": [
        "Remove the app's access: Entra ID &gt; Enterprise applications &gt; the app &gt; Permissions. "
        "If you do not know the app, delete it.",
        "Find out which data the app read: Microsoft Purview &gt; Audit.",
    ],
    "attack_tool": [
        "Treat the account as compromised. Check it for new inbox rules, mailbox forwarding, "
        "app consents, and MFA methods.",
    ],
    "suspicious_user_agent": [
        "If the client is not known (for example a script from your IT team), treat the account "
        "as compromised. Check it for new inbox rules, mailbox forwarding, and app consents.",
    ],
    "legacy_auth": [
        "Block legacy authentication: Entra ID &gt; Overview &gt; Properties &gt; Manage security "
        "defaults (on), or a Conditional Access policy (Entra ID P1).",
        "Check the account for new inbox rules, mailbox forwarding, app consents, and MFA methods.",
    ],
    "device_code": [
        "Ask the user (by phone, not email) if they entered a code on microsoft.com/devicelogin, "
        "for example for a TV, a meeting room device, or Azure CLI. If not, treat the account as "
        "compromised.",
        "Check the account for new MFA methods, inbox rules, mailbox forwarding, and app consents.",
    ],
    "mail_flow_rule": [
        "Remove or turn off the rule: Exchange admin center &gt; Mail flow &gt; Rules.",
        "Find out which mail the rule copied or deleted: Exchange admin center &gt; Mail flow &gt; "
        "Message trace.",
    ],
    "mailbox_delegation": [
        "Remove the permission: Exchange admin center &gt; Mailboxes &gt; the mailbox &gt; Delegation. "
        "For a folder: Remove-MailboxFolderPermission in Exchange Online PowerShell.",
        "Find out what the delegate read or sent: Microsoft Purview &gt; Audit.",
    ],
    "audit_disabled": [
        "Turn auditing on again. Exchange Online PowerShell: "
        "Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true, "
        "Set-OrganizationConfig -AuditDisabled $false, Set-Mailbox -AuditEnabled $true, or "
        "Set-MailboxAuditBypassAssociation -AuditBypassEnabled $false.",
        "Only an admin can do this. Review what the admin account did before and after: "
        "Microsoft Purview &gt; Audit.",
    ],
    "mail_protection_weakened": [
        "Restore the setting: Microsoft Defender portal &gt; Email &amp; collaboration &gt; Policies "
        "&amp; rules &gt; Threat policies. For DKIM: Email authentication settings &gt; DKIM.",
        "Look for mail that the change let through: Exchange admin center &gt; Mail flow &gt; "
        "Message trace.",
    ],
    "mfa_change": [
        "Check the sign-in methods: Entra ID &gt; Users &gt; the user &gt; Authentication methods. "
        "Ask the user (by phone, not email) about each method. Delete methods they do not know.",
        "An attacker adds an MFA method to keep access after a password reset.",
    ],
    "admin_role": [
        "Check the role members: Entra ID &gt; Roles and administrators &gt; the role. Remove members "
        "that no one approved.",
        "Review what the new admin did: Microsoft Purview &gt; Audit.",
    ],
    "app_credential": [
        "Check the app: Entra ID &gt; App registrations (or Enterprise applications) &gt; the app &gt; "
        "Certificates &amp; secrets. Delete credentials that no one on your team created.",
        "Find out what the app accessed: Microsoft Purview &gt; Audit.",
    ],
    "mail_access": [
        "Ask the user (by phone, not email) if they used a VPN, a hotel or guest network, or a new device at "
        "this time. The IP did not sign in as the user in the last 7 days, so a stolen session or token can "
        "be the cause.",
        "Open the user page &gt; Audit log. Compare the IP addresses of the sign-ins with the IP addresses of "
        "the mail reads and sends. Sent messages have a subject in the record; find the recipients with "
        "message trace (Exchange admin center &gt; Mail flow &gt; Message trace).",
        "If the user did not do it: revoke sessions, reset the password, and check MFA methods, inbox rules, "
        "and app consents. Tell the recipients of the sent mail that it is not genuine.",
    ],
    "session_reuse": [
        "Ask the user (by phone, not email) where they are, and if they use a VPN. A session that moves "
        "between countries within minutes or hours, or to a VPN or hosting IP that did not sign in, "
        "is often a stolen cookie or token. A VPN or travel can also cause it.",
        "Check the account for new inbox rules, mailbox forwarding, MFA methods, and app consents. "
        "Revoking sessions ends the stolen session; a password reset alone does not.",
    ],
    "domain_federation": [
        "Check the domains: Microsoft 365 admin center &gt; Settings &gt; Domains. Remove a domain or "
        "federation that no one on your team set up.",
        "A federated domain lets the owner of its sign-in server sign in as any user of that domain, "
        "without a password or MFA.",
    ],
}

# Changes that an admin or the user can make on purpose. The email asks the
# reader to confirm before the account is treated as compromised.
_CONFIRM_FIRST = {
    "suspicious_user_agent", "device_code", "mfa_change", "mail_flow_rule", "mailbox_delegation",
    "audit_disabled", "mail_protection_weakened", "admin_role", "app_credential", "domain_federation",
}


def send_compromise_alert(finding: dict, ip_context: str = "", subject_prefix: str = "",
                          outbox=None, action_result: str = "", related=None) -> bool:
    """Send an alert for one compromise indicator. ``related``: journal rows for the same user."""
    ftype = str(finding.get("type", ""))
    raw_user = str(finding.get("user", "Unknown"))
    level = "high" if finding.get("severity") == "high" else "medium"
    severity = level.upper()
    event = finding.get("event") or {}
    description = str(finding.get("description", ""))
    ip = str(finding.get("ip") or "")
    title = _FINDING_TITLES.get(ftype, ftype.replace("_", " ").capitalize() or "Compromise indicator")
    short = _FINDING_SHORT.get(ftype, title)
    is_test = "SELF-TEST" in subject_prefix

    raw_json = json.dumps(event, indent=2, default=str)
    if len(raw_json) > _MAX_EVENT_JSON_CHARS:
        raw_json = raw_json[:_MAX_EVENT_JSON_CHARS] + "\n... (truncated; see the unified audit log)"

    parts = []
    if is_test:
        parts.append(_notice("info", "<strong>Self-test.</strong> This alert is for a synthetic event "
                                     "from <code>/api/selftest</code>. No action is necessary."))
    parts.append(_p(f"<strong>{_e(raw_user)}</strong>: {_e(description)}"))
    if ip_context:
        parts.append(_notice(level, _e(ip_context) + "."))
    if action_result:
        parts.append(_response_notice(action_result))
    parts.append(_related(related))
    parts.append(_heading("What to do"))
    parts.append(_user_button(event, raw_user))
    first = ("If no one on your team made this change, treat the account that made it as "
             "compromised: revoke its sessions and reset its password."
             if ftype in _CONFIRM_FIRST or finding.get("confirm_first")
             else "Revoke the user's sessions and reset the password.")
    parts.append(_steps([first]
                        + _COMPROMISE_STEPS.get(ftype, ["Look for other attacker activity on the account."])))
    if not is_test:
        parts.append(_respond_links(raw_user, ftype, level, str(finding.get("rule_name") or "")))
    parts.append(_heading("Details"))
    facts = [("User", _e(raw_user))]
    # The account that made the change and the account it applies to, where they are not the user.
    for label, value in (("Changed by", finding.get("actor")), ("Changed account", finding.get("target"))):
        value = str(value or "")
        if value and value.lower() != raw_user.lower():
            facts.append((label, _e(value)))
    facts += [
        ("Time", _e(_fmt_time(event.get("CreationTime")))),
        ("Operation", _e(event.get("Operation", ""))),
        ("Source IP", _e(ip or "not in the record")),
        ("Audit record ID", _e(event.get("Id", ""))),
    ]
    parts.append(_facts(facts))
    parts.append(_heading("Audit record"))
    parts.append(_code(raw_json))

    body = _document(
        preheader=f"{raw_user}: {description}",
        level=level, badge=severity, kicker="Compromise indicator", title=title,
        body="".join(parts),
        footer_note="One email per finding. Severity is high when the source IP is a VPN, proxy, or "
                    "hosting address, or is in a country that is new for the user.",
    )
    subject = f"{ALERT_TAG} {subject_prefix}{severity}: {short} - {raw_user}"
    summary = f"{raw_user}: {description}" + (f" {ip_context}." if ip_context else "")
    return _deliver(subject, body, outbox, summary=summary, link=ui_link("user", raw_user) if "@" in raw_user else "")


# -----------------------------------------------------------------------------
# Sign-ins
# -----------------------------------------------------------------------------

def _subject_result(result: str) -> str:
    """Short result for a subject line: 'success', 'correct password', 'failed'."""
    if result == "Success":
        return "success"
    m = re.fullmatch(r"Failed \((\d+)\)", result)
    if m and _SIGNIN_ERRORS.get(m.group(1), "").startswith("correct password"):
        return "correct password"
    return "failed" if result.startswith("Failed") else result.lower()


def _signin_sentence(user: str, result: str, where_html: str) -> str:
    """One sentence that says what happened, from the sign-in result."""
    if result == "Success":
        return f"<strong>{_e(user)}</strong> signed in from {where_html}."
    m = re.fullmatch(r"Failed \((\d+)\)", result)
    note = _SIGNIN_ERRORS.get(m.group(1), "") if m else ""
    if note.startswith("correct password"):
        return (f"Someone entered the <strong>correct password</strong> for <strong>{_e(user)}</strong> "
                f"from {where_html}. The sign-in stopped at the next step ({_e(note[18:])}).")
    if not result.startswith("Failed"):
        return f"<strong>{_e(user)}</strong>: sign-in (result: {_e(result.lower())}) from {where_html}."
    detail = _describe_result(result)
    detail = f" ({_e(detail[8:-1])})" if detail.startswith("Failed (") else ""
    return f"<strong>{_e(user)}</strong>: failed sign-in{detail} from {where_html}."


def send_suspicious_login_alert(event: dict, ip: str, analysis: dict, outbox=None, related=None) -> bool:
    """Email one suspicious sign-in (flagged source IP).

    This is a weaker signal than a compromise indicator. Event dedup sends each
    sign-in at most one time.
    """
    raw_user = str(event.get("UserId", "Unknown"))
    result = login_result(event)
    confidence = str(analysis.get("confidence") or "low").lower()
    level = "high" if confidence == "high" else "medium"
    flags = _flag_text(analysis.get("flags", []))
    org = str(analysis.get("org") or "Unknown")
    asn = str(analysis.get("asn") or "")
    network = org + (f", {asn}" if asn else "")
    location = ", ".join(str(p) for p in (analysis.get("city"), analysis.get("country"))
                         if p and p != "Unknown") or "unknown"
    risk = analysis.get("risk_score", 0)

    where = f"<strong>{_e(ip)}</strong>, a <strong>{_e(flags)}</strong> address: {_e(network)}, {_e(location)}"
    parts = [
        _p(_signin_sentence(raw_user, result, where)),
        _related(related),
        _notice("info", "Many alerts like this are legitimate VPN use. If this IP is a known corporate "
                        "VPN or office, add it to " + (
                            _link(ui_url("settings"), "Allowed IPs in the management UI") if ui_url()
                            else _inline_code("ALLOWED_IPS")) + " to stop these alerts."),
        _heading("If you do not recognize this sign-in"),
        _user_button(event),
        _steps([
            "Revoke the user's sessions and reset the password.",
            "Check the mailbox for new inbox rules and forwarding.",
            "Check the user's app consents and MFA methods.",
        ]),
        _respond_links(raw_user, "suspicious_signin", level),
        _heading("Details"),
        _facts([
            ("User", _e(raw_user)),
            ("Result", _e(_describe_result(result))),
            ("Time", _e(_fmt_time(event.get("CreationTime")))),
            ("Source IP", _e(ip)),
            ("IP type", _e(flags)),
            ("Risk score", f"{_e(risk)}/100 (proxycheck.io)"),
            ("Network", _e(network)),
            ("Location", _e(location)),
        ]),
    ]
    body = _document(
        preheader=f"{raw_user}: {result} sign-in from {ip} ({flags}, {location})",
        level=level, badge=confidence.upper(), kicker="Suspicious sign-in",
        title=f"Sign-in from a {flags} address",
        body="".join(parts),
        footer_note=f"Settings: {_inline_code('LOGIN_ALERT_CONFIDENCE=' + config.LOGIN_ALERT_CONFIDENCE)}, "
                    f"{_inline_code('LOGIN_ALERT_MODE=' + config.LOGIN_ALERT_MODE)}. For fewer emails, "
                    "see docs/HOW_TO.md.",
    )
    subject = (f"{ALERT_TAG} {confidence.upper()}: Suspicious sign-in - {raw_user} from {ip}, "
               f"{_subject_result(result)}")
    return _deliver(subject, body, outbox, summary=f"{raw_user}: {result} sign-in from {ip} ({flags}, {location}).",
                    link=ui_link("user", raw_user) if "@" in raw_user else "")


def _response_notice(action_result: str) -> str:
    """Show the automatic response result ("A: done; B failed: ...; none (reason)")."""
    parts = [p.strip() for p in action_result.split(";") if p.strip()]
    done = [p.split(":")[0].strip() for p in parts if p.endswith(": done")]
    failed = [p for p in parts if "failed" in p]
    skipped = [p[4:].strip(" ()") for p in parts if p.startswith("none")]
    if not done and not failed:
        return _notice("info", f"<strong>No automatic response</strong> ({_e('; '.join(skipped))}).")
    words = {"Block sign-in": "sign-in blocked", "Revoke sessions": "sessions revoked",
             "Disable inbox rule": "inbox rule turned off"}
    pieces = []
    if done:
        pieces.append("<strong>Automatic response:</strong> " + ", ".join(words.get(d, d) for d in done) + ".")
    if failed:
        pieces.append("<strong>Failed:</strong> " + _e("; ".join(failed)) + ". Do these steps by hand.")
    if skipped:
        pieces.append("Not done: " + _e("; ".join(skipped)) + ".")
    return _notice("high" if failed else "ok", " ".join(pieces))


def send_country_anomaly_alert(anomaly: dict, action_result: str, outbox=None, related=None) -> bool:
    """Email one sign-in from a country outside the user's baseline."""
    event = anomaly["event"]
    analysis = anomaly.get("analysis") or {}
    raw_user = str(event.get("UserId", "Unknown"))
    cc = str(anomaly.get("country", "??"))
    country = f"{analysis.get('country') or cc} ({cc})"
    result = login_result(event)
    password_ok = anomaly.get("outcome") == "password_ok"
    ip = str(anomaly.get("ip", ""))
    org = str(analysis.get("org") or "Unknown")
    asn = str(analysis.get("asn") or "")
    network = org + (f", {asn}" if asn else "")
    usual = ", ".join(anomaly.get("known") or []) or "none recorded"
    blocked = "Block sign-in: done" in action_result

    where = f"<strong>{_e(country)}</strong>: IP {_e(ip)}, {_e(network)}"
    parts = [
        _p(_signin_sentence(raw_user, result, where)),
        _p(f"This user usually signs in from: <strong>{_e(usual)}</strong>."),
        _response_notice(action_result),
        _related(related),
        _heading("If you do not recognize this sign-in"),
        _user_button(event),
        _steps(
            (["Reset the password now. The attacker knows it."] if password_ok else
             ["Revoke the user's sessions (if not done above) and reset the password."])
            + ["Check the mailbox for new inbox rules and forwarding.",
               "Check the user's app consents and MFA methods."]
        ),
        _respond_links(raw_user, "new_country", "high"),
    ]
    approve = ui_url(f"countries:{raw_user.lower()}")
    if blocked or approve:
        parts.append(_heading("If the sign-in is legitimate (for example travel)"))
        if approve:
            parts.append(_p(f"{_link(approve, f'Approve {cc} for this user')} in the management UI. "
                            "Then this country causes no more alerts for the user."))
        if blocked:
            parts += [
                _p("Enable the account again: Entra ID &gt; Users &gt; the user &gt; Edit properties &gt; "
                   "Account enabled. Or run:"),
                _code(f"az ad user update --id {raw_user} --account-enabled true"),
            ]
    parts += [
        _heading("Details"),
        _facts([
            ("User", _e(raw_user)),
            ("Result", _e(_describe_result(result))),
            ("Time", _e(_fmt_time(event.get("CreationTime")))),
            ("Country", _e(country)),
            ("Usual countries", _e(usual)),
            ("Source IP", _e(ip)),
            ("Network", _e(network)),
            ("City", _e(analysis.get("city") or "")),
        ]),
    ]
    body = _document(
        preheader=f"{raw_user}: {result} sign-in from {country}. Usual countries: {usual}.",
        level="high", badge="HIGH", kicker="New sign-in country",
        title=f"Sign-in from a new country: {analysis.get('country') or cc}",
        body="".join(parts),
        footer_note=f"One alert per user and country in 24 hours. A country becomes usual for a user "
                    f"after successful sign-ins on {config.GEO_PROMOTE_DAYS} different days.",
    )
    subject = f"{ALERT_TAG} HIGH: Sign-in from new country {cc} - {raw_user}, {_subject_result(result)}"
    return _deliver(subject, body, outbox, summary=f"{raw_user}: {result} sign-in from {country}. Usual countries: {usual}.",
                    link=ui_link("user", raw_user) if "@" in raw_user else "")


def send_login_digest(entries: list, outbox=None) -> bool:
    """Send one email that lists several queued suspicious sign-ins."""
    count = len(entries)
    ordered = sorted(entries, key=lambda x: str(x.get("creation_time", "")), reverse=True)
    top = "high" if any(str(e.get("confidence")) == "high" for e in entries) else "medium"

    cards = []
    for e in ordered:
        flags = _flag_text([f.strip() for f in str(e.get("flags", "")).split(",") if f.strip()])
        result = _describe_result(str(e.get("result", "")))
        cards.append(
            f'<tr><td style="padding:12px 0;border-bottom:1px solid {_BORDER};font-size:14px;line-height:1.5;">'
            f'<strong>{_e(e.get("user", ""))}</strong> &middot; {_e(result)}<br>'
            f'<span style="color:{_TEXT};">{_e(e.get("ip", ""))} &middot; {_e(flags)} &middot; '
            f'risk {_e(e.get("risk", ""))}/100 &middot; {_e(str(e.get("confidence", "")))} confidence</span><br>'
            f'<span style="color:{_MUTED};font-size:13px;">{_e(e.get("org", ""))} &middot; '
            f'{_e(e.get("location", "") or "unknown")} &middot; {_e(_fmt_time(e.get("creation_time")))}</span>'
            f'</td></tr>'
        )
    users_link = _entra_user_link({})
    parts = [
        _p(f"proxycheck.io flagged the source IP of these {count} sign-ins. Many are legitimate VPN use."),
        f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
        f'style="border-top:1px solid {_BORDER};margin:0 0 8px;">{"".join(cards)}</table>',
        _heading("For each sign-in that you do not recognize"),
        _steps([
            f"Open the user: {_link(users_link, 'Entra ID users')}.",
            "Revoke the user's sessions and reset the password.",
            "Check the mailbox for new inbox rules and forwarding.",
        ]),
    ]
    body = _document(
        preheader=f"{count} flagged sign-ins. Newest: {ordered[0].get('user', '')} from {ordered[0].get('ip', '')}."
        if ordered else "No sign-ins.",
        level=top, badge=top.upper(), kicker="Suspicious sign-ins (digest)",
        title=f"{count} suspicious sign-in{'s' if count != 1 else ''}",
        body="".join(parts),
        footer_note=f"Digest mode is on ({_inline_code('LOGIN_ALERT_MODE=digest')}). Set "
                    f"{_inline_code('immediate')} for one email per sign-in.",
    )
    # With the outbox, an email that Graph refuses waits there. Without it, the next run would send
    # the digest again, also to the webhook.
    return _deliver(f"{ALERT_TAG} {top.upper()}: {count} suspicious sign-in{'s' if count != 1 else ''}", body, outbox,
                    summary=f"{count} flagged sign-ins in the digest.")


# -----------------------------------------------------------------------------
# Information emails
# -----------------------------------------------------------------------------

def _stat(value, label: str, level: str) -> str:
    color = _LEVELS[level][0] if value else _TEXT
    return (f'<td width="25%" style="padding:12px 8px;text-align:center;vertical-align:top;'
            f'border:1px solid {_BORDER};">'
            f'<div style="font-size:26px;font-weight:700;line-height:1.2;color:{color};">{int(value):,}</div>'
            f'<div style="font-size:12px;line-height:1.4;color:{_MUTED};">{_e(label)}</div></td>')


def send_summary_email(total: int, suspicious: int, unique_ips: int, period_label: str,
                       outbox=None, compromise: int = 0, country: int = 0) -> bool:
    """Send the monthly roll-up email (counts for the last 30 days)."""
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=30)
    period = f"{start.day} {start:%b} to {now.day} {now:%b %Y}"
    to_review = int(compromise) + int(country) + int(suspicious)
    if compromise or country:
        level, badge = "high", f"{to_review} TO REVIEW"
    elif suspicious:
        level, badge = "medium", f"{to_review} TO REVIEW"
    else:
        level, badge = "ok", "NO ALERTS"

    tiles = (f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
             f'style="border-collapse:collapse;margin:0 0 16px;"><tr>'
             f'{_stat(compromise, "Compromise indicators", "high")}'
             f'{_stat(country, "New-country sign-ins", "high")}'
             f'{_stat(suspicious, "Suspicious sign-ins", "medium")}'
             f'{_stat(unique_ips, "Unique suspicious IPs", "medium")}'
             f'</tr></table>')
    if to_review:
        review = _p("Each item had its own alert email. The management UI lists them by user. To list "
                    "them all, run these queries in "
                    "Application Insights &gt; Logs: <em>Compromise indicators</em>, <em>New-country "
                    "sign-ins and response actions</em>, and <em>Suspicious sign-ins</em> "
                    "(docs/APP_INSIGHTS_QUERIES.md).")
    else:
        review = _p("No compromise indicators, new-country sign-ins, or suspicious sign-ins in this period.")
    parts = [
        _p(f"In the last 30 days, the monitor checked <strong>{int(total):,}</strong> sign-ins."),
        tiles,
        review,
        _posture_section(),
    ]
    body = _document(
        preheader=f"{period}: {compromise} compromise indicators, {country} new-country sign-ins, "
                  f"{suspicious} suspicious sign-ins.",
        level=level, badge=badge, kicker=f"{period_label} report",
        title=f"{period_label} report: {period}",
        body="".join(parts),
        footer_note="This report arrives on the 1st of each month. If it does not arrive, the monitor "
                    "did not run: check /api/status.",
    )
    summary = f"{to_review} alert{'s' if to_review != 1 else ''} to review" if to_review else "no alerts"
    subject = f"{INFO_TAG} {period_label} report, {period}: {summary}"
    return _deliver(subject, body, outbox)


# -----------------------------------------------------------------------------
# Posture: settings that weaken protection (weekly, monthly, onboarding reports)
# -----------------------------------------------------------------------------

_RESPONSE_TEXT = {"none": "email only", "revoke": "revoke sessions", "disable": "block sign-in"}
_CONFIDENCE_TEXT = {"low": "all", "medium": "medium and high confidence", "high": "high confidence only"}


def posture(now: datetime = None) -> list:
    """[(label, text, review)]. ``review`` is True for a setting that weakens protection or needs action."""
    import settings as settings_mod
    now = now or datetime.now(timezone.utc)
    rows = []
    scope = os.environ.get("MAIL_SEND_SCOPE", "tenant")
    group = os.environ.get("MAIL_SEND_GROUP", "")
    rows.append(("Mail.Send permission",
                 (f"Members of the Exchange group {group} only" if group else "Alert mailbox only")
                 if scope == "mailbox" else
                 f"Any mailbox in the tenant. To limit it to the alert mailbox ({config.ADMIN_EMAIL}), run "
                 "./install.ps1 -MailSendScope mailbox as shown (the word \"mailbox\", not an address).",
                 scope != "mailbox"))
    if config.ALERT_DELIVERY == "webhook" and config.WEBHOOK_URL:
        rows.append(("Alert delivery", "Webhook only. Alerts go by email only when the webhook fails. "
                     "Changes in the management UI still go by email.", True))
    labels = dict(settings_mod.ALERT_TYPES)
    off = [labels.get(t, t) for t in sorted(config.ALERTS_OFF)]
    rows.append(("Alert types off", ", ".join(off) if off else "None", bool(off)))
    mutes = admin_store.active_mutes(now)
    rows.append(("Active mutes", "; ".join(admin_store.describe_mute(m) for m in mutes[:3])
                 + (f"; and {len(mutes) - 3} more" if len(mutes) > 3 else "") if mutes else "None", bool(mutes)))
    conf = config.LOGIN_ALERT_CONFIDENCE
    signin_off = conf in ("off", "none", "disabled", "never")
    rows.append(("Suspicious sign-in emails", "Off (log only)" if signin_off else
                 _CONFIDENCE_TEXT.get(conf, "all").capitalize(), signin_off))
    rows.append(("New-country alerts", "On" if config.GEO_ANOMALY_ENABLED else "Off", not config.GEO_ANOMALY_ENABLED))
    rows.append(("Stolen-session check", "On" if config.SESSION_CHECK_ENABLED else "Off",
                 not config.SESSION_CHECK_ENABLED))
    rows.append(("Mail access check", "On" if config.MAIL_ACCESS_CHECK else "Off", not config.MAIL_ACCESS_CHECK))
    allow = (f"{len(config.ALLOWED_NETWORKS)} IP ranges, {len(config.ALLOWED_ASNS)} networks (ASNs), "
             f"{len(config.INTERNAL_DOMAINS)} extra internal domains. iCloud Private Relay: "
             f"{'treated as normal' if config.PRIVATE_RELAY_TRUSTED else 'checked as VPN'}.")
    rows.append(("Allowlists", allow, bool(config.ALLOWED_NETWORKS or config.ALLOWED_ASNS)))
    rows.append(("Automatic response",
                 f"New country: {_RESPONSE_TEXT.get(config.ANOMALY_ACTION, config.ANOMALY_ACTION)}. "
                 f"High account-takeover alert: {_RESPONSE_TEXT.get(config.COMPROMISE_ACTION, config.COMPROMISE_ACTION)}. "
                 f"Malicious inbox rules: {'turned off' if config.AUTO_DISABLE_INBOX_RULES else 'email only'}.",
                 False))
    extra = sorted(set(config.ALERT_RECIPIENTS) | set(config.REPORT_RECIPIENTS))
    if extra:
        rows.append(("Extra recipients", ", ".join(extra), False))
    return rows


def _posture_section(now: datetime = None) -> str:
    rows = posture(now)
    review = sum(1 for r in rows if r[2])
    cells = []
    for label, text, flag in rows:
        mark = (f'<span style="display:inline-block;background:{_LEVELS["medium"][1]};color:{_LEVELS["medium"][0]};'
                f'font-size:11px;font-weight:700;padding:1px 6px;border-radius:3px;margin-right:6px;">REVIEW</span>'
                if flag else "")
        cells.append((label, mark + _e(text)))
    intro = (f"{review} setting{'s' if review != 1 else ''} weaken{'' if review != 1 else 's'} protection "
             "or need action. Change them in the management UI > Settings."
             if review else "No setting weakens protection.")
    return _heading("Settings that affect protection") + _p(intro) + _facts(cells)


def _findings_table(rows: list, limit: int = 25, total: int = 0) -> str:
    """Journal rows as a compact list, high first, then newest. ``total``: the count of all rows."""
    ordered = sorted(rows, key=lambda r: str(r.get("at", "")), reverse=True)
    ordered = sorted(ordered, key=lambda r: r.get("severity") != "high")   # stable: high first, newest first
    items = []
    for r in ordered[:limit]:
        level = "high" if r.get("severity") == "high" else "medium"
        user = str(r.get("user") or "")
        page = ui_link("user", user) if "@" in user else ""
        who = _link(page, user) if page else _e(user)
        items.append(
            f'<tr><td style="padding:8px 0;border-bottom:1px solid {_BORDER};font-size:14px;line-height:1.5;">'
            f'<span style="color:{_LEVELS[level][0]};font-weight:700;">{_e(level.upper())}</span> '
            f'<strong>{_e(short_title(r.get("type", "")))}</strong> &middot; {who}<br>'
            f'<span style="color:{_MUTED};font-size:13px;">{_e(_fmt_time(r.get("at")))} &middot; '
            f'{_e(_STATUS_TEXT.get(r.get("status"), r.get("status", "")))}</span><br>'
            f'{_e(str(r.get("description") or "")[:300])}</td></tr>')
    shown = min(limit, len(rows))
    total = max(total, len(rows))
    more = _p(f"And {total - shown} more. See the management UI.", muted=True) if total > shown else ""
    return (f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
            f'style="border-top:1px solid {_BORDER};margin:0 0 8px;">{"".join(items)}</table>{more}')


def _count_rows(counts: dict) -> str:
    rows = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    return _facts([(short_title(t), _e(f"{n:,}")) for t, n in rows])


# -----------------------------------------------------------------------------
# Weekly health report
# -----------------------------------------------------------------------------

def send_weekly_report(stats, findings: list, health: dict, now: datetime = None, outbox=None,
                       totals: dict = None) -> bool:
    """Weekly report: the monitor ran, what it checked, the week's alerts, and posture.

    ``stats``: insights_client.get_stats(7), or None. ``findings``: journal
    rows of the last 7 days (it can be a shorter list, high first).
    ``totals``: journal.summary of all alert rows of the week; without it,
    the counts come from ``findings``. ``health``: {"last_content": datetime
    or None, "queues": {...}, "onboarding": summary or None}.
    """
    now = now or datetime.now(timezone.utc)
    start = now - timedelta(days=7)
    period = f"{start.day} {start:%b} to {now.day} {now:%b %Y}"
    alerts = [f for f in findings if f.get("status") not in ("onboarding", "install", "microsoft")]
    high = [f for f in alerts if f.get("severity") == "high"]
    if totals is None:
        totals = {"total": len(alerts), "high": len(high), "by_type": {}, "by_status": {}}
        for f in alerts:
            totals["by_type"][f.get("type", "")] = totals["by_type"].get(f.get("type", ""), 0) + 1
            totals["by_status"][f.get("status")] = totals["by_status"].get(f.get("status"), 0) + 1
    n_alerts, n_high, by_status = totals["total"], totals["high"], totals["by_status"]

    problems = []
    expected = 7 * 24 * 30
    if stats is None:
        problems.append("Run and sign-in counts are not available: the Application Insights query failed.")
    else:
        if stats.get("runs", 0) < expected * 0.95:
            problems.append(f"The monitor completed {stats.get('runs', 0):,} runs. About {expected:,} were "
                            "expected (one every 2 minutes). Check Application Insights for errors.")
        if stats.get("gaps"):
            problems.append(f"{stats['gaps']} coverage gap{'s' if stats['gaps'] != 1 else ''}: some audit "
                            "content was not fully processed. Search Application Insights for 'Coverage gap'.")
        if stats.get("errors"):
            problems.append(f"{stats['errors']:,} errors in the log. Run the query 'Errors' "
                            "(docs/APP_INSIGHTS_QUERIES.md).")
    last = health.get("last_content")
    if last is None:
        problems.append("No audit content was received yet.")
    elif now - last > timedelta(hours=24):
        problems.append(f"The last audit content arrived {_fmt_time(last.isoformat())}. Check that unified "
                        "audit logging is on.")
    queues = health.get("queues") or {}
    if queues.get("outbox"):
        problems.append(f"{queues['outbox']} email(s) wait in the outbox: Graph refused them.")
    if queues.get("pending_ip_checks"):
        problems.append(f"{queues['pending_ip_checks']} sign-in IP check(s) wait: check the proxycheck.io quota.")
    lookups = health.get("ip_lookups") or {}
    usage = quota_usage_text(lookups)
    if lookups.get("level") == "exhausted":
        problems.append("The proxycheck.io quota is used up" + (f": {usage}" if usage else " today")
                        + ". Sign-in checks wait until it resets.")
    elif lookups.get("level") == "low":
        problems.append("The proxycheck.io quota is low" + (f": {usage}" if usage else " today") + ".")
    elif lookups.get("level") == "refused":
        problems.append("proxycheck.io refuses IP lookups. Check the key in the proxycheck.io dashboard.")
    onboarding = health.get("onboarding")
    if onboarding and onboarding.get("step") not in (None, "done"):
        problems.append(f"The onboarding scan is not finished (step: {onboarding.get('step')}).")

    if n_high or problems:
        level, badge = "high" if n_high else "medium", f"{n_high + len(problems)} TO REVIEW"
    elif n_alerts:
        level, badge = "info", f"{n_alerts} ALERT{'S' if n_alerts != 1 else ''}"
    else:
        level, badge = "ok", "ALL CLEAR"

    if stats is not None:
        checked = (f"In the last 7 days, the monitor completed <strong>{stats.get('runs', 0):,}</strong> runs "
                   f"and checked <strong>{stats.get('total_events', 0):,}</strong> sign-ins.")
    else:
        checked = "In the last 7 days, the monitor ran. The counts are not available."
    if last is not None:
        checked += f" The last audit content arrived {_e(_fmt_time(last.isoformat()))}."
    parts = [_p(checked)]
    if problems:
        parts.append(_notice("high" if any("not" in p for p in problems) else "medium",
                             "<strong>Check these:</strong>" + _steps([_e(p) for p in problems])))
    else:
        parts.append(_notice("ok", "<strong>The monitor works.</strong> No gaps, errors, or queued emails."))

    tiles = (f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
             f'style="border-collapse:collapse;margin:0 0 16px;"><tr>'
             f'{_stat(n_high, "High alerts", "high")}'
             f'{_stat(n_alerts - n_high, "Medium alerts", "medium")}'
             f'{_stat(by_status.get("muted", 0), "Muted", "medium")}'
             f'{_stat(by_status.get("alert off", 0), "Alert type off", "medium")}'
             f'</tr></table>')
    parts.append(_heading("Alerts this week"))
    parts.append(tiles)
    if n_alerts:
        parts.append(_count_rows(totals["by_type"]))
        if high:
            parts.append(_heading("High alerts"))
            parts.append(_findings_table(high, 10, total=n_high))
    else:
        parts.append(_p("No alerts this week."))
    if "mail_access" in health:
        parts.append(_heading("Mail access logging"))
        parts.append(_p(_e(mail_access.describe(health.get("mail_access"))), muted=True))
    parts.append(_posture_section(now))
    body = _document(
        preheader=f"{period}: {n_high} high alerts, {n_alerts} alerts in total, "
                  f"{len(problems)} health items.",
        level=level, badge=badge, kicker="Weekly report", title=f"Weekly report: {period}",
        body="".join(parts),
        footer_note="This report arrives each Monday. If it does not arrive, the monitor did not run. "
                    "Turn it off: management UI &gt; Settings &gt; Alerts.",
    )
    summary = (f"{n_high} high alert{'s' if n_high != 1 else ''}" if n_high else
               f"{n_alerts} alert{'s' if n_alerts != 1 else ''}" if n_alerts else "all clear")
    if problems:
        summary += f", {len(problems)} health item{'s' if len(problems) != 1 else ''}"
    return _deliver(f"{INFO_TAG} Weekly report, {period}: {summary}", body, outbox)


# -----------------------------------------------------------------------------
# Onboarding report (starting state)
# -----------------------------------------------------------------------------

_MANUAL_CHECKS = [
    "Mailbox forwarding. Run in Exchange Online PowerShell:"
    + _code("Get-Mailbox -ResultSize Unlimited |\n  Where-Object { $_.ForwardingSmtpAddress -or $_.ForwardingAddress } |\n"
            "  Format-Table Name, ForwardingSmtpAddress, ForwardingAddress"),
    "App consents: Entra ID &gt; Enterprise applications &gt; All applications. Look for apps that no one "
    "on your team added, and apps with mail or file permissions.",
    "Admin roles: Entra ID &gt; Roles and administrators &gt; Global Administrator (and other admin "
    "roles). Remove members that no one approved.",
    "MFA methods: Entra ID &gt; Authentication methods &gt; User registration details. Look for phone "
    "numbers and apps that users do not know.",
    "Mail flow rules: Exchange admin center &gt; Mail flow &gt; Rules.",
    "Domains and federation: Microsoft 365 admin center &gt; Settings &gt; Domains.",
]


def _search_text(sr: dict) -> str:
    """The audit search part of the onboarding report (older history, up to 180 days)."""
    if sr.get("skipped"):
        level = "medium" if "permission" in sr["skipped"] else "info"
        return _notice(level, f"<strong>Older history not searched</strong>: {_e(sr['skipped'])}. The audit log "
                              "keeps 180 days. Run the scan again after the fix: management UI &gt; Overview &gt; Tools.")
    n = int(sr.get("records") or 0)
    text = (f"Before that: the audit search read <strong>{n:,}</strong> records of changes (no sign-ins)"
            + (f" from {_e(_fmt_time(sr.get('earliest')))} to {_e(_fmt_time(sr.get('latest')))}." if n else
               f" from {_e(_fmt_time(sr.get('from')))} to {_e(_fmt_time(sr.get('to')))}."))
    if sr.get("limit_exceeded"):
        text += " Microsoft stopped the search at its record limit, so some records can be missing."
    return _p(text)


def send_onboarding_report(state: dict, findings: list, outbox=None) -> bool:
    """The starting state of the tenant (onboarding.py): history, sign-ins, inbox rules, posture."""
    h, r = state.get("history", {}), state.get("rules", {})
    sr = state.get("search") or {}
    flagged = r.get("flagged") or []
    # The scan counts every finding. ``findings`` can be a shorter list (high first).
    counted = int(h.get("findings") or 0) + int(sr.get("findings") or 0)
    found = max(len(findings), counted) if state.get("kind") == "full" else len(findings)
    high = max(sum(f.get("severity") == "high" for f in findings), int(h.get("high") or 0) + int(sr.get("high") or 0))
    high_rules = [x for x in flagged if x.get("severity") == "high"]
    to_review = found + int(r.get("flagged_count") or 0)
    if high or high_rules:
        level, badge = "high", f"{to_review} TO REVIEW"
    elif to_review:
        level, badge = "medium", f"{to_review} TO REVIEW"
    else:
        level, badge = "ok", "NOTHING FOUND"
    name = config.TENANT_LABEL or "your tenant"

    parts = [_p(f"The monitor checked the current state of {_e(name)}. It found <strong>{to_review}</strong> "
                f"item{'s' if to_review != 1 else ''} to review. No separate alert email was sent for these.")]

    parts.append(_heading("Audit history"))
    records = int(h.get("records") or 0) + int(sr.get("records") or 0)
    if state.get("kind") == "rules":
        parts.append(_p("Not read in this scan (inbox rules only)."))
    else:
        if int(h.get("records") or 0):
            parts.append(_p(f"Last 7 days: the monitor read <strong>{int(h['records']):,}</strong> audit records "
                            f"from {_e(_fmt_time(h.get('earliest')))} to {_e(_fmt_time(h.get('latest')))}, with "
                            f"{int(h.get('signins') or 0):,} sign-ins."))
        else:
            parts.append(_p("Last 7 days: no audit content was available. The feed has content only from when the "
                            "audit subscription started. For a new deployment, this is normal."))
        parts.append(_search_text(sr))
    for err in h.get("errors") or []:
        parts.append(_p("Error: " + _e(err), muted=True))
    if findings:
        counts = dict(h.get("by_type") or {})
        for k, v in (sr.get("by_type") or {}).items():
            counts[k] = counts.get(k, 0) + v
        if sum(counts.values()) < len(findings):
            counts = {}
            for f in findings:
                counts[f.get("type", "")] = counts.get(f.get("type", ""), 0) + 1
        parts.append(_count_rows(counts))
        parts.append(_findings_table(findings, 25, total=found))
    elif records:
        parts.append(_p("No compromise indicators in the audit history."))
    if int(h.get("flagged_signins") or 0):
        users = sorted((h.get("flagged_users") or {}).items(), key=lambda kv: -kv[1])[:10]
        parts.append(_p(f"{int(h['flagged_signins']):,} sign-ins came from VPN, proxy, or hosting IPs. Users "
                        "with the most: " + _e(", ".join(f"{u} ({n})" for u, n in users)) + "."))
    if int(h.get("seeded_users") or 0):
        parts.append(_p(f"The sign-in countries of {int(h['seeded_users'])} users went into the country "
                        "baseline.", muted=True))
    microsoft = int(h.get("microsoft") or 0) + int(sr.get("microsoft") or 0)
    if microsoft:
        parts.append(_p(f"{microsoft} change{'s' if microsoft != 1 else ''} by Microsoft services (apps that belong to "
                        "Microsoft) are not listed. The management UI shows them in Alerts as \"Microsoft service\".",
                        muted=True))

    parts.append(_heading("Inbox rules in all mailboxes"))
    if r.get("skipped"):
        parts.append(_notice("medium", f"<strong>Not checked</strong>: {_e(r['skipped'])}. To turn the check "
                                       "on, run <code>./install.ps1 -Update</code> (it grants the permissions), "
                                       "then select Tools &gt; Scan inbox rules "
                                       "in the management UI."))
    else:
        parts.append(_p(f"The monitor read the inbox rules of <strong>{int(r.get('checked') or 0):,}</strong> "
                        f"of {int(r.get('mailboxes') or 0):,} users ({int(r.get('no_mailbox') or 0):,} have no "
                        f"mailbox, {int(r.get('errors') or 0):,} errors). Rules that only Outlook desktop runs "
                        "are not visible."))
        if r.get("error_text"):
            parts.append(_p("First error: " + _e(r["error_text"]), muted=True))
        if flagged:
            items = []
            for x in sorted(flagged, key=lambda x: x.get("severity") != "high"):
                page = ui_link("user", x.get("mailbox", ""))
                who = _link(page, x.get("mailbox", "")) if page else _e(x.get("mailbox", ""))
                items.append(f"<strong>{_e(x.get('severity', '').upper())}</strong> {who}: rule "
                             f"'{_e(x.get('name', ''))}' {_e('; '.join(x.get('reasons') or []))}.")
            parts.append(_steps(items))
            extra = int(r.get("flagged_count") or 0) - len(flagged)
            if extra > 0:
                parts.append(_p(f"And {extra} more. See the management UI.", muted=True))
            parts.append(_p("Ask each user (by phone, not email) if they made the rule. Remove rules that they "
                            "did not make, then treat the account as compromised."))
        else:
            parts.append(_p("No suspicious inbox rules."))

    parts.append(_heading("Not checked by this scan"))
    parts.append(_p("Check these by hand one time:"))
    parts.append(_steps(_MANUAL_CHECKS))
    parts.append(_posture_section())
    body = _document(
        preheader=f"Starting state: {to_review} items to review.",
        level=level, badge=badge, kicker="Onboarding scan", title=f"Starting state of {name}",
        body="".join(parts),
        footer_note="Run the scan again: management UI &gt; Overview &gt; Tools.",
    )
    summary = f"{to_review} item{'s' if to_review != 1 else ''} to review" if to_review else "nothing found"
    return _deliver(f"{INFO_TAG} Starting state: {summary}", body, outbox)


def send_setup_confirmation() -> bool:
    """One-time email: the monitor fetched audit data for the first time."""
    levels = {"low": "all confidence levels", "medium": "medium and high confidence",
              "high": "high confidence only"}
    if config.LOGIN_ALERT_CONFIDENCE in ("off", "none", "disabled", "never"):
        signin = "No email (LOGIN_ALERT_CONFIDENCE=off). Logged in Application Insights only."
    else:
        how = "One email each" if config.LOGIN_ALERT_MODE == "immediate" else "One digest email"
        signin = (f"{how}, {levels.get(config.LOGIN_ALERT_CONFIDENCE, 'all confidence levels')}. "
                  "VPN users can cause alerts.")
    responses = {"none": "off (email only)", "revoke": "revoke sessions",
                 "disable": "block sign-in and revoke sessions"}
    if config.GEO_ANOMALY_ENABLED:
        geo = (f"One email per user and new country, after a {config.GEO_LEARNING_DAYS}-day learning "
               f"period. Automatic response: {responses.get(config.ANOMALY_ACTION, config.ANOMALY_ACTION)}.")
    else:
        geo = "Off (GEO_ANOMALY_ENABLED=false)."
    rows = [
        ("Compromise indicators", "One email each: inbox rules, mailbox forwarding, OAuth consents, attack tools."),
        ("Suspicious sign-ins", signin),
        ("New sign-in countries", geo),
        ("Monthly report", "The 1st of each month, for the last 30 days."),
        ("Health alerts", "From Azure Monitor, if the monitor stops or errors repeat."),
    ]
    steps = [
        ("Send a test alert: management UI &gt; Overview &gt; Send test alert" if ui_url()
         else f"Send a test alert: run {_inline_code('./install.ps1 -Verify -SendTestAlerts')}")
        + ". You get an email whose subject contains [SELF-TEST].",
        f"Keep alerts out of junk mail: add a mail rule for subjects that start with "
        f"{_inline_code(ALERT_TAG)}.",
    ]
    if os.environ.get("MAIL_SEND_SCOPE", "tenant") != "mailbox":
        steps.append(f"Limit Mail.Send to this mailbox: run {_inline_code('./install.ps1 -MailSendScope mailbox')} "
                     "as shown (the word \"mailbox\", not an address; the script uses this mailbox). "
                     "Now the app can send as any mailbox.")
    if not config.PROXYCHECK_API_KEY:
        steps.append("Add a free proxycheck.io API key: management UI &gt; Settings &gt; Suspicious sign-ins. "
                     "Without a key, the limit is 100 IP lookups per day.")
    parts = [
        _p("The monitor fetched audit data from your tenant. It checks the audit log every 2 minutes."),
        _button(ui_url(), "Open the management UI") if ui_url() else "",
        _heading("What you will receive"),
        _facts([(label, _e(text)) for label, text in rows]),
        _heading("Next steps"),
        _steps(steps),
    ]
    body = _document(
        preheader="The monitor is active. Next: send a test alert.",
        level="ok", badge="ACTIVE", kicker="Setup", title="M365 ATO Monitor is active",
        body="".join(parts),
        footer_note="You receive this email one time only.",
    )
    return _deliver(f"{INFO_TAG} Setup complete: the monitor is active", body, None)


def quota_usage_text(state: dict) -> str:
    """ "850 of 1,000 queries used today (Free plan)", or "" if the count is not known."""
    used, limit = state.get("used"), state.get("limit")
    if used is None or not limit:
        return ""
    plan = f" ({state['plan']} plan)" if state.get("plan") else ""
    return f"{used:,} of {limit:,} queries used today{plan}"


def send_quota_warning(state: dict) -> bool:
    """Email: the proxycheck.io daily query limit is almost or completely used, or the key is refused."""
    import proxycheck_quota
    level = state.get("level")
    titles = {"low": "proxycheck.io quota is low",
              "exhausted": "proxycheck.io quota is used up",
              "refused": "proxycheck.io refuses IP lookups"}
    title = titles.get(level, "proxycheck.io quota")
    usage = quota_usage_text(state)
    said = state.get("message") or ""
    lines = []
    if said:
        lines.append(_p(f"proxycheck.io answered: <strong>{_e(said)}</strong>"))
    if usage:
        lines.append(_p(_e(usage[0].upper() + usage[1:]) + "."))
    if level == "low":
        lines.append(_p("When the limit is used up, the monitor cannot check sign-in IPs until proxycheck.io "
                        "resets the count the next day."))
    steps = []
    if level == "refused":
        steps.append("Check the key and the account in the proxycheck.io dashboard. Enter a new key: "
                     "management UI &gt; Settings &gt; Suspicious sign-ins.")
    elif not state.get("key"):
        steps.append("Get a free proxycheck.io API key (1,000 queries per day; without a key the limit is 100). "
                     "Enter it: management UI &gt; Settings &gt; Suspicious sign-ins.")
    else:
        steps.append("Buy a larger proxycheck.io plan, or wait for the daily reset.")
    steps.append("Each new IP is one query. The monitor keeps each answer for 24 hours. Many new IPs in one "
                 "day (a password spray, mobile users) use the quota faster.")
    parts = lines + [
        _heading("What stops or waits"),
        _facts([(name, _e(text)) for name, text in proxycheck_quota.EFFECTS]),
        _heading("What to do"),
        _steps(steps),
        _button(ui_url(), "Open the management UI") if ui_url() else "",
    ]
    body = _document(
        preheader=f"{title}. {usage}".strip(". ")[:200],
        level="high" if level == "exhausted" else "medium",
        badge={"low": "LOW", "exhausted": "USED UP", "refused": "REFUSED"}.get(level, "CHECK"),
        kicker="IP lookups", title=title, body="".join(parts),
        footer_note="You receive this email at most one time per day for each state (low, used up, refused).",
    )
    return _deliver(f"{INFO_TAG} {title}" + (f": {usage}" if usage else ""), body, None)


def send_settings_changed(user: str, changes: list, outbox=None, title: str = "Settings changed",
                          summary: str = "") -> bool:
    """Tell the admin mailbox that somebody changed settings in the management UI.

    An attacker who gets into the UI could weaken detection. This email makes
    every change visible. ``title`` and ``summary`` are for other changes made
    in the UI (mutes, response actions).
    """
    rows = "".join(
        f'<tr><td style="padding:8px 12px 8px 0;border-bottom:1px solid {_BORDER};font-size:14px;'
        f'vertical-align:top;width:34%;"><strong>{_e(c.get("label") or c.get("name"))}</strong></td>'
        f'<td style="padding:8px 0;border-bottom:1px solid {_BORDER};font-size:14px;vertical-align:top;'
        f'word-break:break-word;"><span style="color:{_MUTED};">{_e(c.get("old"))}</span> &rarr; '
        f'<strong>{_e(c.get("new"))}</strong></td></tr>'
        for c in changes
    )
    count = len(changes)
    summary = summary or (f"changed {count} setting{'s' if count != 1 else ''} in the management UI. "
                          "The new values apply from the next run (within 2 minutes).")
    parts = [
        _p(f"<strong>{_e(user)}</strong> {_e(summary)}"),
        f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
        f'style="border-top:1px solid {_BORDER};margin:0 0 16px;">{rows}</table>',
        _notice("info", "If you did not expect this change, sign in to the "
                        + (_link(ui_url("history"), "management UI") if ui_url() else "management UI")
                        + ", undo it, and check who has access: Settings &gt; Management UI access (listed "
                        "users and directory roles), and the Monitor.Admin role (Entra ID &gt; Enterprise "
                        "applications &gt; the admin UI app &gt; Users and groups)."),
    ]
    body = _document(
        preheader=f"{user} {summary}"[:200],
        level="info", badge="CHANGE", kicker="Management UI", title=title,
        body="".join(parts),
        footer_note="You receive this email for every change in the management UI.",
    )
    return _deliver(f"{ALERT_TAG} {title} by {user}", body, outbox, summary=f"{user} {summary}"[:300],
                    link=ui_url("history"), always_email=True)


# -----------------------------------------------------------------------------
# Outbox: alerts that Graph refused, sent again on later runs
# -----------------------------------------------------------------------------

_OUTBOX_PARTITION = "outbox"
# The reason of the last Graph refusal ("HTTP 404 MailboxNotEnabledForRESTAPI"), kept on outbox rows.
_last_send_error = ""
# A Table Storage string property holds at most 32K UTF-16 characters.
_MAX_QUEUED_BODY_CHARS = 30_000
_MAX_EVENT_JSON_CHARS = 16_000


def labeled(subject: str) -> str:
    """Insert TENANT_LABEL after the tag: '[M365 Alert][Contoso] HIGH: ...'."""
    label = config.TENANT_LABEL
    if not label:
        return subject
    for tag in (ALERT_TAG, INFO_TAG):
        if subject.startswith(tag) and not subject.startswith(f"{tag}[{label}]"):
            return f"{tag}[{label}]{subject[len(tag):]}"
    return subject


def recipients(subject: str) -> list:
    """ADMIN_EMAIL, plus ALERT_RECIPIENTS for alerts or REPORT_RECIPIENTS for reports."""
    extra = config.ALERT_RECIPIENTS if subject.startswith(ALERT_TAG) else config.REPORT_RECIPIENTS
    out = [config.ADMIN_EMAIL] if config.ADMIN_EMAIL else []
    for address in extra:
        if address.lower() not in {a.lower() for a in out}:
            out.append(address)
    return out


def _deliver(subject: str, body_html: str, outbox, summary: str = "", link: str = "",
             always_email: bool = False) -> bool:
    """Send now, or put the message in the outbox. True if sent or queued.

    An alert ([M365 Alert]) also goes to the webhook, or only to the webhook, as ALERT_DELIVERY
    says (webhook.py). ``summary`` and ``link`` are the webhook text. With "webhook" only, a
    failed webhook falls back to email. ``always_email``: the notices of changes in the management
    UI also go by email with "webhook" only, so that a change of the delivery settings cannot hide
    itself. Records each result in the email journal.
    """
    subject = labeled(subject)
    mode = config.ALERT_DELIVERY if subject.startswith(ALERT_TAG) and config.WEBHOOK_URL else "email"
    if always_email and mode == "webhook":
        mode = "both"
    if mode in ("both", "webhook"):
        sent, reason = webhook.post(subject, summary, link or ui_url())
        admin_store.record_email(subject, "webhook sent" if sent else f"webhook failed ({reason})"[:60])
        if mode == "webhook":
            if sent:
                return True
            logging.error(f"Webhook failed ({reason}): the alert goes by email")
    if _send_email(subject, body_html):
        admin_store.record_email(subject, "sent")
        return True
    if outbox is None or len(body_html) > _MAX_QUEUED_BODY_CHARS:
        admin_store.record_email(subject, "failed")
        return False
    row_key = hashlib.sha256((subject + body_html).encode("utf-8")).hexdigest()[:32]
    try:
        outbox.upsert_entity({
            "PartitionKey": _OUTBOX_PARTITION,
            "RowKey": row_key,
            "subject": subject[:1000],
            "body": body_html,
            "queued_at": datetime.now(timezone.utc).isoformat(),
            "last_error": _last_send_error[:200],
        })
    except Exception as e:
        logging.error(f"Email not queued: {type(e).__name__}: {subject}")
        admin_store.record_email(subject, "failed")
        return False
    logging.warning(f"Email queued in outbox for retry: {subject}")
    admin_store.record_email(subject, "queued")
    return True


def _queued_at(row) -> datetime:
    try:
        dt = datetime.fromisoformat(str(row.get("queued_at", "")))
    except ValueError:
        return datetime.min.replace(tzinfo=timezone.utc)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def flush_outbox(outbox) -> None:
    """Send queued emails, oldest first. Stop at the first failure. Never raises."""
    if outbox is None:
        return
    try:
        rows = sorted(outbox.query_entities(f"PartitionKey eq '{_OUTBOX_PARTITION}'"), key=_queued_at)
    except Exception as e:
        logging.warning(f"Outbox: query failed: {type(e).__name__}")
        return
    if not rows:
        return

    now = datetime.now(timezone.utc)
    sent = 0
    for i, row in enumerate(rows):
        try:
            if now - _queued_at(row) > timedelta(days=config.OUTBOX_MAX_DAYS):
                logging.error(f"Email dropped after {config.OUTBOX_MAX_DAYS} days in the outbox: {row.get('subject')}")
                outbox.delete_entity(row["PartitionKey"], row["RowKey"])
                continue
            if not _send_email(str(row.get("subject", "")), str(row.get("body", ""))):
                logging.error(
                    f"Outbox: {len(rows) - i} email(s) not delivered ({_last_send_error or 'no reason'}). "
                    "Check that ADMIN_EMAIL is a licensed mailbox and that Mail.Send has consent."
                )
                if _last_send_error and row.get("last_error") != _last_send_error[:200]:
                    try:
                        outbox.upsert_entity({**row, "last_error": _last_send_error[:200]})
                    except Exception as e:
                        logging.warning(f"Outbox: reason not kept: {type(e).__name__}")
                return
            outbox.delete_entity(row["PartitionKey"], row["RowKey"])
            admin_store.record_email(str(row.get("subject", "")), "sent from outbox")
            sent += 1
        except Exception as e:
            logging.warning(f"Outbox: row failed: {type(e).__name__}")
    if sent:
        logging.info(f"Outbox: sent {sent} queued email(s)")


def _send_email(subject: str, body_html: str) -> bool:
    """Send an email from ADMIN_EMAIL to ``recipients(subject)``. Return True on HTTP 202."""
    global _last_send_error
    if not config.ADMIN_EMAIL:
        logging.error("Email not sent: ADMIN_EMAIL is not set")
        _last_send_error = "no alert mailbox (ADMIN_EMAIL)"
        return False
    ok, reason = _graph_send(config.ADMIN_EMAIL, recipients(subject), subject, body_html)
    _last_send_error = "" if ok else reason
    return ok


def _graph_send(sender: str, to: list, subject: str, body_html: str) -> tuple:
    """Graph sendMail from ``sender``. Return (True, "") on HTTP 202, else (False, short reason)."""
    mailbox = quote(sender, safe="@")
    url = f"https://graph.microsoft.com/v1.0/users/{mailbox}/sendMail"
    payload = {
        "message": {
            "subject": subject,
            "body": {"contentType": "HTML", "content": body_html},
            "toRecipients": [{"emailAddress": {"address": a}} for a in to],
        },
        "saveToSentItems": False,
    }

    try:
        token = token_manager.get_graph_token()
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        response = config.http.post(url, headers=headers, json=payload, timeout=30)
    except Exception as e:
        logging.error(f"Email not sent: {type(e).__name__}: {config.redact(e)}")
        return False, type(e).__name__

    if response.status_code == 202:
        logging.info(f"Email sent: {subject}")
        return True, ""
    logging.error(f"Email not sent: HTTP {response.status_code} - {response.text[:500]}")
    try:
        code = str((response.json().get("error") or {}).get("code") or "")[:60]
    except ValueError:
        code = ""
    return False, f"HTTP {response.status_code}" + (f" {code}" if code else "")


def send_mailbox_test(address: str, by: str) -> tuple:
    """Send a test email from ``address`` to itself before it becomes the alert mailbox.

    Return (True, "") if Graph accepts it, else (False, a reason for the person).
    """
    body = _document(
        preheader="Test email from the new alert mailbox.",
        level="info", badge="TEST", kicker="Management UI", title="Test of the new alert mailbox",
        body=_p(f"<strong>{_e(by)}</strong> set this mailbox as the alert mailbox in the management UI. "
                "The monitor sent this test email from it. No action is necessary."),
    )
    ok, reason = _graph_send(address, [address], labeled(f"{INFO_TAG} Test of the new alert mailbox"), body)
    if ok:
        return True, ""
    return False, f"Microsoft Graph refused to send from this mailbox ({reason}). {mailbox_refusal_hint(reason)}"


def mailbox_refusal_hint(reason: str) -> str:
    """What to do when Graph refuses to send from a new alert mailbox."""
    group = os.environ.get("MAIL_SEND_GROUP", "")
    if reason.startswith("HTTP 403") and os.environ.get("MAIL_SEND_SCOPE", "tenant") == "mailbox":
        where = f"the Exchange group {group}" if group else "the Exchange Mail.Send scope"
        return (f"The app can send only as a member of {where}. Add this mailbox to {where} "
                "(Microsoft 365 admin center > Teams & groups > Active teams & groups). Exchange applies it in "
                "30 minutes to 2 hours. Then save again.")
    if "MailboxNotEnabledForRESTAPI" in reason:
        return ("This account has no Exchange Online mailbox, for example an admin account with no license. "
                "Use a licensed mailbox, or a shared mailbox (free, no license). A new shared mailbox can need "
                "some minutes before it works.")
    hint = {"HTTP 403": "Mail.Send has no admin consent. Run ./install.ps1 -Update.",
            "HTTP 404": "No such mailbox in this tenant. Use a licensed mailbox or a shared mailbox of this tenant."}
    return next((v for k, v in hint.items() if reason.startswith(k)), "Check the license and Mail.Send.")


def send_mailbox_changed_notice(old: str, new: str, by: str, monitor_result: str) -> bool:
    """Tell the old alert mailbox that alerts now go to a new mailbox (sent from the new mailbox)."""
    body = _document(
        preheader=f"Alerts now go to {new}.",
        level="info", badge="CHANGE", kicker="Management UI", title="Alert mailbox changed",
        body=_p(f"<strong>{_e(by)}</strong> changed the alert mailbox from <strong>{_e(old)}</strong> to "
                f"<strong>{_e(new)}</strong>. This mailbox gets no more alerts.")
        + _p(_e(monitor_result))
        + _notice("info", "If you did not expect this change, sign in to the management UI and check History."),
    )
    return _graph_send(new, [old], labeled(f"{ALERT_TAG} Alert mailbox changed by {by}"), body)[0]
