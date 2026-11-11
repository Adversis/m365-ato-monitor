"""Optional automatic response.

Two triggers, each off by default:
  ANOMALY_ACTION     - a successful sign-in from a new country (geo_monitor).
  COMPROMISE_ACTION  - a high account-takeover alert (RESPONSE_TYPES).
AUTO_DISABLE_INBOX_RULES turns off the rule of a high inbox rule alert.
The password is never changed: an admin resets it.

ANOMALY_ACTION:
  none    - no change (default)
  revoke  - revoke sign-in sessions: refresh tokens and browser sessions stop
            working. Access tokens already issued stay valid until they
            expire (usually within about 1 hour).
  disable - block sign-in (accountEnabled = false), then revoke sessions.

Safeguards:
  - ADMIN_EMAIL and ANOMALY_ACTION_EXEMPT are never changed.
  - At most ANOMALY_ACTION_MAX_PER_DAY actions per UTC day, so a bad
    geolocation result cannot lock out many users.
  - The app has no directory role. Graph refuses changes to admin accounts
    (HTTP 403). The alert email then says that the action failed.
  - COMPROMISE_ACTION acts only on the account that the alert is about, and
    only when the record shows that account by address (response_target). A
    change that one person made to another person's account gets no action:
    either account can be the compromised one.

Permissions (install.ps1 grants them with -ResponsePermissions yes):
  revoke:  User.RevokeSessions.All
  disable: User.EnableDisableAccount.All, User.Read.All, User.RevokeSessions.All
  inbox rules: MailboxSettings.ReadWrite
"""

import logging
import re
from datetime import datetime, timezone
from urllib.parse import quote

from azure.core.exceptions import ResourceNotFoundError

import config
from o365_client import token_manager

_GRAPH = "https://graph.microsoft.com/v1.0"
_COUNTER_PARTITION = "actions"


def _exempt(upn: str) -> bool:
    upn = upn.strip().lower()
    return upn in config.ANOMALY_ACTION_EXEMPT or upn == (config.ADMIN_EMAIL or "").strip().lower()


def _take_daily_slot(table, now: datetime) -> bool:
    """Count one action for today. False if today's limit is reached."""
    if table is None:
        return False
    day = now.strftime("%Y-%m-%d")
    try:
        entity = table.get_entity(partition_key=_COUNTER_PARTITION, row_key=day)
        count = int(entity.get("count", 0))
    except ResourceNotFoundError:
        count = 0
    except Exception as e:
        logging.warning(f"Response: cannot read the daily counter: {type(e).__name__}")
        return False
    if count >= config.ANOMALY_ACTION_MAX_PER_DAY:
        return False
    try:
        table.upsert_entity({"PartitionKey": _COUNTER_PARTITION, "RowKey": day, "count": count + 1})
    except Exception as e:
        logging.warning(f"Response: cannot write the daily counter: {type(e).__name__}")
        return False
    return True


def _graph(method: str, path: str, json_body=None):
    token = token_manager.get_graph_token()
    return config.http.request(
        method, f"{_GRAPH}{path}", json=json_body, timeout=30,
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
    )


def _call(label: str, method: str, path: str, json_body, ok_codes) -> str:
    try:
        resp = _graph(method, path, json_body)
    except Exception as e:
        return f"{label} failed: {type(e).__name__}"
    if resp.status_code in ok_codes:
        return f"{label}: done"
    hint = " (no admin consent for the permission, or an admin account)" if resp.status_code == 403 else ""
    return f"{label} failed: HTTP {resp.status_code}{hint}"


def _account_action(table, upn: str, action: str, now: datetime, label: str) -> str:
    """Apply ``action`` (revoke or disable) to ``upn`` with the safeguards. Return result text."""
    if not upn or "@" not in upn or _exempt(upn):
        return "none (account is exempt)"
    if not _take_daily_slot(table, now):
        return f"none (daily limit of {config.ANOMALY_ACTION_MAX_PER_DAY} actions reached)"
    user_path = f"/users/{quote(upn.strip(), safe='@')}"
    results = []
    if action == "disable":
        results.append(_call("Block sign-in", "PATCH", user_path, {"accountEnabled": False}, (204,)))
    results.append(_call("Revoke sessions", "POST", f"{user_path}/revokeSignInSessions", None, (200, 204)))
    text = "; ".join(results)
    level = logging.ERROR if "failed" in text else logging.WARNING
    logging.log(level, f"Response action ({label}): User={upn}, Action={action}, Result={text}")
    return text


def respond(table, upn: str, outcome: str, learning: bool, now: datetime = None) -> str:
    """Apply ANOMALY_ACTION to ``upn`` (new-country sign-in). Return a short result text for the alert."""
    now = now or datetime.now(timezone.utc)
    action = config.ANOMALY_ACTION
    if action == "none":
        return "none (ANOMALY_ACTION=none)"
    if outcome != "success":
        return "none (the sign-in did not complete)"
    if learning:
        return "none (learning period)"
    return _account_action(table, upn, action, now, "new country")


# -----------------------------------------------------------------------------
# Manual response from the management UI (user page)
# -----------------------------------------------------------------------------
# An admin chooses the action, so the exempt list and the daily limit do not
# apply. Two accounts are refused: the alert mailbox (blocking it stops every
# alert) and the admin's own account (blocking it locks the admin out).

MANUAL_ACTIONS = {
    "revoke": ("Revoke sessions", ("User.RevokeSessions.All",)),
    "block": ("Block sign-in", ("User.EnableDisableAccount.All", "User.Read.All", "User.RevokeSessions.All")),
    "unblock": ("Unblock sign-in", ("User.EnableDisableAccount.All", "User.Read.All")),
}


def manual_missing_roles(action: str, granted) -> tuple:
    """Graph roles that ``action`` needs and that are not granted (() if granted is unknown)."""
    if granted is None or action not in MANUAL_ACTIONS:
        return ()
    return tuple(r for r in MANUAL_ACTIONS[action][1] if r not in granted)


def manual_action(upn: str, action: str, by: str) -> str:
    """Apply ``action`` (revoke, block, unblock) to ``upn``. Return result text.

    Raises ValueError for an action that is refused (the text says why).
    """
    upn = str(upn or "").strip().lower()
    if action not in MANUAL_ACTIONS:
        raise ValueError("Unknown action.")
    if "@" not in upn:
        raise ValueError("Enter a user principal name.")
    if action == "block" and upn == (config.ADMIN_EMAIL or "").strip().lower():
        raise ValueError("The alert mailbox cannot be blocked: the monitor sends every alert from it.")
    if action == "block" and upn == str(by or "").strip().lower():
        raise ValueError("You cannot block your own account.")
    user_path = f"/users/{quote(upn, safe='@')}"
    if action == "revoke":
        results = [_call("Revoke sessions", "POST", f"{user_path}/revokeSignInSessions", None, (200, 204))]
    elif action == "block":
        results = [_call("Block sign-in", "PATCH", user_path, {"accountEnabled": False}, (204,)),
                   _call("Revoke sessions", "POST", f"{user_path}/revokeSignInSessions", None, (200, 204))]
    else:
        results = [_call("Unblock sign-in", "PATCH", user_path, {"accountEnabled": True}, (204,))]
    text = "; ".join(results)
    level = logging.ERROR if "failed" in text else logging.WARNING
    logging.log(level, f"Response action (manual): User={upn}, Action={action}, By={by}, Result={text}")
    return text


def account_state(upn: str, granted) -> dict:
    """{"display_name", "enabled"} from Graph (needs User.Read.All), or {} if not available."""
    if granted is None or "User.Read.All" not in granted or "@" not in str(upn or ""):
        return {}
    try:
        resp = _graph("GET", f"/users/{quote(upn.strip(), safe='@')}?$select=displayName,accountEnabled")
    except Exception as e:
        logging.warning(f"Account state not read: {type(e).__name__}")
        return {}
    if resp.status_code != 200:
        return {"error": f"HTTP {resp.status_code}" + (" (user not found)" if resp.status_code == 404 else "")}
    data = resp.json()
    return {"display_name": str(data.get("displayName") or ""), "enabled": data.get("accountEnabled")}


# Alerts about the affected account itself. Admin changes (the actor is an admin,
# and Graph refuses changes to admins) and OAuth consents (revoking sessions does
# not remove the app's access) are not included.
RESPONSE_TYPES = {
    "inbox_rule", "mailbox_forwarding", "session_reuse", "attack_tool", "legacy_auth",
    "mfa_change", "device_code", "suspicious_user_agent",
}
# Alerts about a sign-in: the account that signed in is the affected account.
SIGNIN_TYPES = {"session_reuse", "attack_tool", "legacy_auth", "device_code", "suspicious_user_agent"}
# A Microsoft service can write the record of a change that the user made (for example
# "Azure MFA StrongAuthenticationService" when the user adds an MFA method in My Sign-Ins).
_SERVICE_ACTOR_TYPES = {"mfa_change"}

_ADDRESS_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_GUID_RE = re.compile(r"^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")


def _upn_by_id(object_id: str) -> str:
    """The UPN of the Entra ID user with this object ID (User.ReadBasic.All), or ""."""
    try:
        resp = _graph("GET", f"/users/{quote(object_id, safe='')}?$select=userPrincipalName")
    except Exception as e:
        logging.warning(f"Response: user lookup failed: {type(e).__name__}")
        return ""
    if resp.status_code != 200:
        return ""
    upn = str((resp.json() or {}).get("userPrincipalName") or "")
    return upn if _ADDRESS_RE.match(upn) else ""


def affected_account(finding: dict) -> tuple:
    """(address, "") of the account or mailbox that the change applies to, or ("", why not).

    "target" in the finding is the account as the record names it: an address, an alias,
    an Exchange identity path ("<server>/.../contoso.onmicrosoft.com/bob"), or an object ID.
    An alias that is the local part of the actor's address is the actor. An object ID is
    looked up in Entra ID. Any other name is not used: the app does not guess.
    """
    target = str(finding.get("target") or "").strip()
    if target.lower().startswith("smtp:"):
        target = target[5:]
    name = re.split(r"[\\/]", target)[-1].strip()
    if not name:
        return "", "the record does not name the account that was changed"
    if _ADDRESS_RE.match(name):
        return name, ""
    actor = str(finding.get("actor") or "").strip()
    if "@" in actor and name.lower() in (actor.lower(), actor.split("@")[0].lower()):
        return actor, ""
    if _GUID_RE.match(name):
        upn = _upn_by_id(name)
        if upn:
            return upn, ""
    return "", f"the record names the account as '{name[:80]}', not by its address"


def response_target(finding: dict) -> tuple:
    """(UPN, "") of the account to revoke or block for this finding, or ("", why not).

    A sign-in alert: the account that signed in. A change (inbox rule, forwarding, MFA): the
    account that was changed, only if the same account made the change, or a Microsoft
    service wrote the record (an MFA method). A change that one account made to another
    gets no action: the actor or the changed account can be the compromised one.
    """
    ftype = finding.get("type")
    if ftype in SIGNIN_TYPES:
        upn = str(finding.get("user") or "").strip()
        return (upn, "") if _ADDRESS_RE.match(upn) else ("", "no account address in the record")
    upn, why = affected_account(finding)
    if not upn:
        return "", why
    actor = str(finding.get("actor") or "").strip()
    if actor.lower() == upn.lower():
        return upn, ""
    if "@" in actor:
        return "", f"{actor} changed {upn}: check both accounts"
    if ftype in _SERVICE_ACTOR_TYPES:
        return upn, ""
    return "", f"an app or service ({actor[:80] or 'unknown'}) changed {upn}: check the app and the account"


def respond_to_finding(table, finding: dict, now: datetime = None) -> str:
    """COMPROMISE_ACTION and AUTO_DISABLE_INBOX_RULES for one finding. "" if nothing applies."""
    now = now or datetime.now(timezone.utc)
    if finding.get("severity") != "high" or finding.get("type") not in RESPONSE_TYPES:
        return ""
    results = []
    if config.COMPROMISE_ACTION != "none":
        upn, why = response_target(finding)
        results.append(_account_action(table, upn, config.COMPROMISE_ACTION, now, finding["type"])
                       if upn else f"none ({why})")
    if config.AUTO_DISABLE_INBOX_RULES and finding.get("type") == "inbox_rule":
        results.append(disable_inbox_rule(finding))
    return "; ".join(r for r in results if r)


def _rule_addresses(rule: dict) -> set:
    actions = rule.get("actions") or {}
    out = set()
    for key in ("forwardTo", "redirectTo", "forwardAsAttachmentTo"):
        for recipient in actions.get(key) or []:
            address = ((recipient or {}).get("emailAddress") or {}).get("address")
            if address:
                out.add(str(address).lower())
    return out


def _rule_is_risky(rule: dict) -> bool:
    actions = rule.get("actions") or {}
    return bool(_rule_addresses(rule) or actions.get("delete") or actions.get("permanentDelete")
                or actions.get("moveToFolder") or actions.get("markAsRead"))


def disable_inbox_rule(finding: dict) -> str:
    """Turn off the inbox rule of a finding (Graph messageRules, isEnabled = false).

    The rule is found by name, or by an external recipient if the name is not
    in the record. The rule is not deleted, so it stays for investigation.
    """
    label = "Disable inbox rule"
    mailbox, why = affected_account({**finding, "target": finding.get("mailbox") or finding.get("target")
                                     or finding.get("user")})
    if not mailbox:
        return f"{label} failed: {why}"
    base = f"/users/{quote(mailbox, safe='@')}/mailFolders/inbox/messageRules"
    try:
        resp = _graph("GET", base)
    except Exception as e:
        return f"{label} failed: {type(e).__name__}"
    if resp.status_code != 200:
        hint = " (no admin consent for MailboxSettings.ReadWrite)" if resp.status_code == 403 else ""
        return f"{label} failed: HTTP {resp.status_code}{hint}"
    rules = [r for r in (resp.json().get("value") or []) if r.get("isEnabled")]
    name = str(finding.get("rule_name") or "").strip()
    targets = {t.lower() for t in finding.get("targets") or []}
    matches = [r for r in rules if name and r.get("displayName") == name and _rule_is_risky(r)]
    if not matches and targets:
        matches = [r for r in rules if _rule_addresses(r) & targets]
    if not matches:
        return (f"{label} failed: no enabled rule found (it can be off or removed already, "
                "or be a rule that only Outlook desktop runs)")
    results = [_call(label, "PATCH", f"{base}/{quote(str(r.get('id')), safe='')}", {"isEnabled": False}, (200,))
               for r in matches]
    failed = [r for r in results if "failed" in r]
    text = failed[0] if failed else f"{label}: done"
    logging.warning(f"Response action (inbox rule): Mailbox={mailbox}, Rules={len(matches)}, Result={text}")
    return text
