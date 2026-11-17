"""Read and assess inbox rules through Microsoft Graph (messageRules).

Used by the user page in the management UI (list, turn off, turn on) and by
the onboarding scan (sweep every mailbox for rules that existed before the
monitor started).

Graph shows the server-side rules of a mailbox. Rules that only Outlook
desktop runs (client-only rules) are not shown.

The assessment uses the same signs as the audit-record detector
(compromise_detector): external forwarding, or delete with another sign, is high
(a rule that only deletes mail is no sign); a keyword
condition with mark-as-read, move, or delete, or a name with no letters, is
medium. A rule holds the ID of its move target, not the name. Reading the
folder name needs a Mail permission, which the app does not have, so a move
to a hidden folder (RSS Feeds) is not high here as it is in the detector.

Permissions: MailboxSettings.Read (list) or MailboxSettings.ReadWrite (list,
turn off, turn on).
"""

import re
from urllib.parse import quote

import config
from compromise_detector import (HIDDEN_FOLDERS, _is_internal, _rule_name_indicator, _user_domain,
                                 is_directory_address, short_address)
from o365_client import token_manager

_GRAPH = "https://graph.microsoft.com/v1.0"
READ_ROLES = ("MailboxSettings.Read", "MailboxSettings.ReadWrite")
WRITE_ROLE = "MailboxSettings.ReadWrite"
_KEYWORD_CONDITIONS = ("subjectContains", "bodyContains", "bodyOrSubjectContains", "senderContains",
                       "headerContains", "recipientContains")


def can_read(granted) -> bool:
    return granted is not None and any(r in granted for r in READ_ROLES)


def can_write(granted) -> bool:
    return granted is not None and WRITE_ROLE in granted


def _get(path: str):
    token = token_manager.get_graph_token()
    return config.http.get(f"{_GRAPH}{path}", timeout=30,
                           headers={"Authorization": f"Bearer {token}"})


def _base(mailbox: str) -> str:
    return f"/users/{quote(mailbox.strip(), safe='@')}/mailFolders/inbox/messageRules"


def list_rules(mailbox: str) -> tuple:
    """Return (rules, error). ``rules`` is a list of Graph messageRule objects, or None.

    ``error`` is "" on success, "no mailbox" if the user has no Exchange
    mailbox, or a short error text.
    """
    if "@" not in str(mailbox or ""):
        return None, "no mailbox address"
    try:
        resp = _get(_base(mailbox))
    except Exception as e:
        return None, f"{type(e).__name__}"
    if resp.status_code == 200:
        try:
            return list(resp.json().get("value") or []), ""
        except ValueError:
            return None, "response not JSON"
    if resp.status_code == 404:
        return None, "no mailbox"
    try:
        code = (resp.json().get("error") or {}).get("code", "")
    except ValueError:
        code = ""
    if code in ("MailboxNotEnabledForRESTAPI", "ErrorMailboxNotFound", "ResourceNotFound"):
        return None, "no mailbox"
    hint = " (no admin consent for MailboxSettings.Read)" if resp.status_code == 403 else ""
    return None, f"HTTP {resp.status_code}{hint}"


def _addresses(actions: dict, key: str) -> list:
    out = []
    for recipient in actions.get(key) or []:
        address = ((recipient or {}).get("emailAddress") or {}).get("address")
        if address:
            out.append(str(address).strip())
    return out


def _words(conditions: dict) -> list:
    words = []
    for key in _KEYWORD_CONDITIONS:
        words += [str(w) for w in conditions.get(key) or [] if str(w).strip()]
    return words


def assess(rule: dict, mailbox: str, folder: str = "") -> tuple:
    """Return (severity, reasons). severity is "high", "medium", or "" (no sign).

    ``folder`` is the display name of the moveToFolder target, if known (the
    caller normally does not know it; see the module docstring).
    """
    actions = rule.get("actions") or {}
    conditions = rule.get("conditions") or {}
    domain = _user_domain(mailbox)
    strong, weak = [], []

    for key, verb in (("forwardTo", "forwards"), ("forwardAsAttachmentTo", "forwards as attachment"),
                      ("redirectTo", "redirects")):
        addresses = _addresses(actions, key)
        external = [a for a in addresses
                    if not is_directory_address(a) and not _is_internal(_user_domain(a), domain)]
        if external:
            strong.append(f"{verb} externally to {'; '.join(external)}")
        directory = [short_address(a) for a in addresses if is_directory_address(a)]
        if directory:
            weak.append(f"{verb} to unverified directory recipients: {'; '.join(directory)} "
                        "(the final addresses can be external; check the rule)")
    if actions.get("delete") or actions.get("permanentDelete"):
        strong.append("deletes matching messages")
    if folder and folder.strip().lower() in HIDDEN_FOLDERS:
        strong.append(f"moves to hidden folder: {folder}")

    hides = bool(actions.get("markAsRead") or actions.get("moveToFolder") or actions.get("delete")
                 or actions.get("permanentDelete"))
    text = " ".join(_words(conditions)).lower()
    found = [w for w in config.INBOX_RULE_KEYWORDS if w and w.lower() in text]
    if found and hides:
        weak.append("matches mail that contains " + ", ".join(f"'{w}'" for w in found[:5])
                    + " and hides it")
    name_note = _rule_name_indicator(str(rule.get("displayName") or ""), hides)
    if name_note:
        weak.insert(0, name_note)
    # A rule that only deletes mail (newsletters, notifications) is common and alone no sign of an
    # attack. The alert for a new one needs context (function_app._context_review); an existing one has none.
    if strong == ["deletes matching messages"] and not weak:
        return "", []
    return ("high" if strong else "medium" if weak else ""), strong + weak


_CONDITION_LABELS = {
    "fromAddresses": "from", "sentToAddresses": "sent to", "subjectContains": "subject contains",
    "bodyContains": "body contains", "bodyOrSubjectContains": "subject or body contains",
    "senderContains": "sender contains", "recipientContains": "recipient contains",
    "headerContains": "header contains", "hasAttachments": "has attachments", "sentToMe": "sent to me",
    "sentOnlyToMe": "sent only to me", "sentCcMe": "Cc to me", "sentToOrCcMe": "sent or Cc to me",
    "notSentToMe": "not sent to me", "isAutomaticForward": "automatic forward",
    "isAutomaticReply": "automatic reply", "isMeetingRequest": "meeting request",
    "isNonDeliveryReport": "non-delivery report", "withinSizeRange": "size",
}


def describe_conditions(conditions: dict) -> str:
    """Graph messageRulePredicates as text: "from billing@supplier.com; subject contains 'invoice'"."""
    parts = []
    for key, val in (conditions or {}).items():
        if val in (None, [], False, "", {}):
            continue
        label = _CONDITION_LABELS.get(key) or re.sub(r"(?<!^)([A-Z])", r" \1", str(key)).lower()
        if val is True:
            parts.append(label)
        elif isinstance(val, list):
            items = []
            for v in val:
                if isinstance(v, dict):
                    address = (v.get("emailAddress") or {})
                    v = address.get("address") or address.get("name") or ""
                if str(v).strip():
                    items.append(short_address(v))
            shown = ", ".join(f"'{i}'" if "contains" in label else i for i in items[:5])
            parts.append(f"{label} {shown}" + (f" (and {len(items) - 5} more)" if len(items) > 5 else ""))
        elif isinstance(val, dict):
            parts.append(f"{label} " + ", ".join(f"{k} {v}" for k, v in val.items() if v is not None))
        else:
            parts.append(f"{label} {val}")
    return "; ".join(parts)


def summarize(rule: dict, mailbox: str, folder: str = "") -> dict:
    """A rule in the shape the UI and the report use."""
    actions = rule.get("actions") or {}
    conditions = rule.get("conditions") or {}
    severity, reasons = assess(rule, mailbox, folder)
    does = []
    for key, verb in (("forwardTo", "forward to"), ("forwardAsAttachmentTo", "forward as attachment to"),
                      ("redirectTo", "redirect to")):
        if _addresses(actions, key):
            does.append(f"{verb} {', '.join(short_address(a) for a in _addresses(actions, key))}")
    if actions.get("moveToFolder"):
        does.append(f"move to {folder or 'a folder'}")
    if actions.get("copyToFolder"):
        does.append("copy to a folder")
    if actions.get("markAsRead"):
        does.append("mark as read")
    if actions.get("delete"):
        does.append("delete")
    if actions.get("permanentDelete"):
        does.append("delete permanently")
    if actions.get("stopProcessingRules"):
        does.append("stop other rules")
    when = describe_conditions(conditions)
    unless = describe_conditions(rule.get("exceptions") or {})
    if unless:
        when = f"{when or 'all mail'}; except {unless}"
    return {
        "id": str(rule.get("id") or ""), "name": str(rule.get("displayName") or ""),
        "enabled": bool(rule.get("isEnabled")), "sequence": rule.get("sequence"),
        "conditions": when[:500] or "all mail",
        "actions": "; ".join(does)[:500] or "none",
        "severity": severity, "reasons": reasons,
        "targets": sorted({a.lower() for k in ("forwardTo", "forwardAsAttachmentTo", "redirectTo")
                           for a in _addresses(actions, k)}),
    }


def read(mailbox: str) -> tuple:
    """Return (summaries, error) for one mailbox."""
    rules, error = list_rules(mailbox)
    if rules is None:
        return None, error
    return [summarize(rule, mailbox) for rule in rules], ""


LIST_ROLES = ("User.ReadBasic.All", "User.Read.All")


def can_list_users(granted) -> bool:
    return granted is not None and any(r in granted for r in LIST_ROLES)


def list_mailbox_users(limit: int = 5000) -> tuple:
    """Return (upns, error): members with a mail address, sorted. Guests (#EXT#) are left out."""
    upns = []
    url = f"{_GRAPH}/users?$select=userPrincipalName,mail&$top=999"
    try:
        token = token_manager.get_graph_token()
        while url and len(upns) < limit:
            if not url.startswith(_GRAPH + "/"):
                return None, "unexpected next page link"
            resp = config.http.get(url, timeout=30, headers={"Authorization": f"Bearer {token}"})
            if resp.status_code != 200:
                hint = " (no admin consent for User.ReadBasic.All)" if resp.status_code == 403 else ""
                return None, f"HTTP {resp.status_code}{hint}"
            data = resp.json()
            for user in data.get("value") or []:
                upn = str(user.get("userPrincipalName") or "").strip().lower()
                if upn and user.get("mail") and "#ext#" not in upn:
                    upns.append(upn)
            url = data.get("@odata.nextLink")
    except Exception as e:
        return None, f"{type(e).__name__}"
    return sorted(set(upns))[:limit], ""


def set_enabled(mailbox: str, rule_id: str, enabled: bool) -> str:
    """Turn one rule on or off. Return result text ("...: done" or "... failed: ...")."""
    label = "Turn on inbox rule" if enabled else "Turn off inbox rule"
    if "@" not in str(mailbox or "") or not rule_id:
        return f"{label} failed: no mailbox or rule"
    try:
        token = token_manager.get_graph_token()
        resp = config.http.request(
            "PATCH", f"{_GRAPH}{_base(mailbox)}/{quote(str(rule_id), safe='')}",
            json={"isEnabled": bool(enabled)}, timeout=30,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    except Exception as e:
        return f"{label} failed: {type(e).__name__}"
    if resp.status_code == 200:
        return f"{label}: done"
    hint = " (no admin consent for MailboxSettings.ReadWrite)" if resp.status_code == 403 else ""
    return f"{label} failed: HTTP {resp.status_code}{hint}"
