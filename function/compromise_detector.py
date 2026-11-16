"""Compromise indicator detection.

These detect attacker actions after access, not only a suspicious sign-in IP.
Each detector returns a list of findings. Each finding is a dict with:
type, severity, user, description, ip, event.

Detectors (finding type):
- Inbox rules (inbox_rule): external forward or redirect, delete, move to a
  hidden folder (high); an obfuscated rule name, or a finance or security
  keyword with mark-as-read or a move (medium).
- Mailbox forwarding (mailbox_forwarding): Set-Mailbox forwarding.
- OAuth consents (oauth_consent): a scope in HIGH_RISK_OAUTH_SCOPES.
- User agents (attack_tool, suspicious_user_agent).
- Sign-in methods (legacy_auth, device_code): a successful sign-in with
  legacy authentication (BAV2ROPC) or with the device code flow.
- Mail flow rules (mail_flow_rule): transport rules that copy, redirect, or
  delete mail, skip spam filtering, or are new.
- Mailbox delegation (mailbox_delegation): FullAccess, SendAs, SendOnBehalf,
  and folder sharing with everyone or an external address.
- Audit (audit_disabled): unified audit, mailbox audit, or audit bypass off.
- Mail protection (mail_protection_weakened): anti-phishing, anti-malware,
  anti-spam, Safe Links, or Safe Attachments policy removed or off; DKIM off;
  external auto-forwarding allowed; senders allowed past the spam filter.
- MFA (mfa_change): a method added to an account that had MFA; per-user MFA
  off; tenant MFA settings changed.
- Admin roles (admin_role): a member added to an Entra ID role; an Exchange
  management role assigned.
- App credentials (app_credential): a secret or certificate added to an app.
- Domain federation (domain_federation): federation set on a domain; a
  domain added.

Most tenant-level changes are rare in a small tenant, so one change is an
alert. The pipeline sets high if the source IP is a proxy or hosting
address, or its country is new for the user.

The rules follow public detection content (Elastic, Splunk, Sigma) for the
same audit records. A record that a detector cannot parse is logged and
skipped. It does not stop the detector.
"""

import json
import logging
import os
import re
from datetime import datetime, timedelta, timezone
from typing import Callable, Optional

import config
from ip_checker import extract_ip


EXCHANGE_RECORD_TYPES = {1, 2}

SUSPICIOUS_INBOX_RULE_OPERATIONS = {
    "New-InboxRule",
    "Set-InboxRule",
    "Enable-InboxRule",
    "UpdateInboxRules",
}

MAILBOX_FORWARDING_OPERATIONS = {"Set-Mailbox"}

SUSPICIOUS_CONSENT_OPERATIONS = {
    "Consent to application.",
    "Add app role assignment to service principal.",
    "Add OAuth2PermissionGrant.",
    "Add delegated permission grant.",
}


# Folders that users seldom open. Attackers move mail there to hide replies.
HIDDEN_FOLDERS = {
    "deleted items", "rss feeds", "rss subscriptions", "junk email", "conversation history",
    "calendar",
}


_EMAIL_RE = re.compile(r"[A-Za-z0-9.!#$%&'*+=?^_`{|}~-]+@((?:[A-Za-z0-9-]+\.)+[A-Za-z0-9-]+)")
_SCOPE_TOKEN_RE = re.compile(r"[A-Za-z0-9_.\-]+")


# ResultStatus of an operation that did not complete: Exchange admin cmdlets
# write "False", other workloads "Failed" or "Failure".
_FAILED_STATUS = {"false", "failed", "failure"}


def _run(events: list, check: Callable[[dict], Optional[dict]], include_failed: bool = False) -> list:
    """Apply ``check`` to each event. Log and skip an event that raises.

    Records of failed operations are skipped (a failed cmdlet changed nothing),
    unless ``include_failed`` is set.
    """
    findings = []
    failures = 0
    for event in events:
        if not isinstance(event, dict):
            continue
        if not include_failed and str(event.get("ResultStatus", "")).strip().lower() in _FAILED_STATUS:
            continue
        try:
            finding = check(event)
        except Exception as e:
            failures += 1
            if failures == 1:
                logging.warning(f"{check.__name__}: skipped a record that did not parse: {type(e).__name__}: {e}")
            continue
        if finding:
            # "user" is the account the alert is about (for the user page, mutes, and the subject).
            # "actor" is the account that made the change. "target", where a detector sets it, is
            # the account or mailbox that the change applies to. The automatic response uses
            # these two (responder.response_target), not "user".
            finding.setdefault("actor", _user(event))
            findings.append(finding)
    if failures > 1:
        logging.warning(f"{check.__name__}: skipped {failures} records that did not parse")
    return findings


def _join(items: list) -> str:
    """'a', 'a and b', 'a, b and c'."""
    items = [str(i) for i in items]
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " and " + items[-1]


def _user(event: dict) -> str:
    return str(event.get("UserId") or "Unknown")


def _user_domain(user: str) -> str:
    return user.rsplit("@", 1)[-1].lower() if "@" in user else ""


def _is_internal(domain: str, user_domain: str) -> bool:
    return domain == user_domain or domain in config.INTERNAL_DOMAINS


# An X.500 address (legacyExchangeDN) of a recipient in the tenant's directory, as Outlook writes
# it when a person picks a recipient from the address book:
# "/o=ExchangeLabs/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/cn=<hex>-jane".
_X500_RE = re.compile(r"^\s*(?:ex:)?/o=[^/]+/ou=", re.IGNORECASE)


def is_directory_address(value) -> bool:
    """True for an X.500 address: a mailbox, group, or contact in the tenant's directory."""
    return bool(_X500_RE.match(str(value or "")))


def short_address(value) -> str:
    """An address for a person to read. An X.500 address becomes its name: 'jane (directory)'."""
    text = str(value or "").strip()
    if not is_directory_address(text):
        return text
    cn = re.split(r"/cn=", text, flags=re.IGNORECASE)[-1].strip()
    name = re.sub(r"^[0-9a-f]{32}-", "", cn, flags=re.IGNORECASE)
    return f"{name or cn} (directory)"


def _external_targets(value, user_domain: str) -> list:
    """Return the targets in a recipient value that are not internal.

    ``value`` can hold several recipients, for example
    "a@contoso.com;b@evil.com" or '"Bob" [SMTP:bob@evil.com]'. Each SMTP
    address is checked. A value with no SMTP address (for example a display
    name or an X.500 address) is returned as-is: the app cannot prove that it
    is internal. Inbox rules report directory references as unverified.
    """
    text = str(value or "").strip()
    if not text:
        return []
    addresses = [(m.group(0), m.group(1).lower().rstrip(".")) for m in _EMAIL_RE.finditer(text)]
    if not addresses:
        return [text[:200]]
    return [addr for addr, domain in addresses if not _is_internal(domain, user_domain)]


def _folder_name(value) -> str:
    """Last segment of a folder path, lowercase: ':\\Inbox\\RSS Feeds' -> 'rss feeds'."""
    return re.split(r"[\\/]", str(value or ""))[-1].strip().strip(":").strip().lower()


def _is_true(value) -> bool:
    return str(value).strip().lower() in ("true", "$true", "1")


def _is_false(value) -> bool:
    return str(value).strip().lower() in ("false", "$false", "0")


def _finding(ftype: str, severity: str, user: str, description: str, event: dict, target: str = None) -> dict:
    finding = {
        "type": ftype,
        "severity": severity,
        "user": user,
        "description": description,
        "ip": extract_ip(event),
        "event": event,
    }
    if target is not None:
        finding["target"] = target
    return finding


def _is_system_actor(event: dict) -> bool:
    """Exchange service accounts that change permissions during provisioning.

    UserType 3 (DCAdmin) and 4 (System), "NT AUTHORITY\\SYSTEM (...)", Windows
    service accounts such as "NT SERVICE\\MSExchangeAdminApiNetCore (...)" (it
    grants Discovery Management FullAccess on the DiscoverySearchMailbox again
    and again), and the service SIDs S-1-5-18, -19, -20. No user or app of the
    tenant can act as these accounts. The Graph audit search can name the
    UserType ("DcAdmin", "System") where the Management API uses the number.
    """
    actor = str(event.get("UserId") or "").strip().upper()
    return (actor.startswith(("NT AUTHORITY\\", "NT SERVICE\\")) or actor in _SERVICE_SIDS
            or str(event.get("UserType")).strip().lower() in ("3", "4", "dcadmin", "system"))


# Local System, Local Service, Network Service. A user SID is S-1-5-21-...
_SERVICE_SIDS = {"S-1-5-18", "S-1-5-19", "S-1-5-20"}
# App IDs of Microsoft first-party apps with a fixed form, for example 00000014-0000-0000-c000-000000000000
# (Microsoft.Azure.SyncFabric) and 00000002-0000-0ff1-ce00-000000000000 (Exchange Online). Entra ID
# gives other apps random app IDs, so no tenant can register an app with one of these.
_MICROSOFT_APP_ID_RE = re.compile(r"^[0-9a-f]{8}-0000-(0000-c000|0ff1-ce00)-000000000000$", re.IGNORECASE)


def _spn_app_id(value: str) -> str:
    """The app ID at the start of a service principal name list ("<appId>/host;<appId>;..."), or ""."""
    first = str(value or "").split(";")[0].split("/")[0].strip()
    return first if re.fullmatch(r"[0-9a-fA-F-]{36}", first) else ""


def _actor_name(event: dict) -> str:
    """Who made a change, for the alert text.

    A UPN if the record has one. For a service principal (UserId
    "ServicePrincipal_<id>"), the display name from Actor (type 1), for
    example "Azure MFA StrongAuthenticationService".
    """
    actor = _user(event)
    if "@" in actor:
        return actor
    for item in event.get("Actor") or []:
        if isinstance(item, dict) and str(item.get("Type")).strip() == "1" and item.get("ID"):
            return str(item["ID"])
    return actor


def _short_identity(value) -> str:
    """'EURPR01A002.prod.outlook.com/Microsoft Exchange Hosted Organizations/contoso.onmicrosoft.com/Bob' -> 'Bob'."""
    text = str(value or "").strip()
    if "Microsoft Exchange Hosted Organizations/" in text:
        return text.rsplit("/", 1)[-1]
    return text


def _clean(value) -> str:
    """A ModifiedProperties value without JSON quotes or brackets: '["X"]' -> 'X'."""
    return str(value or "").strip().strip("[]").strip().strip('"').strip()


def _modified_properties(event: dict) -> dict:
    """ModifiedProperties as {name: (old value, new value)}."""
    props = {}
    for prop in event.get("ModifiedProperties") or []:
        if isinstance(prop, dict):
            props[str(prop.get("Name", ""))] = (prop.get("OldValue", ""), prop.get("NewValue", ""))
    return props


def _extended_property(event: dict, name: str) -> str:
    for prop in event.get("ExtendedProperties") or []:
        if isinstance(prop, dict) and prop.get("Name") == name:
            return str(prop.get("Value") or "")
    return str(event.get(name) or "")


def _target_user(event: dict) -> str:
    """The account that an Entra ID change applies to (UPN if the record has one)."""
    for target in event.get("Target") or []:
        if isinstance(target, dict) and str(target.get("Type")).strip() == "5" and "@" in str(target.get("ID", "")):
            return str(target["ID"])
    return str(event.get("ObjectId") or "Unknown")


def _extract_parameters(event: dict) -> dict:
    """Return Parameters and OperationProperties of an audit record as one flat dict."""
    params = {}
    for key in ("Parameters", "OperationProperties"):
        for param in event.get(key) or []:
            if isinstance(param, dict):
                params[str(param.get("Name", ""))] = param.get("Value", "")
    return params


# -----------------------------------------------------------------------------
# Inbox rules
# -----------------------------------------------------------------------------

def _inbox_rule_finding(event: dict) -> Optional[dict]:
    operation = _operation(event)
    if operation not in SUSPICIOUS_INBOX_RULE_OPERATIONS:
        return None

    params = _extract_parameters(event)
    user = _user(event)
    user_domain = _user_domain(user)
    mailbox = _rule_mailbox(event, params, operation) or user
    confirm_first = False

    if operation == "UpdateInboxRules":
        name = str(params.get("RuleName") or params.get("Name") or "")
        strong = _update_inbox_rules_indicators(params, user_domain)
        weak = []
        actions = " ".join(str(params.get(k) or "") for k in ("RuleActions", "Actions")).lower()
        hides = any(word in actions for word in ("move", "delete", "read"))
    else:
        # Set-InboxRule has Name only for a rename. Identity (and ObjectId) is
        # "mailbox\\rule name" or ".../mailbox/rule name".
        ident = str(params.get("Identity") or event.get("ObjectId") or "")
        name = str(params.get("Name") or re.split(r"[\\/]", ident)[-1])
        strong = _cmdlet_rule_indicators(params, user_domain)
        directory = _directory_rule_indicators(params)
        weak = _rule_keyword_indicators(params) + directory
        confirm_first = bool(directory) and not strong
        hides = (_is_true(params.get("MarkAsRead")) or bool(str(params.get("MoveToFolder") or "").strip())
                 or _is_true(params.get("DeleteMessage")) or _is_true(params.get("SoftDeleteMessage")))

    removed = str(params.get("RuleOperation", "")).lower()
    if not any(word in removed for word in _RULE_REMOVE_OPERATIONS):
        name_note = _rule_name_indicator(name, hides)
        if name_note:
            weak.insert(0, name_note)
        # A rule made by a script (for example EWS with python-requests).
        tool = _client_tool(event)
        if tool:
            strong.append(f"was made with {tool} ({str(event.get('ClientInfoString'))[:80]})")

    if not strong and not weak:
        return None

    # External recipients, so a response can find the rule in the mailbox.
    if operation == "UpdateInboxRules":
        recipients = _rule_recipients(params) or []
    else:
        recipients = [m.group(0) for f in ("ForwardTo", "ForwardAsAttachmentTo", "RedirectTo")
                      for m in _EMAIL_RE.finditer(str(params.get(f) or ""))]
    targets = sorted({a for a in recipients if not _is_internal(_user_domain(a), user_domain)})

    return {
        "type": "inbox_rule",
        "severity": "high" if strong else "medium",
        "user": user,
        "description": (f"Inbox rule '{name or 'Unknown'}' ({operation}) {_join(strong + weak)}."
                        + (f" {cmdlet_rule_summary(params)}" if operation != "UpdateInboxRules"
                           and cmdlet_rule_summary(params) else "")),
        "ip": extract_ip(event),
        "event": event,
        "rule_name": name,
        "mailbox": mailbox,
        "target": mailbox,
        "targets": targets,
        "confirm_first": confirm_first,
    }


def _rule_mailbox(event: dict, params: dict, operation: str) -> str:
    """The mailbox that holds the rule, as the record names it, or "" for the actor's own mailbox.

    The -Mailbox parameter. For UpdateInboxRules (a mailbox audit record), MailboxOwnerUPN. For
    Set-InboxRule and others, the mailbox part of -Identity ("mailbox\\rule name"). A cmdlet
    without -Mailbox and with a plain rule name changes the actor's own mailbox.
    """
    mailbox = str(params.get("Mailbox") or "").strip()
    if not mailbox and operation == "UpdateInboxRules":
        mailbox = str(event.get("MailboxOwnerUPN") or "").strip()
    if not mailbox and operation != "UpdateInboxRules":
        ident = str(params.get("Identity") or "").strip()
        if "\\" in ident:
            mailbox = ident.rsplit("\\", 1)[0].strip()
    return mailbox[:300]


_NO_LETTERS_OR_DIGITS = re.compile(r"^[\W_]+$")


def _rule_name_indicator(name: str, hides: bool) -> Optional[str]:
    """Attackers give rules names that users do not notice: '.', '..', 'a'.

    A name with no letters or digits is always flagged. A name of one or two
    characters is flagged only if the rule also marks as read, moves, or deletes.
    """
    if not name:
        return None
    stripped = name.strip()
    if not stripped or _NO_LETTERS_OR_DIGITS.match(stripped):
        return f"has a name with no letters or digits ('{name[:40]}')"
    if hides and len(stripped) <= 2:
        return f"has a very short name ('{stripped}')"
    return None


_KEYWORD_FIELDS = (
    "SubjectContainsWords", "SubjectOrBodyContainsWords", "BodyContainsWords",
    "FromAddressContainsWords", "HeaderContainsWords",
)


def _rule_keyword_indicators(params: dict) -> list:
    """A rule that hides mail about payments or security (classic BEC).

    Flagged: a word in INBOX_RULE_KEYWORDS in a condition, and the rule marks
    the mail as read, moves it, or deletes it.
    """
    text = " ".join(str(params.get(f) or "") for f in _KEYWORD_FIELDS).lower()
    if not text.strip():
        return []
    words = [w for w in config.INBOX_RULE_KEYWORDS if w and w.lower() in text]
    if not words:
        return []
    actions = []
    if _is_true(params.get("MarkAsRead")):
        actions.append("marks it as read")
    if str(params.get("MoveToFolder") or "").strip():
        actions.append(f"moves it to {params.get('MoveToFolder')}")
    if _is_true(params.get("DeleteMessage")) or _is_true(params.get("SoftDeleteMessage")):
        actions.append("deletes it")
    if not actions:
        return []
    quoted = ", ".join(f"'{w}'" for w in words[:5])
    return [f"matches mail that contains {quoted} and {_join(actions)}"]


def _directory_rule_indicators(params: dict) -> list:
    """Directory recipients can be external mail contacts. Ask for verification."""
    indicators = []
    for field, verb in (("ForwardTo", "forwards"), ("ForwardAsAttachmentTo", "forwards as attachment"),
                        ("RedirectTo", "redirects")):
        recipients = [short_address(part) for part in re.split(r"[;,]", str(params.get(field) or ""))
                      if is_directory_address(part)]
        if recipients:
            indicators.append(f"{verb} to unverified directory recipients: {'; '.join(recipients)} "
                              "(the final addresses can be external; check the rule)")
    return indicators


def _cmdlet_rule_indicators(params: dict, user_domain: str) -> list:
    """Indicators for New-InboxRule, Set-InboxRule, and Enable-InboxRule parameters."""
    indicators = []
    for field, verb in (("ForwardTo", "forwards"),
                        ("ForwardAsAttachmentTo", "forwards as attachment"),
                        ("RedirectTo", "redirects")):
        # Directory references get a medium verification finding above, not
        # an assertion that the recipient is external and a high response.
        targets = [t for t in _external_targets(params.get(field), user_domain) if not is_directory_address(t)]
        if targets:
            indicators.append(f"{verb} externally to {'; '.join(targets)}")

    for field in ("DeleteMessage", "SoftDeleteMessage"):
        if str(params.get(field, "")).strip().lower() == "true":
            indicators.append("deletes matching messages")
            break

    folder = params.get("MoveToFolder", "")
    if _folder_name(folder) in HIDDEN_FOLDERS:
        indicators.append(f"moves to hidden folder: {folder}")
    return indicators


_RULE_REMOVE_OPERATIONS = ("remove", "delete")

# New-InboxRule and Set-InboxRule parameters, for the text of the alert: what the rule does, and
# for which mail.
_CMDLET_ACTIONS = (("ForwardTo", "forward to"), ("ForwardAsAttachmentTo", "forward as attachment to"),
                   ("RedirectTo", "redirect to"), ("MoveToFolder", "move to"), ("CopyToFolder", "copy to"))
_CMDLET_FLAGS = (("DeleteMessage", "delete"), ("SoftDeleteMessage", "delete"), ("MarkAsRead", "mark as read"),
                 ("StopProcessingRules", "stop other rules"))
_CMDLET_CONDITIONS = (("From", "from"), ("FromAddressContainsWords", "sender contains"),
                      ("SentTo", "sent to"), ("SubjectContainsWords", "subject contains"),
                      ("BodyContainsWords", "body contains"), ("SubjectOrBodyContainsWords", "subject or body contains"),
                      ("HeaderContainsWords", "header contains"), ("RecipientAddressContainsWords", "recipient contains"))


def _values(value) -> list:
    """A cmdlet parameter value as a list: 'a;b', '["a","b"]', or a list."""
    if isinstance(value, list):
        items = value
    else:
        text = str(value or "").strip()
        try:
            items = json.loads(text) if text.startswith("[") else re.split(r"[;,]", text)
        except ValueError:
            items = re.split(r"[;,]", text)
    return [short_address(_short_identity(str(i).strip().strip('"'))) for i in items if str(i).strip().strip('"')]


def cmdlet_rule_summary(params: dict) -> str:
    """'Actions: forward to x@evil.com; mark as read. Conditions: subject contains 'invoice'.' or ''."""
    actions = []
    for field, verb in _CMDLET_ACTIONS:
        items = _values(params.get(field))
        if items:
            actions.append(f"{verb} {', '.join(items[:5])}")
    actions += list(dict.fromkeys(verb for field, verb in _CMDLET_FLAGS if _is_true(params.get(field))))
    conditions = []
    for field, label in _CMDLET_CONDITIONS:
        items = _values(params.get(field))
        if items:
            words = ", ".join(f"'{i}'" if "contains" in label else i for i in items[:5])
            conditions.append(f"{label} {words}")
    parts = []
    if actions:
        parts.append("Actions: " + "; ".join(actions) + ".")
    if conditions:
        parts.append("Conditions: " + "; ".join(conditions) + ".")
    return " ".join(parts)[:600]


def _update_inbox_rules_indicators(params: dict, user_domain: str) -> list:
    """Indicators for UpdateInboxRules (rule changes from Outlook or EWS).

    Two record formats exist:
      - Outlook: RuleActions = '[{"ActionType":"Forward","Recipients":[...]}]'
      - EWS: Actions = "ForwardToRecipientsAction", and ServerRule holds the
        full rule as JSON (recipients included).
    The detector reads the action names from RuleActions and Actions, and the
    recipient addresses from those fields and ServerRule.
    """
    operation = str(params.get("RuleOperation", "")).lower()
    if any(word in operation for word in _RULE_REMOVE_OPERATIONS):
        return []

    action_text = " ".join(str(params.get(k) or "") for k in ("RuleActions", "Actions"))
    all_text = action_text + " " + str(params.get("ServerRule") or "")
    actions = action_text.lower()
    indicators = []

    if "forward" in actions or "redirect" in actions:
        recipients = _rule_recipients(params)
        text = " ".join(recipients) if recipients is not None else all_text
        addresses = [(m.group(0), m.group(1).lower().rstrip(".")) for m in _EMAIL_RE.finditer(text)]
        external = sorted({addr for addr, domain in addresses if not _is_internal(domain, user_domain)})
        if external:
            indicators.append(f"forwards or redirects externally to {'; '.join(external)}")
        elif not addresses:
            indicators.append("forwards or redirects; no SMTP address in the record (check the rule)")

    if "delete" in actions:
        indicators.append("deletes matching messages")

    if "move" in actions or "folder" in actions:
        hidden = sorted(f for f in HIDDEN_FOLDERS if f in all_text.lower())
        if hidden:
            indicators.append(f"moves to hidden folder: {', '.join(hidden)}")
    return indicators


def _rule_recipients(params: dict) -> Optional[list]:
    """Addresses in the rule's actions only, not in its conditions.

    Outlook: RuleActions = [{"ActionType":"Forward","Recipients":["a@x"],...}].
    EWS: ServerRule = {..., "Condition": {...}, "Actions": [{"ActionType":7,
    "Recipients":[{"Values":[{"PropType":31,"Value":"a@x"}, ...]}]}]}.
    Returns None if neither value is JSON (the caller then reads all text).
    """
    found = []

    def walk(node, in_recipients):
        if isinstance(node, dict):
            for key, value in node.items():
                walk(value, in_recipients or str(key).lower() == "recipients")
        elif isinstance(node, list):
            for value in node:
                walk(value, in_recipients)
        elif in_recipients and isinstance(node, str):
            found.extend(m.group(0) for m in _EMAIL_RE.finditer(node))

    parsed = False
    for key in ("RuleActions", "ServerRule"):
        raw = params.get(key)
        if not raw:
            continue
        try:
            data = json.loads(raw) if isinstance(raw, str) else raw
        except ValueError:
            continue
        parsed = True
        if key == "ServerRule" and isinstance(data, dict):
            data = data.get("Actions", [])
        walk(data, False)
    return found if parsed else None


def _client_tool(event: dict) -> Optional[str]:
    """An attack tool or automation library named in ClientInfoString (mailbox records)."""
    info = str(event.get("ClientInfoString") or "")
    lower = info.lower()
    for tool in list(config.ATTACK_TOOL_USER_AGENTS) + list(config.AUTOMATION_USER_AGENTS):
        if tool and tool.lower() in lower:
            return tool
    return None


def detect_suspicious_inbox_rules(events: list[dict]) -> list[dict]:
    """Flag inbox rule changes that match attacker patterns.

    Flagged: forwarding or redirection to an external address, message
    deletion, a move to a folder in HIDDEN_FOLDERS. All forward fields and all
    recipients in each field are checked.
    """
    return _run(events, _inbox_rule_finding)


# -----------------------------------------------------------------------------
# Mailbox forwarding (Set-Mailbox)
# -----------------------------------------------------------------------------

def _mailbox_forwarding_finding(event: dict) -> Optional[dict]:
    if _operation(event) not in MAILBOX_FORWARDING_OPERATIONS:
        return None

    params = _extract_parameters(event)
    user = _user(event)
    user_domain = _user_domain(user)
    # The mailbox that was changed. It is not always the account that ran Set-Mailbox.
    mailbox = str(params.get("Identity") or event.get("ObjectId") or "").strip()[:300] or user

    smtp = str(params.get("ForwardingSmtpAddress") or "").strip()
    recipient = str(params.get("ForwardingAddress") or "").strip()
    if not smtp and not recipient:
        return None  # not a forwarding change, or forwarding removed ("")

    # ForwardingSmtpAddress is "smtp:user@domain". ForwardingAddress is a
    # recipient in the directory: an address, an alias, or a name.
    external = _external_targets(smtp, user_domain)
    if recipient and "@" in recipient:
        external += _external_targets(recipient, user_domain)

    indicators = []
    if external:
        indicators.append(f"forwards externally to {'; '.join(external)}")
    if recipient and recipient not in " ".join(external):
        indicators.append(f"forwards to recipient {recipient[:200]}")
    if smtp and not external:
        indicators.append(f"forwards to {smtp[:200]}")
    if str(params.get("DeliverToMailboxAndForward", "")).strip().lower() == "false":
        indicators.append("does not keep a copy in the mailbox")

    return {
        "type": "mailbox_forwarding",
        "severity": "high" if external else "medium",
        "user": user,
        "description": f"Mailbox '{_short_identity(mailbox)}' {_join(indicators)}.",
        "ip": extract_ip(event),
        "event": event,
        "target": mailbox,
    }


def detect_mailbox_forwarding(events: list[dict]) -> list[dict]:
    """Flag Set-Mailbox changes that set mailbox-level forwarding."""
    return _run(events, _mailbox_forwarding_finding)


# -----------------------------------------------------------------------------
# OAuth consents
# -----------------------------------------------------------------------------

def _consent_finding(event: dict) -> Optional[dict]:
    operation = _operation(event)
    if operation not in SUSPICIOUS_CONSENT_OPERATIONS:
        return None

    risky_lower = {s.lower() for s in config.HIGH_RISK_OAUTH_SCOPES}
    risky_scopes = {s for s in _extract_granted_scopes(event) if s.lower() in risky_lower}
    if not risky_scopes:
        return None

    app_name = _extract_target(event).get("app_name", "Unknown App")
    return {
        "type": "oauth_consent",
        "severity": "high",
        "user": _user(event),
        "description": (
            f"{operation.rstrip('.')} '{app_name}' with risky scopes: {', '.join(sorted(risky_scopes))}"
        ),
        "ip": extract_ip(event),
        "event": event,
    }


# Application permissions that install.ps1 grants to the monitor app (Graph and the Office 365
# Management APIs). tests/test_install_grants.py checks this against install.ps1.
INSTALL_ROLES = frozenset({
    "User.ReadBasic.All", "MailboxSettings.Read", "AuditLogsQuery.Read.All", "Mail.Send",
    "User.RevokeSessions.All", "User.EnableDisableAccount.All", "User.Read.All", "MailboxSettings.ReadWrite",
    "RoleManagement.Read.Directory", "Application.Read.All", "ActivityFeed.Read",
})
_RESPONSE_ROLES = frozenset({"User.RevokeSessions.All", "User.EnableDisableAccount.All", "User.Read.All",
                             "MailboxSettings.ReadWrite"})


def install_roles() -> frozenset:
    """The roles that install.ps1 grants with the choices of this installation (its app settings).

    Mail.Send only with MAIL_SEND_SCOPE tenant; the response roles only with
    RESPONSE_PERMISSIONS true. A grant outside this set to the monitor app alerts.
    """
    roles = set(INSTALL_ROLES) - _RESPONSE_ROLES - {"Mail.Send"}
    if os.environ.get("MAIL_SEND_SCOPE", "tenant").strip().lower() != "mailbox":
        roles.add("Mail.Send")
    if os.environ.get("RESPONSE_PERMISSIONS", "").strip().lower() == "true":
        roles |= _RESPONSE_ROLES
    return frozenset(roles)
# ModifiedProperties that name the app that gets an app role (not the resource).
_GRANTEE_PROPERTIES = {"ServicePrincipal.AppId", "ServicePrincipal.ObjectID", "ServicePrincipal.Name"}


def install_grant(finding: dict) -> bool:
    """True for a consent finding about the monitor app itself, with only the roles that install.ps1 grants.

    install.ps1 (an install, an update, or -ResponsePermissions yes) makes these grants. They
    go to the Starting state report and the journal, not to an alert email. The record must
    name the monitor app as the app that gets the permission, by its app ID or service
    principal ID (not by a display name, which anyone can copy). A grant of any other risky
    scope to the monitor app still alerts.

    In a Management Activity API record of "Add app role assignment to service principal.",
    the app that gets the role is in ModifiedProperties ServicePrincipal.AppId, .ObjectID,
    and .Name; Target is the resource (Microsoft Graph). In "Consent to application.", Target
    is the app.
    """
    ids = {i.lower() for i in (config.CLIENT_ID, config.MONITOR_SP_ID) if i}
    if not ids:
        return False
    event = finding.get("event") or {}
    if finding.get("type") == "admin_role":
        return _install_exchange_grant(event, ids)
    if finding.get("type") != "oauth_consent":
        return False
    names = set()
    for prop in event.get("ModifiedProperties") or []:
        if isinstance(prop, dict) and prop.get("Name") in _GRANTEE_PROPERTIES:
            names |= {str(prop.get("NewValue") or "").strip().strip('"').lower(),
                      str(prop.get("OldValue") or "").strip().strip('"').lower()}
    for target in event.get("Target") or []:
        if isinstance(target, dict):
            names.add(str(target.get("ID") or "").lower().removeprefix("serviceprincipal_"))
    if not names & ids:
        return False
    risky_lower = {s.lower() for s in config.HIGH_RISK_OAUTH_SCOPES}
    risky = {s.lower() for s in _extract_granted_scopes(event)} & risky_lower
    if not risky:
        return False
    return risky <= {r.lower() for r in install_roles()} or _granted_by_install_run(event, risky)


# How long after a grant install.ps1 writes INSTALL_GRANTS (the grant is in step 6, the setting in
# step 8; the Exchange sign-in and the role wait are between them).
_RUN_WINDOW = timedelta(hours=2)
_CLOCK_SKEW = timedelta(minutes=5)


def install_runs() -> list:
    """[(time, account, roles)] from INSTALL_GRANTS: the grants that recent install.ps1 runs made."""
    runs = []
    for entry in os.environ.get("INSTALL_GRANTS", "").split("/"):
        parts = entry.split(";")
        if len(parts) != 3:
            continue
        try:
            at = datetime.fromisoformat(parts[0].strip().replace("Z", "+00:00"))
        except ValueError:
            continue
        at = at if at.tzinfo else at.replace(tzinfo=timezone.utc)
        roles = {r.strip().lower() for r in parts[2].split(",") if r.strip()}
        if parts[1].strip() and roles:
            runs.append((at, parts[1].strip().lower(), roles))
    return runs


def _granted_by_install_run(event: dict, risky: set) -> bool:
    """True if an install.ps1 run made this grant: the same account, the same roles, and the time of that run.

    For a grant that the current choices do not expect, for example Mail.Send from a run with
    -MailSendScope tenant before a run with mailbox. Only install.ps1 (or a person with write
    access to the Function App settings, which sends the Azure change alert) sets INSTALL_GRANTS.
    """
    actor = _user(event).strip().lower()
    try:
        when = datetime.fromisoformat(str(event.get("CreationTime") or "")[:19]).replace(tzinfo=timezone.utc)
    except ValueError:
        return False
    return any(by == actor and risky <= roles and -_CLOCK_SKEW <= at - when <= _RUN_WINDOW
               for at, by, roles in install_runs())


# Parameters that install.ps1 passes to New-ManagementRoleAssignment, and common parameters that
# do not change the grant. Any other parameter (for example another scope type) alerts.
_INSTALL_ASSIGNMENT_PARAMETERS = {"name", "app", "role", "customresourcescope", "erroraction", "warningaction",
                                  "confirm", "verbose", "debug", "informationaction"}


def _install_exchange_grant(event: dict, ids: set) -> bool:
    """True for the Exchange role assignment that install.ps1 makes with -MailSendScope mailbox.

    New-ManagementRoleAssignment -App <monitor service principal> -Role 'Application Mail.Send'
    -CustomResourceScope '<MAIL_SEND_GROUP> scope'. The scope must be the scope of the
    installation's group: the same role with no scope, or with another scope, gives the app
    Mail.Send for more mailboxes, and alerts.
    """
    params = {str(k).strip().lower(): str(v or "").strip() for k, v in _extract_parameters(event).items()}
    group = os.environ.get("MAIL_SEND_GROUP", "").strip()
    return (_operation(event) == "New-ManagementRoleAssignment"
            and os.environ.get("MAIL_SEND_SCOPE", "").strip().lower() == "mailbox"
            and bool(group)
            and params.get("role", "").lower() == "application mail.send"
            and params.get("app", "").lower() in ids
            and params.get("customresourcescope", "").lower() == f"{group} scope".lower()
            and set(params) <= _INSTALL_ASSIGNMENT_PARAMETERS)


def detect_suspicious_oauth_consents(events: list[dict]) -> list[dict]:
    """Flag consents and app role assignments that grant a scope in HIGH_RISK_OAUTH_SCOPES.

    Benign consents (User.Read, openid, profile) are not flagged.
    """
    return _run(events, _consent_finding)


def _extract_target(event: dict) -> dict:
    result = {}
    for target in event.get("Target") or []:
        if not isinstance(target, dict):
            continue
        # IdentityType: 1 = Name, 2 = Other (IDs). Some records carry it as a string.
        kind = str(target.get("Type")).strip()
        if kind == "1" and "app_name" not in result:
            result["app_name"] = str(target.get("ID", "Unknown"))
        elif kind == "2" and "app_id" not in result:
            result["app_id"] = str(target.get("ID", ""))
    for prop in event.get("ModifiedProperties") or []:
        if not isinstance(prop, dict):
            continue
        name = str(prop.get("Name", ""))
        if name == "ServicePrincipal.DisplayName" and prop.get("NewValue"):
            result["app_name"] = str(prop.get("NewValue")).strip().strip('"')
        elif name == "ConsentAction.Permissions":
            result["permissions"] = prop.get("NewValue", "")
    if "app_name" not in result:
        name = _extended_property(event, "targetName")
        if name:
            result["app_name"] = name
    return result


def _scope_tokens(value) -> set:
    return set(_SCOPE_TOKEN_RE.findall(str(value or "")))


def _extract_granted_scopes(event: dict) -> set[str]:
    """Return the words in the permission fields of a consent record.

    Sources: ModifiedProperties whose name contains "permission" or "scope"
    (delegated consent), AppRole.Value (application permission), and the
    additionalDetails extended property. The caller compares the words with
    HIGH_RISK_OAUTH_SCOPES, case-insensitive.
    """
    scopes = set()
    for prop in event.get("ModifiedProperties") or []:
        if not isinstance(prop, dict):
            continue
        name = str(prop.get("Name", "")).lower()
        if "permission" in name or "scope" in name or name == "approle.value":
            scopes |= _scope_tokens(prop.get("NewValue"))
    for prop in event.get("ExtendedProperties") or []:
        if isinstance(prop, dict) and prop.get("Name") == "additionalDetails":
            scopes |= _scope_tokens(prop.get("Value"))
    return scopes


# -----------------------------------------------------------------------------
# User agents
# -----------------------------------------------------------------------------

def _user_agent_finding(event: dict) -> Optional[dict]:
    ua = _extract_user_agent(event)
    if not ua:
        return None
    ua_lower = ua.lower()

    attack_matches = [t for t in config.ATTACK_TOOL_USER_AGENTS if t.lower() in ua_lower]
    if attack_matches:
        return {
            "type": "attack_tool",
            "severity": "high",
            "user": _user(event),
            "description": f"Sign-in with a known attack tool ({', '.join(attack_matches)}). User agent: {ua[:120]}",
            "ip": extract_ip(event),
            "event": event,
        }

    auto_matches = [t for t in config.AUTOMATION_USER_AGENTS if t.lower() in ua_lower]
    if auto_matches:
        return {
            "type": "suspicious_user_agent",
            "severity": "medium",
            "user": _user(event),
            "description": f"Sign-in with an automation library ({', '.join(auto_matches)}). User agent: {ua[:120]}",
            "ip": extract_ip(event),
            "event": event,
        }
    return None


def detect_suspicious_user_agents(events: list[dict]) -> list[dict]:
    """Flag records whose UserAgent matches an attack tool or an automation library.

    Failed sign-ins are included. The pipeline emails a failed one (wrong password) only
    with LOGIN_ALERT_FAILED; a correct password stopped by MFA always alerts.
    """
    return _run(events, _user_agent_finding, include_failed=True)


def _extract_user_agent(event: dict) -> Optional[str]:
    for prop in event.get("ExtendedProperties") or []:
        if isinstance(prop, dict) and prop.get("Name") == "UserAgent":
            value = prop.get("Value", "")
            return value if isinstance(value, str) else str(value or "")
    return None


# -----------------------------------------------------------------------------
# Sign-in methods
# -----------------------------------------------------------------------------

def _sign_in_method_finding(event: dict) -> Optional[dict]:
    if _operation(event) != "UserLoggedIn":
        return None
    user = _user(event)
    ua = (_extract_user_agent(event) or "").lower()
    if "bav2ropc" in ua:
        return _finding(
            "legacy_auth", "high", user,
            "Successful sign-in with legacy authentication (BAV2ROPC). The password alone was "
            "enough: MFA did not apply.", event)
    if _extended_property(event, "RequestType").lower() == "cmsi:cmsi":
        return _finding(
            "device_code", "medium", user,
            "Successful sign-in with the device code flow. Device code phishing uses this flow "
            "to get tokens for the account without the password.", event)
    return None


def detect_sign_in_methods(events: list[dict]) -> list[dict]:
    """Flag successful sign-ins with legacy authentication or the device code flow."""
    return _run(events, _sign_in_method_finding)


# -----------------------------------------------------------------------------
# Mail flow (transport) rules
# -----------------------------------------------------------------------------

MAIL_FLOW_RULE_OPERATIONS = {"New-TransportRule", "Set-TransportRule"}

_TRANSPORT_COPY_FIELDS = (
    ("RedirectMessageTo", "redirects mail"),
    ("BlindCopyTo", "sends a blind copy"),
    ("CopyTo", "sends a copy"),
    ("AddToRecipients", "adds a recipient"),
)


def _mail_flow_rule_finding(event: dict) -> Optional[dict]:
    operation = _operation(event)
    if operation not in MAIL_FLOW_RULE_OPERATIONS:
        return None
    params = _extract_parameters(event)
    actor = _user(event)
    domain = _user_domain(actor)
    name = params.get("Name") or params.get("Identity") or event.get("ObjectId") or "Unknown"

    high = []
    for field, verb in _TRANSPORT_COPY_FIELDS:
        targets = _external_targets(params.get(field), domain)
        if targets:
            high.append(f"{verb} to external {'; '.join(targets)}")
    if _is_true(params.get("DeleteMessage")):
        high.append("deletes matching messages")
    connector = str(params.get("RouteMessageOutboundConnector") or "").strip()
    if connector:
        high.append(f"routes mail through connector '{connector[:100]}'")

    medium = []
    if str(params.get("SetSCL", "")).strip() == "-1":
        medium.append("skips spam filtering (SCL -1)")
    if not high and not medium:
        if operation != "New-TransportRule" or not config.MAIL_FLOW_RULE_ANY:
            return None
        medium.append("was created")

    return _finding(
        "mail_flow_rule", "high" if high else "medium", actor,
        f"Mail flow rule '{name}' ({operation}) {_join(high + medium)}.", event)


def detect_mail_flow_rules(events: list[dict]) -> list[dict]:
    """Flag transport rules that copy, redirect, or delete mail, skip spam filtering, or are new."""
    return _run(events, _mail_flow_rule_finding)


# -----------------------------------------------------------------------------
# Mailbox delegation
# -----------------------------------------------------------------------------

DELEGATION_OPERATIONS = {
    "Add-MailboxPermission", "Add-RecipientPermission", "Set-Mailbox",
    "Add-MailboxFolderPermission", "Set-MailboxFolderPermission",
    # Mailbox audit actions for folder sharing from Outlook. UpdateFolderPermissions
    # is the current action (audited by default); the other two are older names.
    "UpdateFolderPermissions", "AddFolderPermissions", "ModifyFolderPermissions",
}
# Add-MailboxPermission rights that give control of the mailbox.
_MAILBOX_RIGHTS = ("fullaccess", "changepermission", "changeowner")
# Folder roles (cmdlets) and rights (cmdlets and Outlook audit records) that
# let the member read mail. Other values (AvailabilityOnly, FreeBusySimple,
# Visible, CreateItems, ...) do not.
_READ_FOLDER_RIGHTS = {
    "readany", "readitems", "reviewer", "author", "noneditingauthor", "editor",
    "publishingeditor", "publishingauthor", "owner",
}
# Folder members that mean "everyone": "Default" in cmdlets, "Everyone" in
# mailbox audit records from Outlook.
_EVERYONE = {"default", "everyone", "anonymous"}


def _folder_share_text(folder: str, member: str, rights: str, actor: str) -> Optional[str]:
    """Text for a mail folder shared with everyone or an external address, else None."""
    if not member or not rights or "calendar" in folder.lower():
        return None  # calendar sharing is normal
    if not any(r.lower() in _READ_FOLDER_RIGHTS for r in re.split(r"[\s,;]+", rights.strip("[]")) if r):
        return None
    external = _external_targets(member, _user_domain(actor)) if "@" in member else []
    if member.lower() not in _EVERYONE and not external:
        return None
    who = ("everyone in the organization" if member.lower() in ("default", "everyone")
           else "anyone (anonymous)" if member.lower() == "anonymous" else member)
    return f"Folder '{folder}' was shared with {who} ({rights})"


def _delegation_finding(event: dict) -> Optional[dict]:
    operation = _operation(event)
    if operation not in DELEGATION_OPERATIONS or _is_system_actor(event):
        return None
    params = _extract_parameters(event)
    actor = _user(event)
    mailbox = _short_identity(params.get("Identity") or event.get("ObjectId") or "Unknown")

    if operation in ("UpdateFolderPermissions", "AddFolderPermissions", "ModifyFolderPermissions"):
        # Mailbox audit record (Outlook or OWA folder sharing). The member and
        # rights are in Item.ParentFolder. The actor may be a SID.
        parent = ((event.get("Item") or {}).get("ParentFolder") or {}) if isinstance(event.get("Item"), dict) else {}
        owner = str(event.get("MailboxOwnerUPN") or "")
        who = actor if "@" in actor else (owner or actor)
        folder = str(parent.get("Path") or parent.get("Name") or "")
        text = _folder_share_text(folder, str(parent.get("MemberUpn") or "").strip(),
                                  str(parent.get("MemberRights") or "").strip(), who)
        if not text:
            return None
        mailbox_note = f" in the mailbox of {owner}" if owner and owner != who else ""
        return _finding("mailbox_delegation", "medium", who, f"{text}{mailbox_note}. Changed by {who}.", event)

    if operation == "Add-MailboxPermission":
        rights = str(params.get("AccessRights", ""))
        granted = [r for r in _MAILBOX_RIGHTS if r in rights.lower()]
        if not granted:
            return None
        grantee = _short_identity(params.get("User") or "Unknown")
        text = f"{rights} on mailbox '{mailbox}' was granted to {grantee}"
    elif operation == "Add-RecipientPermission":
        if "sendas" not in str(params.get("AccessRights", "")).lower():
            return None
        text = f"Send As for '{mailbox}' was granted to {params.get('Trustee') or 'Unknown'}"
    elif operation == "Set-Mailbox":
        grantee = str(params.get("GrantSendOnBehalfTo") or "").strip()
        if not grantee:
            return None
        text = f"Send on behalf for '{mailbox}' was granted to {grantee[:200]}"
    else:
        # Identity is "mailbox:\\Folder[\\Subfolder]".
        folder = str(mailbox)
        if ":" not in folder:
            return None
        text = _folder_share_text(folder, str(params.get("User") or "").strip(),
                                  str(params.get("AccessRights") or "").strip(), actor)
        if not text:
            return None

    return _finding("mailbox_delegation", "medium", actor, f"{text}. Changed by {actor}.", event)


def detect_mailbox_delegation(events: list[dict]) -> list[dict]:
    """Flag FullAccess, SendAs, SendOnBehalf, and folder sharing with everyone or outside."""
    return _run(events, _delegation_finding)


# -----------------------------------------------------------------------------
# Audit turned off
# -----------------------------------------------------------------------------

def _audit_finding(event: dict) -> Optional[dict]:
    operation = _operation(event)
    if operation not in ("Set-AdminAuditLogConfig", "Set-OrganizationConfig",
                         "Set-MailboxAuditBypassAssociation", "Set-Mailbox"):
        return None
    params = _extract_parameters(event)
    identity = _short_identity(params.get("Identity") or event.get("ObjectId") or "Unknown")
    if operation == "Set-AdminAuditLogConfig" and _is_false(params.get("UnifiedAuditLogIngestionEnabled")):
        text = "Unified audit logging was turned off for the tenant. The monitor gets no more records"
    elif operation == "Set-OrganizationConfig" and _is_true(params.get("AuditDisabled")):
        text = "Mailbox auditing was turned off for the organization"
    elif operation == "Set-MailboxAuditBypassAssociation" and _is_true(params.get("AuditBypassEnabled")):
        text = f"Audit bypass was set for '{identity}'. Its actions on mailboxes are not logged"
    elif operation == "Set-Mailbox" and _is_false(params.get("AuditEnabled")):
        text = f"Mailbox auditing was turned off for '{identity}'"
    else:
        return None
    return _finding("audit_disabled", "high", _user(event), f"{text} ({operation}).", event)


def detect_audit_disabled(events: list[dict]) -> list[dict]:
    """Flag changes that turn off unified audit or mailbox audit."""
    return _run(events, _audit_finding)


# -----------------------------------------------------------------------------
# Mail protection weakened
# -----------------------------------------------------------------------------

_PROTECTION_OBJECTS = {
    "AntiPhishPolicy", "AntiPhishRule", "MalwareFilterPolicy", "MalwareFilterRule",
    "HostedContentFilterPolicy", "HostedContentFilterRule", "SafeLinksPolicy", "SafeLinksRule",
    "SafeAttachmentPolicy", "SafeAttachmentRule", "ATPProtectionPolicyRule", "EOPProtectionPolicyRule",
    "HostedOutboundSpamFilterPolicy", "HostedOutboundSpamFilterRule",
}


def _protection_finding(event: dict) -> Optional[dict]:
    operation = _operation(event)
    verb, _, noun = operation.partition("-")
    params = _extract_parameters(event)
    identity = _short_identity(params.get("Identity") or event.get("ObjectId") or "Unknown")
    severity = "medium"

    if verb in ("Remove", "Disable") and noun in _PROTECTION_OBJECTS:
        kind = "policy" if noun.endswith("Policy") else "rule"
        done = "removed" if verb == "Remove" else "turned off"
        text = f"Mail protection {kind} '{identity}' was {done}"
    elif operation == "Set-OrganizationConfig" and _is_false(params.get("RejectDirectSend")):
        text = ("Direct Send protection was turned off (RejectDirectSend = False). Anyone on the internet "
                "can again send mail that claims to come from your domains to your users")
        severity = "high"
    elif operation == "Set-DkimSigningConfig" and _is_false(params.get("Enabled")):
        text = f"DKIM signing was turned off for '{identity}'"
    elif (noun == "HostedOutboundSpamFilterPolicy" and verb in ("Set", "New")
          and str(params.get("AutoForwardingMode", "")).strip().lower() == "on"):
        text = f"Automatic forwarding to external addresses was allowed (policy '{identity}')"
        severity = "high"
    elif noun == "HostedContentFilterPolicy" and verb in ("Set", "New"):
        allowed = [str(params.get(f) or "").strip() for f in ("AllowedSenderDomains", "AllowedSenders")]
        allowed = [a for a in allowed if a and a.lower() not in ("$null", "{}", "[]")]
        if not allowed:
            return None
        text = f"Senders were allowed past the spam filter: {'; '.join(allowed)[:200]} (policy '{identity}')"
    else:
        return None
    return _finding("mail_protection_weakened", severity, _user(event), f"{text} ({operation}).", event)


def detect_mail_protection_weakened(events: list[dict]) -> list[dict]:
    """Flag removed or disabled mail protection, DKIM off, external auto-forwarding allowed."""
    return _run(events, _protection_finding)


# -----------------------------------------------------------------------------
# MFA changes
# -----------------------------------------------------------------------------

_MFA_PROPERTIES = {
    "StrongAuthenticationMethod": "MFA methods",
    "StrongAuthenticationPhoneAppDetail": "Authenticator app devices",
}


def _count_methods(value) -> int:
    """Number of entries in a StrongAuthentication* value (a JSON list)."""
    text = str(value or "").strip()
    if not text:
        return 0
    try:
        data = json.loads(text)
        if isinstance(data, str):
            data = json.loads(data)
        if isinstance(data, list):
            return len([d for d in data if d])
    except (ValueError, TypeError):
        pass
    return len(re.findall(r'"(?:MethodType|DeviceName)"', text))


_PHONE_FIELDS = ("PhoneNumber", "AlternativePhoneNumber", "VoiceOnlyPhoneNumber")


def _phone_numbers(value) -> set:
    """Phone numbers in a StrongAuthenticationUserDetails value (JSON list of one object)."""
    try:
        data = json.loads(str(value or "").strip() or "[]")
        if isinstance(data, str):
            data = json.loads(data)
    except (ValueError, TypeError):
        return set()
    items = data if isinstance(data, list) else [data]
    return {str(d.get(f)).strip() for d in items if isinstance(d, dict) for f in _PHONE_FIELDS
            if d.get(f) and str(d.get(f)).strip()}


def _mfa_finding(event: dict) -> Optional[dict]:
    operation = _operation(event)
    actor = _user(event)
    if operation == "Disable Strong Authentication.":
        target = _target_user(event)
        return _finding("mfa_change", "high", target,
                        f"Per-user MFA was turned off for {target}. Changed by {_actor_name(event)}.", event,
                        target=target)
    if operation == "Set Company Information." and "StrongAuthenticationPolicy" in _modified_properties(event):
        return _finding("mfa_change", "medium", actor,
                        f"Tenant MFA settings were changed (for example trusted IPs that skip MFA). "
                        f"Changed by {_actor_name(event)}.", event)
    if operation != "Update user.":
        return None

    props = _modified_properties(event)
    changes = []
    for name, label in _MFA_PROPERTIES.items():
        if name in props:
            old, new = (_count_methods(v) for v in props[name])
            # A first registration (old == 0) is normal for a new user.
            if new > old > 0:
                changes.append(f"{label}: {old} to {new}")
    if "StrongAuthenticationUserDetails" in props:
        old_phones, new_phones = (_phone_numbers(v) for v in props["StrongAuthenticationUserDetails"])
        added = sorted(new_phones - old_phones)
        # A first phone number (none before) is a normal registration.
        if old_phones and added:
            changes.append(f"phone number added or changed: {', '.join(added)}")
    if not changes:
        return None
    target = _target_user(event)
    actor = _actor_name(event)
    # The MFA service writes the record when the user registers a method in My Sign-ins.
    by = (f"Changed by {actor}." if "@" in actor else
          f"Registered by the user, or by someone with the user's sign-in (record written by {actor}).")
    return _finding("mfa_change", "medium", target,
                    f"An MFA method was added or changed for {target}, which already had MFA "
                    f"({'; '.join(changes)}). {by}", event, target=target)


def detect_mfa_changes(events: list[dict]) -> list[dict]:
    """Flag an MFA method added to an account that had MFA, per-user MFA off, tenant MFA changes."""
    return _run(events, _mfa_finding)


# -----------------------------------------------------------------------------
# Admin roles
# -----------------------------------------------------------------------------

# Roles that can take over the tenant. Other roles are medium.
_TOP_ROLES = {
    "global administrator", "company administrator", "privileged role administrator",
    "privileged authentication administrator",
}


def _admin_role_finding(event: dict) -> Optional[dict]:
    operation = _operation(event)
    actor = _user(event)
    if operation == "Add member to role.":
        role = _clean(_modified_properties(event).get("Role.DisplayName", ("", ""))[1]) or "Unknown role"
        target = _target_user(event)
        app_id = _spn_app_id(target)
        # Microsoft's own provisioning (actor "Certificate") adds its first-party apps to roles.
        if actor.strip().lower() == "certificate" and _MICROSOFT_APP_ID_RE.match(app_id):
            return None
        if app_id and ";" in target:
            target = f"the service principal of app {app_id}"
        severity = "high" if role.lower() in _TOP_ROLES else "medium"
        return _finding("admin_role", severity, actor,
                        f"{target} was added to the role '{role}'. Changed by {_actor_name(event)}.", event)
    if operation == "New-ManagementRoleAssignment" and not _is_system_actor(event):
        params = _extract_parameters(event)
        role = str(params.get("Role") or "Unknown role")
        assignee = (params.get("User") or params.get("SecurityGroup") or params.get("App")
                    or params.get("Policy") or "Unknown")
        severity = "high" if role.lower() == "applicationimpersonation" else "medium"
        return _finding("admin_role", severity, actor,
                        f"Exchange role '{role}' was assigned to {assignee}. Changed by {actor}.", event)
    return None


def detect_admin_roles(events: list[dict]) -> list[dict]:
    """Flag a member added to an Entra ID role, and Exchange management role assignments."""
    return _run(events, _admin_role_finding)


# -----------------------------------------------------------------------------
# App credentials
# -----------------------------------------------------------------------------

def _app_credential_finding(event: dict) -> Optional[dict]:
    operation = _operation(event)
    is_app = operation.startswith("Update application") and "Certificates and secrets" in operation
    if not is_app and operation != "Add service principal credentials.":
        return None
    target = _extract_target(event)
    app = target.get("app_name") or str(event.get("ObjectId") or "Unknown app")
    kind = "app registration" if is_app else "service principal"
    return _finding("app_credential", "medium", _user(event),
                    f"A secret or certificate was added to the {kind} '{app}'. An app credential "
                    f"gives access that does not need a user sign-in or MFA.", event)


def detect_app_credentials(events: list[dict]) -> list[dict]:
    """Flag a secret or certificate added to an app registration or service principal."""
    return _run(events, _app_credential_finding)


# -----------------------------------------------------------------------------
# Domain federation
# -----------------------------------------------------------------------------

_FEDERATION_OPERATIONS = {
    "Set domain authentication.": "high",
    "Set federation settings on domain.": "high",
    "Add-FederatedDomain": "medium",
    "Add domain to company.": "medium",
    "Verify domain.": "medium",
    "Add unverified domain.": "medium",
    "Add verified domain.": "medium",
}


def _federation_finding(event: dict) -> Optional[dict]:
    operation = _operation(event)
    severity = _FEDERATION_OPERATIONS.get(operation)
    if not severity:
        return None
    domain = (_extract_parameters(event).get("DomainName") or _target_user(event))
    if severity == "high":
        text = (f"Federation was set on domain '{domain}'. The owner of the federation server "
                f"can sign in as any user in that domain")
    else:
        text = f"Domain '{domain}' was added or verified ({operation.rstrip('.')})"
    return _finding("domain_federation", severity, _user(event), f"{text}. Changed by {_actor_name(event)}.", event)


def detect_domain_federation(events: list[dict]) -> list[dict]:
    """Flag federation set on a domain, and domains added to the tenant."""
    return _run(events, _federation_finding)


# -----------------------------------------------------------------------------
# Operation names
# -----------------------------------------------------------------------------

def _known_operations() -> set:
    ops = (SUSPICIOUS_INBOX_RULE_OPERATIONS | MAILBOX_FORWARDING_OPERATIONS | SUSPICIOUS_CONSENT_OPERATIONS
           | MAIL_FLOW_RULE_OPERATIONS | DELEGATION_OPERATIONS | set(_FEDERATION_OPERATIONS))
    ops |= {"UserLoggedIn", "Set-AdminAuditLogConfig", "Set-OrganizationConfig",
            "Set-MailboxAuditBypassAssociation", "Set-DkimSigningConfig",
            "Disable Strong Authentication.", "Set Company Information.", "Update user.",
            "Add member to role.", "New-ManagementRoleAssignment", "Add service principal credentials."}
    for noun in _PROTECTION_OBJECTS:
        ops |= {f"Remove-{noun}", f"Disable-{noun}", f"Set-{noun}", f"New-{noun}"}
    return ops


APP_CREDENTIAL_OPERATION = "Update application – Certificates and secrets management"
_SIGN_IN_OPERATIONS = {"UserLoggedIn", "UserLoginFailed"}


def history_operations() -> list:
    """The operations that the detectors read, without sign-ins (for the audit search)."""
    return sorted((_known_operations() - _SIGN_IN_OPERATIONS) | {APP_CREDENTIAL_OPERATION})


# Microsoft documents some names in a different case than records use (for
# example "Set company information." on Learn). Match without case, then use
# the spelling this module compares against.
_CANONICAL = {op.lower(): op for op in _known_operations()}


def _operation(event: dict) -> str:
    raw = str(event.get("Operation") or "").strip()
    if raw.lower().startswith("update application") and "certificates and secrets" in raw.lower():
        return APP_CREDENTIAL_OPERATION
    return _CANONICAL.get(raw.lower(), raw)
