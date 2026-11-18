"""Runtime settings: defaults from the environment, overrides from the management UI.

install.ps1 sets the environment (app settings). These are the defaults. The
management UI stores overrides in Table Storage. Each run reads the overrides
and sets the values on the ``config`` module, so every module that reads
``config.X`` at call time uses them. install.ps1 does not touch the overrides,
so ``install.ps1 -Update`` does not revert a change made in the UI.

One schema (SETTINGS) defines each setting: how the UI shows it, how the
server validates it, and how it maps to ``config``.
"""

import ipaddress
import logging
import re
from dataclasses import dataclass, field

import config
import webhook


@dataclass(frozen=True)
class Setting:
    name: str
    group: str
    label: str
    help: str
    kind: str                     # int, bool, choice, label (one line of text), mailbox (one address),
                                  # secret (write-only text), ip_list, domain_list,
                                  # country_list, email_list, word_list, asn_list, type_set (the choices that
                                  # are OFF), role_set (the choices that are selected)
    choices: tuple = ()           # ((value, label), ...) for kind "choice"
    minimum: int = None
    maximum: int = None
    # Graph application roles that a value needs: {value: (role, ...)}
    needs: dict = field(default_factory=dict)
    # Values that weaken detection: the UI asks for confirmation.
    risky: tuple = ()


# Alert types that can be turned off (finding types). Same keys as alerting._FINDING_TITLES.
ALERT_TYPES = (
    ("inbox_rule", "Inbox rules"),
    ("mailbox_forwarding", "Mailbox forwarding"),
    ("mail_flow_rule", "Mail flow (transport) rules"),
    ("mailbox_delegation", "Mailbox and folder access"),
    ("oauth_consent", "Risky OAuth consents"),
    ("mfa_change", "MFA changes"),
    ("admin_role", "Admin roles"),
    ("app_credential", "App secrets and certificates"),
    ("domain_federation", "Domains and federation"),
    ("audit_disabled", "Audit turned off"),
    ("mail_protection_weakened", "Mail protection weakened"),
    ("session_reuse", "Session used from a second country or a risky IP"),
    ("mail_access", "Mail read or sent from a risky IP"),
    ("legacy_auth", "Legacy authentication sign-ins"),
    ("device_code", "Device code sign-ins"),
    ("attack_tool", "Attack tool sign-ins"),
    ("suspicious_user_agent", "Automation client sign-ins"),
)

# Entra built-in roles whose members can be given access to the management UI, by role template
# ID (learn.microsoft.com: Microsoft Entra built-in roles). Graph role assignments of a built-in
# role use this ID as roleDefinitionId.
DIRECTORY_ROLES = (
    ("62e90394-69f5-4237-9190-012177145e10", "Global Administrator"),
    ("e8611ab8-c189-46e8-94e1-60213ab1f814", "Privileged Role Administrator"),
    ("194ae4cb-b126-40b2-bd5b-6091b380977d", "Security Administrator"),
    ("5f2222b1-57c3-48ba-8ad5-d4759f1fde6f", "Security Operator"),
    ("29232cdf-9323-42fd-ade2-1d097af3e4de", "Exchange Administrator"),
)

# Types that are always high. A mute hides medium alerts only, so these cannot be muted.
ALWAYS_HIGH = {"oauth_consent", "attack_tool", "legacy_auth", "audit_disabled"}
# Types that a targeted mute can hide (management UI > Mutes).
MUTE_TYPES = tuple(t for t in ALERT_TYPES if t[0] not in ALWAYS_HIGH) + (
    ("suspicious_signin", "Suspicious sign-ins (VPN, proxy, hosting IP)"),
)

GROUPS = (
    ("alerts", "Alerts"),
    ("email", "Email"),
    ("webhook", "Webhook"),
    ("signin", "Suspicious sign-ins"),
    ("countries", "New sign-in countries"),
    ("response", "Automatic response"),
    ("access", "Management UI access"),
    ("allow", "Allowlists"),
    ("detection", "Detection lists"),
    ("advanced", "Advanced"),
)

SETTINGS = (
    Setting("ALERTS_OFF", "alerts", "Alert types that send email",
            "Clear a box to stop email for that alert type. The detection is still written to the "
            "log. Sign-in and new-country emails have their own settings below.",
            "type_set", choices=ALERT_TYPES, risky=("*",)),
    Setting("WEEKLY_REPORT", "alerts", "Weekly health report",
            "Each Monday, email a short report: the monitor ran, how many sign-ins it checked, the "
            "alerts of the week, and settings that weaken protection.", "bool"),
    Setting("MAIL_FLOW_RULE_ANY", "alerts", "Alert on every new mail flow rule",
            "Off: alert only on mail flow rules that copy, redirect, or delete mail, route it through "
            "a connector, or skip spam filtering. On: also alert on any other new rule.", "bool"),

    Setting("ADMIN_EMAIL", "email", "Alert mailbox",
            "Sends and receives every email. It must be a licensed or shared mailbox in this tenant. If Mail.Send "
            "is limited to the alert mailbox, first add the new mailbox to the Exchange group of the monitor "
            "(Overview > Access shows its name) and wait up to 2 hours. Before the save, the app sends a "
            "test email from it; the save stops if Microsoft Graph refuses. The old address gets a notice. The "
            "Azure Monitor health alerts move to the new address.", "mailbox"),
    Setting("TENANT_LABEL", "email", "Tenant name in subjects",
            "For people who get alerts from more than one tenant. \"Contoso\" gives \"[M365 Alert][Contoso] "
            "...\". At most 40 characters, no [ or ]. Empty: no name.", "label", maximum=40),
    Setting("ALERT_RECIPIENTS", "email", "Extra recipients of alerts",
            "One address per line, for example a ticket system. These get every [M365 Alert] email. The "
            "alert mailbox always gets them. Alerts contain user names, IP addresses, and audit records.",
            "email_list"),
    Setting("REPORT_RECIPIENTS", "email", "Extra recipients of reports",
            "One address per line. These get the weekly, monthly, and starting-state reports "
            "([M365 Monitor]). The alert mailbox always gets them.", "email_list"),

    Setting("LOGIN_ALERT_CONFIDENCE", "signin", "Which suspicious sign-ins send email",
            "The app always logs suspicious sign-ins. This controls email only.",
            "choice", choices=(("low", "All (includes VPN users)"),
                               ("medium", "Medium and high confidence"),
                               ("high", "High confidence only (Tor, proxy, compromised server)"),
                               ("off", "None (log only)")),
            risky=("off",)),
    Setting("LOGIN_ALERT_FAILED", "signin", "Email failed sign-ins",
            "Off: a failed sign-in (wrong password) from a suspicious IP, an automation client, or an attack "
            "tool is logged and shown in Alerts, with no email. A correct password that stopped at MFA or "
            "Conditional Access always sends email. On: also email failed sign-ins, for example each IP of a "
            "password spray.", "bool"),
    Setting("LOGIN_ALERT_MODE", "signin", "Email format",
            "Digest batches sign-ins into one email. Use it if a password spray sends many emails.",
            "choice", choices=(("immediate", "One email per sign-in"), ("digest", "One digest email"))),
    Setting("LOGIN_DIGEST_MINUTES", "signin", "Digest delay (minutes)",
            "Digest mode: send when the oldest queued sign-in is this old.",
            "int", minimum=0, maximum=1440),
    Setting("ALERT_DELIVERY", "webhook", "Send alerts by",
            "Where each alert goes. Reports (weekly, monthly, starting state) and the notices of changes "
            "in the management UI always go by email. With \"Webhook only\", an alert goes by email when "
            "the webhook fails.",
            "choice", choices=(("email", "Email only"), ("both", "Email and webhook"),
                               ("webhook", "Webhook only (email if the webhook fails)")),
            risky=("webhook",)),
    Setting("WEBHOOK_URL", "webhook", "Webhook URL",
            "An incoming webhook URL, for example from Slack (Incoming Webhooks) or Microsoft Teams "
            "(Workflows: \"Post to a channel when a webhook request is received\"). HTTPS only. The URL is a "
            "secret: it is stored in Table Storage and is never shown again. To test it, send test alerts "
            "from the Overview page.", "secret"),
    Setting("WEBHOOK_FORMAT", "webhook", "Webhook message format",
            "Slack: a text message. Microsoft Teams: an Adaptive Card for a Workflows webhook. JSON: the "
            "fields subject, text, link, tenant, and sent_at, for other services.",
            "choice", choices=(("slack", "Slack"), ("teams", "Microsoft Teams (Workflows)"), ("json", "JSON"))),

    Setting("PROXYCHECK_API_KEY", "signin", "proxycheck.io API key",
            "A free key from proxycheck.io gives 1,000 IP lookups per day (100 without a key). The key is "
            "stored in Table Storage and is never shown again. Enter a new key to replace it.", "secret"),
    Setting("RISK_SCORE_THRESHOLD", "signin", "Risk score threshold (0-100)",
            "proxycheck.io risk score that flags an IP. Lower gives more alerts.",
            "int", minimum=0, maximum=100),

    Setting("GEO_ANOMALY_ENABLED", "countries", "Alert on a sign-in from a new country",
            "The app learns the countries of each user's sign-ins and alerts on a new one.",
            "bool", risky=(False,)),
    Setting("SESSION_CHECK_ENABLED", "countries", "Alert when a session moves to another country or a risky IP",
            "Sign-ins and mailbox records carry the Entra session ID. A stolen session cookie or token "
            "keeps it. An alert is sent when a session appears in a second country, or when a session "
            "that started on a normal network is used from a VPN, proxy, hosting, or Tor IP that did not "
            "sign in.", "bool",
            risky=(False,)),
    Setting("MAIL_ACCESS_CHECK", "countries", "Alert on mail read or sent from a risky IP",
            "Mail read or sent (MailItemsAccessed, Send) from a VPN, proxy, hosting, or new-country IP "
            "that did not sign in as the user in 7 days. This can be a stolen session or token. Works only "
            "if the tenant logs mail access: see Overview > Mail access records.", "bool", risky=(False,)),
    Setting("HOME_COUNTRIES", "countries", "Home countries",
            "Two-letter codes, for example US, CA. Never alert for these. If set, alerts start "
            "before the learning period ends.", "country_list"),
    Setting("GEO_LEARNING_DAYS", "countries", "Learning period (days)",
            "Days the app only learns, from the first run. No country alerts in this period.",
            "int", minimum=0, maximum=90),
    Setting("GEO_PROMOTE_DAYS", "countries", "Days until a new country is usual",
            "A new country becomes usual for a user after sign-ins on this many different days.",
            "int", minimum=1, maximum=30),
    Setting("GEO_BASELINE_DAYS", "countries", "Forget a country after (days)",
            "A country leaves a user's usual countries after this many days with no sign-in.",
            "int", minimum=7, maximum=365),

    Setting("ANOMALY_ACTION", "response", "Action on a sign-in from a new country",
            "Applies to successful sign-ins only, after the learning period. Revoke stops refresh "
            "tokens and browser sessions. Block also disables the account.",
            "choice", choices=(("none", "Email only"), ("revoke", "Revoke sessions"),
                               ("disable", "Block sign-in and revoke sessions")),
            needs={"revoke": ("User.RevokeSessions.All",),
                   "disable": ("User.RevokeSessions.All", "User.EnableDisableAccount.All", "User.Read.All")}),
    Setting("COMPROMISE_ACTION", "response", "Action on a high account-takeover alert",
            "Applies to high alerts on the affected account: stolen session, forwarding or hiding inbox "
            "rule, mailbox forwarding, attack tool, legacy authentication, and others raised to high "
            "by the source IP. Not to admin changes or OAuth consents, or to a change that one account "
            "made to another account. Revoke stops refresh tokens "
            "and browser sessions. Block also disables the account. The password is not changed.",
            "choice", choices=(("none", "Email only"), ("revoke", "Revoke sessions"),
                               ("disable", "Block sign-in and revoke sessions")),
            needs={"revoke": ("User.RevokeSessions.All",),
                   "disable": ("User.RevokeSessions.All", "User.EnableDisableAccount.All", "User.Read.All")}),
    Setting("AUTO_DISABLE_INBOX_RULES", "response", "Turn off malicious inbox rules",
            "On a high inbox rule alert, turn the rule off through Microsoft Graph. The rule is kept "
            "for investigation; turn it on again in Outlook if it was legitimate.", "bool",
            needs={True: ("MailboxSettings.ReadWrite",)}),
    Setting("ANOMALY_ACTION_EXEMPT", "response", "Never change these accounts",
            "One address per line. Put break-glass and admin accounts here. The alert mailbox is "
            "always exempt. Applies to both actions above.", "email_list"),
    Setting("ANOMALY_ACTION_MAX_PER_DAY", "response", "Maximum account actions per day",
            "For both actions above together. Protects against a wrong result that would lock out "
            "many users. Inbox rule changes do not count.", "int", minimum=0, maximum=50),

    Setting("UI_ADMIN_USERS", "access", "Users who can open the management UI",
            "One sign-in address per line, for example sam@contoso.com. For a guest, use the guest's own "
            "address (bob@fabrikam.com), not the #EXT# name. These users can open this page, change settings, "
            "and use the response buttons, like users with the Monitor.Admin role.",
            "email_list"),
    Setting("UI_ADMIN_ROLES", "access", "Directory roles that can open the management UI",
            "Members of a selected Entra role can open this page, like users with the Monitor.Admin role. "
            "Only active, direct role assignments count (not PIM-eligible roles that are not activated, "
            "and not roles assigned through a group).",
            "role_set", choices=DIRECTORY_ROLES, needs={"*": ("RoleManagement.Read.Directory",)}),
    Setting("UI_ACCOUNT_CHECK", "access", "End the session of a blocked or revoked admin",
            "Off by default. The sign-in to this page lasts until its cookie expires (8 hours, or the "
            "time set with ./install.ps1 -UiSessionHours): blocking an admin or revoking the admin's "
            "sessions does not end it. On: each request reads the admin's account from Microsoft Graph "
            "(at most once a minute) and refuses it if the account is blocked or its sessions were revoked "
            "after the sign-in. If Graph does not answer, the request is allowed. Needs User.Read.All "
            "(the response permissions).", "bool", needs={True: ("User.Read.All",)}),

    Setting("ALLOWED_IPS", "allow", "Allowed IPs and ranges",
            "One per line, for example 203.0.113.0/24. Sign-ins from these IPs cause no suspicious "
            "sign-in, new-country, or session alert. Compromise alerts still apply.", "ip_list", risky=("*",)),
    Setting("PRIVATE_RELAY_TRUSTED", "allow", "Treat iCloud Private Relay as normal",
            "Safari on iPhone and Mac can send sign-ins through iCloud Private Relay. Its IPs look like "
            "a VPN. On: an IP in Apple's relay list causes no suspicious sign-in alert, and its country "
            "comes from Apple's list. New-country, session, and compromise alerts still apply.",
            "bool", risky=(True,)),
    Setting("ALLOWED_ASNS", "allow", "Allowed networks (ASNs)",
            "One per line, for example AS21928. Sign-in IPs in these networks never count as VPN, "
            "proxy, or hosting. Use it for mobile carriers that cause false alerts. New-country, "
            "session, and compromise alerts still apply. Attackers can rent mobile carrier IPs.",
            "asn_list", risky=("*",)),
    Setting("INTERNAL_DOMAINS", "allow", "Internal mail domains",
            "One per line. Forwarding to these domains is not external. The user's own domain and "
            "the tenant's verified domains (read by install.ps1) are always internal.", "domain_list", risky=("*",)),

    Setting("HIGH_RISK_OAUTH_SCOPES", "detection", "High-risk OAuth scopes",
            "One per line. A consent that grants one of these causes an alert.", "word_list"),
    Setting("ATTACK_TOOL_USER_AGENTS", "detection", "Attack tool user agents",
            "One per line. A sign-in whose user agent contains one of these is a high alert.", "word_list"),
    Setting("AUTOMATION_USER_AGENTS", "detection", "Automation user agents",
            "One per line. A sign-in whose user agent contains one of these is a medium alert.", "word_list"),
    Setting("INBOX_RULE_KEYWORDS", "detection", "Inbox rule keywords",
            "One per line. An inbox rule that looks for one of these words and marks the mail as "
            "read, moves it, or deletes it is a medium alert.", "word_list"),

    Setting("UPDATE_CHECK", "advanced", "Check for updates",
            "Once a day, ask GitHub for the latest release (no sign-in, no data about your tenant). "
            "Overview and the weekly report then say when an update is available. The monitor never "
            "installs code itself: run ./install.ps1 -Update.", "bool"),
    Setting("IP_CACHE_DAYS", "advanced", "Keep clean IP lookups (days)",
            "How long the monitor keeps a proxycheck.io answer for an IP that is not flagged (office, home, "
            "mobile). Each new lookup uses the daily quota. A flagged IP (VPN, proxy, hosting, Tor) is looked "
            "up again after 24 hours. If a clean IP becomes a proxy, the monitor sees it after this time.",
            "int", minimum=1, maximum=7),
    Setting("LOOKBACK_MINUTES", "advanced", "Fetch window (minutes)",
            "Minutes of audit content each 2-minute run fetches. A failed alert is retried while "
            "its content stays in this window.", "int", minimum=3, maximum=60),
    Setting("NO_CONTENT_ALERT_HOURS", "advanced", "Error after no audit content (hours)",
            "Log an error (and fire the errors alert) if no audit content arrives for this long. "
            "0 turns the check off.", "int", minimum=0, maximum=720),
    Setting("RESOLVE_USER_IDS", "advanced", "Link alerts to the exact user",
            "Look up each user's object ID in Graph, so the alert button opens the user.",
            "bool", needs={True: ("User.ReadBasic.All",)}),
)

BY_NAME = {s.name: s for s in SETTINGS}

_LIST_MAX_ITEMS = 500
_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
_EMAIL_RE = re.compile(r"^[^@\s,;]+@[a-z0-9.-]+\.[a-z]{2,}$")
_COUNTRY_RE = re.compile(r"^[A-Z]{2}$")


# -----------------------------------------------------------------------------
# Validation: UI value -> normalized UI value (or ValueError with a message)
# -----------------------------------------------------------------------------

def _items(raw) -> list:
    if raw is None:
        return []
    if isinstance(raw, str):
        raw = re.split(r"[\n,;]+", raw)
    if not isinstance(raw, (list, tuple)):
        raise ValueError("Must be a list.")
    out, seen = [], set()
    for item in raw:
        if not isinstance(item, str):
            raise ValueError("Each entry must be text.")
        item = item.strip()
        if item and item.lower() not in seen:
            seen.add(item.lower())
            out.append(item)
    if len(out) > _LIST_MAX_ITEMS:
        raise ValueError(f"At most {_LIST_MAX_ITEMS} entries.")
    return out


def validate(setting: Setting, raw):
    """Return the normalized value, or raise ValueError with a message for the user."""
    kind = setting.kind
    if kind == "int":
        if isinstance(raw, bool) or not isinstance(raw, (int, str)):
            raise ValueError("Must be a whole number.")
        try:
            value = int(str(raw).strip())
        except ValueError:
            raise ValueError("Must be a whole number.")
        if setting.minimum is not None and value < setting.minimum:
            raise ValueError(f"Must be {setting.minimum} or more.")
        if setting.maximum is not None and value > setting.maximum:
            raise ValueError(f"Must be {setting.maximum} or less.")
        return value
    if kind == "bool":
        if isinstance(raw, bool):
            return raw
        if isinstance(raw, str) and raw.strip().lower() in ("true", "false"):
            return raw.strip().lower() == "true"
        raise ValueError("Must be true or false.")
    if kind == "choice":
        allowed = [c[0] for c in setting.choices]
        if raw not in allowed:
            raise ValueError("Must be one of: " + ", ".join(allowed) + ".")
        return raw
    if kind == "secret":
        if raw is None:
            return ""
        if not isinstance(raw, str):
            raise ValueError("Must be text.")
        value = raw.strip()
        if setting.name == "WEBHOOK_URL":
            reason = webhook.check_url(value) if value else ""
            if reason:
                raise ValueError(reason)
            return value
        if value and not re.fullmatch(r"[A-Za-z0-9-]{6,100}", value):
            raise ValueError("Must be 6 to 100 letters, digits, or hyphens.")
        return value
    if kind == "mailbox":
        if not isinstance(raw, str):
            raise ValueError("Must be an email address.")
        value = raw.strip().lower()
        if not _EMAIL_RE.match(value):
            raise ValueError(f"'{raw.strip()[:80]}' is not an email address.")
        return value
    if kind == "label":
        if raw is None:
            return ""
        if not isinstance(raw, str):
            raise ValueError("Must be text.")
        if any(not c.isprintable() for c in raw):
            raise ValueError("Must be one line, with no control characters.")
        if "[" in raw or "]" in raw:
            raise ValueError("Must not contain [ or ].")
        value = " ".join(raw.split())
        if setting.maximum is not None and len(value) > setting.maximum:
            raise ValueError(f"At most {setting.maximum} characters.")
        return value

    items = _items(raw)
    if kind == "ip_list":
        out = []
        for item in items:
            try:
                net = ipaddress.ip_network(item, strict=False)
            except ValueError:
                raise ValueError(f"'{item}' is not an IP address or range.")
            if net.prefixlen == 0:
                raise ValueError(f"'{item}' would allow every address.")
            out.append(str(net.network_address) if net.prefixlen == net.max_prefixlen else str(net))
        return out
    if kind == "domain_list":
        out = [i.lower().rstrip(".") for i in items]
        for item in out:
            if not _DOMAIN_RE.match(item):
                raise ValueError(f"'{item}' is not a domain name.")
        return out
    if kind == "country_list":
        out = [i.upper() for i in items]
        for item in out:
            if not _COUNTRY_RE.match(item):
                raise ValueError(f"'{item}' is not a two-letter country code.")
        return out
    if kind == "email_list":
        out = [i.lower() for i in items]
        for item in out:
            if not _EMAIL_RE.match(item):
                raise ValueError(f"'{item}' is not an email address.")
        return out
    if kind == "asn_list":
        out = []
        for item in items:
            asn = config.normalize_asn(item)
            if not asn:
                raise ValueError(f"'{item}' is not an ASN. Use the form AS21928.")
            if asn not in out:
                out.append(asn)
        return out
    if kind == "type_set":
        allowed = [c[0] for c in setting.choices]
        unknown = [i for i in items if i not in allowed]
        if unknown:
            raise ValueError(f"Unknown alert type: {', '.join(unknown)}.")
        return [c for c in allowed if c in items]
    if kind == "role_set":
        allowed = [c[0] for c in setting.choices]
        lowered = [i.lower() for i in items]
        unknown = [i for i in lowered if i not in allowed]
        if unknown:
            raise ValueError(f"Unknown directory role: {', '.join(unknown)}.")
        return [c for c in allowed if c in lowered]
    if kind == "word_list":
        for item in items:
            if len(item) > 100 or any(ord(c) < 32 for c in item):
                raise ValueError(f"'{item[:40]}' is not valid (at most 100 characters, no control characters).")
        return items
    raise ValueError(f"Unknown setting kind {kind}.")


def missing_roles(setting: Setting, value, granted) -> tuple:
    """Graph roles that ``value`` needs and that are not granted. () if unknown or none."""
    if granted is None or not setting.needs:
        return ()
    if setting.kind == "role_set":
        # Any selected role needs the roles under "*" (Graph reads the role assignments).
        return tuple(r for r in setting.needs.get("*", ()) if r not in granted) if value else ()
    if isinstance(value, (list, set, dict)):
        return ()
    return tuple(r for r in setting.needs.get(value, ()) if r not in granted)


# -----------------------------------------------------------------------------
# Mapping to and from the config module
# -----------------------------------------------------------------------------

def current(setting: Setting, reveal: bool = False):
    """The value in use now, in UI form. A secret is "" unless ``reveal``."""
    name = setting.name
    if setting.kind == "secret" and not reveal:
        return ""
    if name == "ALLOWED_IPS":
        return [x for x in (s.strip() for s in config.ALLOWED_IPS_RAW.split(",")) if x]
    value = getattr(config, name)
    if setting.kind in ("type_set", "role_set"):
        return [c[0] for c in setting.choices if c[0] in value]
    if isinstance(value, (set, frozenset)):
        return sorted(value)
    if isinstance(value, list):
        return list(value)
    return value


def _assign(setting: Setting, value) -> None:
    name = setting.name
    if name == "ALLOWED_IPS":
        config.ALLOWED_IPS_RAW = ",".join(value)
        config.ALLOWED_NETWORKS = [ipaddress.ip_network(v, strict=False) for v in value]
    elif name in ("INTERNAL_DOMAINS", "HOME_COUNTRIES", "ANOMALY_ACTION_EXEMPT", "HIGH_RISK_OAUTH_SCOPES",
                  "ALERTS_OFF", "ALLOWED_ASNS", "UI_ADMIN_USERS", "UI_ADMIN_ROLES"):
        setattr(config, name, set(value))
    elif name == "LOOKBACK_MINUTES":
        config.LOOKBACK_MINUTES = value
        config.DEDUP_WINDOW_MINUTES = max(60, value * 3)
        config.MAX_CATCHUP_MINUTES = config.DEDUP_WINDOW_MINUTES
    else:
        setattr(config, name, value)


# The values from the environment, before any override.
DEFAULTS = {s.name: current(s, reveal=True) for s in SETTINGS}


def apply(overrides: dict) -> list:
    """Set every setting to its override, or to its default. Return warnings."""
    warnings = []
    for setting in SETTINGS:
        value = DEFAULTS[setting.name]
        if setting.name in overrides:
            try:
                value = validate(setting, overrides[setting.name])
            except ValueError as e:
                warnings.append(f"{setting.name}: stored value not valid ({e}); using the default")
        _assign(setting, value)
    for w in warnings:
        logging.warning(f"Settings: {w}")
    return warnings


def describe_for(setting: Setting, value) -> str:
    """describe(), but a secret is only "(set)" or "(not set)"."""
    if setting.kind == "secret":
        return "(set)" if value else "(not set)"
    if setting.kind == "role_set" and isinstance(value, list):
        names = dict(setting.choices)
        return ", ".join(names.get(v, v) for v in value) if value else "(empty)"
    return describe(value)


def describe(value) -> str:
    """Short text for a value in history and email."""
    if isinstance(value, bool):
        return "on" if value else "off"
    if isinstance(value, list):
        return ", ".join(value) if value else "(empty)"
    return str(value) if value != "" else "(empty)"
