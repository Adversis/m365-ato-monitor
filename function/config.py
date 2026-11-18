"""Application configuration loaded from environment variables."""

import ipaddress
import logging
import os
import time
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# The azure-data-tables client logs headers for every request. Keep only
# warnings and errors.
logging.getLogger("azure").setLevel(logging.WARNING)
# urllib3 logs the full request URL (with query string) on each retry. The
# proxycheck.io URL contains the API key, so keep urllib3 at ERROR.
logging.getLogger("urllib3").setLevel(logging.ERROR)

# -----------------------------------------------------------------------------
# Environment variables
# -----------------------------------------------------------------------------

TENANT_ID = os.environ.get("AZURE_TENANT_ID")
CLIENT_ID = os.environ.get("AZURE_CLIENT_ID")
# Object ID of the monitor app's service principal (install.ps1). Audit records of a
# permission grant name the app by this ID or by its app ID (CLIENT_ID).
MONITOR_SP_ID = os.environ.get("MONITOR_SP_ID", "")
# Credential of the app registration: the user-assigned managed identity as a
# federated credential (Azure; set by install.ps1; see identity.py), or a client
# secret for local development only (local.settings.json).
CLIENT_SECRET = os.environ.get("AZURE_CLIENT_SECRET")
MANAGED_IDENTITY_CLIENT_ID = os.environ.get("MANAGED_IDENTITY_CLIENT_ID", "")
# Default only: the management UI stores the key (Settings > Suspicious sign-ins).
PROXYCHECK_API_KEY = os.environ.get("PROXYCHECK_API_KEY", "") or ""
# Alerts to a webhook (webhook.py): email (default), both, or webhook. WEBHOOK_URL is a secret.
ALERT_DELIVERY = os.environ.get("ALERT_DELIVERY", "email").strip().lower() or "email"
WEBHOOK_URL = os.environ.get("WEBHOOK_URL", "").strip()
WEBHOOK_FORMAT = os.environ.get("WEBHOOK_FORMAT", "slack").strip().lower() or "slack"
ADMIN_EMAIL = os.environ.get("ADMIN_EMAIL")
# Table Storage: the storage account name with the managed identity (Azure; set by
# install.ps1; no key), or a connection string for local development (Azurite).
STORAGE_CONNECTION_STRING = os.environ.get("STORAGE_CONNECTION_STRING")
STORAGE_ACCOUNT_NAME = os.environ.get("STORAGE_ACCOUNT_NAME", "")
ALLOWED_IPS_RAW = os.environ.get("ALLOWED_IPS", "")
# Application Insights App ID (GUID). The monthly roll-up queries this resource.
APP_INSIGHTS_APP_ID = os.environ.get("APP_INSIGHTS_APP_ID", "")
# Resource ID of the Azure Monitor action group of the health alerts. When the
# alert mailbox changes in the UI, the app sets the action group email too.
ACTION_GROUP_ID = os.environ.get("ACTION_GROUP_ID", "")


def _address_list(name: str) -> list:
    """Comma-separated email addresses. Entries that are not an address are logged and dropped."""
    out = []
    for item in os.environ.get(name, "").replace(";", ",").split(","):
        item = item.strip().lower()
        if not item:
            continue
        local, _, domain = item.partition("@")
        if not local or "." not in domain or any(c.isspace() or c in "<>,;" for c in item):
            logging.warning("%s: '%s' is not an email address; ignored", name, item)
            continue
        if item not in out and item != (ADMIN_EMAIL or "").strip().lower():
            out.append(item)
    return out


# Extra recipients. Alert emails ([M365 Alert]) go to ADMIN_EMAIL and
# ALERT_RECIPIENTS (for example a ticket system). Reports ([M365 Monitor]) go
# to ADMIN_EMAIL and REPORT_RECIPIENTS. ADMIN_EMAIL always sends and receives.
ALERT_RECIPIENTS = _address_list("ALERT_RECIPIENTS")
REPORT_RECIPIENTS = _address_list("REPORT_RECIPIENTS")


def _label(raw: str) -> str:
    """A short tenant name for subjects: no brackets or control characters, at most 40 characters."""
    text = "".join(c for c in str(raw or "") if c.isprintable() and c not in "[]").strip()
    return " ".join(text.split())[:40]


# Tenant name in each subject: "[M365 Alert][Contoso] ...". For people who get
# alerts from more than one tenant.
TENANT_LABEL = _label(os.environ.get("TENANT_LABEL", ""))


def has_credential() -> bool:
    """True if the app can authenticate: a client secret or the managed identity."""
    return bool(TENANT_ID and CLIENT_ID and (CLIENT_SECRET or MANAGED_IDENTITY_CLIENT_ID))


def storage_configured() -> bool:
    return bool(STORAGE_CONNECTION_STRING or STORAGE_ACCOUNT_NAME)


def table_service():
    """A TableServiceClient: connection string if set, else the managed identity. Raises if neither."""
    from azure.data.tables import TableServiceClient
    if STORAGE_CONNECTION_STRING:
        return TableServiceClient.from_connection_string(STORAGE_CONNECTION_STRING)
    if STORAGE_ACCOUNT_NAME:
        import identity
        return TableServiceClient(endpoint=f"https://{STORAGE_ACCOUNT_NAME}.table.core.windows.net",
                                  credential=identity.TableCredential())
    raise RuntimeError("Table Storage is not configured (STORAGE_ACCOUNT_NAME)")


class CachedTable:
    """A table client that is made on first use and then kept.

    A failure is not kept: the next call after RETRY_SECONDS tries again. Just
    after an install, role assignments and the managed identity can take some
    minutes to work, and a worker can run for hours.
    """

    RETRY_SECONDS = 60

    def __init__(self, name: str, label: str):
        self.name, self.label = name, label
        self._table = None
        self._retry_at = 0.0

    def get(self):
        """The table client, or None if storage is not configured or not available now."""
        if self._table is not None:
            return self._table
        if not storage_configured():
            return None
        now = time.monotonic()
        if now < self._retry_at:
            return None
        try:
            self._table = table_service().create_table_if_not_exists(self.name)
        except Exception as e:
            self._retry_at = now + self.RETRY_SECONDS
            logging.warning(f"{self.label} not available: {type(e).__name__}. "
                            f"Next try in {self.RETRY_SECONDS} seconds.")
        return self._table


def redact(text) -> str:
    """Return ``text`` as a string with secrets removed. Use on exception text before logging."""
    s = str(text)
    secrets = [PROXYCHECK_API_KEY, WEBHOOK_URL]
    if WEBHOOK_URL:
        # requests shows the host and the path apart ("host='hooks.slack.com' ... url: /services/T/B/x").
        parts = urlparse(WEBHOOK_URL)
        secrets += [parts.path if len(parts.path) > 1 else "", parts.query]
    for secret in sorted((x for x in secrets if x), key=len, reverse=True):
        s = s.replace(secret, "***")
    return s


# -----------------------------------------------------------------------------
# Tunable parameters
# -----------------------------------------------------------------------------

def _int_env(name, default, minimum=None, maximum=None):
    """Parse an integer setting. Use the default if the value is not an integer.

    Operators edit these settings in the Portal. A typo must not stop the app.
    """
    raw = os.environ.get(name, default)
    try:
        value = int(raw)
    except (ValueError, TypeError):
        logging.warning("Invalid %s=%r; using default %s", name, raw, default)
        value = int(default)
    if minimum is not None and value < minimum:
        logging.warning("%s=%s is below minimum %s; using %s", name, value, minimum, minimum)
        value = minimum
    if maximum is not None and value > maximum:
        logging.warning("%s=%s is above maximum %s; using %s", name, value, maximum, maximum)
        value = maximum
    return value


# Minimum 3: the window must be longer than the 2-minute timer interval.
LOOKBACK_MINUTES = _int_env("LOOKBACK_MINUTES", 8, minimum=3, maximum=60)
RISK_SCORE_THRESHOLD = _int_env("RISK_SCORE_THRESHOLD", 33, minimum=0, maximum=100)

# Event-dedup query window. It must be larger than any fetch window. A failed
# alert is retried while its content blob stays in the fetch window. Dedup must
# still know every event that was already processed in that window.
DEDUP_WINDOW_MINUTES = max(60, LOOKBACK_MINUTES * 3)

# After an outage, the next run fetches from the last checkpoint, but not more
# than this many minutes back. This must not exceed DEDUP_WINDOW_MINUTES.
MAX_CATCHUP_MINUTES = DEDUP_WINDOW_MINUTES

# Log a warning if one audit_log_monitor run takes longer than this.
RUN_DURATION_WARN_SECONDS = 60

HIGH_CONFIDENCE_TYPES = {"TOR", "SOCKS", "SOCKS4", "SOCKS5", "Compromised Server"}
MEDIUM_CONFIDENCE_TYPES = {"VPN", "Inference Engine", "Hosting"}
SUSPICIOUS_NETWORK_TYPES = {"Hosting"}

# Minimum confidence of a suspicious login that sends an email. The app always
# logs suspicious logins to App Insights.
#   low    - every suspicious login (default)
#   medium - VPN, hosting, Tor, SOCKS, compromised server, or risk >= 66
#   high   - Tor, SOCKS, compromised server only
#   off    - no login emails
_CONFIDENCE_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3}
_CONFIDENCE_OFF = ("off", "none", "disabled", "never")
LOGIN_ALERT_CONFIDENCE = os.environ.get("LOGIN_ALERT_CONFIDENCE", "low").strip().lower()
if LOGIN_ALERT_CONFIDENCE not in _CONFIDENCE_RANK and LOGIN_ALERT_CONFIDENCE not in _CONFIDENCE_OFF:
    logging.warning("Invalid LOGIN_ALERT_CONFIDENCE=%r; using 'low'", LOGIN_ALERT_CONFIDENCE)

# "immediate": one email per suspicious login. "digest": one batched email.
LOGIN_ALERT_MODE = os.environ.get("LOGIN_ALERT_MODE", "immediate").strip().lower()
if LOGIN_ALERT_MODE not in ("immediate", "digest"):
    logging.warning("Invalid LOGIN_ALERT_MODE=%r; using 'immediate'", LOGIN_ALERT_MODE)
    LOGIN_ALERT_MODE = "immediate"
# Digest mode: send the digest when the oldest queued login is this old.
LOGIN_DIGEST_MINUTES = _int_env("LOGIN_DIGEST_MINUTES", 60, minimum=0)

# Base URL for Entra links in alert emails. This changes only the links. The
# app supports the commercial cloud only.
PORTAL_BASE_URL = os.environ.get("PORTAL_BASE_URL", "https://entra.microsoft.com").rstrip("/")

# Resolve UPN to Entra objectId through Graph so that the email link opens the
# user. Needs the User.ReadBasic.All application permission. Off by default.
RESOLVE_USER_IDS = os.environ.get("RESOLVE_USER_IDS", "false").strip().lower() in ("1", "true", "yes", "on")


def should_email_login(confidence: str) -> bool:
    """True if a suspicious login at ``confidence`` meets LOGIN_ALERT_CONFIDENCE.

    An unknown setting value acts as "low": the app sends more email, not less.
    """
    if LOGIN_ALERT_CONFIDENCE in _CONFIDENCE_OFF:
        return False
    threshold = _CONFIDENCE_RANK.get(LOGIN_ALERT_CONFIDENCE, _CONFIDENCE_RANK["low"])
    return _CONFIDENCE_RANK.get(confidence, 0) >= threshold


_DEFAULT_ATTACK_TOOLS = "AADInternals,ROADtools,GraphRunner,Gophish,Evilginx"
_DEFAULT_AUTO_UAS = "python-requests,Python-urllib,Go-http-client,axios,node-fetch,undici,curl,PowerShell"
_DEFAULT_RISKY_SCOPES = ",".join([
    # Mailbox read, write, send
    "Mail.Read", "Mail.ReadWrite", "Mail.Send",
    "Mail.Read.Shared", "Mail.ReadWrite.Shared", "Mail.Send.Shared",
    "MailboxSettings.ReadWrite", "EWS.AccessAsUser.All", "full_access_as_app",
    # Files
    "Files.ReadWrite.All", "Sites.ReadWrite.All",
    # Directory and privilege escalation
    "User.ReadWrite.All", "Directory.ReadWrite.All", "Application.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All", "RoleManagement.ReadWrite.Directory",
])

_DEFAULT_RULE_KEYWORDS = ",".join([
    "invoice", "payment", "wire", "transfer", "bank", "payroll", "direct deposit", "remittance",
    "fraud", "phish", "hack", "malware", "suspicious", "unusual", "compromise", "security",
    "password", "reset", "MFA", "verification", "sign-in", "login",
])


def _csv_env(name, default):
    return [s.strip() for s in os.environ.get(name, default).split(",") if s.strip()]


ATTACK_TOOL_USER_AGENTS = _csv_env("ATTACK_TOOL_USER_AGENTS", _DEFAULT_ATTACK_TOOLS)
AUTOMATION_USER_AGENTS = _csv_env("AUTOMATION_USER_AGENTS", _DEFAULT_AUTO_UAS)
HIGH_RISK_OAUTH_SCOPES = set(_csv_env("HIGH_RISK_OAUTH_SCOPES", _DEFAULT_RISKY_SCOPES))
# Words in an inbox rule condition that, with mark-as-read, a move, or delete,
# make the rule suspicious (attackers hide replies about payments and security).
INBOX_RULE_KEYWORDS = _csv_env("INBOX_RULE_KEYWORDS", _DEFAULT_RULE_KEYWORDS)
# Extra mail domains that count as internal for forwarding checks (for example
# a second accepted domain). The domain of the acting user always counts.
INTERNAL_DOMAINS = {d.lower() for d in _csv_env("INTERNAL_DOMAINS", "")}
# The tenant's verified domains (install.ps1 writes them from Graph /organization on each run).
# They count as internal too, so forwarding to a second accepted domain is not "external".
TENANT_DOMAINS = {d.lower() for d in _csv_env("TENANT_DOMAINS", "")}

# proxycheck.io answers in the cache. A clean answer (not a VPN, proxy, hosting, or Tor address,
# risk under the threshold) is kept for IP_CACHE_DAYS: an office or home IP seldom changes, and
# each lookup uses the daily quota. A flagged answer is kept for IP_CACHE_TTL_HOURS: Tor exits and
# proxy pools change often. The cleanup deletes rows after EVENT_RETENTION_DAYS, so 7 is the maximum.
IP_CACHE_TTL_HOURS = 24
IP_CACHE_DAYS = _int_env("IP_CACHE_DAYS", 7, minimum=1, maximum=7)
NEGATIVE_CACHE_TTL_MINUTES = 5
EVENT_RETENTION_DAYS = 7

# A sign-in whose IP lookup failed (for example proxycheck.io quota used) waits
# in a queue and is checked again. The free quota resets daily, so keep it for
# a little more than 24 hours. Each run reads at most PENDING_IP_MAX_ROWS rows.
PENDING_IP_MAX_HOURS = 26
PENDING_IP_MAX_ROWS = 500

# An alert email that Graph refuses waits in an outbox and is sent again on
# each run, for this many days.
OUTBOX_MAX_DAYS = 7

# Log an error if no audit content arrives for this many hours (0 = off).
# Usual cause: unified audit logging is off. 48 h covers the first-day delay.
NO_CONTENT_ALERT_HOURS = _int_env("NO_CONTENT_ALERT_HOURS", 48, minimum=0)


# -----------------------------------------------------------------------------
# Sign-in country anomaly (per-user baseline) and response
# -----------------------------------------------------------------------------

def _bool_env(name, default):
    return os.environ.get(name, default).strip().lower() in ("1", "true", "yes", "on")


GEO_ANOMALY_ENABLED = _bool_env("GEO_ANOMALY_ENABLED", "true")
# Email a suspicious sign-in that failed (wrong password, for example a password
# spray). Off: such sign-ins are logged and kept in the alert history, with no
# email. A correct password that stopped at MFA or Conditional Access is not a
# failure here: it always alerts.
LOGIN_ALERT_FAILED = _bool_env("LOGIN_ALERT_FAILED", "false")
# Alert when one Entra session (stolen cookie or token) appears in a second country.
SESSION_CHECK_ENABLED = _bool_env("SESSION_CHECK_ENABLED", "true")
# Alert when mail is read or sent from a VPN, proxy, hosting, Tor, or new-country IP that did
# not sign in as the user (MailItemsAccessed, Send). Needs mail access records (mail_access.py).
MAIL_ACCESS_CHECK = _bool_env("MAIL_ACCESS_CHECK", "true")
# proxycheck.io lookups per run for the mail access check.
MAIL_ACCESS_MAX_LOOKUPS = _int_env("MAIL_ACCESS_MAX_LOOKUPS", 25, minimum=0)
# ISO 3166 alpha-2 codes that are never anomalous (for example "US,CA").
# If set, alerts start before the learning period ends.
HOME_COUNTRIES = {c.strip().upper() for c in os.environ.get("HOME_COUNTRIES", "").split(",") if c.strip()}
# Days to learn the baseline before alerts start (if HOME_COUNTRIES is empty).
GEO_LEARNING_DAYS = _int_env("GEO_LEARNING_DAYS", 14, minimum=0)
# A country not seen for a user in this many days leaves the user's baseline.
GEO_BASELINE_DAYS = _int_env("GEO_BASELINE_DAYS", 90, minimum=7)
# A new country becomes normal for a user after successful sign-ins on this
# many different days (for example during travel).
GEO_PROMOTE_DAYS = _int_env("GEO_PROMOTE_DAYS", 3, minimum=1)

# Response to a successful sign-in from an anomalous country:
#   none    - email only (default)
#   revoke  - revoke the user's sign-in sessions (refresh tokens, browser sessions)
#   disable - block sign-in (accountEnabled=false), then revoke sessions
ANOMALY_ACTION = os.environ.get("ANOMALY_ACTION", "none").strip().lower()
if ANOMALY_ACTION not in ("none", "revoke", "disable"):
    logging.warning("Invalid ANOMALY_ACTION=%r; using 'none'", ANOMALY_ACTION)
    ANOMALY_ACTION = "none"
# Response to a high-severity account-takeover alert (stolen session, forwarding
# rule, attack tool, ...). Same choices, exempt list, and daily limit.
COMPROMISE_ACTION = os.environ.get("COMPROMISE_ACTION", "none").strip().lower()
if COMPROMISE_ACTION not in ("none", "revoke", "disable"):
    logging.warning("Invalid COMPROMISE_ACTION=%r; using 'none'", COMPROMISE_ACTION)
    COMPROMISE_ACTION = "none"
# Turn off a malicious inbox rule (high alert) through Graph. Needs MailboxSettings.ReadWrite.
AUTO_DISABLE_INBOX_RULES = _bool_env("AUTO_DISABLE_INBOX_RULES", "false")
# Accounts that the response never changes. ADMIN_EMAIL is always exempt.
ANOMALY_ACTION_EXEMPT = {u.lower() for u in _csv_env("ANOMALY_ACTION_EXEMPT", "")}
ANOMALY_ACTION_MAX_PER_DAY = _int_env("ANOMALY_ACTION_MAX_PER_DAY", 3, minimum=0)

# Alert types that send no email (finding types, for example "mail_flow_rule").
# The finding is still logged.
ALERTS_OFF = set(_csv_env("ALERTS_OFF", ""))
# Alert on every new mail flow rule, not only rules that copy, redirect, or delete mail.
MAIL_FLOW_RULE_ANY = _bool_env("MAIL_FLOW_RULE_ANY", "false")
# Weekly health report (Mondays): runs, sign-ins checked, findings, posture.
WEEKLY_REPORT = _bool_env("WEEKLY_REPORT", "true")
# Check once a day for a newer release (GitHub API, no sign-in, no tenant data). Notify only.
UPDATE_CHECK = _bool_env("UPDATE_CHECK", "true")
# Opt-in: each management UI request checks that the admin's account is not blocked and that its
# sessions were not revoked after the sign-in (ui_access.session_refused). Needs User.Read.All.
UI_ACCOUNT_CHECK = _bool_env("UI_ACCOUNT_CHECK", "false")
# The GitHub repository ("owner/name") whose releases the check reads. A fork can set its own.
UPDATE_REPO = os.environ.get("UPDATE_REPO", "Adversis/m365-ato-monitor").strip()


def normalize_asn(value) -> str:
    """'AS21928', 'as21928', '21928', 21928 -> 'AS21928'; anything else -> ''."""
    text = str(value or "").strip().upper()
    if text.startswith("AS"):
        text = text[2:]
    return f"AS{int(text)}" if text.isdigit() and 0 < int(text) < 4294967296 else ""


# Networks (ASNs) whose IPs never count as VPN, proxy, or hosting for sign-in
# alerts (for example mobile carriers). New-country and session checks still apply.
ALLOWED_ASNS = {a for a in (normalize_asn(v) for v in _csv_env("ALLOWED_ASNS", "")) if a}

# Management UI access, besides the Monitor.Admin app role (management UI > Settings).
# Users by user principal name, and Entra directory roles by role template ID.
UI_ADMIN_USERS = {u.lower() for u in _csv_env("UI_ADMIN_USERS", "")}
UI_ADMIN_ROLES = {r.lower() for r in _csv_env("UI_ADMIN_ROLES", "")}
# iCloud Private Relay (Safari): egress IPs from Apple's list are not VPN or proxy,
# and their country comes from the list. See private_relay.py.
PRIVATE_RELAY_TRUSTED = _bool_env("PRIVATE_RELAY_TRUSTED", "true")

LOGIN_RECORD_TYPES = {
    9,   # AzureActiveDirectoryAccountLogon (legacy OrgId path)
    15,  # AzureActiveDirectoryStsLogon (eSTS path)
}


def record_type(record: dict):
    """RecordType as an int, or None.

    The schema defines RecordType as Edm.Int32, but some records (and some
    tools that relay them) carry it as a string ("15").
    """
    try:
        return int(str(record.get("RecordType")).strip())
    except (TypeError, ValueError):
        return None


# AADSTS error names in LogonError, mapped to the numeric code. Records carry
# the code in ErrorNumber (ErrorCode in the schema document); some carry only
# the name. Source: Microsoft Entra authentication error codes reference.
LOGON_ERROR_CODES = {
    "IdsLocked": "50053",
    "InvalidPasswordExpiredPassword": "50055",
    "UserDisabled": "50057",
    "UserStrongAuthEnrollmentRequiredInterrupt": "50072",
    "UserStrongAuthClientAuthNRequiredInterrupt": "50074",
    "UserStrongAuthClientAuthNRequired": "50076",
    "UserStrongAuthEnrollmentRequired": "50079",
    "InvalidUserNameOrPassword": "50126",
    "KmsiInterrupt": "50140",
    "DeviceAuthenticationRequired": "50097",
    "DeviceNotCompliant": "53000",
    "DeviceNotDomainJoined": "53001",
    "ApplicationUsedIsNotAnApprovedApp": "53002",
    "BlockedByConditionalAccess": "53003",
    "ProofUpBlockedDueToRisk": "53004",
}


def sign_in_error_code(record: dict) -> str:
    """Numeric AADSTS code of a failed sign-in ("50126"), or "" if unknown."""
    for key in ("ErrorNumber", "ErrorCode"):
        value = str(record.get(key) or "").strip()
        if value.isdigit():
            return value
    return LOGON_ERROR_CODES.get(str(record.get("LogonError") or "").strip(), "")

# -----------------------------------------------------------------------------
# IP allowlist
# -----------------------------------------------------------------------------

def _parse_allowlist(raw: str) -> list:
    """Parse comma-separated IPs and CIDRs into ip_network objects."""
    networks = []
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:
            logging.warning(f"Invalid ALLOWED_IPS entry ignored: {entry}")
    return networks


ALLOWED_NETWORKS = _parse_allowlist(ALLOWED_IPS_RAW)

# -----------------------------------------------------------------------------
# HTTP session with retry
# -----------------------------------------------------------------------------

class _CappedRetry(Retry):
    """Retry that limits a server Retry-After value.

    Without a limit, one throttled call can use all of the function timeout.
    """

    RETRY_AFTER_MAX_SECONDS = 10.0

    def get_retry_after(self, response):
        value = super().get_retry_after(response)
        return None if value is None else min(value, self.RETRY_AFTER_MAX_SECONDS)


def _create_session() -> requests.Session:
    """Create a requests session that retries transient failures."""
    session = requests.Session()
    retries = _CappedRetry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        respect_retry_after_header=True,
        allowed_methods=["GET", "POST"],
    )
    adapter = HTTPAdapter(max_retries=retries)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


http = _create_session()
