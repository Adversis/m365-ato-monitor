"""Office 365 Management Activity API client and token cache.

Functions:
  - Get and cache client-credentials tokens, one per scope, in process memory.
  - List audit content blobs for one content type and time window.
  - Fetch the audit records in those blobs.

SSRF guard:
  The API returns blob URLs in ``contentUri`` values and in the ``NextPageUri``
  header. The client sends a bearer token to these URLs. It accepts only HTTPS
  URLs on manage.office.com or its subdomains, so a changed response cannot
  send the token to another host. This limits the app to the commercial cloud.
"""

import base64
import hashlib
import json
import logging
import re
import time
from datetime import datetime, timedelta, timezone
from typing import Optional
from urllib.parse import quote, urlparse


import config


# -----------------------------------------------------------------------------
# OAuth token management
# -----------------------------------------------------------------------------

_TOKEN_ENDPOINT = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
_O365_SCOPE = "https://manage.office.com/.default"
_GRAPH_SCOPE = "https://graph.microsoft.com/.default"
_APPINSIGHTS_SCOPE = "https://api.applicationinsights.io/.default"
_ARM_SCOPE = "https://management.azure.com/.default"

# Refresh slightly before real expiry so a token can't lapse mid-request.
_EXPIRY_SKEW = timedelta(seconds=300)


class TokenManager:
    """Acquires and caches client-credentials tokens, keyed by scope.

    Tokens live in ``self._tokens`` as ``{key: (token, expiry_datetime)}``.
    """

    def __init__(self):
        self._tokens: dict = {}

    def _get_token(self, key: str, scope: str) -> str:
        cached = self._tokens.get(key)
        if cached:
            token, expiry = cached
            if datetime.now(timezone.utc) < expiry - _EXPIRY_SKEW:
                return token

        if not config.has_credential():
            raise RuntimeError("Azure AD credentials are not configured")

        data = {"client_id": config.CLIENT_ID, "scope": scope, "grant_type": "client_credentials"}
        if config.CLIENT_SECRET:
            data["client_secret"] = config.CLIENT_SECRET
        else:
            # Federated credential: the managed identity's token is the proof (identity.py).
            import identity
            data["client_assertion_type"] = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            data["client_assertion"] = identity.client_assertion()
        resp = config.http.post(_TOKEN_ENDPOINT.format(tenant=config.TENANT_ID), data=data, timeout=30)
        # Do not log the full body. Log only the error name and the AADSTS codes
        # (for example 7000222 = client secret expired).
        if resp.status_code != 200:
            detail = ""
            try:
                err = resp.json()
                codes = ",".join(str(c) for c in (err.get("error_codes") or [])[:3])
                detail = f" {str(err.get('error', ''))[:40]} [{codes}]"
            except Exception:
                pass
            raise RuntimeError(f"Token request for {scope} failed: HTTP {resp.status_code}{detail}")

        data = resp.json()
        token = data.get("access_token")
        if not token:
            raise RuntimeError(f"Token response for {scope} contained no access_token")

        expires_in = int(data.get("expires_in", 3599))
        expiry = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
        self._tokens[key] = (token, expiry)
        return token

    def get_o365_token(self) -> str:
        """Token for the Office 365 Management Activity API."""
        return self._get_token("o365", _O365_SCOPE)

    def get_graph_token(self) -> str:
        """Token for Microsoft Graph (email alerts via sendMail)."""
        return self._get_token("graph", _GRAPH_SCOPE)

    def granted_graph_roles(self):
        """Graph application roles in the current token (from its "roles" claim), or None.

        The app reads its own token, which it got from Entra over TLS. It does not
        need to check the signature to read the claim.
        """
        try:
            payload = self.get_graph_token().split(".")[1]
            payload += "=" * (-len(payload) % 4)
            claims = json.loads(base64.urlsafe_b64decode(payload))
            return sorted(str(r) for r in claims.get("roles", []))
        except Exception as e:
            logging.warning(f"Could not read Graph roles: {type(e).__name__}")
            return None

    def get_arm_token(self) -> str:
        """Token for Azure Resource Manager (update the health alert action group)."""
        return self._get_token("arm", _ARM_SCOPE)

    def get_app_insights_token(self) -> str:
        """Token for the Application Insights data-plane query API (monthly roll-up)."""
        return self._get_token("appinsights", _APPINSIGHTS_SCOPE)


token_manager = TokenManager()


# -----------------------------------------------------------------------------
# Graph user lookup (optional: UPN -> Entra objectId for alert links)
# -----------------------------------------------------------------------------

_GRAPH_BASE = "https://graph.microsoft.com/v1.0"

# A UPN -> objectId mapping does not change. Two caches hold it:
#   - an in-process dict (hits and 404 misses) for a warm worker
#   - the Table Storage table "useridcache" (hits only), which survives restarts
# The weekly cleanup does not purge "useridcache".
_USERID_TABLE_NAME = "useridcache"
_USERID_PARTITION = "useridcache"
_user_id_cache: dict = {}
_userid_table_cache = config.CachedTable(_USERID_TABLE_NAME, "User-id cache table")


def _userid_table_client():
    """The Table Storage client for the user-id cache, or None."""
    return _userid_table_cache.get()


def _userid_row_key(upn: str) -> str:
    return hashlib.sha256(upn.strip().lower().encode("utf-8")).hexdigest()


def resolve_user_object_id(upn: str) -> Optional[str]:
    """Resolve a UPN to its Entra objectId through Graph, with caching.

    Needs the optional ``User.ReadBasic.All`` application permission. Returns
    ``None`` on any failure. Called only when ``config.RESOLVE_USER_IDS`` is on.
    """
    if not upn:
        return None
    if upn in _user_id_cache:
        return _user_id_cache[upn]

    table = _userid_table_client()
    row_key = _userid_row_key(upn)

    # Persistent cache. It holds hits only.
    if table is not None:
        try:
            entity = table.get_entity(_USERID_PARTITION, row_key)
            cached_id = entity.get("object_id")
            if cached_id:
                _user_id_cache[upn] = cached_id
                return cached_id
        except Exception:
            pass  # not cached: do a live lookup

    object_id = None
    definitive = False  # True when Graph gave an answer (found or 404)
    try:
        token = token_manager.get_graph_token()
        resp = config.http.get(
            f"{_GRAPH_BASE}/users/{quote(upn, safe='')}?$select=id",
            headers={"Authorization": f"Bearer {token}"},
            timeout=10,
        )
        if resp.status_code == 200:
            object_id = resp.json().get("id")
            definitive = True
        elif resp.status_code == 404:
            definitive = True
        else:
            logging.warning(f"User objectId lookup failed: HTTP {resp.status_code}")
    except Exception as e:
        logging.warning(f"User objectId lookup error: {type(e).__name__}")

    # Do not cache a transient failure. The next alert retries the lookup.
    if definitive:
        _user_id_cache[upn] = object_id
    if object_id and table is not None:
        try:
            table.upsert_entity({
                "PartitionKey": _USERID_PARTITION,
                "RowKey": row_key,
                "upn": upn,
                "object_id": object_id,
                "cached_at": datetime.now(timezone.utc).isoformat(),
            })
        except Exception as e:
            logging.warning(f"Failed to persist user-id cache: {e}")

    return object_id


# -----------------------------------------------------------------------------
# SSRF guard — only follow content URLs on Microsoft-owned hosts
# -----------------------------------------------------------------------------

_ALLOWED_CONTENT_HOST = "manage.office.com"
_ALLOWED_CONTENT_HOST_SUFFIX = ".manage.office.com"


def _is_microsoft_content_url(url: str) -> bool:
    """True only if ``url`` is HTTPS on manage.office.com (or a subdomain)."""
    try:
        parsed = urlparse(url)
    except Exception:
        return False
    if parsed.scheme != "https":
        return False
    host = (parsed.hostname or "").lower()
    return host == _ALLOWED_CONTENT_HOST or host.endswith(_ALLOWED_CONTENT_HOST_SUFFIX)


# -----------------------------------------------------------------------------
# Management Activity API
# -----------------------------------------------------------------------------

_API_BASE = "https://manage.office.com/api/v1.0"
_API_TIME_FMT = "%Y-%m-%dT%H:%M:%S"

AAD_CONTENT_TYPE = "Audit.AzureActiveDirectory"
EXCHANGE_CONTENT_TYPE = "Audit.Exchange"
CONTENT_TYPES = (AAD_CONTENT_TYPE, EXCHANGE_CONTENT_TYPE)


def fetch_audit_content_urls(content_type: str, start_time: datetime, end_time: datetime) -> list:
    """List audit content blob URLs for a content type and time window.

    The API selects blobs by the time each blob became available, not by event
    time. Follows ``NextPageUri`` paging. Returns only Microsoft-owned URLs (SSRF
    guard). Raises if a listing response is not HTTP 200.
    """
    headers = {"Authorization": f"Bearer {token_manager.get_o365_token()}"}
    url = f"{_API_BASE}/{config.TENANT_ID}/activity/feed/subscriptions/content"
    params = {
        "contentType": content_type,
        "startTime": start_time.strftime(_API_TIME_FMT),
        "endTime": end_time.strftime(_API_TIME_FMT),
        # Requests without PublisherIdentifier share one quota with all other
        # callers that leave it out. Microsoft: set it on all requests.
        "PublisherIdentifier": config.TENANT_ID,
    }

    content_urls = []
    while url:
        resp = config.http.get(url, headers=headers, params=params, timeout=30)
        params = None  # paging URLs already carry the query string
        if resp.status_code != 200:
            raise RuntimeError(
                f"Listing {content_type} content failed: HTTP {resp.status_code}{_api_error(resp)}"
            )

        for item in resp.json():
            uri = item.get("contentUri")
            if not uri:
                continue
            if _is_microsoft_content_url(uri):
                content_urls.append(uri)
            else:
                logging.error("Skipped a non-Microsoft content URI (SSRF guard)")

        next_uri = resp.headers.get("NextPageUri")
        if next_uri and not _is_microsoft_content_url(next_uri):
            logging.error("Skipped a non-Microsoft NextPageUri (SSRF guard)")
            next_uri = None
        url = next_uri

    return content_urls


_API_ERROR_HINTS = {
    "AF20022": "no subscription for this content type: the monitor starts it on the next run",
    "AF20023": "subscription is disabled: the monitor starts it on the next run",
    "AF10001": "permission missing: grant admin consent for ActivityFeed.Read (install.ps1 does this)",
}

_SUBSCRIPTION_CHECK_SECONDS = 6 * 3600
_subscriptions_checked_at = 0.0


def ensure_subscriptions(force: bool = False) -> dict:
    """Start each audit content subscription that is not enabled. Return {content_type: status}.

    Runs at most every 6 hours per worker, or now with ``force`` (for example
    after an AF20022 error). Microsoft takes up to 12 hours to deliver the first
    content after a subscription starts. Never raises.
    """
    import time
    global _subscriptions_checked_at
    if not force and time.time() - _subscriptions_checked_at < _SUBSCRIPTION_CHECK_SECONDS:
        return {}
    _subscriptions_checked_at = time.time()
    base = f"{_API_BASE}/{config.TENANT_ID}/activity/feed/subscriptions"
    params = {"PublisherIdentifier": config.TENANT_ID}
    result = {}
    try:
        headers = {"Authorization": f"Bearer {token_manager.get_o365_token()}"}
        resp = config.http.get(f"{base}/list", headers=headers, params=params, timeout=30)
        if resp.status_code != 200:
            logging.error(f"Audit subscriptions not listed: HTTP {resp.status_code}{_api_error(resp)}")
            return {}
        enabled = {str(s.get("contentType")) for s in resp.json() if str(s.get("status")).lower() == "enabled"}
        for content_type in CONTENT_TYPES:
            if content_type in enabled:
                result[content_type] = "enabled"
                continue
            start = config.http.post(f"{base}/start", headers={**headers, "Content-Length": "0"},
                                     params={**params, "contentType": content_type}, timeout=30)
            if start.status_code == 200 or "already enabled" in start.text.lower():
                logging.warning(f"Audit subscription started: {content_type}. The first content can take "
                                "up to 12 hours.")
                result[content_type] = "started"
            else:
                logging.error(f"Audit subscription {content_type} not started: HTTP "
                              f"{start.status_code}{_api_error(start)}")
                result[content_type] = f"failed: HTTP {start.status_code}"
    except Exception as e:
        logging.error(f"Audit subscription check failed: {type(e).__name__}: {config.redact(e)}")
    return result


def _api_error(resp) -> str:
    """Short " code: message (hint)" from a Management API error body, or ""."""
    try:
        err = resp.json().get("error") or {}
        code = str(err.get("code", ""))[:20]
        message = str(err.get("message", ""))[:150]
    except Exception:
        return ""
    if not code and not message:
        return ""
    hint = _API_ERROR_HINTS.get(code)
    return f" {code}: {message}" + (f" ({hint})" if hint else "")


def fetch_audit_events(content_url: str) -> list:
    """Fetch the audit records in one content blob. Raises on failure."""
    if not _is_microsoft_content_url(content_url):
        raise RuntimeError("Refused a non-Microsoft content URL (SSRF guard)")

    headers = {"Authorization": f"Bearer {token_manager.get_o365_token()}"}
    params = None if "publisheridentifier=" in content_url.lower() else {"PublisherIdentifier": config.TENANT_ID}
    resp = config.http.get(content_url, headers=headers, params=params, timeout=30)
    if resp.status_code != 200:
        raise RuntimeError(f"Fetching audit content failed: HTTP {resp.status_code}")

    records = resp.json()
    if not isinstance(records, list):
        raise RuntimeError("Audit content is not a JSON list")
    return [r for r in records if isinstance(r, dict)]


def fetch_content_records(content_type: str, start_time: datetime, end_time: datetime) -> tuple:
    """Return ``(records, complete)`` for one content type and window.

    Raises if the blob listing fails. If one blob fails, the other blobs are
    still returned and ``complete`` is False. The caller must then not move the
    checkpoint past this window.
    """
    records = []
    complete = True
    for url in fetch_audit_content_urls(content_type, start_time, end_time):
        try:
            records.extend(fetch_audit_events(url))
        except Exception as e:
            logging.warning(f"{content_type}: one content blob failed: {e}")
            complete = False
    return records, complete


def login_result(record: dict) -> str:
    """Short sign-in result for a login record: "Success", "Failed (50126)", etc."""
    operation = str(record.get("Operation", ""))
    if operation == "UserLoggedIn":
        result = "Success"
    elif operation == "UserLoginFailed":
        result = "Failed"
    else:
        result = str(record.get("ResultStatus") or operation or "Unknown")
    error = config.sign_in_error_code(record) or record.get("LogonError")
    if result == "Failed" and error:
        result += f" ({str(error)[:40]})"
    return result


_upn_cache: dict = {}
_upn_failed: dict = {}         # object ID -> time before which a failed lookup is not tried again
_UPN_RETRY_SECONDS = 900
_GUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def resolve_user_upn(object_id: str) -> Optional[str]:
    """The UPN of a user object ID through Graph (User.ReadBasic.All), cached in memory. None if unknown."""
    oid = str(object_id or "").lower()
    if not _GUID_RE.match(oid):
        return None
    if oid in _upn_cache:
        return _upn_cache[oid]
    if time.monotonic() < _upn_failed.get(oid, 0.0):
        return None
    upn = None
    try:
        resp = config.http.get(f"{_GRAPH_BASE}/users/{oid}", params={"$select": "userPrincipalName"},
                               headers={"Authorization": f"Bearer {token_manager.get_graph_token()}"}, timeout=5)
        if resp.status_code == 200:
            upn = str(resp.json().get("userPrincipalName") or "") or None
        elif resp.status_code != 404:
            _upn_failed[oid] = time.monotonic() + _UPN_RETRY_SECONDS   # not definitive: try again later
            return None
    except Exception as e:
        logging.warning(f"User {oid} not resolved: {type(e).__name__}")
        _upn_failed[oid] = time.monotonic() + _UPN_RETRY_SECONDS
        return None
    _upn_cache[oid] = upn
    return upn


def filter_login_records(aad_records: list) -> list:
    """Keep only sign-in records (RecordType 9 or 15)."""
    return [r for r in aad_records if config.record_type(r) in config.LOGIN_RECORD_TYPES]
