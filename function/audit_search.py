"""Microsoft Graph audit log search (/security/auditLog/queries).

The Office 365 Management Activity API keeps audit content for 7 days, and
only from when the audit subscription started. The audit log in Microsoft
Purview keeps records for 180 days (Audit Standard), or 1 year for users
with an E5 license. The Graph audit search reads that log. The monitor uses
it for:

- the onboarding scan: run the detectors on up to 180 days of history;
- the user page in the management UI: list the records of one user.

A search is asynchronous. Create a query, wait until its status is
"succeeded" (some minutes to some hours), then read the records page by page.

Permission: AuditLogsQuery.Read.All (Graph application permission). The app
already reads the same audit data through ActivityFeed.Read. The two scoped
permissions AuditLogsQuery-Exchange.Read.All and AuditLogsQuery-Entra.Read.All
also work: the search then returns only Exchange and Entra ID records.

Microsoft's limits: at least 200 searches per tenant per day, 50 queued or
running, and 1,000,000 records per search. A search typically takes 4 to 40
minutes, and up to 48 hours. Microsoft keeps a finished search for 30 days.

No function raises. Each returns a value and an error text ("" if none).
"""

import json
import logging
import re
from datetime import datetime, timezone
from typing import Optional
from urllib.parse import quote

import config
from o365_client import token_manager

_GRAPH = "https://graph.microsoft.com/v1.0"
_QUERIES = f"{_GRAPH}/security/auditLog/queries"
ROLE = "AuditLogsQuery.Read.All"
SCOPED_ROLES = ("AuditLogsQuery-Exchange.Read.All", "AuditLogsQuery-Entra.Read.All")
PAGE_SIZE = 500
_ID_RE = re.compile(r"^[A-Za-z0-9-]{8,80}$")
_TS = "%Y-%m-%dT%H:%M:%SZ"
DONE = ("succeeded", "failed", "cancelled")


def can_search(granted) -> bool:
    """True if the app's Graph token has the permission (None: unknown, assume no)."""
    return granted is not None and (ROLE in granted or all(r in granted for r in SCOPED_ROLES))


def _headers() -> dict:
    return {"Authorization": f"Bearer {token_manager.get_graph_token()}", "Content-Type": "application/json"}


def _error(resp) -> str:
    try:
        err = resp.json().get("error") or {}
        code, message = err.get("code", ""), str(err.get("message", ""))[:200]
    except (ValueError, AttributeError):
        code, message = "", ""
    hint = {403: " (no admin consent for AuditLogsQuery.Read.All: run ./install.ps1 -Update)",
            429: " (Microsoft's search limit: the next try is later)"}.get(resp.status_code, "")
    text = f"HTTP {resp.status_code}{hint}"
    if code:
        text += f" {code}"
    if message and resp.status_code != 403:
        text += f": {message}"
    return text


def create(name: str, start: datetime, end: datetime, *, operations=(), users=(), record_types=()) -> tuple:
    """Start a search. Return (query ID, error)."""
    body = {"displayName": str(name)[:100],
            "filterStartDateTime": start.astimezone(timezone.utc).strftime(_TS),
            "filterEndDateTime": end.astimezone(timezone.utc).strftime(_TS)}
    if operations:
        body["operationFilters"] = list(operations)
    if users:
        body["userPrincipalNameFilters"] = list(users)
    if record_types:
        body["recordTypeFilters"] = list(record_types)
    try:
        resp = config.http.post(_QUERIES, headers=_headers(), data=json.dumps(body), timeout=30)
    except Exception as e:
        return None, config.redact(f"{type(e).__name__}: {e}")[:200]
    if resp.status_code not in (200, 201):
        return None, _error(resp)
    try:
        data = resp.json()
        query_id = str(data.get("id") or "")
    except (ValueError, AttributeError):
        return None, "the response is not JSON"
    if not _ID_RE.match(query_id):
        return None, "the response has no query ID"
    # Graph ignores a filter name that it does not know. Log it if a filter did not stick.
    for key in ("operationFilters", "userPrincipalNameFilters", "recordTypeFilters"):
        if key in body and key in data and not data.get(key):
            logging.warning(f"Audit search {query_id}: Microsoft Graph did not keep the filter {key}")
    return query_id, ""


def get(query_id: str) -> tuple:
    """Return ({"status", "limit_exceeded", "count"}, error) for a search."""
    if not _ID_RE.match(str(query_id or "")):
        return None, "not a query ID"
    try:
        resp = config.http.get(f"{_QUERIES}/{quote(query_id, safe='')}", headers=_headers(), timeout=30)
    except Exception as e:
        return None, config.redact(f"{type(e).__name__}: {e}")[:200]
    if resp.status_code != 200:
        return None, _error(resp)
    try:
        data = resp.json()
    except ValueError:
        return None, "the response is not JSON"
    return {"status": str(data.get("status") or "unknown"),
            "limit_exceeded": bool(data.get("isRecordCountLimitExceeded")),
            "count": data.get("approximateReturnedRecordCount")}, ""


def records(query_id: str, next_link: str = "") -> tuple:
    """Read one page of records. Return (records, next link or "", error).

    ``next_link`` must be a link that this function returned before (it must
    point to the same query on Microsoft Graph).
    """
    if not _ID_RE.match(str(query_id or "")):
        return None, "", "not a query ID"
    first = f"{_QUERIES}/{quote(query_id, safe='')}/records"
    url = next_link or f"{first}?$top={PAGE_SIZE}"
    if not url.startswith(first):
        return None, "", "the next link does not point to this search"
    try:
        resp = config.http.get(url, headers=_headers(), timeout=60)
    except Exception as e:
        return None, "", config.redact(f"{type(e).__name__}: {e}")[:200]
    if resp.status_code != 200:
        return None, "", _error(resp)
    try:
        data = resp.json()
    except ValueError:
        return None, "", "the response is not JSON"
    link = str(data.get("@odata.nextLink") or "")
    if link and not link.startswith(first):
        logging.warning("Audit search: a next link to another address was ignored")
        link = ""
    return list(data.get("value") or []), link, ""


def to_record(item: dict) -> Optional[dict]:
    """A Graph auditLogRecord as a Management Activity API record (the detectors' input).

    ``auditData`` holds the audit record itself. If it is missing, use the
    common fields of the Graph record.
    """
    if not isinstance(item, dict):
        return None
    data = item.get("auditData")
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except ValueError:
            data = None
    record = {k: v for k, v in data.items() if not k.startswith("@odata")} if isinstance(data, dict) else {}
    extra = record.pop("dynamicProperties", None)   # some record types keep their fields here
    if isinstance(extra, dict):
        for k, v in extra.items():
            record.setdefault(k, v)
    record.setdefault("Id", item.get("id"))
    record.setdefault("Operation", item.get("operation"))
    record.setdefault("UserId", item.get("userPrincipalName") or item.get("userId"))
    record.setdefault("ClientIP", item.get("clientIp"))
    record.setdefault("Workload", item.get("service"))
    created = str(item.get("createdDateTime") or "")
    if created and not record.get("CreationTime"):
        record["CreationTime"] = created.replace("Z", "")[:19]
    if not record.get("Operation") or not record.get("CreationTime"):
        return None
    return record


def summary_row(record: dict) -> dict:
    """A short row for the user page: time, operation, workload, IP, result, object."""
    params = {}
    for key in ("Parameters", "ExtendedProperties", "OperationProperties"):
        for p in record.get(key) or []:
            if isinstance(p, dict) and p.get("Name"):
                params[str(p["Name"])] = p.get("Value")
    item = record.get("Item") if isinstance(record.get("Item"), dict) else {}
    target = record.get("ObjectId") or params.get("Identity") or params.get("Name") or item.get("Subject") or ""
    return {
        "at": str(record.get("CreationTime") or "")[:19] + "Z",
        "operation": str(record.get("Operation") or "")[:100],
        "workload": str(record.get("Workload") or "")[:40],
        "ip": str(record.get("ClientIPAddress") or record.get("ClientIP") or record.get("ActorIpAddress") or "")[:64],
        "result": str(record.get("ResultStatus") or "")[:40],
        "object": str(target or "")[:200],
        "client": str(record.get("ClientInfoString") or params.get("UserAgent") or "")[:200],
        "id": str(record.get("Id") or "")[:100],
    }
