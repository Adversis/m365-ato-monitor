"""Application Insights query client for the weekly and monthly reports.

The Management Activity API keeps content for 7 days only. The roll-up needs
30 days, so it counts the monitor's own log traces in Application Insights
(90-day retention, set by install.ps1).

Auth: the app's service principal has the Monitoring Reader role on the App
Insights resource (install.ps1). The client gets a client-credentials
token for the App Insights query API from the shared TokenManager.
"""

import logging
from typing import Optional

import config
from o365_client import token_manager


_QUERY_URL = "https://api.applicationinsights.io/v1/apps/{app_id}/query"

# Counts over the monitor's own traces for the last N days:
#   - "Suspicious login:" warnings -> suspicious count and distinct flagged IPs
#   - "Login check: N events ..."  -> total login events processed
#   - "Compromise indicator:"      -> compromise findings
#   - "Country anomaly:"           -> new-country sign-ins
#   - "audit_log_monitor run completed" -> completed runs (weekly report)
#   - "Coverage gap:"              -> content that was not fully processed
#   - severity Error or higher     -> errors
# host.json excludes traces from sampling. The sums still weight by itemCount,
# so the counts stay correct if sampling is enabled again.
_STATS_KQL = """
traces
| where timestamp > ago({days}d)
| extend ip = extract("IP=([^,]+)", 1, message)
| extend ev = tolong(extract("Login check: ([0-9]+) events", 1, message))
| summarize
    suspicious   = sumif(itemCount, message startswith "Suspicious login:"),
    unique_ips   = dcountif(ip, message startswith "Suspicious login:" and isnotempty(ip)),
    total_events = sumif(ev * itemCount, message startswith "Login check:"),
    compromise   = sumif(itemCount, message startswith "Compromise indicator:"),
    country      = sumif(itemCount, message startswith "Country anomaly:"),
    runs         = sumif(itemCount, message startswith "audit_log_monitor run completed"),
    gaps         = sumif(itemCount, message startswith "Coverage gap"),
    errors       = sumif(itemCount, severityLevel >= 3)
""".strip()
_MONTHLY_KQL = _STATS_KQL.format(days=30)


def get_monthly_login_stats() -> Optional[dict]:
    """Counts for the last 30 days (see get_stats)."""
    return get_stats(30)


def get_stats(days: int) -> Optional[dict]:
    """Return counts for the last ``days`` days: total_events, suspicious, unique_ips, compromise,
    country, runs, gaps, errors.

    Returns ``None`` if App Insights is not configured or the query fails.
    """
    if not config.APP_INSIGHTS_APP_ID:
        logging.warning("APP_INSIGHTS_APP_ID not set: the reports cannot query App Insights")
        return None

    try:
        token = token_manager.get_app_insights_token()
    except Exception as e:
        logging.error(f"Could not acquire App Insights token: {config.redact(e)}")
        return None

    url = _QUERY_URL.format(app_id=config.APP_INSIGHTS_APP_ID)
    try:
        resp = config.http.post(
            url,
            headers={"Authorization": f"Bearer {token}"},
            json={"query": _STATS_KQL.format(days=max(1, int(days)))},
            timeout=30,
        )
    except Exception as e:
        logging.error(f"App Insights query request failed: {config.redact(e)}")
        return None

    if resp.status_code != 200:
        logging.error(f"App Insights query failed: HTTP {resp.status_code}")
        return None

    return _parse_stats(resp.json())


def _parse_stats(payload: dict) -> Optional[dict]:
    """Map the single-row App Insights table response to a stats dict."""
    try:
        table = payload["tables"][0]
        columns = [c["name"] for c in table["columns"]]
        values = dict(zip(columns, table["rows"][0]))
        return {
            "total_events": int(values.get("total_events") or 0),
            "suspicious": int(values.get("suspicious") or 0),
            "unique_ips": int(values.get("unique_ips") or 0),
            "compromise": int(values.get("compromise") or 0),
            "country": int(values.get("country") or 0),
            "runs": int(values.get("runs") or 0),
            "gaps": int(values.get("gaps") or 0),
            "errors": int(values.get("errors") or 0),
        }
    except (KeyError, IndexError, TypeError, ValueError) as e:
        logging.error(f"Could not parse App Insights response: {e}")
        return None
