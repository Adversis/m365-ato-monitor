"""Alerts to a webhook: Slack, Microsoft Teams (Workflows), or plain JSON.

Settings (management UI > Settings > Webhook): ALERT_DELIVERY (email, both,
webhook), WEBHOOK_URL (a secret), WEBHOOK_FORMAT (slack, teams, json). Only
alerts go to the webhook; reports stay in email.

The monitor sends one HTTPS POST (no retry, 5-second connect and 10-second
read timeout) and does not follow redirects. Before each POST it resolves the
host name: every address must be public (no private, loopback, link-local, or
reserved address), so that the URL cannot reach a service inside Azure or the
Function App itself. The name is resolved again for the connection; TLS
certificate checks for the host name stop a changed answer from reaching
another service. A failed POST is logged. With ALERT_DELIVERY = webhook, the
alert then goes out by email.

Alert text contains names from audit records (inbox rule names, app names)
that an attacker chooses. The Slack text escapes & < > (no mentions, no
links); the Teams card uses TextRun elements (no markdown).
"""

import ipaddress
import json
import logging
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

import config

FORMATS = ("slack", "teams", "json")
_MAX_URL = 2048
_TIMEOUT = (5, 10)
# Not config.http: that session retries POST, so a slow receiver would get the same alert up to 4 times
# and one alert could use a large part of the run time.
_http = requests.Session()


def check_url(url: str) -> str:
    """Return "" if ``url`` is a usable webhook URL, else the reason. Does not resolve the host name."""
    if not url:
        return "No webhook URL."
    if len(url) > _MAX_URL or any(c.isspace() for c in url):
        return f"The URL must be one line of at most {_MAX_URL} characters."
    parts = urlparse(url)
    if parts.scheme != "https" or not parts.hostname:
        return "The URL must start with https:// and name a host."
    if parts.username or parts.password:
        return "The URL must not contain a user name or password."
    if parts.port not in (None, 443):
        return "The URL must use port 443."
    try:
        ipaddress.ip_address(parts.hostname)
        return "Use a host name, not an IP address."
    except ValueError:
        pass
    return ""


def _public_host(host: str) -> bool:
    """True if every address of ``host`` is a public address."""
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except OSError:
        return False
    addresses = {info[4][0] for info in infos}
    return bool(addresses) and all(ipaddress.ip_address(a.split("%")[0]).is_global for a in addresses)


def _slack_escape(text: str) -> str:
    """Slack mrkdwn control characters: <!channel>, <url|label>, and &."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _text_run(text: str, bold: bool = False) -> dict:
    """An Adaptive Card RichTextBlock with one TextRun: plain text, no markdown."""
    run = {"type": "TextRun", "text": text}
    if bold:
        run["weight"] = "Bolder"
    return {"type": "RichTextBlock", "inlines": [run]}


def payload(fmt: str, subject: str, text: str, link: str) -> dict:
    """The JSON body for ``fmt``."""
    if fmt == "slack":
        lines = ([f"*{_slack_escape(subject)}*"] + ([_slack_escape(text)] if text else [])
                 + ([f"<{link}|Open the management UI>"] if link else []))
        return {"text": "\n".join(lines)}
    if fmt == "teams":
        body = [_text_run(subject, bold=True)]
        if text:
            body.append(_text_run(text))
        card = {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard",
                "version": "1.4", "body": body}
        if link:
            card["actions"] = [{"type": "Action.OpenUrl", "title": "Open the management UI", "url": link}]
        return {"type": "message", "attachments": [{"contentType": "application/vnd.microsoft.card.adaptive",
                                                    "content": card}]}
    return {"source": "m365-ato-monitor", "tenant": config.TENANT_LABEL or "", "subject": subject,
            "text": text, "link": link, "sent_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}


def post(subject: str, text: str = "", link: str = "") -> tuple:
    """POST one alert to WEBHOOK_URL. Return (True, "") or (False, a short reason)."""
    url = config.WEBHOOK_URL
    reason = check_url(url)
    if reason:
        return False, reason
    if not _public_host(urlparse(url).hostname):
        return False, "The webhook host does not resolve to a public address."
    fmt = config.WEBHOOK_FORMAT if config.WEBHOOK_FORMAT in FORMATS else "json"
    try:
        resp = _http.post(url, data=json.dumps(payload(fmt, subject, text[:2000], link)),
                          headers={"Content-Type": "application/json"}, timeout=_TIMEOUT, allow_redirects=False)
    except Exception as e:
        logging.error(f"Webhook not sent: {type(e).__name__}")
        return False, type(e).__name__
    if 200 <= resp.status_code < 300:
        return True, ""
    logging.error(f"Webhook not sent: HTTP {resp.status_code}")
    return False, f"HTTP {resp.status_code}"
