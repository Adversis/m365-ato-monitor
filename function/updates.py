"""Is a newer release available? A check only: the monitor never installs code itself.

Once a day, the timer reads the latest release of UPDATE_REPO from the GitHub API (no
sign-in, no tenant data in the request) and keeps the answer in the events table. The
management UI (Overview > Monitor) and the weekly report show the result. To update, a
person runs ./install.ps1 -Update.

Turn it off: Settings > Advanced > Check for updates (UPDATE_CHECK). A private repository,
a missing release, or a network error leaves the last answer and logs a warning.
"""

import logging
import re
from datetime import datetime, timezone
from typing import Optional

from azure.core.exceptions import ResourceNotFoundError

import config
from version import VERSION

_KEY = ("updatecheck", "latest")
_REPO_RE = re.compile(r"^[A-Za-z0-9-]{1,39}/[A-Za-z0-9._-]{1,100}$")
_TAG_RE = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)$")


def parse(version: str) -> Optional[tuple]:
    """'v1.2.3' or '1.2.3' -> (1, 2, 3); anything else -> None (pre-releases are not offered)."""
    m = _TAG_RE.match(str(version or "").strip())
    return tuple(int(p) for p in m.groups()) if m else None


def check(table, now: Optional[datetime] = None) -> dict:
    """Read the latest release from GitHub and save it. Returns status()."""
    now = now or datetime.now(timezone.utc)
    repo = str(config.UPDATE_REPO or "").strip()
    if table is None or not config.UPDATE_CHECK or not _REPO_RE.match(repo):
        return status(table)
    row = {"PartitionKey": _KEY[0], "RowKey": _KEY[1], "checked_at": now.isoformat(), "repo": repo, "error": ""}
    try:
        resp = config.http.get(f"https://api.github.com/repos/{repo}/releases/latest", timeout=15,
                               headers={"Accept": "application/vnd.github+json", "User-Agent": "m365-ato-monitor",
                                        "X-GitHub-Api-Version": "2022-11-28"})
        if resp.status_code == 404:
            row["error"] = "no public release found"
        elif resp.status_code != 200:
            row["error"] = f"GitHub answered HTTP {resp.status_code}"
        else:
            data = resp.json() or {}
            tag = str(data.get("tag_name") or "")
            if not parse(tag) or data.get("draft") or data.get("prerelease"):
                row["error"] = "the latest release has no version number"
            else:
                url = str(data.get("html_url") or "")
                row.update(latest=tag.lstrip("v"), published=str(data.get("published_at") or ""),
                           url=url if url.startswith(f"https://github.com/{repo}/") else "")
    except Exception as e:
        row["error"] = f"no answer from GitHub ({type(e).__name__})"
    if row["error"]:
        logging.warning(f"Update check: {row['error']} ({repo})")
    try:
        table.upsert_entity(row)   # merge: an error keeps the last known release
    except Exception as e:
        logging.warning(f"Update check not saved: {type(e).__name__}")
    return status(table)


def status(table) -> dict:
    """{"version", "latest", "newer", "url", "published", "checked_at", "error", "enabled"}."""
    out = {"version": VERSION, "latest": "", "newer": False, "url": "", "published": "", "checked_at": "",
           "error": "", "enabled": bool(config.UPDATE_CHECK)}
    if table is None:
        return out
    try:
        row = table.get_entity(partition_key=_KEY[0], row_key=_KEY[1])
    except ResourceNotFoundError:
        return out
    except Exception as e:
        logging.warning(f"Update check not read: {type(e).__name__}")
        return out
    for k in ("latest", "url", "published", "checked_at", "error"):
        out[k] = str(row.get(k) or "")
    latest, current = parse(out["latest"]), parse(VERSION)
    # With the check off, an old answer is not shown as "Update available".
    out["newer"] = bool(out["enabled"] and latest and current and latest > current)
    return out
