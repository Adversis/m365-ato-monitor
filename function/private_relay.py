"""iCloud Private Relay egress IPs (Apple's published list).

Safari on iPhone, iPad, and Mac sends traffic through iCloud Private Relay
when the user has iCloud+. A Microsoft 365 sign-in in Safari then comes from
a relay egress IP. proxycheck.io classifies many of these IPs as VPN or proxy,
so each such sign-in would cause a suspicious sign-in alert.

Apple publishes every egress range with the country it represents (the
user's approximate location, not the location of the relay server):
https://mask-api.icloud.com/egress-ip-ranges.csv (about 12 MB, 285,000 ranges).
The app downloads it at most once a day per instance, merges adjacent ranges
of the same country (about 18,000 remain), and looks IPs up by binary search.

With PRIVATE_RELAY_TRUSTED on (default), a relay IP is not sent to
proxycheck.io: it gets a result with no VPN or proxy flag, the country from
Apple's list, and the network name "iCloud Private Relay". New-country,
session, and compromise alerts still apply. With it off, proxycheck.io
classifies relay IPs as usual and the result is only labeled.

If the download fails, relay IPs are classified by proxycheck.io as before,
and the app tries again after RETRY_MINUTES.
"""

import bisect
import logging
import socket
from datetime import datetime, timedelta, timezone
from typing import Optional

import config

URL = "https://mask-api.icloud.com/egress-ip-ranges.csv"
REFRESH_HOURS = 24
RETRY_MINUTES = 60
MIN_RANGES = 1000           # a smaller list is treated as a failed download
NAME = "iCloud Private Relay"

_index = None               # {4: (starts, ends, countries), 6: (...)}
_loaded_at = None
_failed_at = None


def parse(text: str) -> dict:
    """Build the lookup index from the CSV text (prefix,country,region,city,)."""
    rows = {4: [], 6: []}
    for line in text.splitlines():
        prefix, _, rest = line.partition(",")
        addr, _, bits = prefix.strip().partition("/")
        country = rest[:2].upper()
        try:
            if ":" in addr:
                version, width = 6, 128
                start = int.from_bytes(socket.inet_pton(socket.AF_INET6, addr), "big")
            else:
                version, width = 4, 32
                start = int.from_bytes(socket.inet_aton(addr), "big")
            length = int(bits) if bits else width
        except (OSError, ValueError):
            continue
        if not 0 < length <= width or not country.isalpha():
            continue
        size = 1 << (width - length)
        start &= ~(size - 1)
        rows[version].append((start, start + size - 1, country))

    index = {}
    for version, items in rows.items():
        items.sort()
        merged = []
        for start, end, country in items:
            if merged and merged[-1][2] == country and start <= merged[-1][1] + 1:
                if end > merged[-1][1]:
                    merged[-1] = (merged[-1][0], end, country)
            else:
                merged.append((start, end, country))
        index[version] = ([m[0] for m in merged], [m[1] for m in merged], [m[2] for m in merged])
    return index


def size(index: Optional[dict] = None) -> int:
    index = index if index is not None else _index
    return sum(len(v[0]) for v in index.values()) if index else 0


def _load(now: datetime) -> None:
    global _index, _loaded_at, _failed_at
    if _index is not None and _loaded_at and now - _loaded_at < timedelta(hours=REFRESH_HOURS):
        return
    if _failed_at and now - _failed_at < timedelta(minutes=RETRY_MINUTES):
        return
    try:
        resp = config.http.get(URL, timeout=60)
        if resp.status_code != 200:
            raise RuntimeError(f"HTTP {resp.status_code}")
        index = parse(resp.text)
        if size(index) < MIN_RANGES:
            raise RuntimeError(f"only {size(index)} ranges")
    except Exception as e:
        _failed_at = now
        logging.warning(f"iCloud Private Relay list not loaded: {type(e).__name__}: {e}. "
                        f"Relay IPs are classified by proxycheck.io until the next try.")
        return
    _index, _loaded_at, _failed_at = index, now, None
    logging.info(f"iCloud Private Relay list loaded: {size(index)} ranges")


def country(ip: str, now: Optional[datetime] = None) -> str:
    """The country of a relay egress IP, or "" if ``ip`` is not a relay IP (or the list is not loaded)."""
    _load(now or datetime.now(timezone.utc))
    if not _index:
        return ""
    try:
        packed = socket.inet_pton(socket.AF_INET6 if ":" in ip else socket.AF_INET, ip)
    except (OSError, ValueError, TypeError):
        return ""
    value = int.from_bytes(packed, "big")
    starts, ends, countries = _index[6 if len(packed) == 16 else 4]
    i = bisect.bisect_right(starts, value) - 1
    return countries[i] if i >= 0 and value <= ends[i] else ""


def result(cc: str) -> dict:
    """A lookup result for a trusted relay IP, in the proxycheck.io shape."""
    return {"proxy": "no", "type": NAME, "risk": 0, "isocode": cc, "country": cc,
            "organisation": NAME, "provider": NAME, "asn": "", "private_relay": True}


def status() -> dict:
    return {"ranges": size(), "loaded_at": _loaded_at.isoformat() if _loaded_at else None,
            "last_failure": _failed_at.isoformat() if _failed_at else None}


def _set_index(index: Optional[dict], now: Optional[datetime] = None) -> None:
    """Tests: install an index without a download."""
    global _index, _loaded_at, _failed_at
    _index, _loaded_at, _failed_at = index, (now or datetime.now(timezone.utc)) if index else None, None
