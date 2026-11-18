"""IP address parsing, proxycheck.io lookups, IP cache, and event dedup."""

import hashlib
import ipaddress
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional

from azure.data.tables import TableClient

import config
import proxycheck_quota


# -----------------------------------------------------------------------------
# IP address parsing
# -----------------------------------------------------------------------------

def _canonical(addr) -> str:
    """Canonical text for an address. Unwrap IPv4-mapped IPv6 (::ffff:a.b.c.d)."""
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        return str(addr.ipv4_mapped)
    return str(addr)


def clean_ip(raw_ip: str) -> Optional[str]:
    """Return the canonical IP from a Microsoft audit ClientIP value, or None.

    Accepts: IPv4, IPv6, IPv4:port, [IPv6]:port, IP:port:IP, CIDR notation.
    Returns None for empty, "null", "no_ip", and other unusable values. The
    result is canonical (lowercase, compressed IPv6), so one address always
    gives one cache key and one allowlist result.
    """
    if not raw_ip or not isinstance(raw_ip, str):
        return None

    ip = raw_ip.strip()
    if not ip or ip in ("no_ip", "null"):
        return None

    if "/" in ip:
        ip = ip.split("/")[0]

    if ip.startswith("["):
        ip = ip[1:].split("]")[0]
        try:
            return _canonical(ipaddress.ip_address(ip))
        except ValueError:
            return None

    # Compound format 1.2.3.4:443:1.2.3.4. The first part is IPv4, the second is a port.
    parts = ip.split(":")
    if len(parts) == 3 and parts[1].isdigit():
        try:
            return _canonical(ipaddress.ip_address(parts[0]))
        except ValueError:
            pass

    try:
        return _canonical(ipaddress.ip_address(ip))
    except ValueError:
        pass

    # IPv4:port
    if ":" in ip:
        candidate = ip.rsplit(":", 1)[0]
        try:
            return _canonical(ipaddress.ip_address(candidate))
        except ValueError:
            pass

    return None


def is_private_ip(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


def is_allowed_ip(ip: str) -> bool:
    if not config.ALLOWED_NETWORKS:
        return False
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in config.ALLOWED_NETWORKS)
    except ValueError:
        return False


# Fields that hold the client IP, by record schema (Management Activity API):
# ClientIP (common schema; Exchange admin records add a port), ClientIPAddress
# and ActorIP (Exchange mailbox), ActorIpAddress (Entra ID audit).
_IP_FIELDS = ("ClientIP", "ClientIPAddress", "ActorIpAddress", "ActorIP")


def network_fields(ip_data: Optional[dict]) -> dict:
    """{"asn": "AS1234", "network": "Name"} for findings (mutes, journal).

    ``ip_data`` is a proxycheck.io answer or an analyze_ip result (``org`` for the organisation).
    """
    data = ip_data or {}
    names = [str(data.get(k) or "").strip() for k in ("organisation", "org", "provider")]
    return {"asn": config.normalize_asn(data.get("asn")), "network": next((n for n in names if n and n != "Unknown"), "")}


def extract_ip(event: dict) -> Optional[str]:
    """Return the first field that holds a valid IP address, in canonical form."""
    candidates = [event.get(f) for f in _IP_FIELDS]
    for prop in event.get("ExtendedProperties") or []:
        if isinstance(prop, dict) and prop.get("Name") == "ClientIPAddress":
            candidates.append(prop.get("Value"))
    first = None
    for raw in candidates:
        if not raw:
            continue
        # A few records hold a list ("a, b"). The first address is the client.
        for part in str(raw).split(","):
            ip = clean_ip(part)
            if ip:
                if not is_private_ip(ip):
                    return ip
                first = first or ip
                break
    # Only private or loopback addresses (for example "::1" for a service).
    return first


# -----------------------------------------------------------------------------
# Event deduplication
# -----------------------------------------------------------------------------

_ROWKEY_UNSAFE = set("/\\#?'\"\t\n\r")


def _sanitize_rowkey(value: str) -> str:
    """Sanitize a value for use as an Azure Table Storage RowKey.
    Disallowed chars (/ \\ # ? ' \" and control chars) are replaced with underscores.
    """
    return "".join("_" if c in _ROWKEY_UNSAFE else c for c in value)


def get_event_key(event: dict) -> str:
    """Unique key for an event: the sanitized Id, or a hash if there is no Id."""
    event_id = event.get("Id", "")
    if event_id:
        return _sanitize_rowkey(str(event_id))
    key_fields = f"{event.get('CreationTime', '')}{event.get('UserId', '')}{event.get('ClientIP', '')}"
    return hashlib.sha256(key_fields.encode()).hexdigest()[:32]


def get_processed_keys(table_client: TableClient, since_minutes: int = 60) -> set[str]:
    """Return all event keys marked processed in the last ``since_minutes``.

    On a query failure, return an empty set. The run then can send duplicate
    alerts, but it does not skip events.
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=since_minutes)).isoformat()
    try:
        entities = table_client.query_entities(
            f"PartitionKey eq 'events' and processed_at ge '{cutoff}'"
        )
        return {e["RowKey"] for e in entities}
    except Exception as e:
        logging.warning(f"Failed to batch-query processed events: {e}")
        return set()


def mark_event_processed(event_key: str, table_client: TableClient):
    try:
        table_client.upsert_entity({
            "PartitionKey": "events",
            "RowKey": event_key,
            "processed_at": datetime.now(timezone.utc).isoformat()
        })
    except Exception as e:
        logging.warning(f"Failed to mark event as processed: {e}")


# -----------------------------------------------------------------------------
# Suspicious-login digest queue (Table Storage, partition "logindigest")
# -----------------------------------------------------------------------------

def queue_login_for_digest(event_key: str, data: dict, table_client: TableClient):
    """Queue a suspicious login for the next digest email.

    Raises on failure. The caller then does not mark the event processed, and
    the next run tries again.
    """
    table_client.upsert_entity({
        "PartitionKey": "logindigest",
        "RowKey": event_key,
        "queued_at": datetime.now(timezone.utc).isoformat(),
        **data,
    })


def read_login_digest(table_client: TableClient) -> list:
    """Return all queued suspicious-login entries (each includes queued_at)."""
    try:
        return list(table_client.query_entities("PartitionKey eq 'logindigest'"))
    except Exception as e:
        logging.warning(f"Failed to read login digest queue: {e}")
        return []


def delete_login_digest(table_client: TableClient, entries: list):
    """Delete queued entries after the digest email is sent.

    If one delete fails, log it and continue. That entry stays in the queue and
    goes into the next digest again. A duplicate is better than a lost alert.
    """
    for entity in entries:
        try:
            table_client.delete_entity(entity["PartitionKey"], entity["RowKey"])
        except Exception as e:
            logging.warning(f"Failed to delete login digest entry: {e}")


# -----------------------------------------------------------------------------
# Pending IP checks (Table Storage, partition "pendingip")
# -----------------------------------------------------------------------------
# A sign-in whose IP lookup failed goes here, so it is not lost when its
# content leaves the fetch window (for example while the proxycheck.io quota
# is used up). Only the fields that the log and the alert use are stored.

_PENDING_IP_PARTITION = "pendingip"
_PENDING_EVENT_FIELDS = (
    "Id", "RecordType", "CreationTime", "Operation", "UserId", "UserKey",
    "ClientIP", "ResultStatus", "ErrorNumber", "LogonError",
)


def queue_pending_ip(event_key: str, event: dict, ip: str, table_client: TableClient) -> bool:
    """Queue a sign-in for a later IP check. Return False on failure."""
    compact = {k: event[k] for k in _PENDING_EVENT_FIELDS if k in event}
    try:
        table_client.upsert_entity({
            "PartitionKey": _PENDING_IP_PARTITION,
            "RowKey": event_key,
            "ip": ip,
            "event": json.dumps(compact, default=str),
            "queued_at": datetime.now(timezone.utc).isoformat(),
        })
        return True
    except Exception as e:
        logging.warning(f"Failed to queue pending IP check: {type(e).__name__}")
        return False


def read_pending_ips(table_client: TableClient, limit: int) -> list:
    """Return up to ``limit`` queued sign-ins as dicts: key, ip, event, queued_at."""
    rows = []
    try:
        for i, entity in enumerate(table_client.query_entities(
            f"PartitionKey eq '{_PENDING_IP_PARTITION}'"
        )):
            if i >= limit:
                break
            try:
                queued_at = datetime.fromisoformat(str(entity.get("queued_at", "")))
                if queued_at.tzinfo is None:
                    queued_at = queued_at.replace(tzinfo=timezone.utc)
                event = json.loads(entity.get("event") or "{}")
            except ValueError:
                queued_at, event = datetime.min.replace(tzinfo=timezone.utc), {}
            rows.append({"key": entity["RowKey"], "ip": entity.get("ip", ""),
                         "event": event, "queued_at": queued_at})
    except Exception as e:
        logging.warning(f"Failed to read pending IP checks: {type(e).__name__}")
    return rows


def delete_pending_ip(table_client: TableClient, event_key: str) -> None:
    try:
        table_client.delete_entity(_PENDING_IP_PARTITION, event_key)
    except Exception as e:
        logging.warning(f"Failed to delete pending IP check: {type(e).__name__}")


# -----------------------------------------------------------------------------
# IP cache (Table Storage)
# -----------------------------------------------------------------------------

def _ip_row_key(ip: str) -> str:
    return ip.replace(".", "_").replace(":", "_")


def get_cached_ip(ip: str, table_client: Optional[TableClient]) -> Optional[dict]:
    """Returns cached data, {"_negative": True} for negative cache, or None."""
    if not table_client:
        return None
    try:
        entity = table_client.get_entity(partition_key="ipcache", row_key=_ip_row_key(ip))
        cached_time = entity.get("cached_at", "")
        if not cached_time:
            return None
        age = datetime.now(timezone.utc) - datetime.fromisoformat(cached_time.replace("Z", "+00:00"))

        is_negative = entity.get("is_negative", False)
        if is_negative and age < timedelta(minutes=config.NEGATIVE_CACHE_TTL_MINUTES):
            return {"_negative": True}
        if not is_negative:
            data = json.loads(entity.get("data", "{}"))
            # A clean answer is kept for IP_CACHE_DAYS, a flagged one for IP_CACHE_TTL_HOURS.
            keep = (timedelta(hours=config.IP_CACHE_TTL_HOURS) if analyze_ip(data)["is_suspicious"]
                    else timedelta(days=config.IP_CACHE_DAYS))
            if age < keep:
                return data
    except Exception:
        pass
    return None


def cache_ip_result(ip: str, ip_data: dict, table_client: Optional[TableClient]):
    if not table_client:
        return
    try:
        table_client.upsert_entity({
            "PartitionKey": "ipcache",
            "RowKey": _ip_row_key(ip),
            "ip": ip,
            "data": json.dumps(ip_data),
            "cached_at": datetime.now(timezone.utc).isoformat(),
            "is_negative": False,
        })
    except Exception as e:
        logging.warning(f"Failed to cache IP result: {e}")


def cache_ip_negative(ip: str, table_client: Optional[TableClient]):
    if not table_client:
        return
    try:
        table_client.upsert_entity({
            "PartitionKey": "ipcache",
            "RowKey": _ip_row_key(ip),
            "ip": ip,
            "data": "{}",
            "cached_at": datetime.now(timezone.utc).isoformat(),
            "is_negative": True,
        })
    except Exception as e:
        logging.warning(f"Failed to write negative cache: {e}")


# -----------------------------------------------------------------------------
# proxycheck.io batch API
# -----------------------------------------------------------------------------

def check_ips_batch(ips: list[str], table_client: Optional[TableClient] = None,
                    cache_only: bool = False) -> dict[str, dict]:
    """Look up IPs: iCloud Private Relay list, then the cache, then proxycheck.io.

    With PRIVATE_RELAY_TRUSTED, a relay egress IP is not sent to proxycheck.io;
    it gets an unflagged result with the country from Apple's list. Without it,
    relay IPs are looked up as usual and only labeled. ``cache_only``: return
    only the answers that need no proxycheck.io query.
    """
    import private_relay  # here, so that tests can patch it per call
    relay = {}
    if ips:
        for ip in ips:
            cc = private_relay.country(ip)
            if cc:
                relay[ip] = cc
    if config.PRIVATE_RELAY_TRUSTED:
        results = {ip: private_relay.result(cc) for ip, cc in relay.items()}
        results.update(_proxycheck_batch([ip for ip in ips if ip not in relay], table_client, cache_only))
        return results
    results = _proxycheck_batch(ips, table_client, cache_only)
    for ip, cc in relay.items():
        if ip in results:
            results[ip] = {**results[ip], "private_relay": True, "isocode": cc,
                           "organisation": f"{private_relay.NAME} ({results[ip].get('organisation', '')})"}
    return results


def _proxycheck_batch(ips: list[str], table_client: Optional[TableClient] = None,
                      cache_only: bool = False) -> dict[str, dict]:
    """Look up IPs in the cache, then send the rest to proxycheck.io in one POST.

    Returns {ip: proxycheck_data}. An IP that is not in the result failed the
    lookup. It is negative-cached for NEGATIVE_CACHE_TTL_MINUTES.
    """
    results = {}
    uncached = []

    for ip in ips:
        cached = get_cached_ip(ip, table_client)
        if cached is not None:
            if not cached.get("_negative"):
                results[ip] = cached
        else:
            uncached.append(ip)

    if not uncached or cache_only:
        return results

    cache_hits = len(ips) - len(uncached)
    if cache_hits > 0:
        logging.info(f"IP cache: {cache_hits} hits, {len(uncached)} to check via API")

    # v3 needs a query string: a POST to a bare /v3/ redirects to a lookup of the caller's own IP.
    url = "https://proxycheck.io/v3/?p=1"
    if config.PROXYCHECK_API_KEY:
        url += f"&key={config.PROXYCHECK_API_KEY}"

    try:
        # The batch API reads the addresses from the POST form field "ips"
        # (comma-separated). Other formats return "No valid IP Addresses supplied."
        response = config.http.post(url, data={"ips": ",".join(uncached)}, timeout=15)
    except Exception as e:
        # The exception text contains the URL, which contains the key.
        logging.error(f"proxycheck.io batch request failed: {config.redact(e)}")
        for ip in uncached:
            cache_ip_negative(ip, table_client)
        return results

    if response.status_code != 200:
        # v3 answers "denied" with HTTP 401, 403, or 429 and "error" with HTTP 400.
        msg = ""
        try:
            body = response.json()
            if isinstance(body, dict):
                msg = config.redact(body.get("message", ""))
                proxycheck_quota.note(table_client, body.get("status", ""), body.get("message", ""))
        except Exception:
            pass
        logging.warning(f"proxycheck.io batch returned HTTP {response.status_code}{': ' + msg if msg else ''}")
        for ip in uncached:
            cache_ip_negative(ip, table_client)
        return results

    try:
        data = response.json()
        if not isinstance(data, dict):
            raise ValueError("response is not a JSON object")
    except ValueError as e:
        logging.warning(f"proxycheck.io batch returned invalid JSON: {e}")
        for ip in uncached:
            cache_ip_negative(ip, table_client)
        return results

    status = str(data.get("status", ""))
    proxycheck_quota.note(table_client, status, data.get("message", ""))
    if status != "ok":
        # "warning" still contains results (for example near the quota, or one
        # invalid address in the batch). "denied" and "error" usually do not.
        msg = config.redact(data.get("message", ""))
        if status == "denied" or "limit" in msg.lower():
            logging.error(
                f"proxycheck.io quota or access problem: status={status}: {msg}. "
                "Limits: 100 queries/day without a key, 1,000/day with a free key."
            )
        else:
            logging.warning(f"proxycheck.io batch returned status={status}: {msg}")

    for ip in uncached:
        ip_data = from_v3(data.get(ip))
        if isinstance(ip_data, dict) and "proxy" in ip_data:
            results[ip] = ip_data
            cache_ip_result(ip, ip_data, table_client)
        else:
            cache_ip_negative(ip, table_client)

    return results


def from_v3(result):
    """A proxycheck.io v3 result in the v2 shape that the rest of the code reads.

    The cache, private_relay, geo_monitor, and analyze_ip read v2 keys (proxy, type, risk,
    isocode, organisation). v3 has booleans per detection and nested sections. The type
    order keeps the v2 confidence: Tor, compromised, and proxy are high; VPN, an anonymous
    IP with no category (v2 "Inference Engine"), and hosting are medium. A v2 answer (an old
    cache entry, a test) is returned unchanged. The key names come from real answers: the
    published spec differs (risk is in detections; location has country_code, city_name).
    """
    if not isinstance(result, dict) or "detections" not in result:
        return result
    d = result.get("detections") if isinstance(result.get("detections"), dict) else {}
    net = result.get("network") if isinstance(result.get("network"), dict) else {}
    loc = result.get("location") if isinstance(result.get("location"), dict) else {}
    op = result.get("operator") if isinstance(result.get("operator"), dict) else {}
    if d.get("tor"):
        ip_type = "TOR"
    elif d.get("compromised"):
        ip_type = "Compromised Server"
    elif d.get("proxy"):
        ip_type = "Proxy"
    elif d.get("vpn"):
        ip_type = "VPN"
    elif d.get("anonymous"):
        ip_type = "Inference Engine"
    elif d.get("hosting"):
        ip_type = "Hosting"
    else:
        ip_type = net.get("type") or ""
    anonymous = any(d.get(k) for k in ("anonymous", "proxy", "vpn", "tor", "compromised"))
    attacks = result.get("attack_history")
    attacks = {str(k): v for k, v in attacks.items() if isinstance(v, int) and v > 0} \
        if isinstance(attacks, dict) else {}
    out = {
        "proxy": "yes" if anonymous else "no",
        "type": ip_type,
        "risk": d.get("risk") if isinstance(d.get("risk"), int) else 0,
        "asn": net.get("asn") or "",
        "range": net.get("range") or "",
        "hostname": net.get("hostname") or "",
        "provider": net.get("provider") or "",
        "organisation": net.get("organisation") or "",
        "network_type": net.get("type") or "",
        "isocode": loc.get("country_code") or loc.get("isocode") or "",
        "country": loc.get("country_name") or loc.get("country") or "",
        "region": loc.get("region_name") or loc.get("region") or "",
        "city": loc.get("city_name") or loc.get("city") or "",
        "operator": str(op.get("name") or ""),
        "attacks": attacks,
        "api": 3,
    }
    return out


# -----------------------------------------------------------------------------
# IP analysis
# -----------------------------------------------------------------------------

def analyze_ip(ip_data: dict) -> dict:
    """Classify a proxycheck.io response into a risk assessment."""
    is_proxy = ip_data.get("proxy") == "yes"
    proxy_type = ip_data.get("type", "")
    try:
        risk_score = max(0, min(100, int(ip_data.get("risk", 0))))
    except (ValueError, TypeError):
        risk_score = 0

    flagged = []
    if is_proxy:
        flagged.append(proxy_type.lower() if proxy_type else "proxy")
    if not is_proxy and proxy_type in config.SUSPICIOUS_NETWORK_TYPES:
        flagged.append("hosting")
    if not is_proxy and not flagged and risk_score >= config.RISK_SCORE_THRESHOLD:
        flagged.append("high-risk")

    # An allowed network (ALLOWED_ASNS, for example a mobile carrier) is never flagged.
    allowed_asn = config.normalize_asn(ip_data.get("asn")) in config.ALLOWED_ASNS if config.ALLOWED_ASNS else False
    if allowed_asn:
        flagged = []

    # A proxy that proxycheck.io saw attacking (login attempts, probing) is known bad.
    attacked = proxy_type == "Proxy" and isinstance(ip_data.get("attacks"), dict) and any(
        isinstance(n, int) and n > 0 for n in ip_data["attacks"].values())
    if allowed_asn:
        confidence = "none"
    elif proxy_type in config.HIGH_CONFIDENCE_TYPES or attacked:
        confidence = "high"
    elif proxy_type in config.MEDIUM_CONFIDENCE_TYPES or risk_score >= 66:
        confidence = "medium"
    elif is_proxy or risk_score >= config.RISK_SCORE_THRESHOLD:
        confidence = "low"
    else:
        confidence = "none"

    return {
        "is_suspicious": len(flagged) > 0,
        "allowed_asn": allowed_asn,
        "flags": flagged,
        "confidence": confidence,
        "risk_score": risk_score,
        "proxy_type": proxy_type,
        "asn": ip_data.get("asn", ""),
        "provider": ip_data.get("provider", ""),
        "org": ip_data.get("organisation", "Unknown"),
        "city": ip_data.get("city", "Unknown"),
        "region": ip_data.get("region", "Unknown"),
        "country": ip_data.get("country", "Unknown"),
        # v3 only (empty for a v2 cache entry): for the alert text, not for the verdict.
        "hostname": str(ip_data.get("hostname") or ""),
        "operator": str(ip_data.get("operator") or ""),
        "attacks": ip_data.get("attacks") if isinstance(ip_data.get("attacks"), dict) else {},
    }
