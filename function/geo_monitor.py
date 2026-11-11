"""Per-user sign-in country baseline and anomaly detection.

The app learns, for each user, the countries of their successful sign-ins.
A sign-in from a country outside the user's baseline is an anomaly.

Rules:
  - Only sign-ins from IPs that the suspicious-IP check did NOT flag are used.
    VPN, proxy, and hosting IPs already cause their own alert, and their
    country says little about the user.
  - Learning: during the first GEO_LEARNING_DAYS, every successful sign-in
    goes into the baseline and nothing is anomalous. If HOME_COUNTRIES is
    set, a sign-in outside it is anomalous already during learning.
  - HOME_COUNTRIES are never anomalous.
  - A user with no baseline (for example a new user) is compared with the
    tenant baseline: the countries in any user's baseline.
  - A new country joins a user's baseline after successful sign-ins on
    GEO_PROMOTE_DAYS different days (travel). Until then, the app alerts at
    most one time per user and country in 24 hours.
  - A country leaves the baseline after GEO_BASELINE_DAYS with no sign-in.
  - Failed sign-ins whose error means the password was correct (MFA or a
    policy stopped them) are anomalies too. They never join the baseline.

Storage: table "signincountries". One row per user (partition "user"), one
tenant row, and one row per day for the response-action counter.
"""

import hashlib
import json
import logging
from datetime import date, datetime, timedelta, timezone
from typing import Optional

from azure.core.exceptions import ResourceNotFoundError

import config

TABLE_NAME = "signincountries"
_USER_PARTITION = "user"
_TENANT_KEY = ("tenant", "tenant")
_MAX_DAYS_KEPT = 10
_REALERT = timedelta(hours=24)

# Sign-in errors that come after a correct password.
PASSWORD_OK_ERRORS = {
    "50055",  # password expired (the old password was correct)
    "50072",  # MFA registration required
    "50074",  # strong authentication required
    "50076",  # MFA required (policy or location)
    "50079",  # MFA registration required
    "50097",  # device authentication required
    "50140",  # "keep me signed in" interrupt
    "50158",  # external security challenge not satisfied
    "500121", # MFA failed or denied (for example MFA fatigue: the attacker has the password)
    "53000",  # Conditional Access: device not compliant
    "53001",  # Conditional Access: device not domain-joined
    "53002",  # Conditional Access: app not approved
    "53003",  # blocked by Conditional Access
    "53004",  # MFA registration blocked (risk)
}

_cache = config.CachedTable(TABLE_NAME, "Country baseline table")


def table_client():
    """Return the baseline table client, or None if storage is not available."""
    return _cache.get()


def sign_in_outcome(event: dict) -> str:
    """'success', 'password_ok' (correct password, stopped later), or 'failed'."""
    operation = str(event.get("Operation", ""))
    if operation == "UserLoggedIn":
        return "success"
    if config.sign_in_error_code(event) in PASSWORD_OK_ERRORS:
        return "password_ok"
    return "failed"


def country_of(ip_data: dict) -> str:
    """ISO alpha-2 country code from a proxycheck.io result, or ""."""
    code = str(ip_data.get("isocode") or "").strip().upper()
    return code if len(code) == 2 and code.isalpha() else ""


def _user_key(upn: str) -> str:
    return hashlib.sha256(upn.strip().lower().encode("utf-8")).hexdigest()


def _event_day(event: dict, now: datetime) -> str:
    raw = str(event.get("CreationTime", ""))[:10]
    try:
        return date.fromisoformat(raw).isoformat()
    except ValueError:
        return now.date().isoformat()


def _load(table, key) -> dict:
    try:
        return dict(table.get_entity(partition_key=key[0], row_key=key[1]))
    except ResourceNotFoundError:
        return {}


def _countries(entity: dict) -> dict:
    try:
        value = json.loads(entity.get("countries") or "{}")
        return value if isinstance(value, dict) else {}
    except ValueError:
        return {}


def _known(countries: dict, today: date) -> set:
    """Countries in the baseline: learned or promoted, seen in GEO_BASELINE_DAYS."""
    cutoff = (today - timedelta(days=config.GEO_BASELINE_DAYS)).isoformat()
    return {
        cc for cc, v in countries.items()
        if (v.get("learned") or len(v.get("days", [])) >= config.GEO_PROMOTE_DAYS)
        and max(v.get("days") or [""]) >= cutoff
    }


def _tenant_known(tenant_countries: dict, today: date) -> set:
    cutoff = (today - timedelta(days=config.GEO_BASELINE_DAYS)).isoformat()
    return {cc for cc, last in tenant_countries.items() if str(last) >= cutoff}


def evaluate(table, observations: list, now: datetime) -> list:
    """Update the baselines and return the anomalies.

    ``observations``: dicts with user, country, outcome, ip, event, analysis.
    Each anomaly is the observation plus ``known`` (the baseline used) and
    ``learning`` (True while the learning period runs). Never raises.
    """
    if table is None or not config.GEO_ANOMALY_ENABLED or not observations:
        return []
    try:
        return _evaluate(table, observations, now)
    except Exception as e:
        logging.error(f"Country anomaly check failed: {type(e).__name__}: {e}")
        return []


def seed(table, observations: list, now: datetime) -> int:
    """Onboarding: add past sign-ins to the baselines during the learning period.

    Outside the learning period, do nothing (past sign-ins must not cause
    alerts or change re-alert times). Return the number of users updated.
    """
    if table is None or not config.GEO_ANOMALY_ENABLED or not observations:
        return 0
    state = status(table, now)
    if state and state.get("learning") is False:
        return 0
    try:
        _evaluate(table, observations, now, seed=True)
    except Exception as e:
        logging.error(f"Country baseline seed failed: {type(e).__name__}: {e}")
        return 0
    return len({str(o["user"]).strip().lower() for o in observations if o.get("country")})


def _evaluate(table, observations: list, now: datetime, seed: bool = False) -> list:
    today = now.date()
    tenant = _load(table, _TENANT_KEY)
    tenant_dirty = False
    if not tenant.get("started"):
        tenant = {"PartitionKey": _TENANT_KEY[0], "RowKey": _TENANT_KEY[1],
                  "started": now.isoformat(), "countries": "{}"}
        tenant_dirty = True
    started = datetime.fromisoformat(tenant["started"])
    if started.tzinfo is None:
        started = started.replace(tzinfo=timezone.utc)
    learning = now < started + timedelta(days=config.GEO_LEARNING_DAYS)
    tenant_countries = _countries(tenant)

    users = {}
    anomalies = []
    for obs in sorted(observations, key=lambda o: str(o["event"].get("CreationTime", ""))):
        cc = obs["country"]
        upn = str(obs["user"]).strip().lower()
        if not cc or not upn:
            continue
        if upn not in users:
            entity = _load(table, (_USER_PARTITION, _user_key(upn)))
            users[upn] = {"entity": entity, "countries": _countries(entity), "dirty": False}
        state = users[upn]
        countries = state["countries"]

        own = _known(countries, today)
        baseline = own or _tenant_known(tenant_countries, today)
        in_baseline = cc in baseline or cc in config.HOME_COUNTRIES
        # Nothing to compare with (no user and no tenant baseline): learn, do not alert.
        no_reference = not baseline and not config.HOME_COUNTRIES
        can_alert = (not learning or bool(config.HOME_COUNTRIES)) and not no_reference
        anomalous = (not in_baseline) and can_alert and obs["outcome"] in ("success", "password_ok")

        if obs["outcome"] == "success":
            entry = countries.setdefault(cc, {"days": []})
            day = _event_day(obs["event"], now)
            if day not in entry["days"]:
                entry["days"] = sorted(entry["days"] + [day])[-_MAX_DAYS_KEPT:]
                state["dirty"] = True
            if (learning or no_reference) and not anomalous and not entry.get("learned"):
                entry["learned"] = True
                state["dirty"] = True
            if cc in _known(countries, today) and tenant_countries.get(cc) != max(entry["days"]):
                tenant_countries[cc] = max(entry["days"])
                tenant_dirty = True

        if anomalous and not seed:
            entry = countries.setdefault(cc, {"days": []})
            last_alert = entry.get("alerted")
            if not last_alert or now - datetime.fromisoformat(last_alert) >= _REALERT:
                entry["alerted"] = now.isoformat()
                state["dirty"] = True
                anomalies.append({**obs, "known": sorted(baseline), "learning": learning})

    for upn, state in users.items():
        if state["dirty"]:
            _prune(state["countries"], today)
            table.upsert_entity({
                "PartitionKey": _USER_PARTITION,
                "RowKey": _user_key(upn),
                "upn": upn,
                "countries": json.dumps(state["countries"], sort_keys=True),
            })
    if tenant_dirty:
        tenant["countries"] = json.dumps(tenant_countries, sort_keys=True)
        table.upsert_entity(tenant)
    return anomalies


def _prune(countries: dict, today: date) -> None:
    cutoff = (today - timedelta(days=config.GEO_BASELINE_DAYS)).isoformat()
    for cc in [cc for cc, v in countries.items() if max(v.get("days") or [""]) < cutoff
               and not v.get("alerted", "") >= cutoff]:
        del countries[cc]


def is_unusual(table, upn: str, cc: str, now: datetime) -> bool:
    """Read-only: True if ``cc`` is outside the user's baseline (after learning)."""
    if table is None or not config.GEO_ANOMALY_ENABLED or not cc or not upn:
        return False
    try:
        if cc in config.HOME_COUNTRIES:
            return False
        tenant = _load(table, _TENANT_KEY)
        if not tenant.get("started"):
            return False
        started = datetime.fromisoformat(tenant["started"])
        if started.tzinfo is None:
            started = started.replace(tzinfo=timezone.utc)
        if now < started + timedelta(days=config.GEO_LEARNING_DAYS) and not config.HOME_COUNTRIES:
            return False
        own = _known(_countries(_load(table, (_USER_PARTITION, _user_key(upn)))), now.date())
        return cc not in (own or _tenant_known(_countries(tenant), now.date()))
    except Exception as e:
        logging.warning(f"Country check failed: {type(e).__name__}")
        return False


def status(table, now: datetime) -> Optional[dict]:
    """Summary for /api/status."""
    if table is None:
        return None
    try:
        tenant = _load(table, _TENANT_KEY)
    except Exception:
        return None
    if not tenant.get("started"):
        return {"enabled": config.GEO_ANOMALY_ENABLED, "learning_started": None}
    started = datetime.fromisoformat(tenant["started"])
    if started.tzinfo is None:
        started = started.replace(tzinfo=timezone.utc)
    ends = started + timedelta(days=config.GEO_LEARNING_DAYS)
    return {
        "enabled": config.GEO_ANOMALY_ENABLED,
        "learning_started": started.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "learning_ends": ends.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "learning": now < ends,
        "tenant_countries": sorted(_tenant_known(_countries(tenant), now.date())),
        "home_countries": sorted(config.HOME_COUNTRIES),
        "anomaly_action": config.ANOMALY_ACTION,
    }


# -----------------------------------------------------------------------------
# Management UI: list, approve, and remove a user's countries
# -----------------------------------------------------------------------------

def user_countries(table, upn: str, now: datetime) -> list:
    """Rows for the UI: country, status (usual, new, alerted), days seen, last day."""
    if table is None or not upn:
        return []
    countries = _countries(_load(table, (_USER_PARTITION, _user_key(upn))))
    known = _known(countries, now.date())
    rows = []
    for cc, v in sorted(countries.items()):
        days = v.get("days") or []
        status = "usual" if cc in known else ("alerted" if v.get("alerted") else "new")
        rows.append({"country": cc, "status": status, "days_seen": len(days),
                     "last_seen": max(days) if days else "", "approved": bool(v.get("approved"))})
    return rows


def set_country(table, upn: str, cc: str, approve: bool, now: datetime) -> bool:
    """Approve ``cc`` as usual for ``upn`` (for example travel), or remove it. True if changed."""
    upn = upn.strip().lower()
    cc = cc.strip().upper()
    key = (_USER_PARTITION, _user_key(upn))
    entity = _load(table, key)
    countries = _countries(entity)
    if approve:
        entry = countries.setdefault(cc, {"days": []})
        today = now.date().isoformat()
        if today not in entry["days"]:
            entry["days"] = sorted(entry["days"] + [today])[-_MAX_DAYS_KEPT:]
        entry["learned"] = True
        entry["approved"] = True
    elif cc in countries:
        del countries[cc]
    else:
        return False
    table.upsert_entity({"PartitionKey": key[0], "RowKey": key[1], "upn": upn,
                         "countries": json.dumps(countries, sort_keys=True)})
    return True
