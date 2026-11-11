"""Changes that Microsoft's own services make, found by the tenant that owns the acting app.

Each service principal has appOwnerOrganizationId: the tenant that owns its
app. Microsoft's first-party apps belong to Microsoft's tenants. A change
whose actor is such a service principal (UserId or Actor
"ServicePrincipal_<object ID>", not a user) is Microsoft's own background
activity. The monitor journals it with status "microsoft" and sends no email.
The reports count these changes.

A change that a person makes, also through a Microsoft app, has the person's
UPN as UserId and still alerts. A service principal of an app that a tenant
registers belongs to that tenant, not to Microsoft.

Only the finding types in NOISE_TYPES are checked. Microsoft services also
write records for changes that a person caused: the MFA service writes the
record when a user (or an attacker in the user's session) adds an MFA method,
and PIM writes the record of a role activation. Those findings always alert.

Needs the Graph permission Application.Read.All (read only). Without it, every
finding alerts as before.
"""

import logging
import re
import time
from typing import Optional

import config
from o365_client import token_manager

# Tenants that own Microsoft first-party apps (appOwnerOrganizationId).
MICROSOFT_TENANTS = frozenset({
    "f8cdef31-a31e-4b4a-93e4-5f571e91255a",   # Microsoft Services
    "72f988bf-86f1-41af-91ab-2d7cd011db47",   # Microsoft
})
# Finding types where a Microsoft service actor is background provisioning (for example the
# delegated grants that Microsoft apps add for themselves). Never mfa_change or admin_role.
NOISE_TYPES = frozenset({"oauth_consent"})
_GRAPH = "https://graph.microsoft.com/v1.0/servicePrincipals"
_ERROR_SECONDS = 900    # a failed lookup is not tried again for 15 minutes
_SP_RE = re.compile(r"^ServicePrincipal_([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$")
_CACHE_SECONDS = 24 * 3600
_cache = {}             # service principal object ID -> (time, owner tenant ID or "")
_refused_until = 0.0    # Graph refused (no permission): do not ask again before this time
_failed = {}            # service principal object ID -> time before which a failed lookup is not tried again


def actor_service_principals(event: dict) -> list:
    """Object IDs of the service principals that made a change (UserId or Actor "ServicePrincipal_<id>")."""
    values = [event.get("UserId")] + [a.get("ID") for a in event.get("Actor") or [] if isinstance(a, dict)]
    out = []
    for value in values:
        m = _SP_RE.match(str(value or "").strip())
        if m and m.group(1).lower() not in out:
            out.append(m.group(1).lower())
    return out


def owner_tenant(sp_id: str) -> Optional[str]:
    """appOwnerOrganizationId of a service principal ("" if none or not found). None if unknown now."""
    global _refused_until
    hit = _cache.get(sp_id)
    if hit and time.monotonic() - hit[0] < _CACHE_SECONDS:
        return hit[1]
    if time.monotonic() < _refused_until:
        return None
    failed = _failed.get(sp_id)
    if failed and time.monotonic() < failed:
        return None
    try:
        resp = config.http.get(f"{_GRAPH}/{sp_id}", params={"$select": "appOwnerOrganizationId"},
                               headers={"Authorization": f"Bearer {token_manager.get_graph_token()}"}, timeout=10)
    except Exception as e:
        logging.warning(f"Service principal {sp_id} not read: {type(e).__name__}")
        _failed[sp_id] = time.monotonic() + _ERROR_SECONDS
        return None
    if resp.status_code in (401, 403):
        _refused_until = time.monotonic() + 3600
        logging.warning("Service principals cannot be read (no Application.Read.All). Run ./install.ps1 -Update.")
        return None
    if resp.status_code == 404:
        owner = ""
    elif resp.status_code == 200:
        try:
            owner = str(resp.json().get("appOwnerOrganizationId") or "").lower()
        except (ValueError, AttributeError):
            _failed[sp_id] = time.monotonic() + _ERROR_SECONDS
            return None
    else:
        _failed[sp_id] = time.monotonic() + _ERROR_SECONDS
        return None
    _cache[sp_id] = (time.monotonic(), owner)
    return owner


def is_microsoft_service(finding: dict) -> bool:
    """True if a service principal of a Microsoft first-party app made the change of this finding.

    Only for the types in NOISE_TYPES.
    """
    if finding.get("type") not in NOISE_TYPES:
        return False
    event = finding.get("event") or {}
    if "@" in str(event.get("UserId") or ""):
        return False    # a person, also when they use a Microsoft app
    return any(owner_tenant(sp) in MICROSOFT_TENANTS for sp in actor_service_principals(event)[:3])


def clear_cache() -> None:
    global _refused_until
    _cache.clear()
    _failed.clear()
    _refused_until = 0.0
