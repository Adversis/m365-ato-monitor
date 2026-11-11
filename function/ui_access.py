"""Who can open the management UI.

A signed-in user has access if one of these is true:

- The user has the Monitor.Admin app role (Entra ID > Enterprise applications >
  the admin UI app > Users and groups, or install.ps1 -UiAdmins).
- The user principal name is in UI_ADMIN_USERS (management UI > Settings).
- The user has an active, direct assignment of a directory role in
  UI_ADMIN_ROLES. Microsoft Graph tells the monitor the roles of the user
  (RoleManagement.Read.Directory). A role assigned through a group, and a
  PIM-eligible role that is not active, do not count.

The admin UI app does not require assignment, so any user of the tenant can
sign in to it. The function refuses every API request of a user without
access (admin_api.guard).
"""

import logging
import re
import time

import config
from o365_client import token_manager

ROLE = "Monitor.Admin"
_GRAPH = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments"
_GUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_CACHE_SECONDS = 300
_ERROR_CACHE_SECONDS = 30
_cache = {}  # object ID -> (time, frozenset of role template IDs)


def _get(params: dict) -> list:
    """All pages of a role assignment list. Raises on an error."""
    headers = {"Authorization": f"Bearer {token_manager.get_graph_token()}"}
    url, out = _GRAPH, []
    for _ in range(20):
        resp = config.http.get(url, headers=headers, params=params, timeout=20)
        if resp.status_code != 200:
            raise RuntimeError(f"Graph HTTP {resp.status_code}")
        data = resp.json()
        out.extend(data.get("value") or [])
        url, params = data.get("@odata.nextLink"), None
        if not url or not url.startswith(_GRAPH):
            break
    return out


def directory_roles(object_id: str) -> frozenset:
    """Role template IDs of the active, direct role assignments of a user. Cached 5 minutes.

    Returns an empty set if the ID is not valid or Graph refuses the request.
    """
    oid = str(object_id or "").lower()
    if not _GUID_RE.match(oid):
        return frozenset()
    hit = _cache.get(oid)
    if hit and time.monotonic() < hit[0]:
        return hit[1]
    try:
        rows = _get({"$filter": f"principalId eq '{oid}'", "$select": "roleDefinitionId,directoryScopeId"})
        # Only assignments for the whole tenant: a role scoped to an administrative unit does not count.
        roles = frozenset(str(r.get("roleDefinitionId") or "").lower() for r in rows
                          if str(r.get("directoryScopeId") or "/") == "/")
        ttl = _CACHE_SECONDS
    except Exception as e:
        logging.warning(f"UI access: directory roles not read: {type(e).__name__}: {config.redact(e)}")
        roles = frozenset()
        ttl = _ERROR_CACHE_SECONDS     # try again soon: an error must not shut out role-based admins for long
    _cache[oid] = (time.monotonic() + ttl, roles)
    return roles


def access(user: dict) -> str:
    """Why the user has access ("app role", "listed user", "directory role"), or "" for no access."""
    if ROLE in user.get("roles", ()):
        return "app role"
    if str(user.get("upn") or "").lower() in config.UI_ADMIN_USERS:
        return "listed user"
    if config.UI_ADMIN_ROLES and directory_roles(user.get("oid", "")) & config.UI_ADMIN_ROLES:
        return "directory role"
    return ""


def role_members(role_ids) -> dict:
    """{role ID: [{"upn", "name"}] or None if Graph refused}: the users with an active, direct assignment."""
    out = {}
    for role_id in role_ids:
        rid = str(role_id).lower()
        if not _GUID_RE.match(rid):
            continue
        try:
            rows = _get({"$filter": f"roleDefinitionId eq '{rid}'", "$expand": "principal"})
        except Exception as e:
            logging.warning(f"UI access: members of role {rid} not read: {type(e).__name__}")
            out[rid] = None
            continue
        members = []
        for r in rows:
            if str(r.get("directoryScopeId") or "/") != "/":
                continue  # scoped to an administrative unit: gives no access
            p = r.get("principal") or {}
            if str(p.get("@odata.type") or "").lower() != "#microsoft.graph.user":
                continue  # a group or a service principal
            members.append({"upn": str(p.get("userPrincipalName") or ""), "name": str(p.get("displayName") or "")})
        out[rid] = sorted(members, key=lambda m: m["upn"].lower())
    return out


def clear_cache() -> None:
    _cache.clear()

