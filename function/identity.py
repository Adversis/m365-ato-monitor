"""Managed identity tokens: no client secret and no storage key.

The installer gives the Function App a user-assigned managed identity (UAMI).
The identity is used two ways:

1. Federated credential. The app registration trusts the UAMI. To get a token
   for the app (Graph, Office 365 Management API, ARM, App Insights), the code
   first gets a UAMI token for the audience api://AzureADTokenExchange, then
   sends it as a client assertion in the client-credentials request. Only code
   that runs in this Function App can get that token. Nothing expires.
2. Table Storage. The UAMI has the role Storage Table Data Contributor on the
   storage account. TableCredential gives azure-data-tables a UAMI token.

The token endpoint is the App Service managed identity endpoint
(IDENTITY_ENDPOINT, IDENTITY_HEADER). MANAGED_IDENTITY_CLIENT_ID selects the UAMI.
"""

import time
from typing import NamedTuple

import config

FEDERATION_AUDIENCE = "api://AzureADTokenExchange"
STORAGE_RESOURCE = "https://storage.azure.com/"
_API_VERSION = "2019-08-01"
_SKEW_SECONDS = 300

_cache = {}   # resource -> (token, expires_on)


class AccessToken(NamedTuple):
    """Same shape as azure.core.credentials.AccessToken."""
    token: str
    expires_on: int


def available() -> bool:
    import os
    return bool(config.MANAGED_IDENTITY_CLIENT_ID and os.environ.get("IDENTITY_ENDPOINT")
                and os.environ.get("IDENTITY_HEADER"))


def get(resource: str) -> AccessToken:
    """A UAMI token for ``resource`` (cached until 5 minutes before it expires). Raises on failure."""
    import os
    cached = _cache.get(resource)
    if cached and cached.expires_on - _SKEW_SECONDS > time.time():
        return cached
    endpoint, header = os.environ.get("IDENTITY_ENDPOINT"), os.environ.get("IDENTITY_HEADER")
    if not (endpoint and header and config.MANAGED_IDENTITY_CLIENT_ID):
        raise RuntimeError("Managed identity is not available (IDENTITY_ENDPOINT, IDENTITY_HEADER, "
                           "MANAGED_IDENTITY_CLIENT_ID)")
    resp = config.http.get(endpoint, timeout=15, headers={"X-IDENTITY-HEADER": header},
                           params={"resource": resource, "api-version": _API_VERSION,
                                   "client_id": config.MANAGED_IDENTITY_CLIENT_ID})
    if resp.status_code != 200:
        raise RuntimeError(f"Managed identity token for {resource} failed: HTTP {resp.status_code}")
    data = resp.json()
    token = data.get("access_token")
    if not token:
        raise RuntimeError(f"Managed identity response for {resource} had no access_token")
    try:
        expires_on = int(float(data.get("expires_on")))
    except (TypeError, ValueError):
        expires_on = int(time.time()) + 3000
    _cache[resource] = AccessToken(token, expires_on)
    return _cache[resource]


def client_assertion() -> str:
    """The UAMI token that the app registration accepts as its credential."""
    return get(FEDERATION_AUDIENCE).token


class TableCredential:
    """A TokenCredential for azure-data-tables (Table Storage over Entra ID)."""

    def get_token(self, *scopes, **kwargs) -> AccessToken:
        return get(STORAGE_RESOURCE)

    # azure-core 1.30+ prefers get_token_info when it exists. Not defining it
    # keeps the classic get_token path.
