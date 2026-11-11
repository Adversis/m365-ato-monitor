"""Keep the Azure Monitor health alerts on the alert mailbox.

install.ps1 makes an action group that emails the alert mailbox when no run
completes for 1 hour, or when errors repeat. When the alert mailbox changes in
the management UI, set_email() sets the same address on that action group.

The app's service principal has the role Monitoring Contributor on the action
group only (install.ps1). ACTION_GROUP_ID is the action group's resource ID.
"""

import logging

import config
from o365_client import token_manager

_API_VERSION = "2023-01-01"


def set_email(address: str, old: str = "") -> str:
    """Move the health alerts of the action group from ``old`` to ``address``. Return a short result text.

    Only receivers with the old address change. Receivers that an admin added
    for other addresses stay. If no receiver has the old address, the receiver
    "admin" (made by install.ps1) changes, or a new one is added.
    """
    group = config.ACTION_GROUP_ID
    if not group:
        return "Azure Monitor health alerts: not configured, nothing changed."
    if not group.startswith("/subscriptions/") or "/providers/microsoft.insights/actiongroups/" not in group.lower():
        return "Azure Monitor health alerts: ACTION_GROUP_ID is not an action group ID."
    url = f"https://management.azure.com{group}?api-version={_API_VERSION}"
    try:
        headers = {"Authorization": f"Bearer {token_manager.get_arm_token()}", "Content-Type": "application/json"}
        resp = config.http.get(url, headers=headers, timeout=30)
        if resp.status_code != 200:
            return _failed(resp.status_code)
        body = resp.json()
        receivers = (body.get("properties") or {}).get("emailReceivers") or []
        old = (old or "").strip().lower()
        targets = [r for r in receivers if old and str(r.get("emailAddress", "")).strip().lower() == old]
        if not targets:
            targets = [r for r in receivers if r.get("name") == "admin"]
        if not targets:
            names = {r.get("name") for r in receivers}
            name = "admin" if "admin" not in names else f"alert-mailbox-{len(receivers) + 1}"
            targets = [{"name": name, "useCommonAlertSchema": True}]
            receivers.append(targets[0])
        for r in targets:
            r["emailAddress"] = address
        for r in receivers:
            r.pop("status", None)
        body.setdefault("properties", {})["emailReceivers"] = receivers
        resp = config.http.request("PUT", url, headers=headers, timeout=30,
                                   json={"location": body.get("location", "Global"), "tags": body.get("tags") or {},
                                         "properties": body["properties"]})
    except Exception as e:
        logging.error(f"Action group not updated: {type(e).__name__}: {config.redact(e)}")
        return f"Azure Monitor health alerts: not updated ({type(e).__name__}). Change the email in Azure Monitor > Action groups."
    if resp.status_code not in (200, 201):
        return _failed(resp.status_code)
    logging.warning(f"Action group email set to {address}")
    return f"Azure Monitor health alerts now go to {address}."


def _failed(status: int) -> str:
    hint = " (no Monitoring Contributor role on the action group)" if status in (401, 403) else ""
    logging.error(f"Action group not updated: HTTP {status}{hint}")
    return (f"Azure Monitor health alerts: not updated, HTTP {status}{hint}. Change the email in "
            "Azure portal > Monitor > Alerts > Action groups.")
