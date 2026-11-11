"""Self-test: one synthetic audit record for each alert type.

Each record goes through the real detectors (all of them, as in a run) and,
on request, through the real alert email code with "[SELF-TEST]" in the
subject. This checks detection, email delivery, and how each email looks,
without changes to the tenant. It does not read the Management API or
proxycheck.io, and it does not write dedup, baseline, or queue state.

The records use reserved names: the .invalid top-level domain (RFC 2606) and
the 203.0.113.0/24 documentation range (RFC 5737).
"""

import json
import logging
from datetime import datetime, timedelta, timezone

from azure.core.exceptions import ResourceNotFoundError

import mail_access
import session_monitor
from ip_checker import analyze_ip
from alerting import send_compromise_alert, send_country_anomaly_alert, send_suspicious_login_alert

USER = "selftest@audit-monitor.invalid"
EXTERNAL = "sink@external-selftest.invalid"
IP = "203.0.113.10"
PREFIX = "[SELF-TEST] "


def _params(**kv) -> list:
    return [{"Name": k, "Value": v} for k, v in kv.items()]


def _signin(ua: str, request_type: str = "OAuth2:Authorize", operation: str = "UserLoggedIn") -> dict:
    return {"RecordType": 15, "Operation": operation, "ResultStatus": "Succeeded",
            "ExtendedProperties": [{"Name": "UserAgent", "Value": ua},
                                   {"Name": "RequestType", "Value": request_type}]}


def _mfa_methods(count: int) -> str:
    return json.dumps([{"MethodType": 6 + i, "Default": i == 0} for i in range(count)])


# type -> (label, record fields). The record triggers that finding type only.
COMPROMISE = {
    "inbox_rule": ("Inbox rule forwards externally", {
        "RecordType": 1, "Operation": "New-InboxRule",
        "Parameters": _params(Name="AUDIT-MONITOR-SELFTEST", ForwardTo=EXTERNAL)}),
    "mailbox_forwarding": ("Mailbox forwarding to an external address", {
        "RecordType": 1, "Operation": "Set-Mailbox",
        "Parameters": _params(Identity=USER, ForwardingSmtpAddress=f"smtp:{EXTERNAL}",
                              DeliverToMailboxAndForward="True")}),
    "oauth_consent": ("Risky OAuth consent", {
        "RecordType": 8, "Operation": "Consent to application.",
        "Target": [{"ID": "ServicePrincipal_0", "Type": 2}, {"ID": "Self-test app", "Type": 1}],
        "ModifiedProperties": [{"Name": "ConsentAction.Permissions", "OldValue": "",
                                "NewValue": "[[Scope: User.Read Mail.Read Mail.Send]]"}]}),
    "attack_tool": ("Sign-in with an attack tool", _signin("AADInternals")),
    "suspicious_user_agent": ("Sign-in with an automation client", _signin("python-requests/2.32.3")),
    "legacy_auth": ("Sign-in with legacy authentication", _signin("BAV2ROPC")),
    "device_code": ("Sign-in with a device code", _signin("Mozilla/5.0", request_type="Cmsi:Cmsi")),
    "mail_flow_rule": ("Mail flow rule with an external BCC", {
        "RecordType": 1, "Operation": "New-TransportRule",
        "Parameters": _params(Name="AUDIT-MONITOR-SELFTEST", BlindCopyTo=EXTERNAL)}),
    "mailbox_delegation": ("Full access to a mailbox", {
        "RecordType": 1, "Operation": "Add-MailboxPermission", "UserType": 2,
        "Parameters": _params(Identity="ceo@audit-monitor.invalid", User=USER, AccessRights="FullAccess")}),
    "audit_disabled": ("Audit bypass on", {
        "RecordType": 1, "Operation": "Set-MailboxAuditBypassAssociation",
        "Parameters": _params(Identity=USER, AuditBypassEnabled="True")}),
    "mail_protection_weakened": ("External auto-forwarding allowed", {
        "RecordType": 1, "Operation": "Set-HostedOutboundSpamFilterPolicy",
        "Parameters": _params(Identity="Default", AutoForwardingMode="On")}),
    "mfa_change": ("MFA method added", {
        "RecordType": 8, "Operation": "Update user.", "ObjectId": USER,
        "Target": [{"ID": USER, "Type": 5}],
        "ModifiedProperties": [{"Name": "StrongAuthenticationMethod",
                                "OldValue": _mfa_methods(1), "NewValue": _mfa_methods(2)}]}),
    "admin_role": ("Global Administrator assigned", {
        "RecordType": 8, "Operation": "Add member to role.", "ObjectId": "new-admin@audit-monitor.invalid",
        "Target": [{"ID": "new-admin@audit-monitor.invalid", "Type": 5}],
        "ModifiedProperties": [{"Name": "Role.DisplayName", "OldValue": "", "NewValue": "Global Administrator"}]}),
    "app_credential": ("Secret added to an app", {
        "RecordType": 8, "Operation": "Update application – Certificates and secrets management ",
        "Target": [{"ID": "Application_0", "Type": 2}, {"ID": "Self-test app", "Type": 1}]}),
    "domain_federation": ("Federation set on a domain", {
        "RecordType": 8, "Operation": "Set domain authentication.", "ObjectId": "audit-monitor.invalid"}),
}

# Checks that need state across records. They run with an in-memory table and
# a fixed IP result, so they need no storage or network.
STATEFUL = {
    "session_reuse": "Session used from a second country or a risky IP",
    "mail_access": "Mail read or sent from a risky IP",
}

# Sign-in emails. The real path needs proxycheck.io, so these use a fixed result.
SIGNIN = {
    "suspicious_signin": "Sign-in from a VPN or hosting IP",
    "new_country": "Sign-in from a new country",
}

LABELS = {**{k: v[0] for k, v in COMPROMISE.items()}, **STATEFUL, **SIGNIN}
ALL = list(COMPROMISE) + list(STATEFUL) + list(SIGNIN)


class _MemoryTable:
    """The two Table Storage calls that session_monitor uses."""

    def __init__(self):
        self.rows = {}

    def get_entity(self, partition_key, row_key):
        try:
            return dict(self.rows[(partition_key, row_key)])
        except KeyError:
            raise ResourceNotFoundError("not found")

    def upsert_entity(self, entity):
        self.rows[(entity["PartitionKey"], entity["RowKey"])] = dict(entity)


# Shared address space (RFC 6598): not routed, and not "private" for the session check.
_SESSION_IPS = {"100.64.0.10": ("US", "Self-test home ISP"), "100.64.0.20": ("ZZ", "Self-test hosting")}


def session_findings(now: datetime) -> list:
    """Two records of one session: a sign-in in US, then mailbox access in ZZ."""
    sid = "5e1f7e57-0000-4000-8000-000000000001"
    start = now - timedelta(minutes=20)
    records = []
    for minutes, (ip, operation) in ((0, ("100.64.0.10", "UserLoggedIn")), (15, ("100.64.0.20", "MailItemsAccessed"))):
        records.append({
            "Id": f"SELFTEST-session_reuse-{minutes}-{now.strftime('%Y%m%dT%H%M%S%fZ')}",
            "CreationTime": (start + timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%S"),
            "Operation": operation, "UserId": USER, "ClientIP": ip,
            "DeviceProperties": [{"Name": "SessionId", "Value": sid}],
            "AppAccessContext": {"AADSessionId": sid},
        })
    data = {ip: {"isocode": cc, "asn": "AS64496", "organisation": org} for ip, (cc, org) in _SESSION_IPS.items()}
    return session_monitor.check(_MemoryTable(), records, lambda ips: {i: data[i] for i in ips if i in data}, now)


def mail_access_findings(now: datetime) -> list:
    """A message sent from Outlook on the web on a VPN IP that never signed in as the user."""
    ip = "100.64.0.30"
    records = [{"Id": f"SELFTEST-mail_access-{now.strftime('%Y%m%dT%H%M%S%fZ')}",
                "CreationTime": now.strftime("%Y-%m-%dT%H:%M:%S"), "Operation": "Send", "Workload": "Exchange",
                "UserId": USER, "MailboxOwnerUPN": USER, "ClientIPAddress": ip,
                "ClientInfoString": "Client=OWA;Action=ViaProxy", "Item": {"Subject": "Self-test: new bank details"}}]
    data = {ip: {"proxy": "yes", "type": "VPN", "risk": 66, "isocode": "ZZ", "asn": "AS64496",
                 "organisation": "Self-test VPN"}}
    return mail_access.check(records, lambda ips: {i: data[i] for i in ips if i in data}, analyze_ip, now)


def record(ftype: str, now: datetime = None) -> dict:
    """The synthetic record for one compromise type."""
    now = now or datetime.now(timezone.utc)
    event = {
        "Id": f"SELFTEST-{ftype}-{now.strftime('%Y%m%dT%H%M%S%fZ')}",
        "CreationTime": now.strftime("%Y-%m-%dT%H:%M:%S"),
        "UserId": USER,
        "ClientIP": IP,
    }
    event.update(json.loads(json.dumps(COMPROMISE[ftype][1])))
    return event


def parse_types(value) -> list:
    """'all', 'inbox_rule,mfa_change', or a list -> list of known types. Raises ValueError."""
    if value is None or value == "" or value == []:
        return ["inbox_rule"]
    items = value if isinstance(value, list) else str(value).split(",")
    items = [str(i).strip() for i in items if str(i).strip()]
    if "all" in items:
        return list(ALL)
    unknown = [i for i in items if i not in LABELS]
    if unknown:
        raise ValueError(f"Unknown test type: {', '.join(unknown)}. Known: all, {', '.join(ALL)}")
    return list(dict.fromkeys(items))


def _signin_email(ftype: str, now: datetime) -> bool:
    event = {"Id": f"SELFTEST-{ftype}", "CreationTime": now.strftime("%Y-%m-%dT%H:%M:%S"),
             "UserId": PREFIX + USER, "Operation": "UserLoggedIn", "ClientIP": IP}
    analysis = {"is_suspicious": True, "flags": ["vpn", "hosting"], "confidence": "medium",
                "risk_score": 66, "proxy_type": "VPN", "asn": "AS64496", "org": "Self-test network",
                "city": "Example City", "country": "Exampleland"}
    if ftype == "suspicious_signin":
        return bool(send_suspicious_login_alert(event, IP, analysis))
    anomaly = {"event": event, "analysis": analysis, "country": "ZZ", "outcome": "success",
               "ip": IP, "known": ["US"]}
    return bool(send_country_anomaly_alert(anomaly, "none (self-test)"))


def run(types, send: bool, detectors) -> dict:
    """Run the self-test for each type. Return one result per type."""
    now = datetime.now(timezone.utc)
    results = []
    for ftype in types:
        item = {"type": ftype, "label": LABELS[ftype]}
        if ftype in SIGNIN:
            item.update(detected=None, severity=None, note="Email only: uses a fixed IP result.")
            item["email_sent"] = _signin_email(ftype, now) if send else False
            results.append(item)
            continue
        if ftype in STATEFUL:
            found = session_findings(now) if ftype == "session_reuse" else mail_access_findings(now)
            findings = [f for f in found if f["type"] == ftype]
        else:
            event = record(ftype, now)
            findings = []
            for detector in detectors:
                findings.extend(f for f in detector([event]) if f["type"] == ftype)
        item["detected"] = bool(findings)
        item["severity"] = findings[0]["severity"] if findings else None
        item["description"] = findings[0]["description"] if findings else ""
        item["email_sent"] = False
        if findings and send:
            finding = dict(findings[0])
            finding["description"] = PREFIX + finding["description"]
            item["email_sent"] = bool(send_compromise_alert(finding, finding.get("ip_context", ""),
                                                            subject_prefix=PREFIX))
        results.append(item)

    passed = all(r["detected"] is not False for r in results) and (not send or all(r["email_sent"] for r in results))
    logging.warning("SELF-TEST: %d types, send=%s, passed=%s, failed=%s", len(results), send, passed,
                    [r["type"] for r in results if r["detected"] is False or (send and not r["email_sent"])])
    return {"passed": passed, "emails_requested": send, "results": results}
