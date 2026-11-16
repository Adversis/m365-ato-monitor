"""Exchange records that a Microsoft service wrote for the user (for example the Teams backend reading
an attachment for the Teams client). The IP is the service's, so the session check skips them.

All IDs are made up. The shapes follow real records: AppId equals AppAccessContext.APIId (the service
whose API the user's token was for), and ClientAppId is the user's app.
"""

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import pytest

import mail_access
import service_actors as sa
import session_monitor as sm
from tests.fakes import FakeTable
from tests.test_session_monitor import DATA, HOME_IP, SID, Lookup, signin

NOW = datetime(2026, 11, 8, 12, 0, tzinfo=timezone.utc)
SERVICE_APP = "5e7c1ce0-0000-4000-8000-00000000a001"     # a Microsoft service API (made up)
CLIENT_APP = "c11e0700-0000-4000-8000-00000000c001"      # the user's app (made up)
OTHER_APP = "0be00000-0000-4000-8000-00000000b001"       # an app of another tenant (made up)
EXCHANGE = "00000002-0000-0ff1-ce00-000000000000"
MICROSOFT = "f8cdef31-a31e-4b4a-93e4-5f571e91255a"
AZURE_IP = "52.123.162.160"                              # Azure: customer space, not on the Microsoft 365 list


def relayed(app=SERVICE_APP, api=SERVICE_APP, client=CLIENT_APP, op="AttachmentAccess", ip=AZURE_IP, **over):
    record = {"Id": f"r-{op}-{app}", "RecordType": 50, "Operation": op, "Workload": "Exchange",
              "UserId": "victim@contoso.com", "MailboxOwnerUPN": "victim@contoso.com",
              "ClientIPAddress": ip, "ClientInfoString": "Client=REST;;", "SessionId": SID,
              "CreationTime": "2026-11-08T11:20:00", "AppId": app, "ClientAppId": client,
              "ActorInfoString": f"Client=REST;SomeService[AppId={app}];",
              "AppAccessContext": {"AADSessionId": SID, "APIId": api, "ClientAppId": client}}
    record.update(over)
    return record


def _graph(owners):
    def get(url, params=None, headers=None, timeout=None):
        app = url.split("appId='")[-1].rstrip("')")
        if app not in owners:
            return MagicMock(status_code=404)
        r = MagicMock(status_code=200)
        r.json.return_value = {"appOwnerOrganizationId": owners[app]}
        return r
    return get


@pytest.fixture(autouse=True)
def graph():
    sa.clear_cache()
    with patch("service_actors.token_manager") as tm, patch("config.http") as http:
        tm.get_graph_token.return_value = "t"
        http.get.side_effect = _graph({SERVICE_APP: MICROSOFT, OTHER_APP: "11111111-2222-4333-8444-555555555555"})
        yield http
    sa.clear_cache()


def _check(record):
    data = dict(DATA, **{AZURE_IP: {"isocode": "CA", "asn": "AS8075", "organisation": "Microsoft Corporation",
                                    "proxy": "yes", "type": "VPN", "risk": 66}})
    lookup = Lookup(data)
    return sm.check(FakeTable(), [signin(HOME_IP, 1), record], lookup, NOW), lookup


def test_microsoft_service_is_skipped(graph):
    # Regression: the Teams backend read an attachment, and a notification service sent a task email,
    # for the user from Azure IPs: "session used from a second country".
    for op in ("AttachmentAccess", "Send", "MailItemsAccessed"):
        found, lookup = _check(relayed(op=op))
        assert found == [] and all(AZURE_IP not in c for c in lookup.calls)
    assert graph.get.call_count == 1                                     # one lookup, then cached
    assert graph.get.call_args.args[0].endswith(f"servicePrincipals(appId='{SERVICE_APP}')")


@pytest.mark.parametrize("record", [
    relayed(app=OTHER_APP, api=OTHER_APP),                              # an app of another tenant
    relayed(app="0000abcd-0000-4000-8000-000000000000",
            api="0000abcd-0000-4000-8000-000000000000"),               # no service principal (404)
    relayed(app=EXCHANGE, api=EXCHANGE),                                # a client token for Exchange
    relayed(api=EXCHANGE),                                              # AppId is not the token's API
    relayed(client=SERVICE_APP),                                        # the client is the API itself
    relayed(client=""),                                                 # no client app
    relayed(AppAccessContext={"AADSessionId": SID}, ClientAppId=CLIENT_APP),   # no API
    relayed(Workload="SharePoint"),
], ids=["other-tenant", "not-found", "exchange-token", "app-not-api", "client-is-api", "no-client",
        "no-api", "not-exchange"])
def test_other_shapes_are_checked(record):
    found, _ = _check(record)
    assert len(found) == 1 and found[0]["country"] == "CA"


def test_graph_unavailable_checks_the_record(graph):
    graph.get.side_effect = OSError("down")
    found, _ = _check(relayed())
    assert len(found) == 1


def test_sign_in_is_never_skipped():
    record = relayed(op="UserLoggedIn")
    assert not mail_access.service_ip_client(record)


def test_app_id_must_be_a_guid(graph):
    assert sa.app_owner_tenant("x') or (1 eq 1") is None and sa.app_owner_tenant("") is None
    assert graph.get.call_count == 0


class TestCompromiseSeverity:
    """An alert from a record with a Microsoft service IP keeps the severity of its content."""

    VPN = {"proxy": "yes", "type": "VPN", "risk": 66, "isocode": "CA", "asn": "AS8075",
           "organisation": "Microsoft Corporation"}

    def _run(self, ip):
        import function_app as fa
        event = {"Id": "x1", "CreationTime": "2026-11-08T11:00:00", "Workload": "Exchange",
                 "Operation": "UpdateInboxRules", "ClientIPAddress": ip,
                 "ClientInfoString": "Client=OutlookService;Outlook-iOS/2.0;"}
        finding = {"type": "inbox_rule", "severity": "medium", "user": "victim@contoso.com", "description": "d",
                   "ip": ip, "rule_name": "r", "event": event}
        with patch("function_app._DETECTORS", (lambda ev: [dict(finding)],)), \
                patch("function_app.check_ips_batch", return_value={ip: self.VPN}) as lookup, \
                patch("function_app.send_compromise_alert", return_value=True) as send, \
                patch("journal.table_client", return_value=FakeTable()), \
                patch("geo_monitor.table_client", return_value=None):
            fa._run_compromise_check(FakeTable(), None, set(), [{"Id": "x1"}])
        sent, ip_context = send.call_args.args[:2]
        return sent["severity"], ip_context, lookup

    def test_microsoft_server_ip_does_not_raise(self):
        # Regression: a rule changed in Outlook mobile (through Microsoft's servers) became HIGH because
        # the server IP looks like a VPN.
        severity, ip_context, lookup = self._run("2603:10b6:930:d1::7")
        assert severity == "medium" and "Microsoft service IP" in ip_context
        assert not lookup.called

    def test_azure_ip_still_raises(self):
        severity, ip_context, lookup = self._run(AZURE_IP)
        assert severity == "high" and ip_context.startswith("Source IP is VPN")
