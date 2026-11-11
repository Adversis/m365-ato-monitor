"""Graph audit search: the client, the onboarding search step, and the user page search."""

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

import audit_search
import journal
from tests.fakes import FakeTable
from tests.test_admin_ui import MUTATE, _req

NOW = datetime(2026, 11, 9, 12, 0, tzinfo=timezone.utc)
QID = "1d9b6d8e-0d2f-4b3a-9f61-3a8b2f0e7c11"
QUERIES = "https://graph.microsoft.com/v1.0/security/auditLog/queries"


def _resp(status, body=None):
    r = MagicMock(status_code=status)
    r.json.return_value = body if body is not None else {}
    return r


def _graph_record(op="New-InboxRule", when="2026-07-01T10:00:00", rid="r1", user="jane@contoso.com", **audit):
    data = {"@odata.type": "#microsoft.graph.security.auditData", "Id": rid, "CreationTime": when,
            "Operation": op, "UserId": user, "Workload": "Exchange", "RecordType": 1, "ClientIP": "198.51.100.5"}
    data.update(audit)
    return {"id": rid, "createdDateTime": when + "Z", "operation": op, "userPrincipalName": user,
            "clientIp": "198.51.100.5", "service": "Exchange", "auditData": data}


FORWARD_RULE = dict(Parameters=[{"Name": "Name", "Value": "x1"}, {"Name": "ForwardTo", "Value": "a@evil.example"}])


@pytest.fixture
def token():
    with patch("audit_search.token_manager.get_graph_token", return_value="t"):
        yield


class FakeGraph:
    """POST creates a query; GET returns its status, then pages of records."""

    def __init__(self, pages, statuses=("running", "succeeded"), limit=False):
        self.pages, self.statuses, self.limit = list(pages), list(statuses), limit
        self.bodies = []

    def post(self, url, headers=None, data=None, timeout=None):
        assert url == QUERIES
        self.bodies.append(json.loads(data))
        return _resp(201, {"id": QID, "status": "notStarted"})

    def get(self, url, headers=None, timeout=None):
        if url == f"{QUERIES}/{QID}":
            status = self.statuses.pop(0) if len(self.statuses) > 1 else self.statuses[0]
            return _resp(200, {"id": QID, "status": status, "isRecordCountLimitExceeded": self.limit})
        page = int(url.rsplit("page=", 1)[1]) if "page=" in url else 0
        body = {"value": self.pages[page]}
        if page + 1 < len(self.pages):
            body["@odata.nextLink"] = f"{QUERIES}/{QID}/records?page={page + 1}"
        return _resp(200, body)


class TestClient:

    def test_create_get_records(self, token):
        g = FakeGraph([[_graph_record()], [_graph_record(rid="r2")]])
        with patch("config.http.post", side_effect=g.post), patch("config.http.get", side_effect=g.get):
            qid, err = audit_search.create("x", NOW - timedelta(days=30), NOW, operations=["New-InboxRule"],
                                           users=["jane@contoso.com"])
            assert (qid, err) == (QID, "")
            assert g.bodies[0]["filterStartDateTime"] == "2026-10-10T12:00:00Z"
            assert g.bodies[0]["operationFilters"] == ["New-InboxRule"]
            assert g.bodies[0]["userPrincipalNameFilters"] == ["jane@contoso.com"]
            info, err = audit_search.get(QID)
            assert info["status"] == "running" and not err
            items, link, err = audit_search.records(QID)
            assert len(items) == 1 and link.endswith("page=1")
            items, link, err = audit_search.records(QID, link)
            assert len(items) == 1 and link == ""

    def test_errors_and_guards(self, token):
        with patch("config.http.post", return_value=_resp(403, {"error": {"code": "Authorization_RequestDenied"}})):
            qid, err = audit_search.create("x", NOW - timedelta(days=1), NOW)
        assert qid is None and "AuditLogsQuery.Read.All" in err
        assert audit_search.get("../../users")[1] == "not a query ID"
        assert audit_search.records(QID, "https://evil.example/x")[2] == "the next link does not point to this search"
        evil = _resp(200, {"value": [], "@odata.nextLink": "https://evil.example/next"})
        with patch("config.http.get", return_value=evil):
            assert audit_search.records(QID)[1] == ""
        with patch("config.http.post", side_effect=OSError("down")):
            assert audit_search.create("x", NOW, NOW)[0] is None

    def test_to_record(self):
        r = audit_search.to_record(_graph_record(**FORWARD_RULE))
        assert r["Operation"] == "New-InboxRule" and r["CreationTime"] == "2026-07-01T10:00:00"
        assert "@odata.type" not in r and r["Parameters"][1]["Value"] == "a@evil.example"
        # auditData as a JSON string, or missing: use the common fields.
        item = _graph_record()
        item["auditData"] = json.dumps(item["auditData"])
        assert audit_search.to_record(item)["Id"] == "r1"
        bare = {"id": "r9", "createdDateTime": "2026-07-02T01:02:03Z", "operation": "UserLoggedIn",
                "userPrincipalName": "a@b.c", "clientIp": "1.2.3.4"}
        assert audit_search.to_record(bare) == {"Id": "r9", "Operation": "UserLoggedIn", "UserId": "a@b.c",
                                                "ClientIP": "1.2.3.4", "Workload": None,
                                                "CreationTime": "2026-07-02T01:02:03"}
        assert audit_search.to_record({"id": "x"}) is None and audit_search.to_record("x") is None

    def test_dynamic_properties_and_first_page_size(self, token):
        item = _graph_record()
        item["auditData"]["dynamicProperties"] = {"Parameters": FORWARD_RULE["Parameters"], "Operation": "ignored"}
        r = audit_search.to_record(item)
        assert r["Parameters"][1]["Value"] == "a@evil.example" and r["Operation"] == "New-InboxRule"
        assert "dynamicProperties" not in r
        with patch("config.http.get", return_value=_resp(200, {"value": []})) as get:
            audit_search.records(QID)
        assert get.call_args.args[0].endswith(f"/records?$top={audit_search.PAGE_SIZE}")

    def test_permissions(self):
        assert audit_search.can_search(["AuditLogsQuery.Read.All"])
        assert audit_search.can_search(["AuditLogsQuery-Exchange.Read.All", "AuditLogsQuery-Entra.Read.All"])
        assert not audit_search.can_search(["AuditLogsQuery-Exchange.Read.All"])
        assert not audit_search.can_search(None) and not audit_search.can_search([])

    def test_system_actor_by_name(self):
        from compromise_detector import _is_system_actor
        assert _is_system_actor({"UserType": "System"}) and _is_system_actor({"UserType": 4})
        assert _is_system_actor({"UserType": "DcAdmin"}) and not _is_system_actor({"UserType": "Admin"})

    def test_summary_row(self):
        row = audit_search.summary_row(audit_search.to_record(_graph_record(
            "MailItemsAccessed", ClientIPAddress="203.0.113.9", ClientInfoString="Client=OWA")))
        assert row["ip"] == "203.0.113.9" and row["client"] == "Client=OWA" and row["at"] == "2026-07-01T10:00:00Z"


# ---------------------------------------------------------------------------
# Onboarding: the search step
# ---------------------------------------------------------------------------

def _run(events, jt, now, graph, granted=("AuditLogsQuery.Read.All", "User.ReadBasic.All", "MailboxSettings.Read")):
    import function_app as fa
    import onboarding
    sent = MagicMock(return_value=True)
    with patch("journal.table_client", return_value=jt), \
            patch("onboarding.fetch_content_records", return_value=([], True)), \
            patch("onboarding.token_manager.granted_graph_roles", return_value=list(granted)), \
            patch("onboarding.mailbox_rules.list_mailbox_users", return_value=([], "")), \
            patch("audit_search.token_manager.get_graph_token", return_value="t"), \
            patch("config.http.post", side_effect=graph.post), patch("config.http.get", side_effect=graph.get), \
            patch("geo_monitor.table_client", return_value=None):
        state = onboarding.run(events, FakeTable(), fa._DETECTORS, now, send_report=sent)
    return state, sent


class TestOnboardingSearch:

    def test_search_finds_old_rule_and_reports_it(self):
        import onboarding
        events, jt = FakeTable(), FakeTable()
        graph = FakeGraph([[_graph_record(**FORWARD_RULE)], [_graph_record("Set-Mailbox", rid="r2")]],
                          statuses=("running", "succeeded"))
        onboarding.start(events, NOW, "full")
        state, sent = _run(events, jt, NOW, graph)
        # First run: history and rules done, the search submitted and still running.
        assert state["step"] == "search" and state["search"]["query_id"] == QID and not sent.called
        body = graph.bodies[0]
        assert "UserLoggedIn" not in body["operationFilters"] and "New-InboxRule" in body["operationFilters"]
        assert body["filterEndDateTime"] == state["history"]["from"]
        later = NOW + timedelta(minutes=5)
        state, sent = _run(events, jt, later, graph)
        s = state["search"]
        assert state["step"] == "done" and s["status"] == "succeeded" and s["records"] == 2 and s["findings"] == 1
        findings = sent.call_args.args[1]
        assert len(findings) == 1 and findings[0]["at"] == "2026-07-01T10:00:00Z"
        assert findings[0]["run_id"] == state["run_id"]

    def test_no_permission_skips_with_a_reason(self):
        import onboarding
        events = FakeTable()
        onboarding.start(events, NOW, "full")
        state, sent = _run(events, FakeTable(), NOW, FakeGraph([[]]), granted=("User.ReadBasic.All",))
        assert state["step"] == "done" and "AuditLogsQuery.Read.All" in state["search"]["skipped"]
        import alerting
        with patch("alerting._deliver", return_value=True) as deliver:
            alerting.send_onboarding_report(state, [], None)
        assert "Older history not searched" in deliver.call_args.args[1]

    def test_failed_search_and_timeout(self):
        import onboarding
        events = FakeTable()
        onboarding.start(events, NOW, "full")
        state, _ = _run(events, FakeTable(), NOW, FakeGraph([[]], statuses=("failed",)))
        state, _ = _run(events, FakeTable(), NOW, FakeGraph([[]], statuses=("failed",)))
        assert state["step"] == "done" and "failed" in state["search"]["skipped"]

        events = FakeTable()
        onboarding.start(events, NOW, "full")
        _run(events, FakeTable(), NOW, FakeGraph([[]], statuses=("running",)))
        state, _ = _run(events, FakeTable(), NOW + timedelta(hours=47), FakeGraph([[]], statuses=("running",)))
        assert state["step"] == "search"
        state, _ = _run(events, FakeTable(), NOW + timedelta(hours=49), FakeGraph([[]], statuses=("running",)))
        assert state["step"] == "done" and "48 hours" in state["search"]["skipped"]

    def test_limit_exceeded_is_reported(self):
        import onboarding
        events = FakeTable()
        onboarding.start(events, NOW, "full")
        graph = FakeGraph([[_graph_record(**FORWARD_RULE)]], statuses=("succeeded",), limit=True)
        state, sent = _run(events, FakeTable(), NOW, graph)      # done at once: one run
        assert state["step"] == "done" and state["search"]["limit_exceeded"] is True
        import alerting
        with patch("alerting._deliver", return_value=True) as deliver:
            alerting.send_onboarding_report(state, sent.call_args.args[1], None)
        assert "record limit" in deliver.call_args.args[1]

    def test_rules_only_scan_does_not_search(self):
        import onboarding
        events = FakeTable()
        onboarding.start(events, NOW, "rules")
        graph = FakeGraph([[]])
        state, _ = _run(events, FakeTable(), NOW, graph)
        assert state["step"] == "done" and graph.bodies == []

    def test_alerted_finding_is_not_counted_again(self):
        import function_app as fa
        import onboarding
        events, jt = FakeTable(), FakeTable()
        record = audit_search.to_record(_graph_record(**FORWARD_RULE))
        finding = fa._DETECTORS[0]([record])[0] if fa._DETECTORS[0]([record]) else None
        assert finding is not None
        journal.record(jt, finding, fa.finding_key(finding), "emailed", now=NOW - timedelta(days=60))
        onboarding.start(events, NOW, "full")
        graph = FakeGraph([[_graph_record(**FORWARD_RULE)]], statuses=("succeeded",))
        state, sent = _run(events, jt, NOW, graph)
        assert state["search"]["records"] == 1 and state["search"]["findings"] == 0
        assert sent.call_args.args[1] == []


# ---------------------------------------------------------------------------
# User page search
# ---------------------------------------------------------------------------

class TestUserSearch:

    def _post(self, body):
        import admin_api
        return admin_api.user_search(_req("POST", "/api/manage/api/usersearch", body, headers=MUTATE))

    def _get(self, qid, user="jane@contoso.com"):
        import admin_api
        return admin_api.user_search(_req("GET", "/api/manage/api/usersearch", params={"id": qid, "user": user}))

    def test_start_poll_and_rows(self, ui_on, token):
        graph = FakeGraph([[_graph_record("MailItemsAccessed", when="2026-11-08T10:00:00", ClientIPAddress="203.0.113.9"),
                            _graph_record("Send", rid="r2", when="2026-11-08T11:00:00")],
                           [_graph_record(rid="r3", when="2026-11-01T09:00:00")]])
        with patch("o365_client.token_manager.granted_graph_roles", return_value=["AuditLogsQuery.Read.All"]), \
                patch("config.http.post", side_effect=graph.post), patch("config.http.get", side_effect=graph.get):
            r = self._post({"user": "Jane@Contoso.com", "days": 30})
            assert r.status_code == 200 and json.loads(r.get_body())["id"] == QID
            assert graph.bodies[0]["userPrincipalNameFilters"] == ["jane@contoso.com"]
            first = json.loads(self._get(QID).get_body())
            assert first["status"] == "running" and "rows" not in first
            done = json.loads(self._get(QID).get_body())
        assert done["status"] == "succeeded" and [x["operation"] for x in done["rows"]] == \
            ["Send", "MailItemsAccessed", "New-InboxRule"]
        assert done["mail_records"] == 2 and done["truncated"] is False
        history = [c for h in ui_on["table"].partition("history").values() for c in json.loads(h["changes"])]
        assert any(c["name"] == "AUDIT_SEARCH" and "jane@contoso.com, last 30 days" in c["new"] for c in history)
        # The user page shows the last search again.
        import admin_api
        page = json.loads(admin_api.user_page(_req("GET", "/api/manage/api/user", params={"user": "jane@contoso.com"})).get_body())
        assert page["search"]["id"] == QID and page["search"]["days"] == 30 and page["search"]["by"] == "admin@contoso.com"

    def test_last_search_expires(self):
        import admin_store
        table = FakeTable()
        admin_store.save_search(table, "jane@contoso.com", QID, 30, "a@contoso.com", NOW - timedelta(days=31))
        assert admin_store.last_search(table, "jane@contoso.com", NOW) is None
        admin_store.save_search(table, "jane@contoso.com", QID, 7, "a@contoso.com", NOW - timedelta(days=1))
        assert admin_store.last_search(table, "jane@contoso.com", NOW)["days"] == 7
        assert admin_store.last_search(table, "bob@contoso.com", NOW) is None and admin_store.last_search(None, "x") is None

    def test_validation_and_permission(self, ui_on, token):
        with patch("o365_client.token_manager.granted_graph_roles", return_value=["AuditLogsQuery.Read.All"]):
            assert self._post({"user": "jane@contoso.com", "days": 5}).status_code == 400
            assert self._post({"user": "not a user", "days": 30}).status_code == 400
            assert self._get("../x").status_code == 400
        with patch("o365_client.token_manager.granted_graph_roles", return_value=["Mail.Send"]):
            r = self._post({"user": "jane@contoso.com", "days": 30})
        assert r.status_code == 403 and "AuditLogsQuery.Read.All" in json.loads(r.get_body())["error"]

    def test_post_needs_the_mutation_header(self, ui_on):
        import admin_api
        r = admin_api.user_search(_req("POST", "/api/manage/api/usersearch", {"user": "jane@contoso.com", "days": 30}))
        assert r.status_code == 403
