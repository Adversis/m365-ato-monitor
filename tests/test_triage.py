"""Alert triage (Open, Investigating, Benign, Resolved), the triage filter, and pages in the management UI."""

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import journal
from tests.fakes import FakeTable
from tests.test_admin_ui import MUTATE, _req

NOW = datetime.now(timezone.utc)


def _seed(jt, n=5, status="emailed"):
    for i in range(n):
        journal.record(jt, {"type": "inbox_rule", "severity": "high" if i % 2 else "medium",
                            "user": f"u{i}@contoso.com", "description": f"rule {i}",
                            "event": {"CreationTime": (NOW - timedelta(hours=i)).strftime("%Y-%m-%dT%H:%M:%S")}},
                       f"k{i}", status)


def _findings(**params):
    import admin_api
    resp = admin_api.findings(_req("GET", "/api/manage/api/findings", params={"days": "7", **params}))
    return resp.status_code, json.loads(resp.get_body())


def _triage(body, headers=MUTATE):
    import admin_api
    resp = admin_api.triage(_req("POST", "/api/manage/api/triage", body, headers=headers))
    return resp.status_code, json.loads(resp.get_body())


class TestTriage:

    def test_set_filter_and_history(self, ui_on):
        jt = FakeTable()
        _seed(jt)
        with patch("journal.table_client", return_value=jt):
            _, data = _findings()
            row = next(r for r in data["findings"] if r["key"] == "k2")
            assert row["triage"] == "" and data["summary"]["by_triage"] == {"open": 5}
            code, body = _triage({"id": row["id"], "state": "benign", "note": "Known supplier rule"})
            assert code == 200 and body["finding"]["triage"] == "benign"
            assert body["finding"]["triage_by"] == "admin@contoso.com"
            _, data = _findings(triage="open")
            assert "k2" not in [r["key"] for r in data["findings"]] and data["count"] == 4
            _, data = _findings(triage="benign")
            assert [r["key"] for r in data["findings"]] == ["k2"]
            assert data["findings"][0]["triage_note"] == "Known supplier rule"
            assert data["summary"]["by_triage"] == {"open": 4, "benign": 1}
        history = [json.loads(r["changes"]) for r in ui_on["table"].partition("history").values()]
        assert history[0][0]["new"] == "Benign: Known supplier rule" and history[0][0]["old"] == "Open"
        ui_on["email"].assert_not_called()           # a triage change does not weaken detection: no email

    def test_refused_requests(self, ui_on):
        jt = FakeTable()
        _seed(jt, 1)
        with patch("journal.table_client", return_value=jt):
            row = _findings()[1]["findings"][0]
            assert _triage({"id": row["id"], "state": "benign"}, headers={})[0] == 403        # no CSRF header
            assert _triage({"id": row["id"], "state": "gone"})[0] == 400
            assert _triage({"id": row["id"], "state": "benign", "note": "a\nb"})[0] == 400
            assert _triage({"id": "u-x|' or 1 eq 1", "state": "benign"})[0] == 404
            assert _triage({"id": "u-" + "0" * 32 + "|0000000000000-000000000000", "state": "benign"})[0] == 404
            assert _findings(triage="nope")[0] == 400

    def test_install_rows_cannot_be_triaged(self, ui_on):
        jt = FakeTable()
        _seed(jt, 1, status="install")
        (pk, rk), = [k for k in jt.rows if k[0].startswith("u-")]
        with patch("journal.table_client", return_value=jt):
            assert _triage({"id": f"{pk}|{rk}", "state": "benign"})[0] == 404


class TestPages:

    def test_findings_pages(self, ui_on):
        jt = FakeTable()
        _seed(jt, 25)
        with patch("journal.table_client", return_value=jt):
            _, p1 = _findings(size="10")
            _, p3 = _findings(size="10", page="3")
        assert len(p1["findings"]) == 10 and p1["count"] == 25 and p1["findings"][0]["key"] == "k0"
        assert [r["key"] for r in p3["findings"]] == [f"k{i}" for i in range(20, 25)]

    def test_history_pages(self, ui_on):
        import admin_api
        import admin_store
        for i in range(15):
            admin_store.record_history(ui_on["table"], "admin@contoso.com", [{"label": f"c{i}", "old": "", "new": "x"}],
                                       NOW - timedelta(minutes=i))
        resp = admin_api.history(_req("GET", "/api/manage/api/history", params={"size": "10"}))
        data = json.loads(resp.get_body())
        assert len(data["history"]) == 10 and data["more"] and data["history"][0]["changes"][0]["label"] == "c0"
        data = json.loads(admin_api.history(_req("GET", "/api/manage/api/history",
                                                 params={"size": "10", "page": "2"})).get_body())
        assert len(data["history"]) == 5 and not data["more"]
