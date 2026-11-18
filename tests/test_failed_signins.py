"""Failed sign-in counts for the Overview (password spraying), and the alert delay text.

All users, IPs, and networks are made up (documentation ranges).
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import failed_signins as fs
from tests.fakes import FakeTable

NOW = datetime(2026, 11, 18, 12, 0, tzinfo=timezone.utc)
HOSTING = {"is_suspicious": True, "asn": "AS64500", "org": "Example Hosting"}
HOME = {"is_suspicious": False, "asn": "AS64501", "org": "Example Broadband"}


def _failed(user, when, code="50126", op="UserLoginFailed"):
    return {"Operation": op, "UserId": user, "ErrorNumber": code, "CreationTime": when.strftime("%Y-%m-%dT%H:%M:%S")}


def test_entry_counts_only_wrong_password_and_account_codes():
    t = NOW - timedelta(hours=1)
    assert fs.entry(_failed("a@contoso.com", t), "203.0.113.1", HOME)["code"] == "50126"
    assert fs.entry(_failed("a@contoso.com", t, "50053"), "203.0.113.1", HOME)["code"] == "50053"
    assert fs.entry(_failed("a@contoso.com", t, "50076"), "203.0.113.1", HOME) is None      # correct password, MFA
    assert fs.entry(_failed("a@contoso.com", t, op="UserLoggedIn"), "203.0.113.1", HOME) is None


def test_spray_from_many_ips_and_residential_ips_counts():
    events = FakeTable()
    entries = [fs.entry(_failed("victim@contoso.com", NOW - timedelta(days=d, hours=1), "50053"),
                        f"2001:db8:{d}::1", HOSTING) for d in range(4)]
    entries.append(fs.entry(_failed("victim@contoso.com", NOW - timedelta(hours=2)), "198.51.100.7", HOME))
    entries.append(fs.entry(_failed("other@contoso.com", NOW - timedelta(hours=3), "50034"), "2001:db8:1::1", HOSTING))
    fs.record(events, entries, NOW)

    s = fs.summary(events, NOW)
    assert s["total"] == 6 and s["flagged"] == 5 and s["users"] == 2 and s["ips"] == 5
    assert s["codes"] == {"50053": 4, "50126": 1, "50034": 1}
    top = s["top_users"][0]
    assert top["user"] == "victim@contoso.com" and top["n"] == 5 and top["ips"] == 5 and top["nets"] == 2
    assert s["top_nets"][0] == {"asn": "AS64500", "name": "Example Hosting", "n": 5, "flagged": 5, "users": 2}
    assert [d["n"] for d in s["per_day"]] == [0, 0, 0, 1, 1, 1, 3]


def test_full_row_stays_under_the_property_limit():
    # Every limit at its maximum: long names, many IPs per user, many networks.
    events = FakeTable()
    entries = []
    for u in range(400):
        user = f"{'a-very-long-mailbox-name-' * 3}{u:03d}@subsidiary.contoso.com"[:100]
        for k in range(12):
            entries.append(fs.entry(_failed(user, NOW - timedelta(minutes=u + k), "50053"), f"2001:db8:{u:x}::{k:x}",
                                    {"is_suspicious": True, "asn": f"AS{64500 + (u * 12 + k) % 60}",
                                     "org": "Example Hosting With A Long Network Name " * 2}))
    for i in range(0, len(entries), 200):              # several runs
        fs.record(events, entries[i:i + 200], NOW)
    row = events.get_entity(partition_key="system", row_key=f"failedsignins-{NOW:%Y-%m-%d}")
    assert len(row["data"]) <= fs.MAX_CHARS
    s = fs.summary(events, NOW)
    assert s["total"] == 4800 and s["users"] == fs.USER_HASHES and s["users_more"]
    assert s["ips"] == fs.IPS and s["ips_more"]


def test_account_count_is_distinct_users():
    events = FakeTable()
    entries = [fs.entry(_failed(f"user{u}@contoso.com", NOW - timedelta(minutes=k)), f"2001:db8::{k:x}", HOME)
               for u in range(60) for k in range(25)]
    fs.record(events, entries, NOW)
    s = fs.summary(events, NOW)
    assert s["users"] == 60 and not s["users_more"] and s["total"] == 1500


def test_a_failed_run_does_not_count_twice():
    from function_app import _run_login_check
    events, cache = FakeTable(), FakeTable()
    rec = dict(_failed("victim@contoso.com", NOW - timedelta(minutes=5)), Id="r1", ClientIP="89.160.20.112")
    answers = {"89.160.20.112": {"proxy": "no", "type": "Residential", "risk": 0, "asn": "AS64501"}}
    with patch("function_app.check_ips_batch", return_value=answers), \
            patch("function_app._handle_country_anomalies", side_effect=RuntimeError("storage down")):
        try:
            _run_login_check(events, cache, set(), [rec])
        except RuntimeError:
            pass
    assert fs.summary(events)["total"] == 0            # not marked: the next run counts it
    with patch("function_app.check_ips_batch", return_value=answers), \
            patch("function_app._handle_country_anomalies"):
        _run_login_check(events, cache, set(), [rec])
    assert fs.summary(events)["total"] == 1


def test_old_days_are_not_counted_or_shown():
    events = FakeTable()
    fs.record(events, [fs.entry(_failed("a@contoso.com", NOW - timedelta(days=20)), "203.0.113.1", HOME)], NOW)
    assert fs.summary(events, NOW)["total"] == 0


def test_login_check_records_flagged_and_clean_failures():
    from function_app import _run_login_check
    events, cache = FakeTable(), FakeTable()
    recs = [dict(_failed("victim@contoso.com", NOW - timedelta(minutes=5)), Id="r1", ClientIP="81.2.69.160"),
            dict(_failed("victim@contoso.com", NOW - timedelta(minutes=4)), Id="r2", ClientIP="89.160.20.112")]
    answers = {"81.2.69.160": {"proxy": "no", "type": "Hosting", "risk": 33, "asn": "AS64500"},
               "89.160.20.112": {"proxy": "no", "type": "Residential", "risk": 0, "asn": "AS64501"}}
    with patch("function_app.check_ips_batch", return_value=answers), \
            patch("function_app.send_suspicious_login_alert", return_value=True), \
            patch("function_app._handle_country_anomalies"):
        _run_login_check(events, cache, set(), recs)
    s = fs.summary(events)
    assert s["total"] == 2 and s["flagged"] == 1


def test_alert_shows_delay_and_session_age():
    import alerting
    when = datetime.now(timezone.utc) - timedelta(minutes=47)
    event = {"UserId": "jane@contoso.com", "CreationTime": when.strftime("%Y-%m-%dT%H:%M:%S"),
             "Operation": "UserLoggedIn"}
    analysis = {"is_suspicious": True, "confidence": "medium", "flags": ["vpn"], "risk_score": 50,
                "org": "Example VPN", "city": "Stockholm", "country": "Sweden"}
    sent = []
    with patch("alerting._send_email", side_effect=lambda s, b: sent.append(b) or True):
        alerting.send_suspicious_login_alert(event, "203.0.113.9", analysis)
        alerting.send_suspicious_login_alert({**event, "Operation": "UserLoginFailed", "ErrorNumber": "50126"},
                                             "203.0.113.9", analysis)
    assert "47 minutes before this alert" in sent[0] or "48 minutes before this alert" in sent[0]
    assert "has had a session for" in sent[0]
    assert "has had a session" not in sent[1] and "before this alert" in sent[1]


def test_age_text():
    import alerting
    now = datetime(2026, 11, 18, 12, 0, tzinfo=timezone.utc)
    assert alerting._age_text("2026-11-18T11:59:40", now) == "less than 1 minute"
    assert alerting._age_text("2026-11-18T11:13:00", now) == "47 minutes"
    assert alerting._age_text("2026-11-18T09:30:00", now) == "2 hours 30 minutes"
    assert alerting._age_text("2026-11-15T12:00:00", now) == "3 days"
    assert alerting._age_text("2026-11-18T12:30:00", now) == ""
    assert alerting._age_text("not a time", now) == ""
