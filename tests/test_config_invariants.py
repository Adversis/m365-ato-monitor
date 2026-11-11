"""Guards for cadence / config invariants that aren't covered elsewhere.

A careless edit to the timer cron or LOOKBACK_MINUTES should fail here rather
than silently change behavior in production.
"""

from unittest.mock import patch

import config


def _timer_schedules() -> dict:
    """Map each timer-triggered function name to its cron schedule."""
    import function_app as fa
    schedules = {}
    for f in fa.app.get_functions():
        for b in f.get_bindings():
            d = b.get_dict_repr()
            if d.get("type") == "timerTrigger":
                schedules[f.get_function_name()] = d.get("schedule")
    return schedules


def test_main_monitor_runs_every_two_minutes():
    assert _timer_schedules().get("audit_log_monitor") == "0 */2 * * * *"


def test_lookback_below_dedup_window():
    # Events re-fetched within LOOKBACK_MINUTES (after a proxycheck/sendMail
    # failure) must still be recognised as already-processed by the dedup query,
    # or they would re-alert once they age past the dedup window.
    assert 0 < config.LOOKBACK_MINUTES < config.DEDUP_WINDOW_MINUTES


def test_lookback_in_reasonable_range():
    assert 1 <= config.LOOKBACK_MINUTES <= 60


def test_login_record_types_cover_both_signin_paths():
    # 9 = legacy/federated AccountLogon, 15 = modern eSTS StsLogon.
    assert {9, 15} <= config.LOGIN_RECORD_TYPES


def test_login_alert_threshold_low_emails_all_suspicious():
    with patch.object(config, "LOGIN_ALERT_CONFIDENCE", "low"):
        assert config.should_email_login("low")
        assert config.should_email_login("medium")
        assert config.should_email_login("high")


def test_login_alert_threshold_high_emails_high_only():
    with patch.object(config, "LOGIN_ALERT_CONFIDENCE", "high"):
        assert config.should_email_login("high")
        assert not config.should_email_login("medium")
        assert not config.should_email_login("low")


def test_login_alert_threshold_off_disables_all():
    with patch.object(config, "LOGIN_ALERT_CONFIDENCE", "off"):
        assert not config.should_email_login("high")
        assert not config.should_email_login("low")


def test_login_alert_unknown_threshold_fails_open_to_low():
    with patch.object(config, "LOGIN_ALERT_CONFIDENCE", "bogus"):
        assert config.should_email_login("low")


def test_int_env_falls_back_on_bad_value(monkeypatch):
    # A typo in a Portal-editable int setting must not crash import.
    monkeypatch.setenv("BOGUS_INT", "60m")
    assert config._int_env("BOGUS_INT", 8) == 8


def test_int_env_clamps_to_minimum(monkeypatch):
    monkeypatch.setenv("BOGUS_INT", "-5")
    assert config._int_env("BOGUS_INT", 8, minimum=0) == 0


def test_int_env_parses_valid(monkeypatch):
    monkeypatch.setenv("BOGUS_INT", "12")
    assert config._int_env("BOGUS_INT", 8) == 12


def test_catchup_within_dedup_window():
    # A catch-up fetch re-lists content up to MAX_CATCHUP_MINUTES back. Dedup
    # must still know every event processed in that span, or it re-alerts.
    assert config.MAX_CATCHUP_MINUTES <= config.DEDUP_WINDOW_MINUTES


def test_lookback_clamped_to_range(monkeypatch):
    monkeypatch.setenv("BOGUS_INT", "1440")
    assert config._int_env("BOGUS_INT", 8, minimum=3, maximum=60) == 60


def test_invalid_alert_mode_falls_back(monkeypatch):
    import importlib
    monkeypatch.setenv("LOGIN_ALERT_MODE", "batch")
    try:
        reloaded = importlib.reload(config)
        assert reloaded.LOGIN_ALERT_MODE == "immediate"
    finally:
        monkeypatch.delenv("LOGIN_ALERT_MODE")
        importlib.reload(config)


def test_rollup_weights_event_totals_by_itemcount():
    # Without the weight, sampled "Login check:" traces under-count the total.
    from insights_client import _MONTHLY_KQL
    assert "sumif(ev * itemCount" in _MONTHLY_KQL


def test_traces_not_sampled():
    import json
    import pathlib
    host = json.loads((pathlib.Path(config.__file__).parent / "host.json").read_text())
    excluded = host["logging"]["applicationInsights"]["samplingSettings"]["excludedTypes"]
    assert "Trace" in excluded.split(";")
