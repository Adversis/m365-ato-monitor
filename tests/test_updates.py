"""The daily update check: GitHub's latest release against version.py. Notify only."""

import re
from unittest.mock import MagicMock, patch

import pytest

import config
import updates
from tests.fakes import FakeTable
from version import VERSION


def _answer(status=200, **data):
    r = MagicMock(status_code=status)
    r.json.return_value = data
    return r


@pytest.fixture
def github():
    with patch.object(config, "UPDATE_CHECK", True), patch.object(config, "UPDATE_REPO", "owner/repo"), \
            patch("config.http") as http:
        yield http


def test_version_is_semver():
    assert re.fullmatch(r"\d+\.\d+\.\d+", VERSION) and updates.parse(VERSION)


@pytest.mark.parametrize("text,expected", [("v1.2.3", (1, 2, 3)), ("10.0.1", (10, 0, 1)), ("v1.2", None),
                                           ("v1.2.3-rc1", None), ("", None), (None, None)])
def test_parse(text, expected):
    assert updates.parse(text) == expected


def test_newer_release(github):
    major = updates.parse(VERSION)[0]
    github.get.return_value = _answer(tag_name=f"v{major + 1}.0.0", html_url="https://github.com/owner/repo/releases/x",
                                      published_at="2026-11-01T00:00:00Z")
    table = FakeTable()
    s = updates.check(table)
    assert s["newer"] and s["latest"] == f"{major + 1}.0.0" and s["url"].endswith("/releases/x")
    assert github.get.call_args.args[0] == "https://api.github.com/repos/owner/repo/releases/latest"
    assert updates.status(table)["newer"]                                    # kept for the UI and the report


def test_same_or_older_release(github):
    github.get.return_value = _answer(tag_name=f"v{VERSION}", html_url="https://github.com/owner/repo/r")
    assert not updates.check(FakeTable())["newer"]
    github.get.return_value = _answer(tag_name="v0.0.1", html_url="https://github.com/owner/repo/r")
    assert not updates.check(FakeTable())["newer"]


def test_link_must_point_to_the_repository(github):
    github.get.return_value = _answer(tag_name="v99.0.0", html_url="https://evil.example/owner/repo")
    assert updates.check(FakeTable())["url"] == ""


@pytest.mark.parametrize("answer,error", [
    (_answer(404), "no public release found"),                       # a private repository
    (_answer(403), "GitHub answered HTTP 403"),
    (_answer(tag_name="nightly"), "the latest release has no version number"),
    (_answer(tag_name="v99.0.0", prerelease=True), "the latest release has no version number"),
])
def test_errors_keep_the_last_answer(github, answer, error):
    table = FakeTable()
    github.get.return_value = _answer(tag_name="v99.0.0", html_url="https://github.com/owner/repo/r")
    updates.check(table)
    github.get.return_value = answer
    s = updates.check(table)
    assert s["error"] == error and s["latest"] == "99.0.0" and s["newer"]


def test_off_hides_an_old_answer(github):
    github.get.return_value = _answer(tag_name="v99.0.0", html_url="https://github.com/owner/repo/r")
    table = FakeTable()
    assert updates.check(table)["newer"]
    with patch.object(config, "UPDATE_CHECK", False):
        assert not updates.status(table)["newer"]


def test_network_error(github):
    github.get.side_effect = OSError("down")
    assert updates.check(FakeTable())["error"].startswith("no answer from GitHub")


def test_off_or_bad_repo_makes_no_request(github):
    with patch.object(config, "UPDATE_CHECK", False):
        assert updates.check(FakeTable())["enabled"] is False
    with patch.object(config, "UPDATE_REPO", "../../evil"):
        updates.check(FakeTable())
    assert github.get.call_count == 0


def test_weekly_report_says_update_available():
    import alerting
    from datetime import datetime, timezone
    health = {"last_content": datetime.now(timezone.utc), "queues": {}, "ip_lookups": {},
              "update": {"version": "1.0.0", "latest": "1.1.0", "newer": True,
                         "url": "https://github.com/owner/repo/releases/tag/v1.1.0"}}
    with patch("alerting._deliver", return_value=True) as deliver:
        alerting.send_weekly_report({"runs": 1, "total_events": 1}, [], health)
    body = deliver.call_args.args[1]
    assert "Update available: version 1.1.0" in body and "./install.ps1 -Update" in body and "Version 1.0.0" in body
