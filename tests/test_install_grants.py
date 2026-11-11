"""Permissions that install.ps1 grants to the monitor app: journal and Starting state report, no alert email."""

import os
import pathlib
import re
from datetime import datetime, timezone
from unittest.mock import patch

import config
import journal
from compromise_detector import INSTALL_ROLES, detect_suspicious_oauth_consents, install_grant
from tests.fakes import FakeTable

APP_ID = "11111111-2222-3333-4444-555555555555"
SP_ID = "66666666-7777-8888-9999-000000000000"
NOW = datetime(2026, 11, 9, 17, 0, tzinfo=timezone.utc)


GRAPH_SP = "ce7199b4-8f52-46f3-b54b-4fd81de961e2"


def grant(role="Mail.Send", app_id=APP_ID, sp_id=SP_ID, app_name="m365-ato-monitor"):
    """"Add app role assignment to service principal." in the Management Activity API shape.

    Shape from real records (Splunk attack_data T1098.003 o365_admin_consent): the app that
    gets the role is in ModifiedProperties ServicePrincipal.*; Target is Microsoft Graph.
    """
    return {
        "Id": f"grant-{role}-{app_id}-{sp_id}", "CreationTime": "2026-11-09T16:40:12",
        "Operation": "Add app role assignment to service principal.", "RecordType": 8,
        "ResultStatus": "Success", "Workload": "AzureActiveDirectory", "UserId": "root@contoso.onmicrosoft.com",
        "ObjectId": "00000003-0000-0000-c000-000000000000;https://graph.microsoft.com",
        "ModifiedProperties": [
            {"Name": "AppRole.Id", "NewValue": "b633e1c5-b582-4048-a93e-9f11b44c7e96", "OldValue": ""},
            {"Name": "AppRole.Value", "NewValue": role, "OldValue": ""},
            {"Name": "ServicePrincipal.ObjectID", "NewValue": sp_id, "OldValue": ""},
            {"Name": "ServicePrincipal.DisplayName", "NewValue": app_name, "OldValue": ""},
            {"Name": "ServicePrincipal.AppId", "NewValue": app_id, "OldValue": ""},
            {"Name": "ServicePrincipal.Name", "NewValue": app_id, "OldValue": ""},
            {"Name": "TargetId.ServicePrincipalNames", "NewValue": "00000003-0000-0000-c000-000000000000", "OldValue": ""},
        ],
        "Target": [{"ID": f"ServicePrincipal_{GRAPH_SP}", "Type": 2}, {"ID": GRAPH_SP, "Type": 2},
                   {"ID": "ServicePrincipal", "Type": 2}, {"ID": "Microsoft Graph", "Type": 1},
                   {"ID": "00000003-0000-0000-c000-000000000000", "Type": 2}],
    }


def finding(event):
    found = detect_suspicious_oauth_consents([event])
    assert len(found) == 1
    return found[0]


class TestInstallGrant:

    def setup_method(self):
        self._patch = patch.multiple(config, CLIENT_ID=APP_ID, MONITOR_SP_ID=SP_ID)
        self._patch.start()
        # An install with tenant-wide Mail.Send and the response permissions: every role is expected.
        self._env = patch.dict(os.environ, {"MAIL_SEND_SCOPE": "tenant", "RESPONSE_PERMISSIONS": "true"})
        self._env.start()

    def teardown_method(self):
        self._env.stop()
        self._patch.stop()

    def test_mail_send_alerts_when_the_install_limits_it_to_the_alert_mailbox(self):
        """With -MailSendScope mailbox, install.ps1 grants no Graph Mail.Send: such a grant is not the installer."""
        with patch.dict(os.environ, {"MAIL_SEND_SCOPE": "mailbox"}):
            assert not install_grant(finding(grant("Mail.Send")))

    def test_response_roles_alert_when_the_install_has_none(self):
        with patch.dict(os.environ, {"RESPONSE_PERMISSIONS": "false"}):
            assert not install_grant(finding(grant("MailboxSettings.ReadWrite")))

    def test_exchange_mail_send_role_for_the_monitor_app(self):
        """-MailSendScope mailbox: New-ManagementRoleAssignment -App <monitor> -Role 'Application Mail.Send'."""
        from compromise_detector import detect_admin_roles

        def assignment(app, role="Application Mail.Send", scope="m365-ato-monitor-senders scope", **extra):
            params = {"Name": "m365-ato-monitor-senders Mail.Send", "App": app, "Role": role, **extra}
            if scope is not None:
                params["CustomResourceScope"] = scope
            event = {"Id": f"ra-{app}-{role}-{scope}", "CreationTime": "2026-11-09T16:41:00", "RecordType": 1,
                     "Workload": "Exchange", "Operation": "New-ManagementRoleAssignment", "ResultStatus": "True",
                     "UserId": "root@contoso.onmicrosoft.com",
                     "Parameters": [{"Name": k, "Value": v} for k, v in params.items()]}
            found = detect_admin_roles([event])
            assert len(found) == 1
            return found[0]

        mailbox = {"MAIL_SEND_SCOPE": "mailbox", "MAIL_SEND_GROUP": "m365-ato-monitor-senders"}
        with patch.dict(os.environ, mailbox):
            assert install_grant(assignment(SP_ID))
            assert install_grant(assignment(SP_ID, scope="M365-ATO-MONITOR-SENDERS SCOPE"))
            assert not install_grant(assignment("aaaaaaaa-0000-0000-0000-000000000000"))   # another app
            assert not install_grant(assignment(SP_ID, "Application Mail.ReadWrite"))        # another role
            # The same role for more mailboxes: no scope, another scope, or another scope type.
            assert not install_grant(assignment(SP_ID, scope=None))
            assert not install_grant(assignment(SP_ID, scope=""))
            assert not install_grant(assignment(SP_ID, scope="All mailboxes"))
            assert not install_grant(assignment(SP_ID, RecipientAdministrativeUnitScope="au-1"))
        with patch.dict(os.environ, {**mailbox, "MAIL_SEND_GROUP": ""}):
            assert not install_grant(assignment(SP_ID))                                       # group unknown
        assert not install_grant(assignment(SP_ID))                                           # tenant scope

    def test_grant_to_the_monitor_app(self):
        f = finding(grant("Mail.Send"))
        assert "'m365-ato-monitor'" in f["description"]
        assert install_grant(f)
        assert install_grant(finding(grant("MailboxSettings.ReadWrite", app_id="x")))     # by the SP object ID
        assert install_grant(finding(grant("Mail.Send", sp_id="y")))                      # by the app ID

    def test_display_name_alone_is_not_enough(self):
        # Anyone can name an app "m365-ato-monitor". Only the IDs count.
        other = "aaaaaaaa-0000-0000-0000-000000000000"
        assert not install_grant(finding(grant("Mail.Send", app_id=other, sp_id=other)))

    def test_other_risky_scope_still_alerts(self):
        assert not install_grant(finding(grant("Mail.ReadWrite")))
        assert not install_grant(finding(grant("full_access_as_app")))

    def test_needs_the_app_ids(self):
        with patch.multiple(config, CLIENT_ID="", MONITOR_SP_ID=""):
            assert not install_grant(finding(grant()))
        assert not install_grant({"type": "inbox_rule", "event": grant()})


def test_install_roles_match_install_ps1():
    """Every role that install.ps1 grants is in INSTALL_ROLES (and nothing else is)."""
    text = (pathlib.Path(__file__).parent.parent / "install.ps1").read_text(encoding="utf-8")
    roles = set()
    for name in ("GraphRolesBase", "GraphRolesMail", "GraphRolesResponse", "GraphRolesAccess"):
        m = re.search(rf"\$script:{name} = @\(([^)]*)\)", text)
        if m:
            roles |= set(re.findall(r"'([A-Za-z.]+)'", m.group(1)))
    roles.add("ActivityFeed.Read")
    assert roles == set(INSTALL_ROLES)


class TestMonitorRun:

    def test_no_email_no_journal_row_and_processed(self):
        import function_app as fa
        events, jt = FakeTable(), FakeTable()
        processed = set()
        with patch.multiple(config, CLIENT_ID=APP_ID, MONITOR_SP_ID=SP_ID), \
                patch("journal.table_client", return_value=jt), \
                patch("function_app.send_compromise_alert", return_value=True) as send, \
                patch("function_app.check_ips_batch", return_value={}):
            fa._run_compromise_check(events, FakeTable(), processed, [grant("Mail.Send")])
        assert send.call_count == 0
        assert jt.rows == {}                                   # no row in any view
        assert len(processed) == 1 and any(k.startswith("oauth_consent_") for k in events.partition("events"))

    def test_older_install_rows_are_hidden(self):
        jt = FakeTable()
        journal.record(jt, finding(grant("Mail.Send")), "k1", "install")
        journal.record(jt, {"type": "inbox_rule", "severity": "high", "user": "a@contoso.com", "description": "d",
                            "event": {"CreationTime": "2026-11-09T16:40:12"}}, "k2", "emailed")
        rows, totals = journal.window(jt, journal.ANY_TIME)
        assert [r["status"] for r in rows] == ["emailed"] and totals["total"] == 1
        assert journal.for_user(jt, "root@contoso.onmicrosoft.com", journal.ANY_TIME) == []

    def test_other_grant_to_the_monitor_app_alerts(self):
        import function_app as fa
        with patch.multiple(config, CLIENT_ID=APP_ID, MONITOR_SP_ID=SP_ID), \
                patch("journal.table_client", return_value=FakeTable()), \
                patch("function_app.send_compromise_alert", return_value=True) as send, \
                patch("function_app.check_ips_batch", return_value={}):
            fa._run_compromise_check(FakeTable(), FakeTable(), set(), [grant("Mail.ReadWrite")])
        assert send.call_count == 1


class TestGrantFromAnEarlierRun:
    """A grant that the current choices do not expect, from an install.ps1 run with other choices."""

    def setup_method(self):
        self._patch = patch.multiple(config, CLIENT_ID=APP_ID, MONITOR_SP_ID=SP_ID)
        self._patch.start()

    def teardown_method(self):
        self._patch.stop()

    def _check(self, runs, role="Mail.Send", actor="root@contoso.onmicrosoft.com"):
        event = grant(role)
        event["UserId"] = actor
        env = {"MAIL_SEND_SCOPE": "mailbox", "RESPONSE_PERMISSIONS": "true", "INSTALL_GRANTS": runs}
        with patch.dict(os.environ, env):
            return install_grant(finding(event))

    def test_mail_send_from_a_tenant_scope_run_before_the_mailbox_scope(self):
        assert not self._check("")                                                   # current choices only
        assert self._check("2026-11-09T16:52:00Z;root@contoso.onmicrosoft.com;Mail.Send,User.ReadBasic.All")

    def test_older_entries_and_case(self):
        runs = ("2026-11-10T09:00:00Z;root@contoso.onmicrosoft.com;MailboxSettings.ReadWrite/"
                "2026-11-09T16:45:00Z;ROOT@contoso.onmicrosoft.com;mail.send")
        assert self._check(runs)

    def test_needs_the_same_account_roles_and_time(self):
        assert not self._check("2026-11-09T16:52:00Z;someone@contoso.onmicrosoft.com;Mail.Send")   # account
        assert not self._check("2026-11-09T16:52:00Z;root@contoso.onmicrosoft.com;User.Read.All")   # role
        assert not self._check("2026-11-09T19:00:00Z;root@contoso.onmicrosoft.com;Mail.Send")       # 2 h later
        assert not self._check("2026-11-09T16:20:00Z;root@contoso.onmicrosoft.com;Mail.Send")       # before
        assert not self._check("2026-11-09T16:52:00Z;root@contoso.onmicrosoft.com;Mail.Send",
                               role="Mail.ReadWrite")                                                 # other scope

    def test_bad_setting_is_ignored(self):
        for runs in ("garbage", "x;y", "not-a-date;root@contoso.onmicrosoft.com;Mail.Send", ";;", "/"):
            assert not self._check(runs)
