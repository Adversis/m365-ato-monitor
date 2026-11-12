"""Inbox rule text and verification alerts for unresolved X.500 recipients."""

import compromise_detector as cd
import mailbox_rules

JANE = ("/o=ExchangeLabs/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/"
        "cn=0a1b2c3d4e5f60718293a4b5c6d7e8f9-jane")
SAM = ("/o=ExchangeLabs/ou=Exchange Administrative Group (FYDIBOHF23SPDLT)/cn=Recipients/"
          "cn=f0e1d2c3b4a5968778695a4b3c2d1e0f-sam")


def _rule(name, actions, conditions=None, exceptions=None):
    return {"id": "r1", "displayName": name, "isEnabled": True, "actions": actions,
            "conditions": conditions or {}, "exceptions": exceptions or {}}


def _to(*addresses):
    return [{"emailAddress": {"address": a, "name": a}} for a in addresses]


class TestDirectoryRecipients:

    def test_short_address(self):
        assert cd.short_address(JANE) == "jane (directory)"
        assert cd.short_address("EX:" + SAM) == "sam (directory)"
        assert cd.short_address("bob@contoso.com") == "bob@contoso.com"
        assert cd.is_directory_address(JANE) and not cd.is_directory_address("Jane Smith")

    def test_directory_recipients_need_verification(self):
        rule = _rule("Northwind Supply, Inc.", {"redirectTo": _to(JANE, SAM)},
                     {"fromAddresses": _to("orders@supplier.example")})
        severity, reasons = mailbox_rules.assess(rule, "jane@contoso.com")
        assert severity == "medium" and "unverified directory recipients" in reasons[0]
        s = mailbox_rules.summarize(rule, "jane@contoso.com")
        assert s["actions"] == "redirect to jane (directory), sam (directory)"
        assert s["conditions"] == "from orders@supplier.example"

    def test_external_smtp_still_high(self):
        rule = _rule("x", {"redirectTo": _to(JANE, "drop@evil.com")})
        severity, reasons = mailbox_rules.assess(rule, "jane@contoso.com")
        assert severity == "high" and "redirects externally to drop@evil.com" in reasons

    def test_audit_record_with_x500_target(self):
        params = {"Name": "Northwind", "RedirectTo": f"{JANE};{SAM}"}
        assert cd._cmdlet_rule_indicators(params, "contoso.com") == []  # no proof of an external destination
        assert "unverified directory recipients" in cd._directory_rule_indicators(params)[0]
        assert cd._cmdlet_rule_indicators({"RedirectTo": "Jane Smith"}, "contoso.com")   # a name: cannot tell


class TestRuleText:

    def test_conditions_and_exceptions(self):
        rule = _rule("..", {"moveToFolder": "AAMkAD", "markAsRead": True},
                     {"subjectContains": ["invoice", "payment"], "hasAttachments": True},
                     {"senderContains": ["boss"]})
        s = mailbox_rules.summarize(rule, "jane@contoso.com")
        assert s["actions"] == "move to a folder; mark as read"
        assert s["conditions"] == "subject contains 'invoice', 'payment'; has attachments; except sender contains 'boss'"
        assert s["severity"] == "medium" and "no letters or digits" in s["reasons"][0]

    def test_unknown_condition_key_is_readable(self):
        assert mailbox_rules.describe_conditions({"isEncrypted": True, "importance": "high"}) == \
            "is encrypted; importance high"

    def test_cmdlet_alert_says_what_the_rule_does(self):
        event = {"Id": "e1", "Operation": "New-InboxRule", "UserId": "jane@contoso.com", "ClientIP": "203.0.113.4",
                 "Parameters": [{"Name": "Name", "Value": ".."}, {"Name": "MoveToFolder", "Value": "Archive"},
                                {"Name": "MarkAsRead", "Value": "True"},
                                {"Name": "SubjectContainsWords", "Value": "invoice;payment"},
                                {"Name": "From", "Value": "billing@supplier.com"}]}
        (f,) = cd.detect_suspicious_inbox_rules([event])
        assert "no letters or digits" in f["description"]
        assert ("Actions: move to Archive; mark as read. Conditions: from billing@supplier.com; "
                "subject contains 'invoice', 'payment'.") in f["description"]
