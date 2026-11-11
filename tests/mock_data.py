"""Shared test fixtures: sample Office 365 audit events and proxycheck.io
responses. Field shapes mirror the real Management Activity API records that
ip_checker / compromise_detector parse.

Audit RecordType reference (see config.LOGIN_RECORD_TYPES):
    9  = AzureActiveDirectoryAccountLogon (legacy / federated path)
    15 = AzureActiveDirectoryStsLogon (modern eSTS sign-in)
    8  = AzureActiveDirectory (directory admin events — NOT a sign-in)
"""

# ---------------------------------------------------------------------------
# Login events
# ---------------------------------------------------------------------------

EVENT_NORMAL_LOGIN = {
    "Id": "a1b2c3d4-e5f6-7890-abcd-000000000001",
    "RecordType": 15,
    "CreationTime": "2024-01-15T10:00:00",
    "Operation": "UserLoggedIn",
    "UserId": "alice.jones@contoso.com",
    "ClientIP": "8.8.8.8",
    "ExtendedProperties": [
        {"Name": "UserAgent", "Value": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
    ],
}

# IP carries a :port to exercise clean_ip's port stripping.
EVENT_VPN_LOGIN = {
    "Id": "a1b2c3d4-e5f6-7890-abcd-000000000002",
    "RecordType": 15,
    "CreationTime": "2024-01-15T10:05:00",
    "Operation": "UserLoggedIn",
    "UserId": "jane.smith@contoso.com",
    "ClientIP": "185.220.101.42:51763",
    "ExtendedProperties": [
        {"Name": "UserAgent", "Value": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"},
    ],
}

EVENT_TOR_LOGIN = {
    "Id": "a1b2c3d4-e5f6-7890-abcd-000000000003",
    "RecordType": 15,
    "CreationTime": "2024-01-15T10:10:00",
    "Operation": "UserLoggedIn",
    "UserId": "bob.wilson@contoso.com",
    "ClientIP": "171.25.193.78",
    "ExtendedProperties": [
        {"Name": "UserAgent", "Value": "Mozilla/5.0 (X11; Linux x86_64)"},
    ],
}

EVENT_PRIVATE_IP_LOGIN = {
    "Id": "a1b2c3d4-e5f6-7890-abcd-000000000004",
    "RecordType": 15,
    "CreationTime": "2024-01-15T10:15:00",
    "Operation": "UserLoggedIn",
    "UserId": "carol.white@contoso.com",
    "ClientIP": "10.0.0.5",
}

# RecordType 9 — must still be treated as a login.
EVENT_FEDERATED_LOGIN = {
    "Id": "a1b2c3d4-e5f6-7890-abcd-000000000005",
    "RecordType": 9,
    "CreationTime": "2024-01-15T10:20:00",
    "Operation": "UserLoggedIn",
    "UserId": "dave.brown@contoso.com",
    "ClientIP": "203.0.113.7",
}

# RecordType 8 — a directory admin event, NOT a sign-in. Must be filtered out.
EVENT_NON_LOGIN = {
    "Id": "a1b2c3d4-e5f6-7890-abcd-000000000006",
    "RecordType": 8,
    "CreationTime": "2024-01-15T10:25:00",
    "Operation": "Add user.",
    "UserId": "admin@contoso.com",
    "ClientIP": "198.51.100.9",
}

# No Id — forces get_event_key to fall back to a content hash.
EVENT_NO_ID = {
    "RecordType": 15,
    "CreationTime": "2024-01-15T11:00:00",
    "Operation": "UserLoggedIn",
    "UserId": "noid.user@contoso.com",
    "ClientIP": "192.0.2.55",
}


# ---------------------------------------------------------------------------
# proxycheck.io responses
# ---------------------------------------------------------------------------
# Keyed by IP -> {ip: data}, matching the shape the batch-POST mock reads as
# `PROXYCHECK_RESPONSES[ip][ip]`. Only suspicious IPs need entries here; the
# mock returns a clean Residential result for anything not listed.

PROXYCHECK_RESPONSES = {
    "185.220.101.42": {
        "185.220.101.42": {
            "proxy": "yes",
            "type": "VPN",
            "risk": 75,
            "provider": "M247",
            "organisation": "NordVPN",
            "city": "Frankfurt",
            "region": "Hesse",
            "country": "Germany",
        }
    },
    "171.25.193.78": {
        "171.25.193.78": {
            "proxy": "yes",
            "type": "TOR",
            "risk": 100,
            "provider": "Tor",
            "organisation": "Tor Exit Node",
            "city": "Amsterdam",
            "region": "North Holland",
            "country": "Netherlands",
        }
    },
}

# Hosting/datacenter IP — proxy "no" but type Hosting, so analyze_ip flags it.
PROXYCHECK_DATACENTER_IP = {
    "54.239.28.85": {
        "proxy": "no",
        "type": "Hosting",
        "risk": 42,
        "provider": "Amazon",
        "organisation": "Amazon.com, Inc.",
        "city": "Ashburn",
        "region": "Virginia",
        "country": "United States",
    }
}

# Clean residential/business IP — not suspicious.
PROXYCHECK_CLEAN_IP = {
    "8.8.8.8": {
        "proxy": "no",
        "type": "Business",
        "risk": 0,
        "provider": "Google",
        "organisation": "Google LLC",
        "city": "Mountain View",
        "region": "California",
        "country": "United States",
    }
}
