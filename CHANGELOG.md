# Changelog

The changes in each release. Versions follow `function/version.py`. The release workflow tags `v<VERSION>`.

## Unreleased

## 1.1.1 (2026-11-24)

- Skip Copilot backend REST mail-read records in session and mail-access checks even when Graph cannot identify the app's owner. The record must identify the Copilot API as the relay. Sign-ins and direct client access still count.
- Session alerts separate observed activity from possible causes. Email and webhook alerts include observation times, elapsed time, client and app details, and both the network provider and organisation when available. Webhooks also summarize related alerts. Alert severity is unchanged.
- Raise dependency minimum versions to address reported vulnerabilities. Pin CI security tools by hash. Keep the dev container on Python 3.12. Include the provenance file with public release archives.
- Document the rulesets on main and release tags.

## 1.1.0 (2026-11-19)

Detection:

- MFA method changes: the alert shows the old and new methods. A change that keeps the same number of methods alerts. A reset to no methods is listed with no email. The learning period is quiet, and 30 days of past sign-ins load once after the update.
- IP reputation moves to proxycheck.io v3. Alerts show the VPN or proxy service, the hostname, and the attacks that proxycheck.io recorded. A proxy is medium, and high with recorded attacks. Cloud hosts show as hosting, not VPN.
- Exchange `SERVICE\` accounts are skipped as service actors.
- An MFA change after a sign-in from a new network of a provider (ASN) that the user signed in from before, from a clean IP, sends no email (a phone on a mobile carrier).
- Webhook alerts name the source network.
- IP lookups go to proxycheck.io in batches of up to 1,000 IPs (100 without a key).

Management UI:

- Overview > Failed sign-ins: 7 days of failed sign-ins from all IPs (password spraying). No alerts.
- Alerts show how long before the alert the event happened, and how long a session has existed.
- A mute that names one alert type, one user, and one network also hides high alerts.
- Opt-in: end the UI session of a blocked or revoked admin (`UI_ACCOUNT_CHECK`). `install.ps1 -UiSessionHours` sets the sign-in length.
- Layout: long user names, the Overview cards, and the Access card.

Security and CI:

- `install.ps1 -HostLogs warnings`: about 85% less log volume (the Functions host logs warnings only).
- bandit in CI. CodeQL, OpenSSF Scorecard, and attested release archives in a public repository.
- Docs: a diagram of the architecture and its controls (docs/SECURITY.md), a comparison with Entra ID P2, revoke timing (continuous access evaluation), cost by tenant size, and the roles needed to install.

## 1.0.0

First version with the update check.
