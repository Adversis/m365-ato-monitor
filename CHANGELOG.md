# Changelog

The changes in each release. Versions follow `function/version.py`. The release workflow tags `v<VERSION>`.

## Unreleased

Detection:

- MFA method changes: the alert shows the old and new methods. A change that keeps the same number of methods alerts. A reset to no methods is listed with no email. The learning period is quiet, and 30 days of past sign-ins load once after the update.
- IP reputation moves to proxycheck.io v3. Alerts show the VPN or proxy service, the hostname, and the attacks that proxycheck.io recorded. A proxy is medium, and high with recorded attacks. Cloud hosts show as hosting, not VPN.
- Exchange `SERVICE\` accounts are skipped as service actors.

Management UI:

- Overview > Failed sign-ins: 7 days of failed sign-ins from all IPs (password spraying). No alerts.
- Alerts show how long before the alert the event happened, and how long a session has existed.
- A mute that names one alert type, one user, and one network also hides high alerts.
- Opt-in: end the UI session of a blocked or revoked admin (`UI_ACCOUNT_CHECK`). `install.ps1 -UiSessionHours` sets the sign-in length.
- Layout: long user names, the Overview cards, and the Access card.

Security and CI:

- bandit in CI. CodeQL, OpenSSF Scorecard, and attested release archives in a public repository.
- Docs: a diagram of the architecture and its controls (docs/SECURITY.md), a comparison with Entra ID P2, and revoke timing (continuous access evaluation).

## 1.0.0

First version with the update check.
