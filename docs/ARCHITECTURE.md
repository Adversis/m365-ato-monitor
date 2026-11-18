# Architecture

How the M365 ATO Monitor works.

## Overview

```
                 every 2 minutes
                       │
                       ▼
          ┌──────────────────────────┐
          │ audit_log_monitor        │  Azure Function (Flex Consumption), timer trigger
          │ 0. check subscriptions   │  (first run, then every 6 hours)
          │ 1. fetch each type       │──── Management Activity API
          │ 2. login IP check        │     (Audit.AzureActiveDirectory, Audit.Exchange)
          │ 3. compromise check      │
          │ 4. digest flush          │
          │ 5. write checkpoints     │
          └────────────┬─────────────┘
                       │
       ┌───────────────┼────────────────┬─────────────────┐
       ▼               ▼                ▼                 ▼
 proxycheck.io   Table Storage     Graph sendMail   Application Insights
 (IP reputation) (dedup, cache,    (alerts)         (logs, roll-up source)
                  checkpoint,                             │
                  digest queue)                           ▼
                                               Azure Monitor alert (no runs in 1 h)

All tokens come from the user-assigned managed identity: Table Storage directly,
Graph, Management API, ARM, and App Insights through the app registration
(managed identity token = client assertion). No secret, no storage key.
```

## Modules

```
function/
├── function_app.py         # Triggers, HTTP endpoints, pipeline, checkpoint
├── config.py               # Settings, thresholds, HTTP session with retry, allowlist, redact()
├── identity.py             # Managed identity tokens: client assertion, Table Storage credential
├── o365_client.py          # Tokens, audit subscriptions, Management API fetch, SSRF guard, Graph user lookup
├── ip_checker.py           # IP parsing, proxycheck.io, IP cache, dedup, digest queue
├── compromise_detector.py  # 13 detectors: inbox rules, forwarding, consents, MFA, roles, ...
├── geo_monitor.py          # Per-user sign-in country baseline, anomaly detection
├── session_monitor.py      # One Entra session in two countries, or moved to a risky IP (stolen cookie or token)
├── responder.py            # Response: revoke sessions, block sign-in (automatic or from the UI)
├── journal.py              # Findings journal (90 days): incident context, user page, weekly report
├── mailbox_rules.py        # Inbox rules through Graph: list, assess, turn off or on
├── onboarding.py           # Onboarding scan: audit history, inbox rule sweep, audit search, starting-state report
├── audit_search.py         # Graph audit log search (up to 180 days): onboarding history, user page audit log
├── failed_signins.py       # Failed sign-ins per day (Overview: password spraying, no alerts)
├── mail_access.py          # MailItemsAccessed and Send counts per day (is mail access logged?)
├── settings.py             # Runtime settings: schema, validation, defaults, overrides
├── admin_store.py          # Table Storage for the UI: overrides, history, email journal, mutes, audit searches
├── admin_api.py            # Management UI: auth checks and JSON API
├── ui/                     # Management UI page (index.html, app.js, app.css)
├── insights_client.py      # App Insights query for the weekly and monthly reports
├── health_alerts.py        # Set the action group email when the alert mailbox changes
└── alerting.py             # Graph sendMail: alerts, digest, reports, posture, recipients
```

Dependencies: `config` ← `o365_client`, `ip_checker` ← `compromise_detector`, `alerting`, `insights_client` ← `function_app`. There are no cycles.

## Runtime settings

`install.ps1` sets the Function App settings for the Azure resources (IDs, storage account, Application Insights, action group) and the first alert mailbox. The other defaults are in `config.py`. The management UI stores overrides in the table `monitoradmin`. At the start of each run, `admin_store.refresh()` applies the defaults and then the overrides to the `config` module. All code reads tunable values as `config.X` at call time, so a change applies from the next run without a restart. `settings.py` has one schema for the UI form, the server validation, and the mapping to `config`.

## Management UI

The management UI has routes under `/api/manage`: the page, the script, the style, and a JSON API. The Function App has App Service Authentication with an Entra ID app registration (`<name>-admin-ui`, no assignment required). The script endpoints (`/api/status`, `/api/health`, `/api/recent`, `/api/test`, `/api/selftest`) and the host admin API (`/admin/*`) are excluded. They keep function keys.

Each API request checks these conditions:

- App Service Authentication is on (`WEBSITE_AUTH_ENABLED`). If the setting is missing, the request fails closed.
- The user is signed in.
- The user has access (`ui_access.py`): the `Monitor.Admin` role, a listed user principal name (`UI_ADMIN_USERS`), or an active, direct assignment of a listed directory role (`UI_ADMIN_ROLES`, read from Microsoft Graph and cached 5 minutes).

A request that changes data also needs the `X-Monitor-Admin` header and a same-origin `Origin`. The Function App's CORS list has its own origin (`install.ps1`). Without it, the Functions host refuses each change request with HTTP 403 before the code runs.

Views:

- Overview: status, alerts of the week, mail access logging, tools, onboarding scan.
- Alerts: the findings journal, in pages, with a triage state per alert (Open, Investigating, Benign, Resolved).
- Users: one user's alerts, countries, inbox rules, audit log search, and the actions revoke sessions, block or unblock sign-in, turn a rule off or on.
- Mutes, Settings, Countries, History.

Each change (settings, countries, mutes, response actions) is recorded in History and emailed. A triage change is recorded in History with no email, because it does not change detection. Each audit log search is recorded in History. The last search per user is kept 30 days (`monitoradmin` / `searches`), so the page shows it again.

## Findings journal

`journal.py` writes one row per alert-worthy finding to the table `monitorfindings` (90 days): compromise findings, session reuse, suspicious sign-ins at or above the email level, and new-country sign-ins. The row has a status (emailed, email failed, alert off, muted, or onboarding). It also has the client of the record (`ClientInfoString`, or the user agent of a sign-in). The audit record itself is in a second row (partition `r-` + the user hash, same RowKey, at most 30,000 characters). So the Alerts list does not download it. The management UI loads it when an admin opens "Audit record" under an alert. The same finding always writes the same row, so a retry does not add a row.

Uses:

- Incident context: each alert email lists the other findings for the same user in the 24 hours before it.
- The user page in the management UI.
- The weekly report.

## Mutes

A mute (`admin_store`, partition `mutes`) has these fields:

- an alert type (or all types that can be muted)
- a user (or all users)
- an optional inbox rule name
- an optional network (ASN, with its name for display)
- an end time (1–3650 days)
- a reason

A mute with an ASN matches only findings whose source IP lookup gave that ASN (`asn` on the finding: sign-ins, session reuse, mail access, and compromise findings with an IP). A finding without a lookup does not match it. `refresh()` loads the active mutes at the start of each run. If a finding matches a mute and is not high, the monitor does not email it. The monitor logs it, writes it to the journal with status "muted", and marks it processed. High findings are always emailed.

## Onboarding scan

`onboarding.py` keeps its state in `processedevents` (`system` / `onboarding`). The first monitor run starts it. The timer `background_jobs` (every 5 minutes, at minute 1, 6, 11, ...) continues it for up to 75 seconds per run (the function timeout is 2.5 minutes):

1. History: content windows of 1 hour, from 7 days back to the start of the monitor's first fetch window. The detectors run on each window. Findings go to the journal (status "onboarding") and are marked processed, so the monitor does not alert them again. A finding that the monitor already alerted is skipped. During the learning period, sign-ins from IPs that are not flagged seed the country baseline (`geo_monitor.seed`, at most 300 IP lookups).
2. Rules: Graph `/users` (members with a mail address), then each mailbox's `messageRules`. Rules with risk signs go to the journal and the report. A rule holds only the ID of its move target folder. Reading the folder name needs a Mail permission. So a move to a hidden folder is not a sign here. The audit-record detector does flag it.
3. Search: the Graph audit log search (`audit_search.py`) from 180 days back to the start of step 1, for the operations that the detectors read (`compromise_detector.history_operations()`, no sign-ins). The scan submits the search when it starts, because Microsoft takes minutes to hours. This step waits for the status `succeeded` (at most 48 hours), then reads the records 500 per page and runs the detectors on them, as in step 1. Without `AuditLogsQuery.Read.All`, the step is skipped and the report says why.
4. Report: one email. The journal rows of the scan carry its run ID. The report selects them by run ID, at any event time. The state then becomes `done`.

A failed or incomplete history fetch keeps the cursor at the start of that window. The next run retries it. Records are counted only after both content types are complete.

A new start writes a new run ID. A step that finds another run ID stops. The state is written with an ETag check, so a new start is not overwritten.

## Audit subscriptions

The function starts the audit subscriptions itself (`o365_client.ensure_subscriptions`). There is no setup script. On the first run, and then every 6 hours, it lists the subscriptions and starts each content type that is not enabled. After an `AF20022` (no subscription) or `AF20023` (subscription disabled) error, it checks at once. Microsoft takes up to 12 hours (often 12–24) to deliver the first content after a subscription starts. The subscriptions are tenant-level. `install.ps1 -Uninstall` does not stop them. They cost nothing.

## Fetch and checkpoint

The Management API selects content blobs by the time each blob became available (`contentCreated`), not by event time. The API accepts a window of 24 hours or less, within the last 7 days.

For each content type, each run:

1. Reads the checkpoint (the end of the last complete fetch) from Table Storage.
2. Sets the window start to the earlier of the checkpoint and `now − LOOKBACK_MINUTES`. The start is not earlier than `now − MAX_CATCHUP_MINUTES`. If the checkpoint is older, the run logs "Coverage gap" and moves the checkpoint to that limit.
3. Lists and downloads the blobs. If one blob fails, the run uses the other blobs, but the fetch is not complete.
4. After processing, writes the window end as the new checkpoint, if the fetch was complete and processing did not fail.

Each content type is independent. If the `Audit.Exchange` listing fails, the run still processes `Audit.AzureActiveDirectory`.

The window overlaps the previous run. Dedup (below) prevents duplicate alerts. `MAX_CATCHUP_MINUTES` equals `DEDUP_WINDOW_MINUTES`, so dedup knows every event in any window.

## Dedup

Dedup uses the table `processedevents`, partition `events`. A row means "done". Each run reads the keys marked in the last `DEDUP_WINDOW_MINUTES` (`max(60, 3 × LOOKBACK_MINUTES)`).

| Check | Key |
|---|---|
| Sign-in IP check | Event key (audit `Id`, sanitized) |
| Compromise finding | `<type>_<event key>`, for example `inbox_rule_<id>` |

The prefix keeps the two checks apart. A sign-in check of an event does not hide a compromise finding on the same event.

An event is marked only after its alert is sent or queued, or a setting or mute suppresses it. If delivery and queueing fail, the run keeps the checkpoint. The first attempted window start is also saved. Later runs retry from that checkpoint, up to `MAX_CATCHUP_MINUTES`.

## Sign-in IP check

Some sign-in records have a `UserId` that is not a UPN (for example `Not Available`). Before the checks, such a record gets the user from another record of the same session (`DeviceProperties` `SessionId`) in the batch, from a UPN in `Actor`, or from a user object ID in `Actor` (Graph, `User.ReadBasic.All`). The original value stays in `UserIdInRecord`.

1. Filter `Audit.AzureActiveDirectory` records to RecordType 9 and 15 (sign-ins, success and failure).
2. Get the IP from `ClientIP`, `ActorIpAddress`, or `ExtendedProperties.ClientIPAddress`. `clean_ip()` returns the canonical form.
3. Skip private IPs, allowlisted IPs, and processed events.
4. Look up the IPs: iCloud Private Relay IPs from Apple's list (if trusted: no flags, country from the list), then the cache (24 h for results, 5 min for failures), then one proxycheck.io batch POST for the rest.
5. Classify. Tor, compromised server, and a proxy with attacks that proxycheck.io recorded: high. VPN, other proxy, hosting, inference engine, risk 66 or more: medium. Risk at or above the threshold: low.
6. Log each suspicious sign-in. Send an email or queue it for the digest, as set by `LOGIN_ALERT_CONFIDENCE` and `LOGIN_ALERT_MODE`. A failed sign-in (wrong password) is only logged and kept in the journal (status "alert off"), unless `LOGIN_ALERT_FAILED` is on. A correct password stopped by MFA or Conditional Access is not a failure here. One alert goes out for each user, IP, outcome (success or failure), and UTC day (row `signinalert-<hash>` in the events table). The other records of the same sign-in are only logged.
7. Send the sign-ins from IPs that are not flagged to the country baseline (`geo_monitor`). Save each new-country anomaly in `signincountries` (partition `pending`) before updating the baseline. Then log it, apply `ANOMALY_ACTION` (`responder`), and send an email. A failed delivery stays pending for up to 7 days, even after the source record leaves the fetch window. The response result is kept so an email retry does not repeat the action. Mark the sign-in processed only after the baseline and pending alerts are saved.

A failed IP lookup is "skipped". The sign-in goes to the `pendingip` queue and is marked processed. Each run checks the queue again, for up to 26 hours. Without storage, the event is not marked, so the next run tries again while it is in the window.

## Session check

`session_monitor.py` follows each Entra session across records. The session ID is in:

- Sign-ins (`UserLoggedIn`): `DeviceProperties[SessionId]`.
- Exchange records: `SessionId`.
- Exchange, SharePoint, and Teams records: `AppAccessContext.AADSessionId`.

Real records show the same GUID in all three. A replayed cookie writes new sign-ins with the original session ID. A replayed refresh token is a non-interactive sign-in, which is not in the unified audit log. But the mailbox and file records that it causes carry the session ID.

Each run:

1. Collects the records that have a session ID, a user, and a public IP that is not allowed. It skips these records:
   - Failed sign-ins.
   - Exchange Graph REST records that have both `Client=REST` and the Graph resource ID in `AppId` or `AppAccessContext.APIId`. Those IPs belong to the service, not the client.
   - Records (not sign-ins) from a Microsoft 365 server IP (`microsoft_nets.py`). Outlook mobile syncs through a Microsoft service. Teams, Copilot, and other Microsoft apps read mail with the user's token from Microsoft's servers. Those records show the server's IP.

     The ranges are the Office 365 endpoints list minus every Azure service tag range (all address space an Azure customer can use, also relays such as Front Door). `INTERNAL_NETS` adds Exchange Online server space that is in neither list, for example `2603:10b6::/32`. `scripts/update_microsoft_nets.py` makes `microsoft_nets.json`. A monthly CI workflow (`microsoft-nets.yml`) fails when the file is out of date.
   - Exchange records that a Microsoft service wrote for the user (`mail_access.relaying_app`). For such a record, the user's token was for that service's API (`AppAccessContext.APIId`, not Exchange or Graph), and `AppId` is that API. `ClientAppId` is the user's app, and the app belongs to a Microsoft tenant (Graph `appOwnerOrganizationId`, cached for 24 hours). Exchange accepts no such token from a client, so only the service can make the call. Examples: the Teams backend reading an attachment, the SharePoint notification service sending a Planner email. If Graph cannot answer, the record is checked.
   - Records of a Power Automate flow. A flow also runs as a Microsoft service.
2. Reads each session from the table `signinsessions` (one row per session: user, IPs with their countries, risky IPs, countries with first and last time, alerts already sent).
3. Looks up the IPs that are new for the session (cache first, then proxycheck.io). Microsoft-owned networks are checked too: Azure hosts customer VMs. A VPN, proxy, hosting, or Tor IP (the same test as the suspicious sign-in check) is marked as risky. IPs that an earlier version excluded by network ownership are checked again.
4. A country that is new for a session that already has another country is a finding (`session_reuse`): high, or medium if the country is a home country or usual for the user.
5. A risky IP that is new for a session in the same country is a finding (`session_reuse`) if all of these are true: the session already has a normal IP, the record is not a sign-in, and the IP did not sign in as the user in the last 7 days. The severity is medium, or high for a Tor or compromised-server IP, or a proxy with recorded attacks. There is one finding per session. A sign-in from a risky IP gets a suspicious sign-in alert. Mail reads and sends are left to the mail access check while it is on.
6. The alert goes out like a compromise indicator. After it is sent, the country (or the risky-IP finding) is marked as alerted for the session.

The weekly cleanup deletes rows older than 30 days. Microsoft's AiTM hunting guidance uses the same join (session ID, different country).

## Mail access check

`mail_access.py` uses the `MailItemsAccessed` and `Send` records of `Audit.Exchange` (setting `MAIL_ACCESS_CHECK`). Each run:

1. Counts the records per day of the event (`system` / `mailaccess-YYYY-MM-DD`). Each record counts once: the run fetches an 8-minute window every 2 minutes, so the IDs of the counted records are kept for 200 minutes (`system` / `mailaccess-seen`). The Overview and the weekly report show if the tenant logs mail access.
2. Keeps each user and IP of a successful sign-in (`signinip`, 7 days).
3. Groups the mail access records by user and IP. Only clients that show the user's own IP count (`Client=OWA`, `MSExchangeRPC`, `OutlookService`, `ActiveSync`, `WebServices`, `IMAP4`, `POP3`). Graph records (`Client=REST`) and records from a Microsoft 365 server IP (`microsoft_nets.py`) carry a Microsoft IP and are skipped.
4. Skips private and allowlisted IPs, IPs that signed in as the user in 7 days, and user, IP, and day combinations that already have a high finding.
5. Looks up the rest, at most `MAIL_ACCESS_MAX_LOOKUPS` per run. The IP cache and iCloud Private Relay list apply. Microsoft-owned networks are checked too.
6. A VPN, proxy, hosting, or Tor IP, or a new country for the user, is a finding (`mail_access`). High: Tor or a similar anonymizer, or mail sent or a folder downloaded from a flagged IP. Other findings are medium.

Each user, IP, and day can have one medium finding and one later high finding. A medium finding that was muted does not suppress the high finding. After a high finding, neither severity sends another alert for that day.

A token refresh is a non-interactive sign-in, which is not in the unified audit log. So mail access from an IP with no sign-in is the visible trace of a replayed refresh token.

## Compromise check

All AAD and Exchange records go to 13 detectors. A record that a detector cannot parse is logged and skipped. One detector failure does not stop the others.

Two kinds of finding are journaled without an email:

- A permission that `install.ps1` grants to the monitor app (status `install`). The record must name the monitor app by its app ID or service principal ID, and grant only roles in `INSTALL_ROLES`.
- An MFA method added or changed on one account (status `known sign-in`, `function_app._context_review`). The record (`Update user.`) has no IP. The person who signed in is the user (My Sign-ins: the MFA service writes the record) or the admin who changed the user's methods.

  The monitor keeps the networks of each user's successful sign-ins (`signin_networks.py`: the /24 of IPv4, the /48 of IPv6, for 90 days). It sends no email when all of these are true:

  - Neither the user nor the admin had another emailed alert in the 7 days before. An alert triaged Benign does not count.
  - A sign-in by the person who made the change was seen in the hour before the change.
  - Every such sign-in came from a network that this person used before.

  When this person's network history is shorter than 14 days, the monitor also sends no email (the reason says so), unless there was another alert. When the monitor has no sign-in of this person at all (for example an admin of a partner tenant), it sends email.

  After an install or the update that adds it, `network_backfill.py` loads the successful sign-ins of the last 30 days once, through the Graph audit search (operation `UserLoggedIn`). Each user's history then starts 30 days back. Until the search is done (4 to 40 minutes, up to 48 hours), MFA changes send email only after another alert.

  The session check runs before the compromise check. These findings are decided after the other findings of the same batch, so that an alert of the same run counts. A late sign-in record can change some decisions: "no email", or "no sign-in seen" for an MFA change. Such a decision waits 30 minutes after the monitor first sees the record (events table, partition `heldreview`). The reason is that Microsoft can publish a sign-in record later than the record of the change.

  A rule's own IP counts as a new network only if the user has sign-in networks of the same IP version. Dual-stack users sign in over IPv4 and change rules over IPv6.

  Gap: an attacker with a stolen session (user or admin) who changes a method from a network that this person used before, with no other alert. A later alert about the user lists the row in its incident context.
- An app consent made by a Microsoft service (status `microsoft`, `service_actors.py`). The actor is `ServicePrincipal_<object ID>` (not a user). That service principal's `appOwnerOrganizationId` is a Microsoft tenant (Graph, `Application.Read.All`, cached 24 hours). A failed lookup is not tried again for 15 minutes. This applies only to app consents (`NOISE_TYPES`). The MFA service writes the record when someone adds an MFA method, and PIM writes role activations, so those always alert.

  The detectors themselves skip Exchange and Windows service accounts (`NT AUTHORITY\`, `NT SERVICE\` and its SIDs `S-1-5-80-...`, UserType DCAdmin or System). A folder shared with `Owner@local` or `Member@local` (the owners and members of a Microsoft 365 group) is not shared outside.

| Detector (finding type) | Operations | Alert condition |
|---|---|---|
| Inbox rules (`inbox_rule`) | `New-InboxRule`, `Set-InboxRule`, `Enable-InboxRule`, `UpdateInboxRules` | High: external forward or redirect (all fields, all recipients), move to a hidden folder, delete with another sign. A rule that only deletes mail sends email (high) only when the user had another alert in the 7 days before, the rule's IP is flagged, in a new country, on a network that the user did not use before, or was not checked (failed lookup), or the user signed in from a new network (`signin_networks.py`) in the 24 hours before; else status `known sign-in`, no email. Medium: an unverified X.500 forwarding recipient in a cmdlet record; a name with no letters or digits; a 1–2 character name with mark-as-read, move, or delete; a word in `INBOX_RULE_KEYWORDS` with mark-as-read, move, or delete |
| Mailbox forwarding (`mailbox_forwarding`) | `Set-Mailbox` | `ForwardingSmtpAddress` external (high), or `ForwardingAddress` set (medium; high if external) |
| OAuth consents (`oauth_consent`) | `Consent to application.`, `Add delegated permission grant.`, `Add app role assignment to service principal.` | A scope in `HIGH_RISK_OAUTH_SCOPES` |
| User agents (`attack_tool`, `suspicious_user_agent`) | Records with `ExtendedProperties.UserAgent` | Attack tool (high), automation library (medium). A failed sign-in (wrong password) is only logged (status "alert off"), unless `LOGIN_ALERT_FAILED` is on |
| Sign-in methods (`legacy_auth`, `device_code`) | `UserLoggedIn` | User agent `BAV2ROPC` (high). `RequestType` `Cmsi:Cmsi`, the device code flow (medium) |
| Mail flow rules (`mail_flow_rule`) | `New-TransportRule`, `Set-TransportRule` | High: external redirect, BCC, copy, or added recipient; delete; route through a connector. Medium: SCL -1; any new rule |
| Mailbox delegation (`mailbox_delegation`) | `Add-MailboxPermission`, `Add-RecipientPermission`, `Set-Mailbox`, `Add-`/`Set-MailboxFolderPermission` | FullAccess, SendAs, SendOnBehalf; a non-calendar folder shared with `Default`, `Anonymous`, or an external address (medium) |
| Audit (`audit_disabled`) | `Set-AdminAuditLogConfig`, `Set-OrganizationConfig`, `Set-MailboxAuditBypassAssociation`, `Set-Mailbox` | Unified audit off, mailbox audit off, audit bypass on (high) |
| Mail protection (`mail_protection_weakened`) | `Remove-*`/`Disable-*` anti-phishing, anti-malware, anti-spam, Safe Links, Safe Attachments; `Set-DkimSigningConfig`; `Set-HostedOutboundSpamFilterPolicy`; `Set-HostedContentFilterPolicy`; `Set-OrganizationConfig` | Removed or off; DKIM off; allowed senders added (medium). External auto-forwarding allowed; Direct Send protection off (high) |
| MFA (`mfa_change`) | `Update user.`, `Disable Strong Authentication.`, `Set Company Information.` | A method added to an account that had one, a method or Authenticator device replaced, or the default method changed (medium; high if the user or the admin who made the change had another alert in the 7 days before). All methods removed: listed with no email (status `list only`). Per-user MFA off (high). Tenant MFA settings changed (medium). No other alert and a sign-in from a known network (see below): status `known sign-in`, no email |
| Admin roles (`admin_role`) | `Add member to role.`, `New-ManagementRoleAssignment` | Global, Privileged Role, or Privileged Authentication Administrator, or ApplicationImpersonation (high). Other roles (medium) |
| App credentials (`app_credential`) | `Update application – Certificates and secrets management`, `Add service principal credentials.` | Any (medium) |
| Domain federation (`domain_federation`) | `Set domain authentication.`, `Set federation settings on domain.`, `Add-FederatedDomain`, `Add verified domain.`, `Add unverified domain.` | Federation set (high). Domain added (medium) |

`UpdateInboxRules` has two formats. Outlook writes `RuleActions` (JSON with `ActionType` and `Recipients`). EWS writes `Actions` and a `ServerRule` JSON. The detector reads both.

Most tenant-level changes are rare in a small tenant, so one change is an alert. An admin or the user can make some changes on purpose: all types except inbox rules, mailbox forwarding, OAuth consents, attack tools, legacy authentication, and session reuse. The alert email for such a change asks the reader to confirm before they treat the account as compromised.

The detectors were compared with public detection content for the same audit records: Elastic prebuilt rules (`rules/integrations/o365`), Splunk Security Content (`detections/cloud/o365_*`), Sigma (`rules/cloud/m365`), and the Wazuh Office 365 ruleset. Rules that need data this tool does not read (Defender alerts, SharePoint, message trace) are not included.

The run looks up the source IP of each new finding. If the IP is a proxy or hosting address, or its country is new for the user, the severity becomes high and the email shows the IP context. A record with a Microsoft service IP (the same test as the session check, `mail_access.service_ip_client`) is not looked up and does not raise the severity. For example, a rule changed in Outlook mobile shows the IP of Microsoft's server. The content of the finding still sets its severity.

## Latency

An alert arrives after Microsoft publishes the audit record, plus up to 2 minutes. Two delays add up:

1. **Microsoft audit pipeline.** Microsoft gives no guaranteed latency. Its documentation gives 60–90 minutes as typical for core services. In practice, many records arrive within about 10 minutes. Some take 1–2 hours or more, and outages take longer. A late record is not lost: the API lists content by the time it became available, so a later run gets it.
2. **Polling interval.** The function runs every 2 minutes.

To block a sign-in in real time, use Conditional Access (Entra ID P1).

## Detection limits

What the monitor does not detect:

- An AiTM sign-in from a residential IP. The phishing server makes the sign-in, so the log shows the server's IP. The tool flags it only if proxycheck.io classifies that IP as VPN, proxy, or hosting, or the country is new for the user. Kits that relay through residential proxies in the user's country are not flagged.
- A stolen session used from a normal home or office network in the same country as the original sign-in. The session check compares countries and flags a move to a VPN, proxy, hosting, or Tor IP. But AiTM kits often use a residential proxy in the victim's country. About half of mailbox and file records carry no session ID (for example Outlook desktop). Refresh-token use (non-interactive sign-ins) is not in the unified audit log. The monitor detects what the attacker does next (rules, forwarding, MFA, consents).
- Passkey, FIDO2, and Windows Hello registration. These are only in the Entra ID audit log, not in the unified audit log. A first MFA method, an added Authenticator, OTP app, or phone number are visible.
- A sign-in from a country that is already normal for the user, or in `HOME_COUNTRIES`.
- New-country alerts in the first 14 days (learning period), unless `HOME_COUNTRIES` is set.
- Mail that the attacker reads or sends with a stolen token from a normal residential IP in the user's country, or from an IP that also signed in as the user. Mail access from a risky IP is detected only if the tenant logs `MailItemsAccessed` and `Send` (Overview > Mail access records). Graph API access shows a Microsoft IP and is not checked.
- A first MFA registration on an account (normal for a new user). An inbox rule that moves mail to a normal folder with no listed keyword and a normal name. An Outlook desktop rule that moves mail to a hidden folder: its record has a folder ID, not the folder name (Outlook on the web records have the name).
- An admin-level attacker who turns off unified audit logging, if that record does not arrive. After `NO_CONTENT_ALERT_HOURS` (48 h) with no content, the monitor logs an error and the errors alert sends an email.
- A new device, browser, or mail client for a user. User agents change with each update and each new phone, so the tool matches only the names of attack tools and scripting libraries.
- Signals that need Entra ID P1/P2 or Defender: risk scores, Conditional Access results, device compliance, Defender alerts.
- SharePoint, OneDrive, and Teams activity.

The tool detects attacker actions after access. It does not prevent an attack. An optional automatic response (off by default) revokes sessions or blocks sign-in after a high account-takeover alert or a new-country sign-in, and turns off a malicious inbox rule. It never changes a password.

The responder rejects failed sign-ins that do not prove the password, independently of `LOGIN_ALERT_FAILED`. That setting controls email only. Successful sign-ins and correct passwords stopped by MFA or Conditional Access remain eligible for the configured response.

## Emails

| Email | Trigger | Frequency |
|---|---|---|
| Setup confirmation | First run with a successful fetch | One time |
| Compromise indicator | New finding | One per finding |
| Suspicious sign-in | Flagged sign-in IP | One per sign-in, or one digest |
| Weekly report | Mondays, 07:17 UTC (`WEEKLY_REPORT`). Runs, sign-ins, gaps, and errors from App Insights for 7 days; findings from the journal; posture | Weekly |
| Roll-up | 1st of the month, 08:00 UTC. Counts from App Insights for 30 days; posture | Monthly |
| Starting state | Onboarding scan finished | After the first run, and on request |
| Management UI change | Settings, countries, mutes, or response actions changed in the UI | One per change |
| Azure Monitor "no-runs" alert | No completed run in 1 hour | Once when it fires, once when it resolves |
| Azure Monitor "errors" alert | 5 or more errors in 1 hour | Once when it fires, once when it resolves |

All app emails go through Graph sendMail from `ADMIN_EMAIL` to `ADMIN_EMAIL`. Alert emails (`[M365 Alert]`) also go to `ALERT_RECIPIENTS`. Reports (`[M365 Monitor]`) also go to `REPORT_RECIPIENTS`. With `TENANT_LABEL`, the subject starts `[M365 Alert][<label>]`. If Graph refuses an alert, the alert goes to the `outbox` queue. Each run sends it again, for up to 7 days. The Azure Monitor alerts go through an action group. They do not use the app's credentials.

With a webhook (`webhook.py`, `ALERT_DELIVERY` both or webhook), each alert also goes, or only goes, to `WEBHOOK_URL`. The monitor sends one HTTPS POST to port 443, with no retry and no redirects. The timeouts are 5 seconds to connect and 10 seconds to read. Every resolved address must be public.

Slack text escapes `& < >`, and the Teams card uses plain TextRun elements. So names from audit records (rule and app names) cannot add mentions or links. With "webhook only", a failed webhook sends the alert by email. Reports and the notices of changes in the management UI always go by email.

## Resilience

- Each content type is fetched separately. One failure does not stop the other.
- The checkpoint closes gaps up to `MAX_CATCHUP_MINUTES` and logs larger gaps.
- An event is marked processed only after its alert is sent or queued (outbox, digest, pending IP check).
- A watchdog logs an error if no audit content arrives for `NO_CONTENT_ALERT_HOURS` (48 h).
- A failed proxycheck.io lookup is cached for 5 minutes, so repeated failures do not use the quota.
- proxycheck.io quota (`proxycheck_quota.py`): each lookup answer tells the level. Status `warning` ("within 10% of your query limit") is low. Status `denied` with a quota message is used up. Another `denied` (for example a disabled key) is refused.

  With a key, the monitor also reads the usage export (`/dashboard/export/usage/`) every 30 minutes, and 80% used counts as low. The export needs **Dashboard API Access** on in the proxycheck.io dashboard. It does not count against the limit. The state is one row in the `ipcache` table (partition `quota`). The monitor emails at most once per level (low, used up, refused) per UTC day. The Overview page, `/api/status` (`ip_lookups`), and the weekly report show the state.
- When lookups fail: suspicious sign-ins and new-country checks wait in the `pendingip` queue for up to 26 hours. The session and mail access checks skip the records after the fetch window (about 8 minutes). Account takeover findings are still sent, without the IP reputation and without the raise to high.
- HTTP retry: 3 retries with exponential backoff on 429, 500, 502, 503, 504. `Retry-After` is capped at 10 seconds.
- Each send function returns False on failure. It does not raise.
- Each detector is isolated. One error does not stop the others.
- Application Insights does not sample traces (`host.json`), so no detection trace is dropped.

## Infrastructure (install.ps1)

`install.ps1` creates these resources with the Azure CLI. `<name>` is the `-Name` parameter (default `m365-ato-monitor`). `<6hex>` comes from the subscription ID and the name, because some names are globally unique. A rerun finds the same resources and repairs them.

| Resource | Name | Purpose |
|---|---|---|
| Resource group | `rg-<name>` | Holds all Azure resources |
| User-assigned managed identity | `id-<name>` | The only credential of the monitor app (federated identity credential), and storage access |
| Storage account | `st<name><6hex>` (no hyphens, at most 24 characters) | No public blobs, TLS 1.2, HTTPS only. Shared key access is turned off after the setup. The managed identity has Storage Blob Data Owner and Storage Table Data Contributor |
| Tables | In the storage account | `processedevents` (partitions: `events` dedup, `system` checkpoints, flags, the onboarding state, mail access counts (15 days), and failed sign-in counts (8 days), `logindigest`, `outbox`, `pendingip`), `ipcache`; created when used: `useridcache`, `signincountries`, `signinsessions` (session countries, 30 days), `monitoradmin` (UI overrides, the proxycheck.io key, history, email journal, mutes, the last audit search per user), `monitorfindings` (findings journal, 90 days) |
| Blob container `deployments` | In the storage account | The code package. The Functions host reads it with the managed identity |
| Log Analytics workspace | `log-<name>` | Logs, 90 days |
| Application Insights | `appi-<name>` | Logs and the source of the reports |
| Function App | `func-<name>-<6hex>` | Flex Consumption, Linux, Python 3.12, 512 MB instance memory, HTTPS only. The pipeline and the management UI |
| App registration and service principal | `<name>` | The monitor app: `ActivityFeed.Read` and the Graph roles, with admin consent. Its only credential is the managed identity. No client secret |
| App registration and service principal | `<name>-admin-ui` | Sign-in to the management UI: app role Monitor.Admin, no assignment required (the function checks access), delegated `User.Read`. The person who runs the script and `-UiAdmins` get the role |
| App Service Authentication | On the Function App | Entra ID sign-in for `/api/manage`. Excluded: `/api/status`, `/api/health`, `/api/recent`, `/api/test`, `/api/selftest`, `/admin/*` |
| Role assignment (Monitoring Reader) | On Application Insights, for the monitor app | Report queries |
| Role assignment (Monitoring Contributor) | On the action group, for the monitor app | Set the health alert email when the alert mailbox changes in the UI |
| Action group | `ag-<name>` | Email to the alert mailbox |
| Log alerts | `alert-<name>-no-runs`, `alert-<name>-errors` | No run in 1 hour; 5 or more errors in 1 hour. Evaluated every 30 minutes |
| Log alert | `alert-<name>-code-deployed` | A write to the blob container `deployments` (a code deployment). Evaluated every 15 minutes |
| Storage logs | Diagnostic setting `<name>-deploy-logs` on the blob service | Blob write logs (`StorageWrite`) to the workspace. A deployment through Kudu (`az functionapp deployment source config-zip`) is not in the activity log |
| Workspace transformation | `dcr-<name>-deploy-logs` | Keeps only the rows of the `deployments` container in `StorageBlobLogs`. The host's other blob writes (leases, timer state) are not stored |
| Activity log alert | `alert-<name>-azure-change` | Successful Azure changes in the resource group: the Function App (settings, sign-in, publishing, stop, delete), identity federated credentials, role assignments, the storage account, Application Insights, the alert rules, the storage logs, and the workspace |
| Role assignment (Monitoring Metrics Publisher) | On Application Insights, for the managed identity | The host sends telemetry with the managed identity (`APPLICATIONINSIGHTS_AUTHENTICATION_STRING`). Local authentication is off: the connection string alone cannot send telemetry |
| Publishing credentials | On the Function App | Deployment with a user name and password (SCM, FTP) is off. Deployments use Entra ID |
| Code | Zip deploy with remote build | The `function` folder. The build installs `requirements.txt` |

There is no client secret and no storage key.

How the app gets tokens (`identity.py`, `o365_client.py`):

1. Table Storage: a managed identity token for `https://storage.azure.com/`.
2. Graph, Office 365 Management API, ARM, Application Insights: the app gets a managed identity token for the audience `api://AzureADTokenExchange`. It sends this token as the client assertion in a client-credentials request for the monitor app registration. The app registration trusts the managed identity through its federated identity credential.

The Functions host uses the same managed identity for its storage (`AzureWebJobsStorage__credential = managedidentity`).

## Costs

Estimates for a small tenant: about $2–10 per month. Your cost depends on log volume and region.

| Resource | Monthly cost | Notes |
|---|---|---|
| Function App (Flex Consumption, 512 MB) | $1–3 | The 2-minute timer uses most of it. Price: $0.000026 per GB-s in most regions ($0.000037 in some) and $0.40 per million executions. Each execution is billed for at least 1 second. Free grant per subscription and month: 100,000 GB-s and 250,000 executions, shared by all Flex Consumption apps in the subscription |
| Storage account | $1–2 | Tables, timer state, and the code package |
| Application Insights / Log Analytics | $0–5 | Log ingestion. Depends on log volume |
| Azure Monitor log alerts | Small per-rule charge | 2 rules at a 30-minute frequency, 1 rule at a 15-minute frequency. See [Azure Monitor pricing](https://azure.microsoft.com/pricing/details/monitor/) |
| Activity log alert | $0 | Activity log alerts have no charge |
| Storage logs for the code deployment alert | A few cents | The workspace transformation drops all rows except the `deployments` container. Azure can charge a small processing fee for the dropped data |
| proxycheck.io | $0 | Free tier: 1,000 queries/day with a key |

Azure has no spending limit for pay-as-you-go subscriptions. Set a Cost Management budget on the resource group to get a warning.
