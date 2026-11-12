# How-To Guide

Procedures for common tasks. Each section is independent.

## Where to change what

| Change | Where |
|---|---|
| Test the alerts | Management UI > Overview > **Test alerts**, `./install.ps1 -Verify -SendTestAlerts`, or `scripts/live-test.ps1` ([Test the alerts](#test-the-alerts)) |
| Turn an alert type on or off; alert mailbox; extra recipients; tenant name in subjects; allowlists (IPs, networks, mail domains); sign-in emails; proxycheck.io key; countries; automatic response; detection lists; weekly report | Management UI > **Settings** |
| A user's usual countries (approve travel) | Management UI > **Countries** |
| Stop email for one expected alert for some days | Management UI > **Mutes** ([Mute an expected alert](#mute-an-expected-alert)) |
| Revoke sessions, block sign-in, turn off an inbox rule | Management UI > **Users** ([Respond from the management UI](#respond-from-the-management-ui)) |
| Run the onboarding scan again | Management UI > Overview > Tools ([Run the onboarding scan](#run-the-onboarding-scan)) |
| Management UI admins | Management UI > Settings > Management UI access, the Entra admin center, or `./install.ps1 -UiAdmins` ([Give other people access](#give-other-people-access-to-the-management-ui)) |
| Graph permissions for the response actions | `./install.ps1 -ResponsePermissions yes` or `no` |
| Mail.Send for the alert mailbox only (the default) | `./install.ps1 -MailSendScope mailbox` ([Limit Mail.Send](#limit-mailsend-to-the-alert-mailbox)) |
| A new version of the code | `./install.ps1 -Update` ([Update the monitor](#update-the-monitor)) |
| Repair the Azure resources or the app registrations | `./install.ps1` (run it again) |
| Remove the monitor | `./install.ps1 -Uninstall` ([Remove the monitor](#remove-the-monitor)) |

The management UI is at `https://<function app>.azurewebsites.net/api/manage`. Sign in with an account that has access (see [Give other people access](#give-other-people-access-to-the-management-ui)). To find the link again:

- Each alert email and each report has an **Open in the management UI** button.
- `./install.ps1 -List` shows the link of each installation on this computer. It needs no sign-in.
- `./install.ps1 -Verify` prints the link at the end. For another tenant, add `-Tenant <domain>`.
- Azure portal > **Function App** > `func-m365-ato-monitor-<id>` (`func-<name>-<id>` if you used `-Name`) > **Overview** > **Default domain**. Add `/api/manage`.

To use your own domain, see [Use a custom domain](#use-a-custom-domain).

After the install, you change everything in the management UI. You need `install.ps1` again only to deploy a new version (`-Update`), to change the permissions (`-ResponsePermissions`, `-MailSendScope`), or to remove the monitor (`-Uninstall`).

How settings work:

- `install.ps1` writes the Function App settings for the Azure resources and the first alert mailbox. The other defaults are in the code (`function/config.py`). The UI stores changes in Table Storage. A UI change overrides the default.
- A UI change applies from the next run (within 2 minutes). No restart.
- A rerun of `install.ps1` (also `-Update`) does not revert UI changes. **Reset to default** in the UI removes a change.
- Each UI change is recorded in **History** and emailed to the alert mailbox.
- An option that needs a Graph permission that is not granted is disabled in the UI, with the reason.

---

## Turn off an alert type

1. Management UI > Settings > Alerts > **Alert types that send email**.
2. Clear the box for each alert type that you do not want, for example **Mail flow (transport) rules**.
3. Select **Save changes**, then confirm.

The detection still runs and is written to Application Insights ("Compromise indicator (alert turned off)"). The automatic response does not run for a type that is off. Sign-in and new-country emails have their own settings: **Which suspicious sign-ins send email** and **Alert on a sign-in from a new country**.

By default, a mail flow rule causes an alert only if it copies, redirects, or deletes mail, routes it through a connector, or skips spam filtering. **Alert on every new mail flow rule** adds all other new rules.

---

## Mark an alert as benign or resolved

1. Management UI > **Alerts**, or **Users** > the user.
2. In the **Triage** column of the alert, select **Investigating**, **Benign** (expected, not an attack), or **Resolved** (an attack that you handled).
3. Enter a note if you want, for example who confirmed it. Select **Save**.

The Alerts view shows open and investigating alerts first; select **Triage** > **All** or one state to see the others. Triage changes only the list: later alerts for the same user or rule still send email (to stop them, use a mute). History records each change. Long lists have pages: use **Previous** and **Next**.

The Overview shows the state as a tag on each recent alert (**Investigating**, **Benign**, or **Resolved**), with the note. Benign and resolved alerts are dimmed. An automatic response shows as "Response: ..." under the alert.

Under each alert, **Mute similar** (medium alerts only) opens the mute form with the alert type, the user, and the rule name filled in. **Respond on the user page** opens the page with revoke sessions, block sign-in, and the user's inbox rules.

---

## Mute an expected alert

A mute stops email for medium alerts that match it, for 1 to 90 days. Use it for an alert that you confirmed and that repeats, for example a known newsletter rule or a user who travels with a hotel VPN.

1. In a medium alert email, select **mute similar alerts**. Or: Management UI > **Alerts** > **Mute similar** under the alert. Or: Management UI > **Mutes**.
2. Make the mute as narrow as possible:
   - **Alert type**: one type, or all types that can be muted.
   - **User**: one user, or `*` for all users. A mute for all users must name one alert type.
   - **Rule name** (inbox rules only): one rule.
3. Set **Days** (1–90). Use the shortest time that covers the case.
4. Enter a **Reason**. It is shown in History, in the email about the change, and in the weekly report.
5. Select **Add mute**, then confirm.

What a mute does not hide:

- High alerts. They are always sent.
- OAuth consent, attack tool, legacy authentication, and audit-off alerts. They are always high.
- New-country alerts (always high). To stop them for a traveler, approve the country (Management UI > Countries).

A muted alert is not lost. It is recorded on the user page (Management UI > Users) with the status "muted", and the weekly report counts it. The automatic response does not run for a muted alert (it runs for high alerts only). To end a mute early, select **End now** in Management UI > Mutes.

---

## Send alerts to Slack or Microsoft Teams

Management UI > Settings > **Webhook**:

1. **Webhook URL**: an incoming webhook URL. Slack: Apps > Incoming Webhooks > Add to Slack, choose a channel, and copy the URL. Microsoft Teams: in the channel, Workflows > "Post to a channel when a webhook request is received", and copy the URL. The URL is a secret: the monitor stores it like the proxycheck.io key and never shows it again.
2. **Webhook message format**: Slack, Microsoft Teams (Workflows), or JSON for other services.
3. **Send alerts by**: Email and webhook, or Webhook only. With Webhook only, an alert goes by email when the webhook fails.
4. Save. Then send test alerts: Overview > Tools.

Only alerts go to the webhook. The weekly, monthly, and starting-state reports go by email. The monitor sends HTTPS only, does not follow redirects, and refuses a host that resolves to a private or internal address. The email list on the Overview page shows each webhook result.

---

## Give other people access to the management UI

These people can open the management UI:

- The person who ran `install.ps1`, and the users in `-UiAdmins`. They have the **Monitor.Admin** app role. To give it in the Entra admin center: Enterprise applications > `<name>-admin-ui` > Users and groups > **Add user/group** > the user and the role **Monitor admin**.
- The users in Settings > Management UI access > **Users who can open the management UI**. Enter the address the person signs in with. For a guest, that is the guest's own address (for example `bob@fabrikam.com`), not the `#EXT#` name.
- The members of the roles in Settings > Management UI access > **Directory roles that can open the management UI**: Global Administrator, Privileged Role Administrator, Security Administrator, Security Operator, or Exchange Administrator.

The settings page shows who has each role now. Only active, direct role assignments for the whole tenant count (not a role scoped to an administrative unit). A PIM-eligible role counts only while it is active. A role assigned through a group does not count. The monitor reads role assignments from Microsoft Graph (`RoleManagement.Read.Directory`) and keeps the result for 5 minutes, so a change can take 5 minutes to apply.

All people with access have the same rights: settings, mutes, and the response buttons. Every UI admin can weaken detection: give access only to security administrators. Each change is in History and is emailed to the alert mailbox, also with "Webhook only" delivery. To see which account you are signed in with, and why it has access, select your name at the top right.

Any user of the tenant can sign in to the management UI app. A user without access sees an error that names this section. Ask an admin of the monitor to add you.

---

## Use a custom domain

Optional. The default address always works. To open the management UI at, for example, `https://monitor.contoso.com/api/manage`:

1. Azure portal > the Function App > **Custom domains** > **Add custom domain**. Add the DNS records that the portal shows (a CNAME record and a TXT record) and a certificate.
2. Entra admin center > **App registrations** > `m365-ato-monitor-admin-ui` > **Authentication** > **Add URI**: `https://monitor.contoso.com/.auth/login/aad/callback`.
3. Allow the new origin, so that changes in the UI work: `az functionapp cors add -g <resource group> -n <function app> --allowed-origins https://monitor.contoso.com`. Without it, a change fails with HTTP 403. Azure Monitor sends the Azure change alert for this step: it is expected.

A rerun of `install.ps1` keeps the redirect URI and the CORS entry. The links in the alert emails keep the default address.

## Respond from the management UI

Management UI > **Users** > enter the UPN. The button "Open in the management UI" in each alert email opens this page.

The page shows the user's alerts for 90 days, sign-in countries, mutes, and account state. It has these actions:

| Action | What it does | Graph permission |
|---|---|---|
| **Revoke sessions** | Ends refresh tokens and browser sessions. Access tokens already issued stay valid until they expire (usually within about 1 hour) | `User.RevokeSessions.All` |
| **Block sign-in** | Sets Account enabled to off, then revokes sessions | `User.EnableDisableAccount.All`, `User.Read.All`, `User.RevokeSessions.All` |
| **Unblock sign-in** | Sets Account enabled to on | `User.EnableDisableAccount.All`, `User.Read.All` |
| **Show inbox rules** | Lists the server-side inbox rules with their risk signs | `MailboxSettings.Read` or `MailboxSettings.ReadWrite` (always granted) |
| **Turn off** / **Turn on** (a rule) | Turns the inbox rule off or on. The rule is kept for investigation | `MailboxSettings.ReadWrite` |

`install.ps1` grants `User.RevokeSessions.All`, `User.EnableDisableAccount.All`, `User.Read.All`, and `MailboxSettings.ReadWrite` together: the response permissions. The script asks for them (default yes), or use `-ResponsePermissions yes`. A button is disabled, with the reason, when the permission is not granted. To grant the permissions later, run `./install.ps1 -ResponsePermissions yes`.

Rules:

- The alert mailbox cannot be blocked: the monitor sends every alert from it.
- You cannot block your own account.
- Graph refuses changes to admin accounts (the app has no directory role). The page shows "failed: HTTP 403". Change admin accounts in the Entra admin center.
- The page does not reset passwords. Reset the password in the Microsoft 365 admin center.
- Each action is recorded in History and emailed ("Response action by ...").

## Search the audit log of a user

Management UI > **Users** > the user > **Audit log**. Select the period (7, 30, 90, or 180 days) and **Search**.

- The list shows everything the user did: sign-ins, mail reads and sends (`MailItemsAccessed`, `Send`), inbox rules, and admin changes. Newest first, with the IP address and the client. At most 1,000 records.
- **Network** and **Location** show the proxycheck.io answer for each IP: the network (organization, ASN), the risk score, the type (for example VPN or Hosting), and the city and country. A VPN, proxy, hosting, or high-risk IP is marked **Flagged**. Answers in the cache cost no query. Each load looks up at most 20 new IPs, newest first; **Look up more** looks up the next ones. When the daily quota is low or used up, the list looks up no new IPs: the monitor keeps the quota for its checks.
- Microsoft runs the search in the background. It typically takes 5 to 40 minutes. You can leave the page: the last search for the user shows again when you come back (for 30 days).
- Use it after an alert: compare the IP addresses of the sign-ins with the IP addresses of the mail reads and sends.
- Each search is recorded in History, with who started it.

---

## Check that mail reads are logged

Mail that an attacker reads or sends with a stolen session leaves no inbox rule. Only `MailItemsAccessed` and `Send` records show it. Microsoft does not document for every license if these records are logged.

Management UI > **Overview** > Monitor > **Mail access records, 7 days** shows the count. The weekly report has the same line.

- A count above zero: the tenant logs mail access. The line also shows how many records have a client IP, a session ID, and an app ID.
- "None" after some days of normal use: the tenant does not log mail reads. Check the mailbox audit settings in Exchange Online PowerShell:

  ```powershell
  Get-Mailbox <user> | Select-Object -ExpandProperty AuditOwner
  ```

  If `MailItemsAccessed` is not in the list, your licenses may not include it.

The mail access check (Settings > New sign-in countries > **Alert on mail read or sent from a risky IP**) uses these records. It alerts when mail is read or sent from a VPN, proxy, hosting, Tor, or new-country IP that did not sign in as the user in 7 days. Without mail access records, it does nothing. See [Alert Triage: mail_access](TRIAGE.md#mail_access).

---

## Run the onboarding scan

The scan starts by itself after the first monitor run. It sends one email, `[M365 Monitor] Starting state`, with:

- Audit history, last 7 days: the detectors run on the audit content of the feed. The feed has content only from when the audit subscription started. For a new deployment, this is normally empty.
- Audit history, older: the detectors run on older changes (not sign-ins) from the audit log search, up to 180 days back. Microsoft runs the search in the background. It typically takes 5 to 40 minutes and can take up to 48 hours, so the report can come some hours after the scan starts. Uses `AuditLogsQuery.Read.All`. `install.ps1` always grants it. If Microsoft stops the search at its record limit, the report says so.
- Sign-ins: VPN, proxy, and hosting sign-ins in the last 7 days. During the learning period, the countries of the other sign-ins go into the country baseline (at most 300 IP lookups).
- Inbox rules: the rules of every mailbox, through Microsoft Graph. This finds rules that existed before the monitor started. Signs: external forwarding or redirect, delete, keywords with mark-as-read, move, or delete, and names with no letters. Graph does not show rules that only Outlook desktop runs, and the app cannot read the name of a rule's target folder. Uses `User.ReadBasic.All` and `MailboxSettings.Read` (or `MailboxSettings.ReadWrite`). `install.ps1` always grants them.
- Checks the scan cannot do (mailbox forwarding, app consents, admin roles, MFA methods, mail flow rules, domains), with the place to check each one by hand.
- Settings that weaken protection.

No separate alert email is sent for the items in the report. Each item is on the user page in the management UI.

The scan runs in the background. Each step works for up to 75 seconds; the next step starts 5 minutes later. The total time depends on the number of mailboxes and on Graph response times. Management UI > Overview > Tools shows the progress.

To run it again: Management UI > Overview > Tools > **Scan inbox rules** (rules only) or **Run the full scan again**. For example, run it after you take over a new tenant, or after an incident.

---

## Receive the weekly report

Each Monday at 07:17 UTC, the monitor sends `[M365 Monitor] Weekly report`. It shows:

- How many runs completed (about 5,040 in a week) and how many sign-ins the monitor checked.
- Problems: missed runs, coverage gaps, errors, queued emails, waiting IP checks, old audit content, an unfinished onboarding scan.
- The week's alerts by type, with muted and turned-off alerts counted.
- Settings that weaken protection (also in the monthly report): tenant-wide Mail.Send, alert types off, active mutes, sign-in email level, country and session checks off, allowlists.

If no report arrives on a Monday, the monitor did not run. To turn the report off: Management UI > Settings > Alerts > **Weekly health report**.

The run and sign-in counts come from Application Insights. If the query fails, the report says so and still lists the alerts.

---

## Send alerts to more addresses or a ticket system

1. Management UI > Settings > Email.
2. Enter one address per line:
   - **Extra recipients of alerts**: every `[M365 Alert]` email, for example a ticket system.
   - **Extra recipients of reports**: the weekly, monthly, and starting-state reports, for example an outside vCISO.
3. Select **Save changes**, then confirm.

The change applies from the next email. It is recorded in History and emailed. The alert mailbox still sends and receives every email. The extra addresses can be outside the tenant. Alert emails contain user names, IP addresses, and audit records: send them only to addresses that may see this data.

---

## Label emails with the tenant name

If you receive alerts from more than one tenant, set Management UI > Settings > Email > **Tenant name in subjects**, for example `Contoso`. Subjects then start with `[M365 Alert][Contoso]` or `[M365 Monitor][Contoso]`. A mail rule that matches `[M365 Alert]` still works. The name is at most 40 characters, with no `[` or `]`.

---

## Ignore mobile carrier networks (ASNs)

proxycheck.io can flag IPs of mobile carriers (shared carrier NAT) as proxy or VPN. Each such sign-in then causes a suspicious sign-in alert. To stop these alerts for a whole network:

1. Find the ASN in an alert email: Details > the network, for example `T-Mobile USA, AS21928`.
2. Management UI > Settings > Allowlists > **Allowed networks (ASNs)**. Add one ASN per line, for example:

   ```
   AS21928
   ```

3. Select **Save changes**, then confirm.

US examples (check the ASN in your own alerts): T-Mobile USA `AS21928`, Verizon Wireless `AS6167` and `AS22394`, AT&T Mobility `AS20057`.

An IP in an allowed network is never VPN, proxy, or hosting for sign-in alerts and for the severity of compromise alerts. New-country, session, and compromise alerts still apply. Attackers can rent IPs in mobile carrier networks ("mobile proxies"), so allow only the networks that cause false alerts. Do not allow cloud or CDN networks (for example Akamai or Cloudflare). For iCloud Private Relay, see the next section.

---

## Handle iCloud Private Relay (Safari on iPhone and Mac)

Users with iCloud+ can turn on iCloud Private Relay. Safari then sends traffic, including Microsoft 365 sign-ins, through Apple relay servers. The sign-in IP is a relay egress IP on Akamai, Cloudflare, or Fastly networks, which IP reputation services flag as VPN or proxy.

The monitor handles this by default (**Treat iCloud Private Relay as normal**, on):

- It downloads Apple's list of relay egress IPs (`https://mask-api.icloud.com/egress-ip-ranges.csv`, about 12 MB) at most once a day.
- A sign-in from a relay IP causes no suspicious sign-in alert and uses no proxycheck.io query.
- The country of a relay IP comes from Apple's list. Apple maps each relay IP to the user's approximate location, so the new-country and session checks still work.
- Compromise alerts (inbox rules, forwarding, MFA changes, and others) are not affected.

`/api/status` shows the list state under `config.private_relay_list` (ranges loaded, load time, last failure). If the download fails, relay IPs are checked by proxycheck.io as before, and the monitor tries again after 1 hour.

To check relay IPs like any other IP: Management UI > Settings > Allowlists > clear **Treat iCloud Private Relay as normal**. Relay sign-ins then cause VPN alerts again, with "iCloud Private Relay" in the network name.

An attacker with an Apple device and iCloud+ can also use Private Relay. The monitor then sees the country that Apple assigns to the attacker's location, which the new-country and session checks still compare.

---

## Add corporate IPs to the allowlist

Do this if VPN or office egress IPs cause sign-in alerts.

1. Management UI > Settings > Allowlists > **Allowed IPs and ranges**.
2. Add one IP or range per line, for example `203.0.113.0/24`.
3. Select **Save changes**, then confirm.

Single IPs and CIDR ranges are both valid. The app ignores and logs an entry that is not valid. The allowlist applies to sign-in alerts. It does not stop compromise alerts.

---

## Add internal mail domains

The forwarding checks (inbox rules, mailbox forwarding, mail flow rules, folder sharing) treat the acting user's mail domain as internal. Forwarding to another domain causes an alert. If the tenant has more than one accepted domain, add the others. Include the `onmicrosoft.com` domain if admins use it:

1. Management UI > Settings > Allowlists > **Internal mail domains**.
2. Add one domain per line, for example `contoso.onmicrosoft.com`.
3. Select **Save changes**, then confirm.

---

## Add or replace the proxycheck.io key

Without a key, proxycheck.io allows 100 IP lookups per day. A free key from the [proxycheck.io dashboard](https://proxycheck.io/dashboard/) allows 1,000.

1. Management UI > Settings > Suspicious sign-ins > **proxycheck.io API key**.
2. Paste the key. Select **Save changes**.

The key is stored in Table Storage. The UI never shows it again. History and the change email show only "(set)" or "(replaced)". To replace the key, enter a new one. `install.ps1` does not ask for the key and does not change it.

`/api/status` shows `proxycheck_io: ok (status=ok)` when the key works. `status=denied` means that the quota is used or the key is not valid.

### Check the proxycheck.io quota

Management UI > Overview > Monitor > **IP lookups (proxycheck.io)** shows the state from the newest lookup answer: OK, Low (less than 10% left), Used up, or Refused (for example a disabled key). With a key, it also shows the count used today. For the count, turn on **Dashboard API Access** in the proxycheck.io dashboard. The monitor reads the count every 30 minutes; it does not use the quota.

The monitor emails the alert mailbox when the quota is low (80% used, or proxycheck.io says less than 10% is left), when it is used up, and when proxycheck.io refuses the key. Each email comes at most once per day. The weekly report also lists it.

When the quota is used up, sign-in and new-country checks wait in a queue for up to 26 hours. The stolen session and mail access checks skip records. Account takeover alerts are still sent, without the IP reputation. To use fewer lookups, add office and VPN addresses to Allowed IPs.

---

## Change the risk score threshold

proxycheck.io gives each IP a risk score from 0 to 100. The default threshold is 33. A lower value gives more alerts.

1. Management UI > Settings > Suspicious sign-ins > **Risk score threshold**.
2. Set a value, for example `50`. Select **Save changes**.

---

## Change the polling interval or the lookback

| Item | Location | Procedure |
|---|---|---|
| Timer interval | `@app.timer_trigger(schedule=...)` in `function/function_app.py` | Edit the cron. Run `./install.ps1 -Update`. |
| Lookback | Management UI > Settings > Advanced > **Fetch window** (`LOOKBACK_MINUTES`) | Range 3–60. |

Each run fetches the last `LOOKBACK_MINUTES` of content. A failed alert is tried again while its content stays in that window. Keep the lookback larger than the timer interval.

The app also stores a checkpoint for each content type. After an outage, the next run starts at the checkpoint. It goes back at most `MAX_CATCHUP_MINUTES` (`max(60, 3 × LOOKBACK_MINUTES)`). An older checkpoint causes a "Coverage gap" error in the log.

A 1-minute timer seldom gives earlier alerts: Microsoft publishes audit content with a delay of minutes. 2 minutes is the recommended minimum.

---

## Change which suspicious sign-ins send email

1. Management UI > Settings > Suspicious sign-ins > **Which suspicious sign-ins send email**:
   - `low`: every suspicious sign-in (default). VPN users cause alerts.
   - `medium`: VPN, hosting, Tor, SOCKS, compromised server, or risk score 66 or more.
   - `high`: Tor, SOCKS, compromised server only.
   - `off`: no sign-in email.
2. Select **Save changes**.

The app always logs suspicious sign-ins to Application Insights and counts them in the roll-up. `/api/status` shows the active value.

A failed sign-in (wrong password, for example error 50126) from a suspicious IP, an automation client, or an attack tool does not send email by default. The Alerts page shows it with the status "alert type off". To email failed sign-ins too, for example to see each IP of a password spray, turn on Settings > Suspicious sign-ins > **Email failed sign-ins** (`LOGIN_ALERT_FAILED`). A password spray can then cause many emails: use digest mode (next section) to batch them.

A sign-in whose password was correct, but that stopped at MFA or Conditional Access (for example errors 50074 and 50076), always sends email. The attacker knows the password.

---

## Detect sign-ins from new countries

The app learns the countries of each user's successful sign-ins. It alerts when a user signs in from a country that is not in their baseline. This works for residential IPs, which the suspicious-IP check does not flag.

Rules:

- The first 14 days (`GEO_LEARNING_DAYS`) are a learning period. All countries go into the baseline. No country alerts are sent.
- Countries in `HOME_COUNTRIES` (for example `US,CA`) are never anomalous. If you set it, alerts for other countries start immediately.
- A user with no baseline (for example a new user) is compared with the countries of all users.
- One alert per user and country in 24 hours.
- A new country becomes normal for the user after successful sign-ins on 3 different days (`GEO_PROMOTE_DAYS`), for example during travel.
- A country leaves the baseline after 90 days with no sign-in (`GEO_BASELINE_DAYS`).
- A failed sign-in whose error shows a correct password (for example 50074 or 50076: MFA required) also causes an alert. It never joins the baseline.
- Sign-ins from VPN, proxy, and hosting IPs are not used. They cause a suspicious-sign-in alert instead.
- IP geolocation can be wrong, mostly for mobile networks.

To set home countries: Management UI > Settings > New sign-in countries > **Home countries**. Add one code per line, for example `US`.

To approve a country for one user (travel): Management UI > **Countries** > look up the user > **Approve**. A new-country alert email has a link that opens this page for the user.

To turn the feature off: Management UI > Settings > New sign-in countries > clear **Alert on a sign-in from a new country**. The Overview page shows the learning state.

---

## Detect a stolen session

A stolen session cookie (AiTM phishing) or token (infostealer) keeps the session ID of the original sign-in. The unified audit log carries that ID in sign-in records and in most Outlook on the web and Exchange records. The monitor records the countries and IPs of each session for 30 days. It sends an alert when:

- A session appears in a second country. High, or medium if the new country is a home country or a usual country for the user.
- A session that started on a normal network is used in the same country from a VPN, proxy, hosting, or Tor IP that did not sign in as the user. This is a token used without a new sign-in. Medium, or high for Tor. One alert per session.

Allowed IPs do not count. Microsoft-owned networks are checked because Azure hosts customer VMs. Exchange Graph REST records are excluded only when the record identifies both the REST client and the Graph resource: those IPs belong to the service, not the client. Each new IP in a session uses one proxycheck.io query (a clean answer is cached for 7 days, a flagged one for 24 hours).

To turn it off: Management UI > Settings > New sign-in countries > **Alert when a session moves to another country or a risky IP**.

Limits: an attacker on a normal home or office network in the same country is not detected, and records without a session ID (Outlook desktop, some API access) are not checked. See README > What it does not detect.

---

## Respond automatically to a new-country sign-in

The app can act on a **successful** sign-in from a new country:

| Action (`ANOMALY_ACTION`) | Effect | Graph permissions |
|---|---|---|
| `none` (default) | Email only | None |
| `revoke` | Revoke sign-in sessions | `User.RevokeSessions.All` |
| `disable` | Block sign-in, then revoke sessions | `User.EnableDisableAccount.All`, `User.Read.All`, `User.RevokeSessions.All` |

Safeguards:

- No action during the learning period, and no action for a sign-in that did not complete.
- The alert mailbox and the accounts in **Never change these accounts** (`ANOMALY_ACTION_EXEMPT`) are never changed. Put break-glass and admin accounts there.
- At most 3 actions per UTC day (`ANOMALY_ACTION_MAX_PER_DAY`).
- The app has no directory role, so Graph refuses changes to admin accounts. The alert then shows "failed: HTTP 403". The same error appears if admin consent for the new permission is missing.
- Revoke stops refresh tokens and browser sessions. Access tokens already issued stay valid until they expire, usually within about 1 hour.
- The audit record arrives some minutes to 1–2 hours after the sign-in, so the action comes that much later.
- The app does not reset passwords. A reset needs a safe way to give the user the new password. Reset it by hand.

To turn it on:

1. Check that the response permissions are granted: Management UI > Overview > Access > **Graph permissions**. If they are not, run `./install.ps1 -ResponsePermissions yes`. The script grants admin consent.
2. Management UI > Settings > Automatic response:
   - **Never change these accounts**: add break-glass and admin accounts, one per line.
   - **Action on a sign-in from a new country**: select the action. An option without its permission is disabled.
3. Select **Save changes**.

To pause the response, select **Email only** in the UI. The permissions stay granted.

To undo a block: Entra admin center > Users > the user > Edit properties > select **Account enabled**. Or run `az ad user update --id <upn> --account-enabled true`.

---

## Respond automatically to account-takeover alerts

The monitor can act on a high alert about an account, in addition to the email:

| Alert (high) | Account action (`COMPROMISE_ACTION`) | Inbox rule action |
|---|---|---|
| Stolen session, inbox rule, mailbox forwarding, attack tool, legacy authentication, and device code, MFA change, or automation client raised to high by the source IP | Revoke sessions, or block sign-in and revoke sessions | Turn off the rule (inbox rule alerts) |

Not included: admin changes (mail flow rules, roles, audit, domains; the actor is an admin, and Graph refuses changes to admins) and OAuth consents (revoking sessions does not remove an app's access). The password is never changed. Reset it by hand.

Which account the action changes:

- Sign-in alerts (stolen session, attack tool, legacy authentication, device code, automation client): the account that signed in.
- Changes (inbox rule, mailbox forwarding, MFA change): the account that was changed, only if the same account made the change. For an MFA method, also when a Microsoft service wrote the record (the user added the method in My Sign-Ins).
- A change that one account made to another account, for example an admin who set forwarding on a user's mailbox: no account action. Either account can be the compromised one. The email shows both accounts ("Changed by", "Changed account") and says why nothing was done.
- The record must name the changed account by its address, by an alias that matches the account that made the change, or by its Entra ID object ID. For any other name, the monitor does not act.

1. Check that the response permissions are granted: Management UI > Overview > Access > **Graph permissions**. If they are not, run `./install.ps1 -ResponsePermissions yes`. This grants `User.RevokeSessions.All`, `User.EnableDisableAccount.All`, `User.Read.All`, and `MailboxSettings.ReadWrite`, with admin consent.
2. Management UI > Settings > Automatic response:
   - **Never change these accounts**: add break-glass and admin accounts.
   - **Action on a high account-takeover alert**: select the action.
   - **Turn off malicious inbox rules**: on.
3. Select **Save changes**.

The alert email says what was done, for example "Automatic response: sessions revoked, inbox rule turned off". The same exempt list and daily limit (**Maximum account actions per day**, default 3) apply to both account actions. Turning off an inbox rule does not count toward the limit.

The inbox rule is turned off, not deleted, so it stays for investigation. The monitor finds it by name, or by its external recipient. A rule that only Outlook desktop runs (client-side) is not visible to Graph; the email then says the step failed.

If you grant the response permissions after the monitor started (`-ResponsePermissions yes` on a rerun), the consent record for the monitor's own app sends no email and is not shown in Alerts. To limit that permission to some mailboxes, use RBAC for Applications with the role "Application MailboxSettings.ReadWrite" (as in [Limit Mail.Send](#limit-mailsend-to-the-alert-mailbox)).

---

## Batch sign-in alerts into a digest

1. Management UI > Settings > Suspicious sign-ins > **Email format**: **One digest email**.
2. Optional: set **Digest delay (minutes)** (default `60`).
3. Select **Save changes**.

The app queues each suspicious sign-in in Table Storage. When the oldest queued sign-in is `LOGIN_DIGEST_MINUTES` old, the next run sends one email for all queued sign-ins. `LOGIN_ALERT_CONFIDENCE` still applies. Compromise alerts do not change: they always send immediately.

Digest mode needs Table Storage (`STORAGE_ACCOUNT_NAME`, which `install.ps1` sets). Without it, the app sends immediate emails. If you change back to `immediate`, the next run sends the sign-ins that are still in the queue.

---

## Make alert links open the exact user

The link in an alert opens the user if the audit record has the user's object ID. Otherwise it opens the user list, and you search for the UPN. To always open the user:

1. Management UI > Settings > Advanced > **Link alerts to the exact user**: on.
2. Select **Save changes**.

The setting uses the `User.ReadBasic.All` application permission. `install.ps1` always grants it.

The app then does one Graph lookup per new user. It caches the result in Table Storage (`useridcache`).

`PORTAL_BASE_URL` changes the base URL of these links only. The app itself supports the commercial cloud only.

---

## Add a user agent to the detection list

1. Management UI > Settings > Detection lists > **Attack tool user agents** (high alert) or **Automation user agents** (medium alert).
2. Add one value per line. The match is a case-insensitive substring match. Select **Save changes**.

---

## Change the inbox rule keywords

An inbox rule is a medium alert if a condition has one of these words and the rule marks the mail as read, moves it, or deletes it. Attackers use such rules to hide replies about payments and security warnings.

1. Management UI > Settings > Detection lists > **Inbox rule keywords**.
2. Add or remove one word or phrase per line. The match is a case-insensitive substring match. Select **Save changes**.

Rules that forward externally, delete, or move to a hidden folder are high alerts with or without a keyword.

---

## Add an OAuth scope to monitor

1. Management UI > Settings > Detection lists > **High-risk OAuth scopes**.
2. Add one scope per line, for example `Calendars.ReadWrite`. Select **Save changes**.

The match is case-insensitive. It covers delegated consent and application permissions (app role assignments).

---

## Test the alerts

There are three levels. Use them in this order.

### 1. Synthetic test (no changes to the tenant)

A synthetic audit record for each alert type goes through the real detectors and the real email code. Each email has `[SELF-TEST]` in the subject. Use it after a deployment, after a code change, and to see how each email looks in your mail client.

- Management UI > Overview > **Test alerts**. Select the alert types, then **Send test emails**. **Check detectors (no email)** checks all detectors and sends nothing.
- Or from the command line:

  ```powershell
  ./install.ps1 -Verify                   # status, and every alert type with no email
  ./install.ps1 -Verify -SendTestAlerts   # also one email for each alert type (18 emails)
  ```

- Or call `/api/selftest?type=all&alert=true` (function key). `type` takes `all` or a comma-separated list, for example `type=mfa_change,admin_role`.

The synthetic test does not read the Management API or proxycheck.io. The two sign-in emails use a fixed IP result.

### 2. Live test (real changes on a test mailbox)

`scripts/live-test.ps1` makes the changes that an attacker makes, on a dedicated test mailbox, and undoes them at once. Microsoft writes an audit record for each change, and the monitor sends a real alert when the record arrives: often within minutes, sometimes 1–2 hours later. This tests the full path: unified audit log, Management API, detectors, IP lookup, and email.

Before you start:

1. Create a licensed test user with a mailbox, for example `ato-test@contoso.com`. Do not use a person's mailbox or an admin account.
2. Pick an outside address that you control, for example a personal mailbox. No mail goes to it.
3. Install PowerShell 7 and the modules:

   ```powershell
   Install-Module ExchangeOnlineManagement -Scope CurrentUser
   Install-Module Microsoft.Graph.Authentication -Scope CurrentUser   # for -IncludeEntra
   ```

Run it:

```powershell
./scripts/live-test.ps1 -TestUser ato-test@contoso.com -ExternalAddress me@example.net
./scripts/live-test.ps1 -TestUser ato-test@contoso.com -ExternalAddress me@example.net -IncludeEntra
```

| Test | Change (undone at once) | Expected alert |
|---|---|---|
| InboxRuleForward | Inbox rule that forwards to the outside address. It matches a subject that never occurs. | HIGH Inbox rule |
| InboxRuleHidden | Inbox rule named `.` that marks "invoice" mail as read and deletes it | HIGH Inbox rule |
| MailboxForwarding | Mailbox forwarding to the outside address, for a few seconds | HIGH Mailbox forwarding |
| MailFlowRule | Mail flow rule with a BCC to the outside address, created turned off | HIGH Mail flow rule |
| MailboxFullAccess | Full Access to the test mailbox for your admin account | MEDIUM Mailbox access |
| InboxShared | Test mailbox Inbox shared with everyone (Reviewer) | MEDIUM Mailbox access |
| AuditBypass | Audit bypass on the test user | HIGH Audit off |
| ExchangeRole | Exchange role "View-Only Recipients" for the test user | MEDIUM Admin role |
| AttackToolSignIn | One failed sign-in (wrong password) for the test user with user agent `AADInternals` | HIGH Attack tool sign-in, in Alerts with the email status "alert type off". An email only if **Email failed sign-ins** is on |
| EntraRole (`-IncludeEntra`) | Entra role "Reports Reader" for the test user | MEDIUM Admin role |
| AppSecret (`-IncludeEntra`) | New app registration with a client secret | MEDIUM App credential |
| OAuthConsent (`-IncludeEntra`) | `Mail.Read` consent for that app, for the test user | HIGH OAuth consent |

The script prints the expected alerts. If a step fails, it says why and continues. `-Tests InboxRuleForward,MailFlowRule` runs only those tests. `-KeepMinutes 10` waits before the undo step. `-Cleanup` removes leftovers of an earlier run.

The Inbox share test uses the folder path `<user>:\Inbox`. If the test mailbox uses another language, the folder name can be different.

Microsoft can also send its own alert for some of these changes (for example the default "Creation of forwarding/redirect rule" policy). That is expected.

### 3. Manual tests (need the test user's sign-in)

| Test | How | Expected alert |
|---|---|---|
| Device code sign-in | `az login --use-device-code --allow-no-subscriptions`, sign in as the test user | MEDIUM Device code sign-in |
| MFA method added | As the test user (with MFA set up), add a second method at https://mysignins.microsoft.com/security-info | MEDIUM MFA change |
| Outlook desktop rule | In Outlook desktop as the test user, create a rule that forwards to the outside address | HIGH Inbox rule (`UpdateInboxRules`) |
| VPN or new country | Sign in as the test user through a VPN exit in another country | Suspicious sign-in; new country after the learning period (or with `HOME_COUNTRIES` set) |
| Session reuse | Sign in as the test user in a browser and open Outlook on the web. Keep the browser open, turn on a VPN with an exit in another country, and reload Outlook on the web. | HIGH Session reuse (the record must carry the session ID; Outlook on the web records do) |

Remove the second MFA method and the Outlook rule after the alerts arrive.

### If an alert does not arrive

Wait 3 hours. Then:

1. Run `./install.ps1 -Verify`. All checks must be `ok`.
2. Run the [Errors query](APP_INSIGHTS_QUERIES.md#errors).
3. Search Microsoft Purview > Audit for the change. If the record is there, compare it with [API Compatibility: record formats](API_COMPATIBILITY.md#record-formats). If the record is not there, Microsoft has not delivered it yet, or auditing is off for that action.

---

## Block Direct Send

Direct Send lets any server on the internet deliver mail to your users through your tenant's MX host (`<tenant>.mail.protection.outlook.com`) with a sender address in your own domains. Phishing campaigns use it to look like internal mail. The audit log does not show these messages, so the monitor cannot detect them. Block Direct Send instead (Exchange Online PowerShell):

```powershell
Set-OrganizationConfig -RejectDirectSend $true
```

Before you turn it on:

- Find the devices and apps that send to your users through the MX host with an address in your domain (printers, scanners, voicemail, alerting systems, some SaaS apps). Give each one a partner inbound connector (by IP or certificate), or move it to authenticated SMTP or Graph.
- Rejected messages get the error `550 5.7.68`.
- Mail forwarded to you by an outside system without SRS can be rejected.

Microsoft lists this setting as not yet generally available, with no fixed date. It is not available in GCC High or DoD. The monitor sends a high alert ("Mail protection weakened") if someone sets `RejectDirectSend` back to `False`.

---

## Limit Mail.Send to the alert mailbox

The monitor sends every email as the alert mailbox (`ADMIN_EMAIL`). With the Microsoft Graph application permission `Mail.Send`, the app could send as any mailbox in the tenant: code that runs in the Function App could send mail as your CEO. Exchange Online RBAC for Applications limits it to the alert mailbox. (RBAC for Applications replaces application access policies.)

`install.ps1` does this by default (`-MailSendScope mailbox`):

1. It makes the mail-enabled security group `<name>-senders` (default `m365-ato-monitor-senders`) in Exchange Online, hidden from the address list. The alert mailbox is the only member.
2. It adds the monitor app to Exchange Online and makes the management scope `<name>-senders scope`: the direct members of that group.
3. It gives the app the Exchange role "Application Mail.Send" in that scope (role assignment `<name>-senders Mail.Send`).
4. It checks the grant with `Test-ServicePrincipalAuthorization`. Then it removes the tenant-wide Graph `Mail.Send`, if the app has it. Graph and Exchange grants add up, so the limit has no effect while the Graph permission exists.

For this step the script needs the PowerShell module ExchangeOnlineManagement (it installs it for the current user if it is missing) and an Exchange Online sign-in with Exchange Administrator or Global Administrator. The script shows a URL and a code: open the URL in any browser, also on another computer, and enter the code within 15 minutes. This works in SSH and Azure Cloud Shell. The monitor sends a "Device code sign-in" alert for this sign-in; that alert is expected. Exchange applies a change in 30 minutes to 2 hours. Until then, alert emails wait in the outbox, and the monitor sends them later.

The app cannot change the group or the scope. So it cannot give itself the right to send as another mailbox.

The management UI shows the scope and the group under Overview > Access.

To change an existing installation from tenant-wide to the alert mailbox, run `./install.ps1 -MailSendScope mailbox`. A rerun without `-MailSendScope` keeps the current choice. `-Update` does not sign in to Exchange Online.

If the alert mailbox was changed in the management UI, `install.ps1` reads it from the running monitor and adds it to the group too.

An earlier version made a scope for one address with `scripts/restrict-mail-send.ps1` ("M365 ATO Monitor alert mailbox"). After the new grant works, `install.ps1` removes that scope and its role assignment. It also removes a role assignment of an earlier, deleted installation.

To go back to tenant-wide Mail.Send: run `./install.ps1 -MailSendScope tenant`. Then remove the Exchange objects in Exchange Online PowerShell:

```powershell
Get-ManagementRoleAssignment -Role 'Application Mail.Send' | Where-Object Name -like 'm365-ato-monitor-senders Mail.Send*' | Remove-ManagementRoleAssignment
Remove-ManagementScope 'm365-ato-monitor-senders scope'
Remove-DistributionGroup m365-ato-monitor-senders
```

After `-Uninstall`, also remove the app from Exchange Online: `Remove-ServicePrincipal <object ID of the deleted monitor app>`.

---

## Change the alert mailbox

The alert mailbox sends and receives every email. To add recipients and keep the sender, see [Send alerts to more addresses](#send-alerts-to-more-addresses-or-a-ticket-system).

1. The new address must be a licensed or shared mailbox in the tenant.
2. If Mail.Send is limited to the alert mailbox (the default; Overview > Access shows the group): add the new mailbox to the group `<name>-senders`. Microsoft 365 admin center > **Teams & groups** > **Active teams & groups** > the group > **Members**. Or Exchange admin center > **Recipients** > **Groups**. Wait 30 minutes to 2 hours: Exchange applies the change in that time.
3. Management UI > Settings > Email > **Alert mailbox**. Enter the new address.
4. Select **Save changes**, then confirm.

Before the save, the app sends a test email from the new mailbox to itself. If Microsoft Graph refuses, the save stops and the field shows the reason. After the save:

- The old address gets a notice.
- The Azure Monitor health alerts (no runs, errors) move to the new address. The app has the Monitoring Contributor role on that action group only.
- The change is in History and is emailed.

If the save stops with "The app can send only as a member of the Exchange group", the new mailbox is not in the group yet, or Exchange did not apply the change yet. Wait, then save again.

When the new mailbox works, remove the old mailbox from the group. Then the app can no longer send as it.

`-AdminEmail` of `install.ps1` sets the first value. A rerun of `install.ps1` (also `-Update`) does not revert a UI change. The plan of the rerun shows the alert mailbox that the monitor uses, with "(set in the management UI; it stays)" for a UI change. After a UI change, `-AdminEmail` on a rerun does not change the alert mailbox: the script warns. Change it in the UI.

---

## Check that the monitor runs

Management UI > **Overview**: the status summary at the top shows if monitoring runs normally and lists the items to check. The Monitor card shows the last complete fetch of each content type, and the queues. **Run dependency checks** tests each dependency.

From a terminal:

```powershell
./install.ps1 -Verify
```

All checks must show `ok`. In `/api/status`, `last_complete_fetch` shows the checkpoint of each content type. It must be less than 10 minutes old. For FAILED checks, see [Troubleshooting](GETTING_STARTED.md#6-troubleshooting).

Four Azure Monitor alerts send email through an action group. They do not use the app's credentials, so they work when the app cannot send email, and code that runs in the app cannot turn them off.

| Alert | Condition |
|---|---|
| `alert-<name>-no-runs` | No run completed in 1 hour |
| `alert-<name>-errors` | 5 or more errors in 1 hour |
| `alert-<name>-code-deployed` | Code was deployed to the monitor (a write to the `deployments` blob container) |
| `alert-<name>-azure-change` | A change to the monitor's Azure resources: app settings, sign-in settings, identity credentials, role assignments in the resource group, the storage account, Application Insights, or the alert rules. The app stopped or deleted |

`<name>` is the `-Name` of `install.ps1` (default `m365-ato-monitor`). The action group is `ag-<name>`. The health alerts (no runs, errors) send one email when they fire and one when they resolve. The two change alerts send one email for each change.

Expected change emails:

- `code-deployed` after each install, rerun, and `-Update` (the code deployment at the end). It can arrive up to 1 hour later.
- `azure-change` when you change the monitor in the Azure portal, or when `install.ps1` repairs or changes something. A rerun that finds everything correct changes nothing and sends no email.

An unexpected email means that someone with access to the resource group changed the monitor. That person can deploy code that runs with all the app's permissions. In the email, open the alert, then **Activity log** (for an Azure change) to see who made it. For a code deployment, check who has Contributor, Owner, or Website Contributor on the resource group, then run `./install.ps1 -Update` to deploy the code of this folder again.

To stop an alert: Azure portal > Monitor > Alerts > Alert rules > the rule > **Disable**. A rerun of `install.ps1` turns it on again.

`/api/status` also shows `queues` (outbox, pending IP checks, digest) and `last_content_seen`.

---

## Understand the retry queues

Three queues in the `processedevents` table keep alerts that cannot go out now:

| Queue (partition) | Content | Retry | Limit |
|---|---|---|---|
| `outbox` | Alert emails that Graph refused | Each run, oldest first | 7 days, then dropped with an error |
| `pendingip` | Sign-ins whose IP lookup failed (for example proxycheck.io quota used) | Each run, after the 5-minute failure cache | 26 hours (past the daily quota reset), then dropped with an error |
| `logindigest` | Digest-mode sign-ins | Each run | Sent when the oldest is `LOGIN_DIGEST_MINUTES` old |

A queued alert arrives late, not never. The errors alert reports a queue that does not empty.

---

## See recent activity

Management UI > **Overview** shows the alerts of the last 7 days and the recent emails.

Or call `/api/recent?hours=24&limit=50` with the function key in the `x-functions-key` header. Keep the key in a variable. Do not print it:

```powershell
$app = 'func-m365-ato-monitor-<6 hex>'   # the Function App name
$key = az functionapp keys list --resource-group rg-m365-ato-monitor --name $app --query functionKeys.default --output tsv
Invoke-RestMethod "https://$app.azurewebsites.net/api/recent?hours=24&limit=50" -Headers @{ 'x-functions-key' = $key }
```

---

## Query history in Application Insights

See [App Insights Queries](APP_INSIGHTS_QUERIES.md).

---

## Remove the monitor

```powershell
./install.ps1 -Uninstall
```

Use the same `-Name` and `-SubscriptionId` as for the install. The script does these steps:

1. Finds the resource group `rg-<name>` and the two app registrations (`<name>`, `<name>-admin-ui`). It shows what it found.
2. Asks you to type the resource group name. With `-Yes`, it does not ask.
3. Deletes the two app registrations.
4. Deletes the resource group and all resources in it. This runs in the background and takes some minutes.

This deletes the monitor, its settings, the history, and the findings journal. It cannot be undone. Run `./install.ps1 -Uninstall -DryRun` to see what it deletes.

The script does not change:

- The audit subscriptions of the tenant. They stay. They cost nothing, and a new installation uses them again.
- The tenant unified audit log.
- The deleted app registrations. They stay in Entra ID > App registrations > Deleted applications for 30 days. Purge them there to remove them now.

---

## Update the monitor

Get the new code, then deploy it:

```powershell
git pull
./install.ps1 -Update     # or: make deploy
```

`-Update` deploys the code of this folder and repairs the setup: the Azure resources, the app registrations, the admin consent, the health and change alerts, and App Service Authentication. Each `-Update` sends one "code deployed" email (alert `alert-<name>-code-deployed`). It keeps all settings: the alert mailbox, the management UI settings, the Mail.Send scope, and the response permissions. Use the same `-Name` and `-SubscriptionId` as for the install.

More than one tenant: `./install.ps1 -Tenant <domain> -Update` updates one installation, and `./install.ps1 -UpdateAll` updates each installation that `./install.ps1 -List` shows. See [Getting Started: Install in another tenant](GETTING_STARTED.md#install-in-another-tenant).

After an update, run `./install.ps1 -Verify`.

To change the permissions, run the script without `-Update` and with the new value, for example `./install.ps1 -ResponsePermissions no`. The script removes the Graph permissions that are no longer wanted.
