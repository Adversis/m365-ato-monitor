# Alert Triage

Use this guide when an alert email arrives. It tells you how to find out if an alert is real, how to contain an account, and when to get help. An AI assistant that helps you must also follow [For AI assistants](#for-ai-assistants).

The monitor detects attacker actions. It does not prevent them. An alert arrives when Microsoft publishes the audit record: often within minutes, sometimes 1–2 hours or more after the event. All times in the emails are UTC.

## First five minutes

Do these steps for each alert.

1. Read the subject: `[M365 Alert] <SEVERITY>: <alert type> - <user>`. If a tenant name is set (Settings > Email), the name follows the tag: `[M365 Alert][Contoso] HIGH: ...`.
   - If the subject has `[SELF-TEST]`, the alert is a test. No action is necessary.
   - The user in the subject depends on the alert type. For a sign-in, a mailbox rule, or forwarding, it is the affected account. For an admin-type change (roles, mail flow rules, domains, audit, mail protection, app credentials, mailbox access), it is the account that made the change. For an MFA method change, it is the account whose methods changed.
2. Read the first sentence of the email. It says what happened.
3. Read the colored notices:
   - The IP notice, for example "Source IP is VPN (...)" or "Source IP country BR is new for this user". This notice made the alert high.
   - The "Automatic response" notice says what the monitor did. If a step "Failed", do it by hand. An automatic response does not finish the work.
   - The "other alerts for this user in the last 24 hours" notice lists the earlier alerts about the same user. Two or more alerts about one user in 24 hours are one incident. Triage them together.
4. Read "What to do". If the first step starts with "If no one on your team made this change", confirm with the person who made it before you act.
5. Open the "Audit record" section (compromise alerts only). Read the fields that the section for the alert type (below) names. The suspicious sign-in and new-country emails have no audit record. For these emails, search Microsoft Purview > Audit for the record.
   The button "Open in the management UI" opens the user page. It shows all alerts about the user for 90 days, the user's sign-in countries, and the inbox rules. It has buttons to revoke sessions, block sign-in, and turn off an inbox rule.
6. Decide:

   | Decision | When | Next step |
   |---|---|---|
   | Real | The user or admin did not make the change, or the record shows signs of an attacker | [Contain an account](#contain-an-account) |
   | Expected | The user, or the admin who made the change, confirms it through a channel other than email | [Options for expected alerts](#options-for-expected-alerts) |
   | Not sure | You cannot reach the person, or the facts do not agree | Contain the account. Revoking sessions costs the user one sign-in |

7. Write down the alert, the time, your decision, and who confirmed it.

Ask the user by phone, in person, or in a chat that you trust. Do not ask by email. An attacker can read and answer the mail of a compromised account.

"Source IP: not in the record" is normal for Entra ID admin changes. In that case, the IP cannot make the alert high.

### Other emails

| Email | Meaning | What to do |
|---|---|---|
| `[M365 Alert] Settings changed by <user>` | Someone changed a setting in the management UI | If you did not expect it, undo it in the management UI. Check who has access: Settings > Management UI access, and the Monitor.Admin role. An attacker in the UI can weaken detection |
| `[M365 Alert] Alerts muted by <user>`, `Mute ended by <user>` | Someone added or ended a mute in the management UI | If you did not expect it, end the mute (Management UI > Mutes). Check who has access: Settings > Management UI access, and the Monitor.Admin role |
| `[M365 Alert] Response action by <user>` | Someone revoked sessions, blocked or unblocked sign-in, or turned an inbox rule off or on in the management UI | If you did not expect it, check the user in the management UI and the History |
| `[M365 Monitor] Weekly report` | Each Monday: the monitor ran, how many sign-ins it checked, the week's alerts, and settings that weaken protection | If "Check these" is shown, read it. If the report does not arrive on a Monday, the monitor did not run |
| `[M365 Monitor] Starting state` | The onboarding scan finished: past audit records, inbox rules of all mailboxes, and manual checks | Triage each item as an alert. Do the manual checks one time |
| `[M365 Monitor] Monthly report` | The 1st of each month: counts for 30 days, and settings that weaken protection | No action unless it shows items to review |
| Azure Monitor `alert-<name>-no-runs` or `alert-<name>-errors` | The monitor stopped, or errors repeat | Run `./install.ps1 -Verify`. See [Getting Started: Troubleshooting](GETTING_STARTED.md#6-troubleshooting) |

## Contain an account

Do these steps in this order for a real or unconfirmed alert. If the attacker is active now (new alerts after you revoke sessions, or mail goes out from the account), do step 8 (block sign-in) first.

1. **Revoke sessions.**
   - Management UI > Users > the user > **Revoke sessions** (needs `User.RevokeSessions.All`). Or: Entra admin center > Users > the user > **Revoke sessions**. Or: Microsoft 365 admin center > Users > Active users > the user > **Sign out of all sessions**.
   - This stops refresh tokens and browser sessions, also a stolen session cookie. Apps that are signed in already stop within about 15 minutes (Outlook, OneDrive, and Office apps: continuous access evaluation) or when their access token expires (60 to 90 minutes: web apps, other clients). See [How fast a revoke or block applies](HOW_TO.md#how-fast-a-revoke-or-block-applies).
   - A password reset alone does not end a stolen session.
2. **Reset the password.**
   - Microsoft 365 admin center > Users > Active users > the user > **Reset password**.
   - Give the new password to the user by phone or in person.
   - For an account that is synced from on-premises Active Directory, reset the password in Active Directory.
   - The monitor never changes passwords.
3. **Check the MFA methods.**
   - Entra admin center > Users > the user > **Authentication methods**.
   - Ask the user about each method. Delete each method that the user does not know.
   - Do this step immediately after step 2. If self-service password reset is on, an attacker's method can reset the password again.
   - The unified audit log does not show passkey, FIDO2, and Windows Hello registrations. The monitor cannot see them. Read the list.
   - Also open Entra admin center > Users > the user > **Devices**. Delete devices that the user does not know.
4. **Check inbox rules and forwarding.**
   - Outlook on the web, as the user > Settings > Mail > **Rules**, and Settings > Mail > **Forwarding**.
   - Exchange admin center > Mailboxes > the user > Mail flow settings > **Email forwarding**.
   - Exchange Online PowerShell (read-only):

     ```powershell
     Get-InboxRule -Mailbox <upn> -IncludeHidden | Format-List Name,Enabled,ForwardTo,ForwardAsAttachmentTo,RedirectTo,DeleteMessage,MoveToFolder,MarkAsRead
     Get-Mailbox <upn> | Format-List ForwardingSmtpAddress,ForwardingAddress,DeliverToMailboxAndForward
     Get-MailboxPermission <upn> | Where-Object { -not $_.IsInherited }
     Get-RecipientPermission <upn>
     ```

   - Management UI > Users > the user > **Show inbox rules** lists the server-side rules with their risk signs. **Turn off** keeps the rule for investigation (needs `MailboxSettings.ReadWrite`).
   - Record the details of a rule before you remove it.
   - Microsoft Graph cannot see a rule that only Outlook desktop runs. Check Outlook desktop on the user's computer: File > Manage Rules & Alerts.
5. **Check app consents.**
   - Entra admin center > Enterprise applications > All applications. Look for apps that you do not know, especially new ones.
   - For each such app: Permissions > **User consent**. Find out if the user gave consent.
   - Remove the access of an app that you do not know: Permissions, or delete the app (Properties > Delete).
   - Revoking sessions and a password reset do not remove an app's access.
6. **Check mail sent from the account.**
   - Exchange admin center > Mail flow > **Message trace**. Search for messages from the user since the first suspicious event.
   - Look for many recipients, external recipients, one subject sent to many people, and replies in threads about payments.
   - Attackers delete the mail that they send. Check Sent Items and Deleted Items with the user.
   - If phishing went out, warn the recipients by phone or from another account.
   - If Microsoft blocked the account from sending, go to Microsoft Defender portal > Email & collaboration > Review > **Restricted entities**.
7. **Check sign-ins.**
   - Entra admin center > Users > the user > **Sign-in logs**. Without Entra ID P1, the portal keeps 7 days. With P1, it keeps 30 days and shows Conditional Access results.
   - For older sign-ins: Microsoft Purview > Audit. Enter the user in **Users** and `UserLoggedIn`, `UserLoginFailed` in **Activities - operation names**. Audit (Standard) keeps records for 180 days.
   - Find the first sign-in that the user did not make. Write down its IP, country, app (`ObjectId`), and user agent. Search for the same IP in the sign-ins of other users.
   - If you have Entra ID P2, read Entra admin center > ID Protection > **Risky users** and **Risky sign-ins**.
8. **Block sign-in, if necessary.**
   - Block sign-in if one of these is true:
     - The attacker is still active.
     - An admin account is involved.
     - You cannot reach the user about a high alert.
     - Mail goes to many recipients.
     - You need time for steps 2–7.
   - Management UI > Users > the user > **Block sign-in** (also revokes sessions). Or: Entra admin center > Users > the user > Edit properties > Settings > clear **Account enabled**. Or: Microsoft 365 admin center > Users > Active users > the user > **Block sign-in**.
   - For an account that is synced from Active Directory, disable it in Active Directory.
   - Revoke sessions again after the block.
   - To enable the account again: Management UI > Users > the user > **Unblock sign-in**. Or: Entra admin center > Users > the user > Edit properties > Settings > select **Account enabled**. Or run `az ad user update --id <upn> --account-enabled true`.

After containment, watch for new alerts about the user for some days. Tell the user what happened and how the attacker got in.

## Alert types

Every compromise alert, except session reuse and mail access, becomes high if its source IP is a VPN, proxy, or hosting address, or is in a country that is new for the user.

| Type | Subject text | Severity | Confirm first | Automatic response |
|---|---|---|---|---|
| [`suspicious_signin`](#suspicious_signin) | Suspicious sign-in | Low, medium, or high (IP confidence) | — | None |
| [`new_country`](#new_country) | Sign-in from new country | High | — | `ANOMALY_ACTION` |
| [`session_reuse`](#session_reuse) | Session reuse | High, or medium | No | If high |
| [`mail_access`](#mail_access) | Mail access from a risky IP | High or medium | No | If high |
| [`legacy_auth`](#legacy_auth) | Legacy auth sign-in | High | No | If high |
| [`device_code`](#device_code) | Device code sign-in | Medium | Yes | If high |
| [`attack_tool`](#attack_tool) | Attack tool sign-in | High | No | If high |
| [`suspicious_user_agent`](#suspicious_user_agent) | Automation client sign-in | Medium | Yes | If high |
| [`inbox_rule`](#inbox_rule) | Inbox rule | High or medium | No | If high; can also turn off the rule |
| [`mailbox_forwarding`](#mailbox_forwarding) | Mailbox forwarding | High or medium | No | If high |
| [`mailbox_delegation`](#mailbox_delegation) | Mailbox access | Medium | Yes | No |
| [`oauth_consent`](#oauth_consent) | OAuth consent | High | No | No |
| [`mfa_change`](#mfa_change) | MFA change | Medium, or high | Yes | If high |
| [`admin_role`](#admin_role) | Admin role | High or medium | Yes | No |
| [`app_credential`](#app_credential) | App credential | Medium | Yes | No |
| [`domain_federation`](#domain_federation) | Domain federation | High or medium | Yes | No |
| [`audit_disabled`](#audit_disabled) | Audit off | High | Yes | No |
| [`mail_flow_rule`](#mail_flow_rule) | Mail flow rule | High or medium | Yes | No |
| [`mail_protection_weakened`](#mail_protection_weakened) | Mail protection | High or medium | Yes | No |

- **Confirm first:** the email asks you to confirm with the person who made the change before you treat the account as compromised.
- **Automatic response:** off by default. If `COMPROMISE_ACTION` is set, a high alert of this type revokes sessions (or blocks sign-in and revokes sessions) for the affected account. The affected account is the account that signed in, or the account that was changed if the same account made the change. A change that one account made to another gets no action. The monitor does not change exempt accounts, the alert mailbox, or admin accounts. The default limit is 3 account actions per day.

<a id="suspicious_signin"></a>
## suspicious_signin — Suspicious sign-in

Subject: `[M365 Alert] <LOW|MEDIUM|HIGH>: Suspicious sign-in - <user> from <IP>, <result>`. In digest mode: `[M365 Alert] <HIGH|MEDIUM>: <n> suspicious sign-ins`.

**What it means.** proxycheck.io flagged the source IP of a sign-in: VPN, Tor, proxy, hosting, or a risk score at or above the threshold. This is a weaker signal than a compromise alert. Many of these alerts are legitimate VPN use.

**How to check it is real.**
- The email has no audit record. Read the Details: `Result`, `Source IP`, `IP type`, `Risk score`, `Network`, `Location`.
- Read the result first:

  | Result in the subject | Meaning |
  |---|---|
  | `success` | The sign-in completed. Someone has a session |
  | `correct password` | The password was correct. MFA or a policy stopped the sign-in (for example 50074, 50076: MFA required). The person who signed in knows the password |
  | `failed` | The sign-in failed. 50126 is a wrong user name or password. The `Result` row explains other codes |

- Compare the network with the user's usual sign-ins: Entra admin center > Users > the user > Sign-in logs. Does the user use this VPN? Is it the office?
- For the full record: Microsoft Purview > Audit, operation `UserLoggedIn` or `UserLoginFailed`, the user, the time. Read `ClientIP`, `ExtendedProperties` (`UserAgent`, `RequestType`), `ErrorNumber` or `LogonError`, and `ObjectId` (the app the user signed in to).
- Many failed sign-ins for one user, or from one IP for many users, are a password spray. Search the sign-in logs for the IP.

**Common benign causes.** The company VPN. A personal VPN. A cloud desktop or remote desktop service on a hosting network. A mobile carrier network that proxycheck.io classifies as proxy. iCloud Private Relay, if **Treat iCloud Private Relay as normal** is off.

**If real.**
- `success`: [contain the account](#contain-an-account).
- `correct password`: reset the password now. Check the MFA methods. Ask the user about MFA prompts that they did not start. Tell them to deny such prompts.
- `failed` with a wrong password: the attacker did not get in. Check that every user has MFA (Security Defaults or Conditional Access). Watch for more attempts.

**If benign.** For a company VPN or office with fixed IPs, add the IPs to **Allowed IPs and ranges**. For a mobile carrier, add its ASN to **Allowed networks (ASNs)**. If you get too many emails, use digest mode or change **Which suspicious sign-ins send email**. Each option hides something: see [Options for expected alerts](#options-for-expected-alerts).

**Severity.** The badge shows the IP confidence, not the result. High: Tor, compromised server, or a proxy with recorded attacks. Medium: VPN, other proxy, hosting, inference engine, or risk 66 or more. Low: risk at or above the threshold. A `success` or `correct password` result needs action at each level.

**How often.** One sign-in writes several audit records, seconds apart (one for each app). The monitor sends one alert for each user, IP, and result (success or failure) in a UTC day. A success after failures from the same IP sends a second alert. Some records have the user "Not Available": the monitor takes the user from another record of the same sign-in session, or from the record's actor.

<a id="new_country"></a>
## new_country — Sign-in from a new country

Subject: `[M365 Alert] HIGH: Sign-in from new country <CC> - <user>, <result>`.

**What it means.** A sign-in came from a country that is not in the user's usual countries. The result was a success, or a correct password that MFA or a policy stopped. The IP was not flagged as VPN, proxy, or hosting, so this alert also covers home and office connections.

**How to check it is real.**
- The email has no audit record. Read `Result`, `Country`, `Usual countries`, `Source IP`, `Network`, `City`. For a user with no history, the usual countries are the countries of all users.
- Ask the user where they are.
- Compare with the user's other sign-ins: Entra admin center > Users > the user > Sign-in logs. A sign-in from the usual country a short time before or after is a strong sign of an attacker.
- Read the network. A home internet provider in a country where the user is not is a strong sign. "iCloud Private Relay" means that the country is Apple's estimate of the user's location.
- Look for other alerts about the user in the next hours: session reuse, inbox rule, MFA change.
- For the full record: Microsoft Purview > Audit, `UserLoggedIn` or `UserLoginFailed`, the user, the time.

**Common benign causes.** Travel. A VPN exit that proxycheck.io does not flag. Wrong IP geolocation, mostly on mobile networks. A user who comes back after more than 90 days. A new user.

**If real.** `correct password`: reset the password now. The attacker knows it. `success`: [contain the account](#contain-an-account).

**Automatic response.** With `ANOMALY_ACTION` set, the monitor revokes sessions, or blocks sign-in and revokes sessions, after a successful sign-in. It does not act during the learning period, for a sign-in that did not complete, for an exempt account, or after the daily limit. The notice in the email says what it did, or why it did nothing. If it blocked a legitimate user, enable the account: Entra admin center > Users > the user > Edit properties > **Account enabled**.

**If benign.** Approve the country for the user: use the link in the email, or Management UI > Countries. A country also becomes usual after successful sign-ins on 3 different days. For countries where all users work, set **Home countries**.

**Severity.** Always high. At most one alert per user and country in 24 hours. No alerts in the first 14 days (learning period) unless **Home countries** is set.

<a id="session_reuse"></a>
## session_reuse — Session reuse

Subject: `[M365 Alert] HIGH: Session reuse - <user>`. Email title: "Session used from a second country or a risky IP".

**What it means.** One Entra session (one session ID) was used from one country, then from another. Or the session started on a normal network, and then a mailbox record in the same country came from a VPN, proxy, hosting, or Tor IP. That IP did not sign in as the user. The session token was used without a new sign-in. The usual cause is a stolen session cookie (AiTM phishing) or a stolen token (infostealer).

**How to check it is real.**
- The first sentence names both IPs and the second network. For two countries, it also names both countries and the minutes between them. The notice says where the session started.
- Fields: `Operation` (for example `UserLoggedIn` or `MailItemsAccessed`), `ClientIP` or `ClientIPAddress`, `DeviceProperties` (`SessionId`), `SessionId`, `AppAccessContext` (`AADSessionId`), `ClientInfoString`.
- Compare: Is the second network a hosting or VPN provider? Is the time between the countries shorter than travel needs? Did the user change networks?
- Ask the user where they are, and if they use a VPN.
- Look next: Microsoft Purview > Audit, the user, the hours around both times. Export the results and search the file for the full session ID from the record.
- Look for mail that the user got just before the first sign-in. An AiTM phishing link often arrives by email.

**Common benign causes.** The user turned a VPN on or off while the browser was open. A company proxy or web gateway with exits in other countries. Travel. Wrong geolocation on a mobile network.

**If real.** [Contain the account](#contain-an-account). Revoke sessions first: that ends the stolen session. A password reset alone does not. Find the phishing email. Find who else got it: Exchange admin center > Mail flow > Message trace.

**If benign.** Add fixed company VPN or proxy IPs to **Allowed IPs and ranges**: the session check ignores them. Approving a country for the user makes the alert medium. It does not stop it.

**Severity.** Two countries: high, or medium if the new country is a home country or usual for the user. One alert per session and country. Same country, risky IP: medium, or high for a Tor or compromised-server IP, or a proxy with recorded attacks. One alert per session. A sign-in from the risky IP gives a suspicious sign-in alert instead. Mail reads and sends from the risky IP give a [`mail_access`](#mail_access) alert instead, unless that check is off.

<a id="mail_access"></a>
## mail_access — Mail access from a risky IP

Subject: `[M365 Alert] MEDIUM: Mail access from a risky IP - <user>` (or HIGH). Email title: "Mail read or sent from a risky IP".

**What it means.** Mail of the user was read (`MailItemsAccessed`) or sent (`Send`) from an IP that is a VPN, proxy, hosting, or Tor address, or that is in a new country for the user. No sign-in of the user came from this IP in the last 7 days. A stolen session cookie or refresh token gives that pattern. The attacker reads and sends mail from their own network. A token refresh writes no sign-in record.

**How to check it is real.**
- The first sentence gives the count of reads and sends, the IP, its network, and the clients (for example `Client=OWA`, `Client=MSExchangeRPC`). It lists the subjects of sent messages.
- Fields: `Operation`, `ClientIPAddress`, `ClientInfoString`, `SessionId`, `MailboxOwnerUPN`, `Item.Subject` (Send), `OperationProperties` (`MailAccessType`: `Bind` opens messages, `Sync` downloads a folder).
- Open the user page > **Audit log** (last 7 days). Compare the IPs of the sign-ins with the IPs of the mail reads and sends. Look for the same `SessionId` on a sign-in from another IP.
- Ask the user if they used a VPN, a hotel or guest network, or a new phone at that time.
- For sent mail: find the recipients with message trace (Exchange admin center > Mail flow > Message trace). `Send` records do not list recipients.

**Common benign causes.** A VPN that the user turned on after they signed in. Outlook mobile on a VPN or a mobile network that a lookup service classifies as hosting. A travel router or hotel network.

**If real.** [Contain the account](#contain-an-account). Revoke sessions first: that ends the stolen session or token. Tell the recipients of the sent mail that it is not genuine. Look for payment or bank detail changes in the threads.

**If benign.** Add the company VPN to **Allowed networks (ASNs)** or **Allowed IPs and ranges**. Mute a medium alert for one user for some days ([Mutes](HOW_TO.md#mute-an-expected-alert)).

**Severity.** High if the IP is Tor or a similar anonymizer, or if mail was sent or a folder was downloaded from a VPN, proxy, or hosting IP. Otherwise medium. One alert per user, IP, and day. The check works only if the tenant logs mail access: Management UI > Overview > **Mail access records**.

<a id="legacy_auth"></a>
## legacy_auth — Legacy auth sign-in

Subject: `[M365 Alert] HIGH: Legacy auth sign-in - <user>`. Email title: "Sign-in with legacy authentication".

**What it means.** A sign-in with legacy authentication (`BAV2ROPC`) succeeded. The password alone was enough: MFA did not apply. Password spray tools use this path.

**How to check it is real.**
- Fields: `Operation` (`UserLoggedIn`), `ExtendedProperties` (`UserAgent` contains `BAV2ROPC`), `ClientIP`, `ObjectId` (the app).
- Compare `ClientIP` with your office IP. A printer or scanner at the office uses the office IP.
- Look for the same account and IP in earlier sign-ins. A device signs in on a regular schedule.
- Ask IT if a device or an app signs in with this account.

**Common benign causes.** A printer or scanner that sends mail with SMTP AUTH. An old mail client (IMAP, POP). A business app that sends mail with a user name and password.

**If real.** [Contain the account](#contain-an-account). Block legacy authentication: Entra admin center > Overview > Properties > Manage security defaults (on), or a Conditional Access policy (Entra ID P1).

**If benign.** Move the device or app to a method without legacy authentication, for example an SMTP relay connector or Microsoft Graph. Until then, each sign-in causes an alert. A mute does not hide this alert, because it is always high.

**Severity.** Always high.

<a id="device_code"></a>
## device_code — Device code sign-in

Subject: `[M365 Alert] MEDIUM: Device code sign-in - <user>`. Email title: "Sign-in with a device code".

**What it means.** A sign-in with the device code flow succeeded: the user entered a code on microsoft.com/devicelogin. In device code phishing, the attacker sends the code, the user signs in, and the attacker gets the tokens without the password.

**How to check it is real.**
- Fields: `ExtendedProperties` (`RequestType` is `Cmsi:Cmsi`, `UserAgent`), `ClientIP`, `ObjectId` (the app that gets the token), `DeviceProperties`.
- Ask the user by phone if they entered a code, and for which device or tool.
- The IP in the record can be the user's own IP, because the user enters the code in their own browser. A normal IP does not show that the sign-in is safe.
- Look for mail or Teams messages that the user got just before. A meeting invitation or a document with a code is a common lure.
- Look next: Entra admin center > Users > the user > Sign-in logs and Devices (a new registered device).
- `install.ps1` uses a device code for the Exchange Online sign-in (`-MailSendScope mailbox`). An alert for the admin who ran it, at that time, to the app "Microsoft Exchange REST API Based Powershell", is expected. Confirm with that admin.

**Common benign causes.** Azure CLI or PowerShell with a device code sign-in. A Teams Rooms or meeting room device. A smart TV or a shared device. The manual test in [How-To: Test the alerts](HOW_TO.md#test-the-alerts).

**If real.** [Contain the account](#contain-an-account). Revoke sessions first: the attacker has tokens, not the password. Delete registered devices that the user does not know. If you have Entra ID P1, block the device code flow in a Conditional Access policy for users who do not need it.

**If benign.** A one-time sign-in needs no change. For a device that signs in often, see [Options](#options-for-expected-alerts).

**Severity.** Medium. High if the source IP is flagged or in a new country for the user.

<a id="attack_tool"></a>
## attack_tool — Attack tool sign-in

Subject: `[M365 Alert] HIGH: Attack tool sign-in - <user>`. Email title: "Sign-in with an attack tool".

**What it means.** The user agent of a sign-in names an attack tool: AADInternals, ROADtools, GraphRunner, Gophish, or Evilginx (or an entry that you added). A correct password stopped by MFA or Conditional Access counts too. A failed sign-in with a wrong password sends email only if **Email failed sign-ins** is on. If it is off, the sign-in is in Alerts with the email status "alert type off".

**How to check it is real.**
- Fields: `Operation` (`UserLoggedIn` is a success, `UserLoginFailed` is a failure), `ExtendedProperties` (`UserAgent`), `ClientIP`, `ErrorNumber` or `LogonError`, `ObjectId`.
- Read the error: 50126 is a wrong password. 50074 or 50076 means that the password was correct and MFA stopped the sign-in.
- Ask your security team or provider if a penetration test or an admin task ran at that time.
- Search the sign-in logs for the IP. The same IP on other users is a password spray.

**Common benign causes.** An authorized penetration test. An admin who uses AADInternals or ROADtools for troubleshooting. The live test (`scripts/live-test.ps1`, test AttackToolSignIn).

**If real.** A success or a correct password: [contain the account](#contain-an-account). A failed sign-in with a wrong password: someone attacks the account but does not have the password. Do the steps in the email. Check that the user has MFA.

**If benign.** Confirm the test with the person who ran it. No change is necessary.

**Severity.** Always high.

<a id="suspicious_user_agent"></a>
## suspicious_user_agent — Automation client sign-in

Subject: `[M365 Alert] MEDIUM: Automation client sign-in - <user>`. Email title: "Sign-in with an automation client".

**What it means.** The user agent of a sign-in names an automation library: python-requests, Python-urllib, Go-http-client, axios, node-fetch, undici, curl, or PowerShell (or an entry that you added). Some AiTM phishing kits sign in with these libraries. A correct password stopped by MFA or Conditional Access counts too. A failed sign-in with a wrong password sends email only if **Email failed sign-ins** is on.

**How to check it is real.**
- Fields: `Operation`, `ExtendedProperties` (`UserAgent`), `ClientIP`, `ObjectId` (the app), `UserId`.
- Compare: Is the account a service account, or an admin who runs scripts? Is the IP your server, your office, or a cloud host that you use? Does the sign-in repeat on a schedule?
- Ask IT who runs scripts with this account.

**Common benign causes.** IT scripts. Backup, sync, or migration tools. Monitoring tools. A developer who tests an app.

**If real.** [Contain the account](#contain-an-account).

**If benign.** **Allowed IPs and ranges** does not stop this alert. A mute can stop the medium alert for the confirmed case. Do not remove the library from **Automation user agents**: that hides it for all users.

**Severity.** Medium. High if the source IP is flagged or in a new country for the user.

<a id="inbox_rule"></a>
## inbox_rule — Inbox rule

Subject: `[M365 Alert] HIGH: Inbox rule - <user>` (or MEDIUM). Email title: "Suspicious inbox rule".

**What it means.** A user, an admin, or an app made or changed an inbox rule that matches an attacker pattern. Attackers use rules to forward mail out, or to hide replies and security warnings from the user.

**How to check it is real.**
- Fields: `Operation` (`New-InboxRule`, `Set-InboxRule`, `Enable-InboxRule`, or `UpdateInboxRules` from Outlook desktop or EWS), `UserId`, `ClientIP`, `ClientInfoString`.
- Rule details in `Parameters`: `Name` or `Identity`, `ForwardTo`, `ForwardAsAttachmentTo`, `RedirectTo`, `DeleteMessage`, `SoftDeleteMessage`, `MoveToFolder`, `MarkAsRead`, and the conditions (`SubjectContainsWords`, `SubjectOrBodyContainsWords`, `FromAddressContainsWords`).
- For `UpdateInboxRules`, read `OperationProperties`: `RuleName`, `RuleOperation`, `RuleActions`, `Actions`, `ServerRule`.
- `ClientInfoString`: `Client=OWA` is Outlook on the web. `Client=MSExchangeRPC` is Outlook desktop. `Client=WebServices;<user agent>` is EWS (a script or an app).
- Compare these items:
  - A name such as `.`, `..`, or one letter.
  - A forward to a free mail service.
  - A condition on words such as invoice, payment, or password.
  - The IP against the user's sign-ins.
  - The time against other alerts for the user.
- If `UserId` is not the mailbox owner, an admin or a delegate made the rule.
- A recipient shown as "name (directory)" is an X.500 address: a mailbox, group, or contact in your directory. Outlook writes it when the person picks the recipient from the address book. The monitor flags it as unverified because it cannot resolve the final address. A contact can point outside your organization. Check it in Microsoft 365 admin center > Contacts. Confirm the destination and the rule with the user before you take action.
- The alert lists what the rule does (Actions) and for which mail (Conditions). For a rule that the onboarding scan found, the email has no audit record: open the rule on the user page (Management UI > Users > the user > Inbox rules).
- Look next: `Get-InboxRule -Mailbox <upn> -IncludeHidden`. Microsoft Purview > Audit: the user's `UserLoggedIn` records in the hours before the rule.

A rule that only deletes mail (no forward, no hidden folder, no payment or security words) sends email only with one of these contexts:

- Another alert for the user in the 7 days before.
- A rule IP that is flagged, new for the user, or not checked.
- A sign-in from a new network in the 24 hours before.

The alert names the context. Without a context, the rule is in the alert list as "Known sign-in", with no email.

**Common benign causes.** The user moves newsletters to RSS Feeds or deletes mail from one sender. The user forwards to a personal address (a policy problem and a data leak, but not an attack). A rule for an assistant. A migration or archive tool (EWS).

**If real.**
- Record the rule details. Then remove the rule: Outlook on the web > Settings > Mail > Rules, or the Exchange admin center.
- Find which mail went out: Exchange admin center > Mail flow > Message trace, with the forward address as the recipient.
- [Contain the account](#contain-an-account) in `UserId`.
- With **Turn off malicious inbox rules**, the notice says "inbox rule turned off". The monitor keeps the rule, turned off. Remove it after you record the details.

**If benign.** The tenant's verified domains are internal. If the forward address is in a domain outside the tenant that belongs to your organization, add the domain to **Internal mail domains**. If the monitor turned off a legitimate rule, turn it on again in Outlook. For a confirmed rule that alerts again, see [Options](#options-for-expected-alerts).

**Severity.**

- High:
  - Forwards or redirects to an external address.
  - Deletes.
  - Moves to a hidden folder (Deleted Items, RSS Feeds, RSS Subscriptions, Junk Email, Conversation History, Calendar).
  - Was made with an attack tool or automation library.
- Medium:
  - A name with no letters or digits.
  - A 1–2 character name on a rule that hides mail.
  - A listed keyword with mark-as-read, move, or delete.

<a id="mailbox_forwarding"></a>
## mailbox_forwarding — Mailbox forwarding

Subject: `[M365 Alert] HIGH: Mailbox forwarding - <user>` (or MEDIUM). Email title: "Mailbox forwarding set".

**What it means.** `Set-Mailbox` set forwarding for a whole mailbox. All new mail goes to the forward address.

**How to check it is real.**
- Fields: `UserId` (who made the change), `ClientIP`, `Parameters`: `Identity` (the mailbox), `ForwardingSmtpAddress`, `ForwardingAddress`, `DeliverToMailboxAndForward` (`False`: no copy stays in the mailbox).
- If `UserId` is the mailbox owner, the user (or an attacker in the user's session) set it in Outlook on the web > Settings > Mail > Forwarding. If `UserId` is an admin, ask that admin.
- Is the target a known person or system? `DeliverToMailboxAndForward` `False` hides the mail from the user.
- Look next: Exchange admin center > Mailboxes > the user > Mail flow settings > Email forwarding.

**Common benign causes.** An admin forwards the mail of a former employee to a manager (internal: medium). A shared mailbox forwards to a help desk system. A user forwards to a personal address (a policy problem).

**If real.** Remove the forwarding. Find which mail went to the forward address: Exchange admin center > Mail flow > Message trace. [Contain the account](#contain-an-account) in `UserId`.

By default, the outbound spam policy blocks automatic forwarding to external addresses. Do not rely on it. An admin can allow it, and the monitor then sends a [Mail protection](#mail_protection_weakened) alert.

**If benign.** The tenant's verified domains are internal. If the forward address is in a domain outside the tenant that belongs to your organization, add the domain to **Internal mail domains**.

**Severity.** High if the address is external. Medium for an internal recipient.

<a id="mailbox_delegation"></a>
## mailbox_delegation — Mailbox access

Subject: `[M365 Alert] MEDIUM: Mailbox access - <user>`. Email title: "Mailbox access granted".

**What it means.** Someone got access to a mailbox: Full Access, Send As, Send on behalf, or a mail folder shared with everyone in the organization, with anyone, or with an external address. Attackers use this to read a mailbox, or to send fraud mail as a finance user.

**How to check it is real.**
- The user in the subject made the change. The description names the mailbox and the account that got access.
- Fields: `Operation` (`Add-MailboxPermission`, `Add-RecipientPermission`, `Set-Mailbox`, `Add-MailboxFolderPermission`, `Set-MailboxFolderPermission`, `UpdateFolderPermissions`), `UserId`, `Parameters` (`Identity`, `User`, `Trustee`, `AccessRights`, `GrantSendOnBehalfTo`).
- For folder sharing from Outlook: `Item` > `ParentFolder` (`Path`, `MemberUpn`, `MemberRights`), `MailboxOwnerUPN`, `ClientIPAddress`.
- Compare: Is the grantee a known person? An external address? A new account? Did a ticket ask for the change? Ask the mailbox owner.
- Look next: Exchange admin center > Mailboxes > the mailbox > Delegation.

**Common benign causes.** An assistant gets access to a manager's mailbox. A shared mailbox setup. A manager gets the mailbox of a former employee. A migration or backup tool. An admin gives themselves access to investigate (this causes an alert too).

**If real.** Remove the permission: Exchange admin center > Mailboxes > the mailbox > Delegation, or `Remove-MailboxFolderPermission` for a folder. Find what the delegate read or sent: Microsoft Purview > Audit. [Contain the account](#contain-an-account) that made the change.

**If benign.** A one-time change needs no tuning.

**Severity.** Medium. High if the source IP is flagged or in a new country for the user.

<a id="oauth_consent"></a>
## oauth_consent — OAuth consent

Subject: `[M365 Alert] HIGH: OAuth consent - <user>`. Email title: "Risky OAuth consent".

**What it means.** A user or an admin gave an app a high-risk permission, for example `Mail.Read`, `Mail.Send`, `EWS.AccessAsUser.All`, `full_access_as_app`, or `Files.ReadWrite.All`. In consent phishing, the attacker's app gets access to the mailbox without the password. The access stays after a password reset.

**How to check it is real.**
- Fields: `Operation` (`Consent to application.`, `Add delegated permission grant.`, `Add OAuth2PermissionGrant.`, `Add app role assignment to service principal.`), `UserId` (who gave consent), `Target` (type 1 is the app name), `ModifiedProperties` (`ConsentAction.Permissions` or `AppRole.Value` for the scopes, and `ServicePrincipal.DisplayName`).
- If the record has `ConsentContext.IsAdminConsent` with `True`, an admin gave consent for all users.
- Open the app: Entra admin center > Enterprise applications > the app. Read Properties (publisher, creation date) and Permissions (User consent, Admin consent).
- Compare: Does your organization use this app? Is its name close to the name of a known app? Did the user get a link by email just before?
- Look next: Microsoft Purview > Audit, `Consent to application.`, for other users and the same app.

**Common benign causes.** An admin approves a known business app (backup, mail signatures, CRM, scheduling). A user connects a mail or calendar app. A permission that `install.ps1` grants to the monitor's own app (for example `Mail.Send` or `MailboxSettings.ReadWrite`) is not emailed and not shown in the management UI or the reports. The monitor knows such a grant by the app ID and the roles that the install's choices give. For an earlier run with other choices than now, it also uses the account and the time of that run (`INSTALL_GRANTS`). A grant of another risky scope to the monitor's app still sends this alert: investigate it.

**If real.** Remove the app's access: Permissions, or delete the app if you do not know it. Find what the app read: Microsoft Purview > Audit. Check the other users who gave consent. Restrict user consent: Entra admin center > Enterprise applications > Consent and permissions > User consent settings.

**If benign.** A consent is a one-time event for each user and app. No change is necessary. Do not remove the scope from **High-risk OAuth scopes**: that hides the scope for all apps.

**Severity.** Always high. The automatic response does not act on this alert: revoking sessions does not remove an app's access.

<a id="mfa_change"></a>
## mfa_change — MFA change

Subject: `[M365 Alert] MEDIUM: MFA change - <user>` (or HIGH). Email title: "MFA changed".

**What it means.** One of these changes occurred:

- An MFA method was added or changed on an account that already had MFA.
- Per-user MFA was turned off.
- Tenant MFA settings were changed (for example, trusted IPs that skip MFA).

An attacker adds a method to keep access after a password reset.

**How to check it is real.**
- The user in the subject is the account whose MFA changed. For tenant MFA settings, it is the account that made the change.
- Fields: `Operation` (`Update user.`, `Disable Strong Authentication.`, `Set Company Information.`), `ModifiedProperties` (`StrongAuthenticationMethod`, `StrongAuthenticationPhoneAppDetail` with the Authenticator `DeviceName`, `StrongAuthenticationUserDetails` with the phone numbers, `StrongAuthenticationPolicy` for the tenant), `Target` (type 5 is the account), `UserId`, `Actor`.
- `UserId` `ServicePrincipal_...` with the actor "Azure MFA StrongAuthenticationService": someone with the user's sign-in registered the method. A UPN in `UserId`: an admin made the change. Confirm with that admin.
- Ask the user by phone about the new device name or phone number.
- Compare the time with other alerts about the user. A new method soon after a suspicious sign-in, a new country, or session reuse is a strong sign of an attacker.
- Look next: Entra admin center > Users > the user > Authentication methods.

**Common benign causes.** A new phone. A second method as a backup. The help desk resets the user's MFA. An admin moves users from per-user MFA to Security Defaults or Conditional Access. A planned change to trusted IPs.

**If real.** Delete the methods that the user does not know. [Contain the account](#contain-an-account). If an admin that you do not know turned off per-user MFA or changed tenant settings, treat that admin account as compromised and [escalate](#when-to-escalate).

**If benign.** A one-time change needs no tuning.

**Severity.** Medium. High: per-user MFA turned off, the source IP is flagged or new for the user, or the user had another alert in the 7 days before.

A method replaced, an Authenticator device replaced, or the default method changed counts as a change too. A first MFA registration and a method removed do not cause an alert. All methods removed (an admin's "Require re-register MFA") is listed in Alerts as "Listed, no email". The next sign-in registers a new method, so check that the user did it.

A method added by the user or by an admin sends no email if both of these are true:

- The sign-in of the person who made the change (in the hour before) came from a network that they used before. A new network also counts if its IP is clean (not VPN, proxy, hosting, or Tor) and its provider (ASN) is one that they signed in from before, for example their mobile carrier.
- Neither the user nor the admin had another alert in 7 days.

The change then shows in the alert list as "Known sign-in". The alert says which case applies: another alert, a sign-in from a new network (its IP), or no sign-in seen. After an install or the update that adds this, the monitor loads 30 days of past sign-ins from the audit log, once. While a user's network history is shorter than 14 days, a change sends no email unless there was another alert ("Known sign-in", the reason says so).

The alert names the methods before and after the change, marks the default method, and lists changed phone numbers, email, and Authenticator devices. Signs of an attacker: a new phone number or email that the user does not know, the default changed to a text message or voice call, or an Authenticator method removed. The monitor cannot see passkey, FIDO2, and Windows Hello registrations.

<a id="admin_role"></a>
## admin_role — Admin role

Subject: `[M365 Alert] HIGH: Admin role - <user>` (or MEDIUM). Email title: "Admin role assigned".

**What it means.** A member was added to an Entra ID role, or an Exchange management role was assigned. An attacker with admin access gives a role to an account that they control.

**How to check it is real.**
- The user in the subject made the change. The description names the new member and the role.
- Fields: `Operation` (`Add member to role.` or `New-ManagementRoleAssignment`), `ModifiedProperties` (`Role.DisplayName`), `Target` (type 5 is the new member), `UserId`, `Actor`. For Exchange: `Parameters` (`Role`, `User`, `SecurityGroup`, `App`).
- Compare: Was the change planned, with a ticket? Is the new member a real employee? Is it a new account? Search Microsoft Purview > Audit for `Add user.` and the member's name.
- Look next: Entra admin center > Roles and administrators > the role.

**Common benign causes.** Planned admin onboarding. A help desk role for a new technician. A role for a project. Setup work by a partner or MSP.

**If real.** Remove the member. Contain both accounts: the account that made the change and the new member. Find what the new admin did: Microsoft Purview > Audit. [Escalate](#when-to-escalate).

**If benign.** A one-time change needs no tuning.

**Severity.** High: Global Administrator, Privileged Role Administrator, Privileged Authentication Administrator, or the Exchange role ApplicationImpersonation. Medium: other roles. The automatic response does not act on admin changes.

<a id="app_credential"></a>
## app_credential — App credential

Subject: `[M365 Alert] MEDIUM: App credential - <user>`. Email title: "App credential added".

**What it means.** A secret or certificate was added to an app registration or a service principal. With it, someone can sign in as the app, with no user and no MFA. Attackers add a credential to an app that already has wide permissions.

**How to check it is real.**
- The user in the subject made the change. The description names the app.
- Fields: `Operation` (`Update application – Certificates and secrets management` or `Add service principal credentials.`), `Target` (type 1 is the app name), `ExtendedProperties` (`targetName`), `ModifiedProperties` (`KeyDescription`), `UserId`, `Actor`.
- Compare: Which permissions does the app have (Entra admin center > Enterprise applications > the app > Permissions)? Is the person who added the credential an owner or developer of the app?
- A credential on a service principal does not show in App registrations > Certificates & secrets. Use Microsoft Graph PowerShell (read-only): `Get-MgServicePrincipal -ServicePrincipalId <id> | Format-List PasswordCredentials,KeyCredentials`.

**Common benign causes.** A planned secret rotation. A developer sets up an integration. The live test (test AppSecret).

**If real.** Delete the credential. Find what the app accessed: Microsoft Purview > Audit. Review the app's permissions. [Contain the account](#contain-an-account) that added the credential.

**If benign.** A one-time change needs no tuning.

**Severity.** Medium. High if the source IP is flagged or in a new country for the user.

<a id="domain_federation"></a>
## domain_federation — Domain federation

Subject: `[M365 Alert] HIGH: Domain federation - <user>` (or MEDIUM). Email title: "Domain or federation changed".

**What it means.** Federation was set on a domain, or a domain was added or verified. The owner of a federation server can sign in as any user of that domain, without a password or MFA. Attackers use this as a backdoor.

**How to check it is real.**
- Fields: `Operation` (`Set domain authentication.`, `Set federation settings on domain.`, `Add-FederatedDomain`, `Add domain to company.`, `Verify domain.`, `Add verified domain.`, `Add unverified domain.`), `Parameters` (`DomainName`) or `Target`, `ModifiedProperties`, `UserId`, `Actor`.
- Compare: Was a single sign-on project (AD FS, Okta, or another identity provider) planned? Is the domain yours?
- Look next: Microsoft 365 admin center > Settings > Domains. Microsoft Graph PowerShell (read-only): `Get-MgDomainFederationConfiguration -DomainId <domain>`. The issuer and the sign-in URL must point to your identity provider.

**Common benign causes.** A planned single sign-on setup. A new company or marketing domain.

**If real.** Remove the federation or the domain. Treat the account that made the change as compromised. [Escalate](#when-to-escalate) immediately.

**If benign.** A one-time change needs no tuning.

**Severity.** High: federation set on a domain. Medium: a domain added or verified.

<a id="audit_disabled"></a>
## audit_disabled — Audit off

Subject: `[M365 Alert] HIGH: Audit off - <user>`. Email title: "Audit logging turned off".

**What it means.** An admin turned off unified audit logging, or mailbox auditing for the organization or for one mailbox, or set audit bypass for an account. Attackers do this to hide their actions. If unified audit logging is off, the monitor gets no more records and sends no more alerts.

**How to check it is real.**
- Fields: `Operation` (`Set-AdminAuditLogConfig`, `Set-OrganizationConfig`, `Set-MailboxAuditBypassAssociation`, `Set-Mailbox`), `Parameters` (`UnifiedAuditLogIngestionEnabled`, `AuditDisabled`, `AuditBypassEnabled`, `AuditEnabled`, `Identity`), `UserId`, `ClientIP`.
- Ask the admin in `UserId` by phone. Is there a documented reason?
- Check the current state (read-only): `Get-AdminAuditLogConfig | Format-List UnifiedAuditLogIngestionEnabled`.
- Look next: Microsoft Purview > Audit, all actions of the admin account before the change.

**Common benign causes.** Rare. A backup or archive vendor asks for audit bypass on its service account. The live test (test AuditBypass).

**If real.** Turn auditing on again (the email gives the commands). Contain the admin account. [Escalate](#when-to-escalate).

**If benign.** If no documented reason exists, turn auditing on again. A mute does not hide this alert.

**Severity.** Always high. If no audit content arrives for 48 hours, the monitor logs an error and the Azure Monitor errors alert sends an email.

<a id="mail_flow_rule"></a>
## mail_flow_rule — Mail flow rule

Subject: `[M365 Alert] HIGH: Mail flow rule - <user>` (or MEDIUM). Email title: "Mail flow rule changed".

**What it means.** A mail flow (transport) rule was made or changed. It copies, redirects, or deletes mail, routes mail through a connector, or skips spam filtering. A mail flow rule applies to all mailboxes.

**How to check it is real.**
- The user in the subject made the change. Only an admin can make this change.
- Fields: `Operation` (`New-TransportRule`, `Set-TransportRule`), `Parameters` (`Name`, `BlindCopyTo`, `RedirectMessageTo`, `CopyTo`, `AddToRecipients`, `DeleteMessage`, `RouteMessageOutboundConnector`, `SetSCL`, the conditions, and `Enabled` or `Mode` if present), `UserId`, `ClientIP`.
- Compare: Is the target address a vendor that you use? Do you know the connector? Exchange admin center > Mail flow > Connectors.
- Look next: Exchange admin center > Mail flow > Rules.

**Common benign causes.** An archive or compliance service that gets a copy. A mail signature service that routes mail through a connector. A phishing simulation vendor whose mail must skip spam filtering (SCL -1). Planned work by an MSP.

**If real.** Turn off or remove the rule. Find which mail the rule copied or deleted: Exchange admin center > Mail flow > Message trace. Treat the admin account as compromised. [Escalate](#when-to-escalate).

**If benign.** If the target is in another domain of your organization, add the domain to **Internal mail domains**.

**Severity.**

- High:
  - An external copy, blind copy, redirect, or added recipient.
  - Delete.
  - Route through a connector.
- Medium:
  - Skip spam filtering.
  - Any new rule (only with **Alert on every new mail flow rule**).

<a id="mail_protection_weakened"></a>
## mail_protection_weakened — Mail protection

Subject: `[M365 Alert] HIGH: Mail protection - <user>` (or MEDIUM). Email title: "Mail protection weakened".

**What it means.** An admin weakened mail protection: a protection policy or rule removed or turned off, DKIM signing turned off, senders allowed past the spam filter, automatic external forwarding allowed, or Direct Send protection turned off.

**How to check it is real.**
- Fields: `Operation` (for example `Remove-AntiPhishPolicy`, `Disable-SafeLinksRule`, `Set-DkimSigningConfig`, `Set-HostedOutboundSpamFilterPolicy`, `Set-HostedContentFilterPolicy`, `Set-OrganizationConfig`), `Parameters` (`Identity`, `Enabled`, `AutoForwardingMode`, `AllowedSenderDomains`, `AllowedSenders`, `RejectDirectSend`), `UserId`, `ClientIP`.
- Ask the admin. Was the change planned? What replaces a removed policy?
- For allowed senders: is the domain a partner? Attackers allow their own phishing domain.
- Look next: Microsoft Defender portal > Email & collaboration > Policies & rules > Threat policies.

**Common benign causes.** An admin moves from custom policies to preset security policies. Cleanup of an old policy. DKIM off for a domain that sends no mail. A vendor domain allowed past the spam filter. External forwarding allowed for a help desk system.

**If real.** Restore the setting. Find mail that the change let through: Exchange admin center > Mail flow > Message trace. Treat the admin account as compromised.

**If benign.** Prefer a narrow setting. For example: a custom outbound spam policy that allows forwarding for one mailbox only, or a Tenant Allow/Block List entry in place of an allowed sender domain.

**Severity.** High: external automatic forwarding allowed, or Direct Send protection turned off. Medium: all other changes.

## Options for expected alerts

Use the narrowest option. Most expected alerts are one-time events: confirm them and change nothing. Each settings change is recorded in Management UI > History and emailed to the alert mailbox.

| Option | Where | What it hides | What still alerts |
|---|---|---|---|
| Confirm and change nothing | — | Nothing | All alerts. Best for a one-time event (a consent, a role, a domain) |
| A mute | Management UI > Mutes, or the link "mute similar alerts" in an alert email | Email for medium alerts that match the mute: one alert type, one user, one inbox rule, one network (ASN), or a combination, for 1 to 3650 days. Muted alerts are still recorded on the user page and counted in the weekly report | High alerts, unless the mute names one alert type, one user, and one network. OAuth consent, attack tool, legacy authentication, and audit-off alerts cannot be muted. Make each mute as narrow and as short as possible |
| Approve a country for a user | Management UI > Countries, or the link in the new-country email | New-country alerts for that user and country. Compromise alerts from that country are not raised to high for the user. Session alerts there become medium | Other users, other countries |
| **Home countries** (`HOME_COUNTRIES`) | Settings > New sign-in countries | The same as an approval, for all users | Other countries |
| **Allowed IPs and ranges** (`ALLOWED_IPS`) | Settings > Allowlists | Suspicious sign-in, new-country, and session alerts from those IPs. Compromise alerts from them are not raised to high | Compromise alerts from those IPs |
| **Allowed networks (ASNs)** (`ALLOWED_ASNS`) | Settings > Allowlists | The VPN, proxy, and hosting flag for all IPs of the network, for all users. Attackers can rent mobile carrier IPs | New-country, session, and compromise alerts |
| **Treat iCloud Private Relay as normal** (`PRIVATE_RELAY_TRUSTED`, on by default) | Settings > Allowlists | Suspicious sign-in alerts for Apple relay IPs | New-country, session, and compromise alerts |
| **Internal mail domains** (`INTERNAL_DOMAINS`) | Settings > Allowlists | Forwarding, copy, and folder sharing alerts to those domains, for all users | Delete, hidden folder, and keyword patterns |
| **Which suspicious sign-ins send email** (`LOGIN_ALERT_CONFIDENCE`) | Settings > Suspicious sign-ins | Email for lower-confidence sign-ins. `off`: all suspicious sign-in email. They are still logged in Application Insights | New-country, session, and compromise alerts |
| **Email format: digest** (`LOGIN_ALERT_MODE`) | Settings > Suspicious sign-ins | Nothing. It puts sign-in alerts into one email | All alerts |
| Detection lists (keywords, user agents, OAuth scopes) | Settings > Detection lists | A removed entry no longer alerts, for all users | Other entries |
| **Alert types that send email** (`ALERTS_OFF`) | Settings > Alerts | All email for that type, and its automatic response. The detection is only logged | Other types |

Add to an allowlist only IPs and networks that your organization controls or knows. Attackers rent VPN, hosting, and mobile carrier IPs.

## When to escalate

Fast containment of one account is often enough. Escalate when you see one of these signs:

| Sign | Why it matters |
|---|---|
| Alerts about several users in a short time | A phishing campaign, or an attacker who moves from account to account |
| An alert about an admin account, or an admin change that no one expected | The attacker can change the tenant, make accounts, and remove evidence |
| `domain_federation` (high), `audit_disabled`, a top admin role, or an unknown credential on an app with wide permissions | A backdoor for the whole tenant, or removal of evidence |
| Mail from the account to many recipients, or to customers and partners | Other organizations are at risk |
| A payment, bank detail, or invoice changed by mail | Business email compromise. A payment recall depends on time |
| Mail with personal, health, or financial data was read or forwarded | You can have a duty to notify |
| New alerts after you contained the account | The attacker has another way in |
| You cannot do the containment steps (no admin access, locked out) | You need help to regain control |

Who to involve:

- Your IT or security lead, and your management.
- An incident response provider. If you have cyber insurance, call the carrier's incident line first. Many policies require this, and the carrier can assign a provider. Read your policy.
- Your bank, immediately, if money went to an attacker's account.
- Microsoft support: Microsoft 365 admin center > Support > Help & support. For example, for a federation backdoor or a locked-out Global Administrator.
- Your legal counsel, for duties to notify. This guide does not give legal advice.
- The police or your national cybercrime reporting service, for fraud.

Keep the evidence:

- Record the details of a rule, an app, or an account before you remove it. Turn it off first if you can.
- Export the audit records: Microsoft Purview > Audit > the search > Export. Audit (Standard) keeps records for 180 days.
- Keep the alert emails.
- Write a timeline: the first suspicious event, each action, who did it, and when.

## For AI assistants

These rules apply when you help a person with an alert. The rules in [AGENTS.md](../AGENTS.md) also apply.

1. Read the audit record before you give an opinion. Ask the person to paste the "Details" and "Audit record" sections of the email. The sign-in and new-country emails have only "Details". Do not judge from the subject alone.
2. Never call an alert benign until the user, or the admin who made the change, confirms it. Until then, say "not confirmed" and say what to check. A known IP or a normal record is not a confirmation.
3. Say which facts support your view, and which facts are missing.
4. When in doubt, recommend containment. Revoking sessions costs the user one sign-in.
5. Do not weaken detection on your own (AGENTS.md rule 4). This includes allowlists, home countries, approved countries, alert types off, mutes, detection lists, and the sign-in email level. Make such a change only when the person asks. Before the change, say what it hides (see [Options for expected alerts](#options-for-expected-alerts)).
6. Get a yes before each command or management UI action that changes the tenant (AGENTS.md rule 1). This includes Revoke sessions, Block sign-in, Unblock sign-in, and Turn off or Turn on an inbox rule in the management UI. Examples of commands: `Revoke-MgUserSignInSession`, `Update-MgUser -AccountEnabled`, `az ad user update`, `Remove-InboxRule`, `Disable-InboxRule`, `Set-Mailbox`, `Remove-MailboxPermission`, `Remove-MailboxFolderPermission`, `Remove-MgServicePrincipal`, `Set-AdminAuditLogConfig`. Read-only commands (`Get-InboxRule`, `Get-Mailbox`, `Get-MailboxPermission`, `Get-AdminAuditLogConfig`, `Get-MgUser`, `Search-UnifiedAuditLog`) need no yes.
7. Keep evidence. Suggest that the person records the details of a rule or app first. Then suggest that they turn it off before they delete it.
8. Tell the person to contact the user by phone or in person, not by email.
9. Do not claim that the monitor did something that it did not do. Read the "Automatic response" notice. The monitor never changes passwords. It does not remove MFA methods, forwarding, permissions, or apps.
10. Remember the delay: the event can have happened some minutes to 1–2 hours (sometimes more) before the email. Compare the time in the record with the time of the email.
11. Do not give legal advice. For duties to notify, refer the person to legal counsel or the insurer.
12. Do not show secrets (AGENTS.md rule 2). Triage needs no secret from the deployment.
