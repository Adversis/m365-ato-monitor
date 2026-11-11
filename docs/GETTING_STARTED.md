# Getting Started

`install.ps1` installs M365 ATO Monitor in your Azure subscription. When it is done:

- An Azure Function reads the Microsoft 365 audit log every 2 minutes.
- Each account takeover finding (inbox rule, forwarding, app consent, attack tool, and others) sends an email.
- Each sign-in from a suspicious IP sends an email, or goes into a digest.
- A report arrives each Monday and on the 1st of each month.
- Azure Monitor sends an email if the monitor stops or errors repeat.
- A web management UI shows the health, the alerts, and the settings.

Time: about 10 minutes of work. Microsoft then takes 12–24 hours to deliver the first audit content.

Microsoft 365 commercial cloud only. GCC, GCC High, DoD, and 21Vianet are not supported.

---

## 1. Prerequisites

### Tools

| Tool | Check | Install |
|---|---|---|
| PowerShell 7.2 or later | `pwsh --version` | Windows: `winget install --id Microsoft.PowerShell --source winget`. macOS: `brew install powershell` (not `--cask`). Linux: [Install PowerShell on Linux](https://learn.microsoft.com/powershell/scripting/install/installing-powershell-on-linux) |
| Azure CLI 2.60 or later | `az version` | Windows: `winget install --id Microsoft.AzureCLI --source winget`. macOS: `brew install azure-cli`. Linux: [Install the Azure CLI on Linux](https://learn.microsoft.com/cli/azure/install-azure-cli-linux). Older version: `az upgrade` |

Windows PowerShell 5.1 is not enough. Azure Cloud Shell (https://shell.azure.com, PowerShell) has both tools. Python is necessary only for the local tests.

Run the commands in PowerShell 7 (`pwsh`). From bash or zsh: `pwsh ./install.ps1`.

### Azure subscription

You need an enabled Azure subscription in the same tenant as Microsoft 365. To check:

```powershell
az login
az account list --query "[].{name:name, tenant:tenantId, state:state}" -o table
```

The tenant ID must match Microsoft Entra admin center > Overview > **Tenant ID**. If no row matches, or `az login` says "No subscriptions found", get a subscription.

#### Get an Azure subscription

Sign in to https://portal.azure.com with your Microsoft 365 work account. Do not use a personal Microsoft account: it makes a separate tenant. Go to **Subscriptions** > **+ Add**. What you see depends on how your organization pays Microsoft:

| The portal shows | Do this |
|---|---|
| A sign-up for pay-as-you-go or a free account | Enter a card and a phone number (no prepaid cards). Choose pay-as-you-go. A free account stops after 30 days, and Flex Consumption can refuse it: upgrade it first (Subscriptions > the subscription > **Upgrade subscription**) |
| **Create a subscription**, with Billing account, Billing profile, and Invoice section | Your organization already has a Microsoft Customer Agreement, for example from a Microsoft 365 purchase. **Billing profile**: the invoice and payment method that pays for the monitor, usually the one that pays for Microsoft 365. **Invoice section**: a group of costs on that invoice. **Plan**: Microsoft Azure Plan. **Advanced** tab: the subscription directory must be the tenant that you monitor. Optional, **Budget** tab: a monthly budget, for example $20 |
| A partner (CSP) bills your Microsoft 365 | Ask the partner for an Azure plan subscription in your tenant, with the **Owner** role for the person who installs. Or create a pay-as-you-go subscription that Microsoft bills to you |

To create a subscription on a billing profile, you need Owner, Contributor, or Azure subscription creator on the invoice section, or Owner or Contributor on the billing profile. You become Owner of the new subscription.

Run `az login` again. `az account show --query tenantId -o tsv` must show your tenant ID. The monitor costs about $2–10 per month ([Costs](ARCHITECTURE.md#costs)).

| Other situations | Do this |
|---|---|
| Somebody else made the subscription | Ask them for the Owner role. Or, as Global Administrator: Microsoft Entra ID > **Properties** > **Access management for Azure resources** > **Yes**; Subscriptions > the subscription > **Access control (IAM)** > add Owner for yourself; set the toggle back to **No** |
| The subscription is in another tenant | Make a new one with your work account. Or move it: Subscriptions > the subscription > **Change directory** (needs Owner and an account in both tenants; CSP subscriptions cannot move) |

Subscriptions > the subscription > **Overview** > **Offer** shows the type (pay-as-you-go, free trial, CSP, Microsoft Azure Plan).

### Roles for the person who installs

| Scope | Role | Why |
|---|---|---|
| Azure subscription | Owner, or Contributor + User Access Administrator | The script creates role assignments for the managed identity and the monitor app |
| Entra ID | Global Administrator. Or Privileged Role Administrator plus Exchange Administrator | The script grants admin consent. With the default `-MailSendScope mailbox`, it also signs in to Exchange Online to limit Mail.Send to the alert mailbox |
| Entra ID | Permission to register applications | The script creates two app registrations: the monitor and the management UI |

### Unified audit logging

The monitor reads the unified audit log. If auditing is off, no content arrives, and each run logs "No login events found."

Auditing is off by default with Business Basic, Business Standard, and Business Premium, and in enterprise trial tenants. An admin or a partner can change it, so check it in each tenant:

- Microsoft Purview portal > **Solutions > Audit**. If the page shows **Start recording user and admin activity**, auditing is off. Select it to turn it on.
- Or Exchange Online PowerShell (not Security & Compliance PowerShell, which always shows `False`):

  ```powershell
  Get-AdminAuditLogConfig | Format-List UnifiedAuditLogIngestionEnabled
  Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true
  ```

The change can take 60 minutes to apply.

In a new tenant, both ways can ask you to run `Enable-OrganizationCustomization` first. Run it once in Exchange Online PowerShell, then turn on auditing again. It can take some minutes to several hours; until then the same message comes back. `Get-OrganizationConfig | Format-List IsDehydrated` shows `False` when it is done.

### Azure region

The Function App uses the Flex Consumption plan, which some regions do not have. The script checks the region and lists the regions that have it. To list them yourself:

```powershell
az functionapp list-flexconsumption-locations --query "[].name" -o tsv
```

### Alert mailbox

A licensed or shared mailbox in the tenant. The monitor sends every email as this mailbox, to this mailbox. To also send alerts to other addresses, add them after the install (Settings > Email > Extra recipients).

### proxycheck.io API key (recommended)

Without a key, proxycheck.io allows 100 IP lookups per day. A free key allows 1,000. Register at the [proxycheck.io dashboard](https://proxycheck.io/dashboard/), confirm your email address, and copy the key. You enter it in the management UI after the install ([Enter the proxycheck.io key](#enter-the-proxycheckio-key)).

---

## 2. Install

```powershell
git clone https://github.com/Adversis/m365-ato-monitor.git
cd m365-ato-monitor
./install.ps1 -AdminEmail security@contoso.com -Location eastus
```

You do not need `az login` first: the script signs in to the tenant of `-AdminEmail`. It asks for each value that you do not give: the region, the alert mailbox, and the response permissions (revoke sessions, block sign-in, turn off inbox rules; they stay off until you turn them on). Then it shows the plan and asks "Continue?".

The script prints 9 numbered steps ([section 3](#3-see-each-step-before-you-install-dry-run)). If the Azure CLI is signed in to another tenant, or the alert mailbox is not a mailbox of the tenant, it stops before any change. If a step fails, it prints `ERROR` and `Fix`. Do the fix and run the script again: each step continues from what exists. A rerun keeps the settings of the management UI.

### Parameters

| Parameter | Default | Function |
|---|---|---|
| `-AdminEmail` | Asks (your account) | The alert mailbox. A rerun without it keeps the current one |
| `-Location` | Asks (`eastus`) | A region with Flex Consumption. A rerun keeps the region of the resource group |
| `-Name` | `m365-ato-monitor` | Base name for all resources (1–30 letters, digits, or hyphens). Use the same name in each later command |
| `-SubscriptionId` | The current `az` subscription | The Azure subscription |
| `-Tenant` | The tenant of the current `az` sign-in | A domain of the tenant, or its tenant ID. For a second tenant ([Install in another tenant](#install-in-another-tenant)). `-Update`, `-Verify`, and `-Uninstall` take it too |
| `-ResponsePermissions` | `ask` | `yes`, `no`, or `ask`. With `ask`, a rerun keeps the earlier choice. `no` removes the permissions |
| `-MailSendScope` | `mailbox` | `mailbox`: the app can send only as the alert mailbox, through the Exchange Online group `<name>-senders`. Needs the module ExchangeOnlineManagement (installed if missing) and an Exchange Online sign-in. `tenant`: Graph `Mail.Send` for every mailbox ([How-To](HOW_TO.md#limit-mailsend-to-the-alert-mailbox)). A rerun keeps the earlier choice |
| `-UiAdmins` | (none) | More users who get the Monitor.Admin role, for example `-UiAdmins sam@contoso.com,alex@contoso.com`. You get it automatically |
| `-DryRun` | | Show each change. Make no change |
| `-Yes` | | Ask no questions. With `-Uninstall`, delete with no confirmation |

### Other commands

| Command | Make target | Function |
|---|---|---|
| `./install.ps1 -Update` | `make deploy` | Deploy the code of this folder and repair the setup. Keeps all settings |
| `./install.ps1 -Verify` | `make verify` | Show `/api/status`, and run each detector on a synthetic record. No email |
| `./install.ps1 -Verify -SendTestAlerts` | `make verify ARGS=-SendTestAlerts` | Also send one `[SELF-TEST]` email for each alert type |
| `./install.ps1 -Uninstall` | `make uninstall` | Delete the resource group and both app registrations ([section 7](#7-remove-the-monitor)) |
| `./install.ps1 -List` | | Show the installations on this computer |
| `./install.ps1 -UpdateAll` | | Run `-Update` for each saved installation. Asks one time; prints a summary |

`./install.ps1 -Help` lists the commands and options. `Get-Help ./install.ps1 -Detailed` shows the full help.

### Install in another tenant

Each tenant gets its own installation, in an Azure subscription of that tenant. For the second tenant and each one after it:

```powershell
./install.ps1 -Tenant fabrikam.com -AdminEmail security@fabrikam.com -Location eastus
```

1. If the Azure CLI is not signed in to that tenant, the browser opens. Sign in with an account of that tenant: Owner of a subscription there, and Global Administrator.
2. The script selects the subscription of that tenant. If there is more than one, it asks (with `-Yes`, give `-SubscriptionId`).
3. Check the tenant name in the plan before you answer "Continue?".
4. For the Exchange Online sign-in, the script shows a URL and a code. Open the URL in any browser (also on another computer), enter the code, and sign in with an account of the same tenant. A private browser window helps if the browser picks another account. The monitor sends a "Device code sign-in" alert for this sign-in; that alert is expected. The script stops before any Exchange change if the sign-in lands in another tenant.
5. The alert subjects start with the organization name: `[M365 Alert][Fabrikam]`.
6. At the end, the Azure CLI goes back to the subscription that you used before.

Each installation is saved in `~/.m365-ato-monitor/tenants.json` (tenant, subscription, `-Name`, region; no secrets):

- `./install.ps1 -List` shows them.
- `./install.ps1 -Tenant fabrikam -Update` updates one. A short name works when it matches a saved installation.
- `./install.ps1 -UpdateAll` updates each one. A tenant with an expired sign-in opens the browser (with `-Yes`, it is skipped and named in the summary). It also puts the organization name in the subjects of an installation that has no tenant name.

The Azure CLI keeps each sign-in for 90 days of no use. On another computer, run `-Tenant ... -Update` once for each tenant.

### Check the status

At the end, the script shows the checks of `/api/status`. `./install.ps1 -Verify` shows them again:

```
  OK    azure_ad_token: ok
  OK    o365_api_aad: ok (0 content blobs in last 60 min)
  OK    o365_api_exchange: ok (0 content blobs in last 60 min)
  OK    graph_api_token: ok
  OK    table_storage: ok (0 events processed in last 24h)
  OK    proxycheck_io: ok (status=ok)
```

"0 content blobs" is normal for the first 12–24 hours. `o365_api_*` can show `AF20022` or `AF20023` for some minutes: the first monitor run starts the audit subscriptions. If `/api/status` does not answer, wait some minutes (role assignments take time to apply), then run `./install.ps1 -Verify`.

Without `-Yes`, the script then waits up to 10 minutes for the first monitor run (Ctrl+C stops the wait; the install is complete), runs the self-test, and asks if it should send one test email for each alert type.

### Open the management UI

Open the link that the script shows (`https://<function app>.azurewebsites.net/api/manage`) and sign in with your Microsoft 365 account. You have the **Monitor.Admin** role. To give other people access: Settings > Management UI access.

**Overview** shows the health of the monitor. **Settings** has all detection and alert settings.

### Enter the proxycheck.io key

Management UI > Settings > Suspicious sign-ins > **proxycheck.io API key**. Paste the key and select **Save changes**. The key is stored in Table Storage and is never shown again.

### Run the self-test

The self-test sends a synthetic audit record for each alert type through the real detectors (test IPs and `.invalid` domains):

```powershell
./install.ps1 -Verify                    # each alert type, no email
./install.ps1 -Verify -SendTestAlerts    # each alert type, one email each
```

Or: Management UI > Overview > **Test alerts**. Each type must show `detected`, then "Self-test passed". With `-SendTestAlerts`, the alert mailbox gets one email per type, with `[SELF-TEST]` in the subject.

### Do the next steps

1. Enter the proxycheck.io key.
2. Add a mail rule so that `[M365 Alert]` mail does not go to junk mail.
3. Check that unified audit logging is on ([Unified audit logging](#unified-audit-logging)).
4. With the default `-MailSendScope mailbox`, Exchange applies the Mail.Send grant in 30 minutes to 2 hours. Until then, emails wait in the outbox. To change the alert mailbox later, add the new one to the group `<name>-senders` first ([How-To](HOW_TO.md#change-the-alert-mailbox)).

---

## 3. See each step before you install (dry run)

A dry run shows each change and makes none. It reads Azure and Entra ID, so it needs a sign-in. Use it to review the changes yourself, or with a colleague or an AI assistant.

```powershell
./install.ps1 -DryRun -AdminEmail security@contoso.com -Location eastus
```

`PLAN` is a change that the real run makes (it shows `DO`). `OK` is something that exists or a check that passed. New objects show the ID `00000000-0000-0000-0000-000000000000`.

| Step | What the script does |
|---|---|
| `[1/9] Check the tools and the Azure sign-in` | Checks the versions. Signs in if necessary. Shows the account, the tenant, and the subscription |
| `[2/9] Choose the settings` | Checks the region and the alert mailbox. Shows the plan: tenant, resource group, Function App, alert mailbox, Mail.Send scope, Graph roles. Asks "Continue?" |
| `[3/9] Register the resource providers` | `Microsoft.Web`, `Microsoft.Storage`, `Microsoft.Insights`, `Microsoft.OperationalInsights`, `Microsoft.ManagedIdentity` |
| `[4/9] Create the Azure resources` | Resource group `rg-<name>`, managed identity `id-<name>`, storage account `st<name><6 hex>` (TLS 1.2, HTTPS only, no public blobs; shared keys stay on until step 8 because `az functionapp create` needs them), the storage data roles for the identity, Log Analytics `log-<name>` (90 days), Application Insights `appi-<name>`, and Monitoring Metrics Publisher on it for the identity |
| `[5/9] Create the Function App` | `func-<name>-<6 hex>`: Flex Consumption, Linux, Python 3.12, 512 MB, HTTPS only, with the managed identity |
| `[6/9] Create the app registrations and grant admin consent` | App registration `<name>`, whose only credential is the managed identity. Admin consent. With `-MailSendScope mailbox` (not with `-Update`): the Exchange Online sign-in, the group `<name>-senders`, the management scope, and the role assignment "Application Mail.Send"; then the Graph `Mail.Send` is removed. App registration `<name>-admin-ui` for the management UI sign-in. Monitoring Reader on Application Insights |
| `[7/9] Set up the health alerts` | Action group `ag-<name>` (email to the alert mailbox). Alerts `alert-<name>-no-runs` and `alert-<name>-errors`. Monitoring Contributor on the action group |
| `[8/9] Configure the Function App` | Waits until the Monitoring Metrics Publisher role is 5 minutes old (first run only). App settings (no key, no secret). Shared keys off. Application Insights accepts telemetry with Entra ID only. App Service Authentication for `/api/manage`. The app's own origin in CORS. Deployment with a password off. The change alerts: `alert-<name>-azure-change` and `alert-<name>-code-deployed` (with the storage logs and the workspace transformation) |
| `[9/9] Deploy the code and check the status` | Starts the app if it is stopped. Deploys the `function` folder (remote build). Shows `/api/status` |

`<6 hex>` comes from the subscription ID and the name, so a rerun finds the same resources.

---

## 4. After installation

| Time | What happens |
|---|---|
| First run | The monitor starts the audit subscriptions. It checks them every 6 hours |
| First audit content | Setup confirmation email |
| 10–60 minutes after the first run | "Starting state" email: the inbox rules of every mailbox, the audit history that Microsoft still has, and manual checks. Triage each item ([Alert Triage](TRIAGE.md)) |
| 0–24 hours | Runs log "No login events found." This is normal |
| After 12–24 hours | Audit content arrives. Alerts start. VPN users can cause sign-in alerts |
| First 14 days | The monitor learns each user's countries. No new-country alerts, unless `HOME_COUNTRIES` is set |
| Each Monday, 07:17 UTC | Weekly report. If it does not arrive, the monitor did not run |
| 1st of each month, 08:00 UTC | Monthly report for the last 30 days |
| No run for 1 hour | Azure Monitor "no-runs" email |
| 5 or more errors in 1 hour | Azure Monitor "errors" email. Run the [Errors query](APP_INSIGHTS_QUERIES.md#errors) |
| No audit content for 48 hours | An error in the log, then the "errors" email. Check unified audit logging |

---

## 5. Settings

Change settings in the management UI > **Settings**. A change applies from the next run, is recorded in History, and is emailed to the alert mailbox. A rerun of `install.ps1` does not revert it. See [How-To: where to change what](HOW_TO.md#where-to-change-what).

The defaults come from `function/config.py`, or from a Function App setting that `install.ps1` writes. A value saved in the UI wins over both.

| Setting | Default | Function |
|---|---|---|
| `ADMIN_EMAIL` | Set by `install.ps1` | The alert mailbox (Settings > Email; a test send runs before the save) |
| `ALERT_RECIPIENTS` | (empty) | Extra addresses for alerts |
| `REPORT_RECIPIENTS` | (empty) | Extra addresses for reports |
| `TENANT_LABEL` | (empty; with `-Tenant`, the organization name) | Tenant name in subjects: `[M365 Alert][Contoso]` |
| `PROXYCHECK_API_KEY` | (empty) | proxycheck.io key. Write-only |
| `WEEKLY_REPORT` | true | Send the weekly report |
| `ALLOWED_IPS` | (empty) | IPs or CIDRs that never cause a sign-in, new-country, or session alert |
| `INTERNAL_DOMAINS` | (empty) | Extra mail domains that count as internal for forwarding checks |
| `RISK_SCORE_THRESHOLD` | 33 | proxycheck.io risk score (0–100) that flags an IP |
| `LOOKBACK_MINUTES` | 8 | Minutes of content each run fetches (3–60) |
| `IP_CACHE_DAYS` | 7 | Days to keep a proxycheck.io answer for an IP that is not flagged (1–7). A flagged answer: 24 hours |
| `LOGIN_ALERT_CONFIDENCE` | low | Sign-in emails: `low` (all), `medium`, `high`, `off` |
| `LOGIN_ALERT_FAILED` | false | Also email failed sign-ins (wrong password) from a suspicious IP, an automation client, or an attack tool. A correct password stopped by MFA always sends email |
| `LOGIN_ALERT_MODE` | immediate | `immediate` (one email per sign-in) or `digest` |
| `LOGIN_DIGEST_MINUTES` | 60 | Digest mode: age of the oldest queued sign-in before the digest goes |
| `GEO_ANOMALY_ENABLED` | true | Alert on a sign-in from a country that is new for the user |
| `HOME_COUNTRIES` | (empty) | Country codes that are never new, for example `US,CA` |
| `SESSION_CHECK_ENABLED` | true | Alert when one session is used from two countries, or moves to a risky IP |
| `MAIL_ACCESS_CHECK` | true | Alert when mail is read or sent from a risky or new-country IP that did not sign in as the user in 7 days |
| `MAIL_ACCESS_MAX_LOOKUPS` | 25 | proxycheck.io lookups per run for the mail access check |
| `ALERT_DELIVERY` | email | `email`, `both` (email and webhook), or `webhook` (email if the webhook fails). Reports and change notices always go by email |
| `WEBHOOK_URL` | (empty) | Incoming webhook URL (Slack, Microsoft Teams Workflows, or other). HTTPS only. A secret |
| `WEBHOOK_FORMAT` | slack | `slack`, `teams`, or `json` |
| `UI_ADMIN_USERS` | (empty) | Users who can open the management UI (their sign-in address) |
| `UI_ADMIN_ROLES` | (empty) | Directory roles whose members can open the management UI. Needs `RoleManagement.Read.Directory` |
| `ANOMALY_ACTION` | none | `none`, `revoke`, or `disable` on a new-country sign-in ([How-To](HOW_TO.md#respond-automatically-to-a-new-country-sign-in)) |
| `ANOMALY_ACTION_EXEMPT` | (empty) | Users that the automatic response never changes |
| `COMPROMISE_ACTION` | none | `none`, `revoke`, or `disable` on a high account-takeover alert ([How-To](HOW_TO.md#respond-automatically-to-account-takeover-alerts)) |
| `AUTO_DISABLE_INBOX_RULES` | false | Turn off the rule of a high inbox rule alert |
| `ALERTS_OFF` | (empty) | Alert types that send no email, for example `mail_flow_rule,device_code` |
| `MAIL_FLOW_RULE_ANY` | false | Alert on every new mail flow rule, not only risky ones |
| `ALLOWED_ASNS` | (empty) | Networks that are never VPN, proxy, or hosting for sign-in alerts, for example `AS21928` |
| `PRIVATE_RELAY_TRUSTED` | true | iCloud Private Relay IPs are not VPN; their country comes from Apple's list |
| `NO_CONTENT_ALERT_HOURS` | 48 | Log an error after this many hours with no audit content. 0 = off |
| `RESOLVE_USER_IDS` | false | Link alerts to the exact user in Entra ID |
| `ATTACK_TOOL_USER_AGENTS` | AADInternals, ROADtools, ... | User agents that cause a high alert |
| `AUTOMATION_USER_AGENTS` | python-requests, PowerShell, ... | User agents that cause a medium alert |
| `HIGH_RISK_OAUTH_SCOPES` | Mail.Read, EWS.AccessAsUser.All, ... | Scopes that cause a consent alert |
| `INBOX_RULE_KEYWORDS` | invoice, payment, wire, password, ... | Words that make an inbox rule with mark-as-read, move, or delete a medium alert |

The response settings need the response permissions (`-ResponsePermissions yes`).

`install.ps1` also writes these settings. They are not in the UI. Do not change them by hand; run `./install.ps1` again.

| Setting | Content |
|---|---|
| `AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `MONITOR_SP_ID` | The tenant and the monitor app |
| `MANAGED_IDENTITY_CLIENT_ID` | The managed identity (the app's credential) |
| `STORAGE_ACCOUNT_NAME`, `AzureWebJobsStorage__*` | Storage through the managed identity (no key) |
| `APPLICATIONINSIGHTS_CONNECTION_STRING`, `APP_INSIGHTS_APP_ID` | Logs, and the source of the reports |
| `APPLICATIONINSIGHTS_AUTHENTICATION_STRING` | The host sends telemetry with the managed identity (`Authorization=AAD;ClientId=<identity>`). Application Insights accepts no other telemetry |
| `ACTION_GROUP_ID` | The health alert action group |
| `ADMIN_UI_ENABLED`, `MONITOR_HOSTNAME` | The management UI and the links in emails |
| `MAIL_SEND_SCOPE`, `MAIL_SEND_GROUP`, `RESPONSE_PERMISSIONS` | The choices of `-MailSendScope` and `-ResponsePermissions` |

---

## 6. Troubleshooting

### The script stops

| Message | Cause | Action |
|---|---|---|
| `Signed in as` shows the wrong account, tenant, or subscription | The Azure CLI is signed in elsewhere | Use `-Tenant <domain>`, or `-SubscriptionId` |
| `<address> is not in the tenant that the Azure CLI is signed in to` | The alert mailbox is in another tenant | To monitor that tenant: the `Fix:` command with `-Tenant`. For an outside address: use a mailbox of this tenant, and add the outside address as an extra recipient |
| `... has no user or shared mailbox <address>` | The address is a group, a contact, or unused | Use a licensed or shared mailbox of the tenant |
| `The tenant has more than one subscription.` | `-Yes` cannot ask | Add `-SubscriptionId` with one of the listed subscriptions |
| `The Exchange Online sign-in went to another tenant` | The browser used another account | Run the script again. Open the URL in a private window and sign in with an account of the tenant in the plan |
| `Exchange Online sign-in failed` with `AADSTS53003` or "blocked" | Conditional Access blocks the device code sign-in | Use `-MailSendScope tenant`. Or allow the device code flow for your admin account for this step |
| `No Microsoft 365 tenant has the domain '<domain>'.` | `-Tenant` has a domain that no tenant has verified | Use a verified domain (for example `<name>.onmicrosoft.com`) or the tenant ID |
| `The Azure sign-in has expired`, `AADSTS700082`, `does not exist in MSAL token cache` | 90 days without use | The script signs in again. With `-Yes`: `az login --tenant <tenant ID>`, then run the script again |
| `The Azure CLI (az) is not installed.`, `Azure CLI <version> is too old.` | No Azure CLI, or older than 2.60 | Install it ([Tools](#tools)), or `az upgrade` |
| macOS: `pwsh: command not found` after `brew install --cask powershell@preview` | The preview installs as `pwsh-preview` | `brew uninstall --cask powershell@preview`, then `brew install powershell` |
| `Azure sign-in failed.`, "No subscriptions found" | No Azure subscription in this tenant | [Get an Azure subscription](#get-an-azure-subscription) |
| "Free trial subscription is not supported for Flex Consumption" | A free trial | Upgrade it to pay-as-you-go ([Get an Azure subscription](#get-an-azure-subscription)). If the error stays after 24 hours, open an Azure support request |
| `Region '<name>' does not offer Flex Consumption.` | No Flex Consumption there | Use a region from the `Fix:` line |
| `role assignment create failed`, `AuthorizationFailed` | Not Owner or User Access Administrator | Get the role |
| A `Grant ... (admin consent)` step fails, `Authorization_RequestDenied` | Not Global Administrator or Privileged Role Administrator | Get the role |
| `/api/status did not answer` | The app is starting, or role assignments are not applied yet | Wait 10 minutes, then `./install.ps1 -Verify`. If it still fails, `./install.ps1 -Update` |
| `WARN  Code deployed. The host check did not pass yet` | The host starts after the changes of step 8 | Wait 10 minutes, then `./install.ps1 -Verify` |
| `Not ready yet ... Next try in 15 seconds.` | A new object is not replicated yet; the script tries for 5 minutes | Wait. If the step fails, run the script again |
| `More than one app registration named '<name>' has the tag m365-ato-monitor.` | Two app registrations with the same name | Delete the unused one, or use another `-Name` |
| `No installation named '<name>' in this subscription.` | `-Update` found no `rg-<name>` | Use the correct `-Name`, `-SubscriptionId`, or `-Tenant`; or install without `-Update` |

Each time: do the action, then run the script again.

### A check in `/api/status` shows FAILED

| Check | Cause | Action |
|---|---|---|
| `azure_ad_token` | The federated credential or the managed identity is missing | `./install.ps1 -Update` |
| `o365_api_aad`, `o365_api_exchange` | `AF20022`/`AF20023`: no audit subscription yet. `AF10001`: no consent for `ActivityFeed.Read` | `AF20022`, `AF20023`: wait; the monitor starts the subscription. `AF10001`: `./install.ps1 -Update` |
| `graph_api_token` | No admin consent for the Graph permissions | `./install.ps1 -Update` |
| `table_storage` | The storage roles are not applied yet, or are missing | Wait 10 minutes, then `./install.ps1 -Update` |
| `proxycheck_io` | `status=denied`: quota used or key not valid. `status=warning` ("within 10% of your query limit"): quota low | Check the key and the usage on the proxycheck.io dashboard. Overview > Monitor > IP lookups shows the state |

### A change in the management UI fails with HTTP 403

Pages load, but a save, mute, or response action fails with "Request failed (HTTP 403...)".

- **"no details from the server"**: the platform refused the request before the code ran, usually because the app's own origin is not in its CORS list. Run `./install.ps1 -Update`, then reload the page. Or add the origin yourself:

  ```bash
  az functionapp cors add -g rg-m365-ato-monitor -n <function app> --allowed-origins https://<function app>.azurewebsites.net
  ```

- **"Request refused: ..."**: the monitor's own check refused it. Application Insights has the trace "Management UI request refused" with the Origin and Host.

### The management UI shows "App Service Authentication is not detected"

The UI trusts the platform's identity header only if the setting `WEBSITE_AUTH_ENABLED` is `true`, which the platform sets when App Service Authentication is on. If it is missing, the UI stays off, so that a forged header is never trusted. Alerts still work.

1. Run `./install.ps1 -Update`. Step 8 turns on App Service Authentication again.
2. Check: Azure portal > the Function App > Settings > Authentication. Microsoft must be the identity provider.
3. If the message stays, report an issue. Do not set `WEBSITE_AUTH_ENABLED` by hand.

### The Function App has no functions after a deployment

A deployment to a stopped Flex Consumption app reports success, but the app starts with no functions (a known Microsoft bug). The script starts the app first. Run `./install.ps1 -Update` again, then `./install.ps1 -Verify`.

### An Azure Monitor "errors" alert arrives

Run the [Errors query](APP_INSIGHTS_QUERIES.md#errors). Common messages:

| Message | Cause | Action |
|---|---|---|
| `No audit content for N hours` | Unified audit logging is off, or the subscriptions stopped | Check [audit logging](#unified-audit-logging). The monitor restarts a stopped subscription within 6 hours |
| `Listing ... content failed: HTTP 400 AF20022` | No subscription for that content type | None. The monitor starts it; content follows within 12 hours |
| `Audit subscription ... not started` | No consent for `ActivityFeed.Read`, or a Microsoft error | `./install.ps1 -Update` |
| `Email not sent`, `Outbox: N email(s) not delivered` | The alert mailbox is not licensed, `Mail.Send` has no consent, or (mailbox scope) the mailbox is not in the group `<name>-senders` or Exchange did not apply the grant yet (up to 2 hours) | Fix the mailbox (Settings > Email), or `./install.ps1 -Update`. Queued emails go on the next run |
| `proxycheck.io quota or access problem`, or the email "proxycheck.io quota is low" or "is used up" | Quota used, or the key is not valid | Add or check the key, or buy a larger plan ([How-To](HOW_TO.md#check-the-proxycheckio-quota)). Waiting sign-ins are checked when lookups work again |
| `Token request ... failed` | The federated credential or the managed identity is missing | `./install.ps1 -Update` |

### "Coverage gap" errors in Application Insights

The monitor did not run, or a fetch failed, for more than 60 minutes. Content in the reported interval was not fully processed. Find the cause in the errors before the gap, and search Microsoft Purview > Audit for that interval by hand.

### No events after 48 hours

1. Check that [unified audit logging](#unified-audit-logging) is on.
2. Run `./install.ps1 -Verify`. `o365_api_aad` and `o365_api_exchange` must be `ok`.
3. Look for "Audit subscription" messages and other [errors](APP_INSIGHTS_QUERIES.md#errors).

### macOS: `az login` or the script stops with no error

An outbound firewall (LuLu, Little Snitch) can block a tool but allow your browser, and the Azure CLI then waits with no end. Allow the Python bundled with the Azure CLI (`…/azure-cli/<ver>/libexec/bin/python3.x`) and `pwsh`, or pause the firewall during the install.

### macOS: "python wants to use … my_service_name in your keychain"

The Azure CLI asks for this when its token cache encryption is on (off by default on macOS). Select **Always Allow**. The prompt can come back after a Homebrew update. To use the macOS default (a token file that only your account can read):

```bash
az config set core.encrypt_token_cache=false
az logout
az login
```

---

## 7. Remove the monitor

```powershell
./install.ps1 -Uninstall
```

The script asks you to type the resource group name. Then it deletes both app registrations and the resource group, with the settings, the history, and the findings journal. The audit subscriptions of the tenant stay; they cost nothing. With the mailbox scope, the Exchange Online group and its role assignment stay too: the script prints the commands to remove them. See [How-To: Remove the monitor](HOW_TO.md#remove-the-monitor).

## Next

- [How-To Guide](HOW_TO.md)
- [App Insights Queries](APP_INSIGHTS_QUERIES.md)
- [Architecture](ARCHITECTURE.md)
