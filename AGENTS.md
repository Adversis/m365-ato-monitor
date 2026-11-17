# AGENTS.md

Instructions for AI assistants (Claude Code, Codex, Cursor, GitHub Copilot, and others) that help a person deploy, run, or change M365 ATO Monitor. People can read it too.

## What this project is

M365 ATO Monitor is an Azure Function (Python 3.12, Flex Consumption plan) that reads the Microsoft 365 unified audit log every 2 minutes through the Office 365 Management Activity API. It detects account takeover and business email compromise activity and sends alert emails through Microsoft Graph. One PowerShell script, `install.ps1`, installs it into the person's own Azure subscription with the Azure CLI. The same script updates, checks, and removes it. The app uses a managed identity: there is no client secret. It is for tenants without Entra ID P2, Defender for Office 365, or Sentinel, and also works in tenants that have them. See [README.md](README.md) for what it detects and what it does not.

## Rules

1. **The person owns the tenant.** Before a command that changes Azure, Entra ID, or Microsoft 365, say what it does and get a yes. These commands make changes: `./install.ps1` without `-DryRun`, `-Verify`, or `-List` (an install, a rerun, `-Update`, `-UpdateAll`, `-Uninstall`), `make install`, `make deploy`, `make uninstall`, `az` writes, and the scripts in `scripts/` (`live-test.ps1` changes a test mailbox), except `errors.ps1`, which only reads Application Insights. `install.ps1` with `-MailSendScope mailbox` (the default) also changes Exchange Online: it makes a group, a management scope, and a role assignment. The management UI actions Revoke sessions, Block sign-in, Unblock sign-in, and Turn off or Turn on a rule also change the tenant. Read-only commands need no confirmation: `az account show`, `./install.ps1 -DryRun`, `./install.ps1 -Verify`, `./install.ps1 -List`, `make verify`, `./scripts/errors.ps1`. `./install.ps1 -Verify -SendTestAlerts` sends one email for each alert type: tell the person before you run it.
2. **Never show or commit secrets.** Do not print, paste, or commit: `function/local.settings.json`, function keys (`az functionapp keys list`), or the proxycheck.io key. Do not print the Function App settings with their values. List the names only (`az functionapp config appsettings list ... --query "[].name"`). Do not take the proxycheck.io key in chat: the person enters it in the management UI. `function/local.settings.json` is in `.gitignore`. Keep it there.
3. **Do not destroy.** Run `./install.ps1 -Uninstall`, `make uninstall`, `az group delete`, or `az ad app delete` only when the person asks for it in this conversation. `./install.ps1 -Uninstall -Yes` deletes with no confirmation.
4. **Do not weaken detection on your own.** Allowlists (`ALLOWED_IPS`, `ALLOWED_ASNS`, `INTERNAL_DOMAINS`, `PRIVATE_RELAY_TRUSTED`), checks off (`SESSION_CHECK_ENABLED`, `MAIL_ACCESS_CHECK`), alert types off (`ALERTS_OFF`), mutes, `LOGIN_ALERT_CONFIDENCE = off`, removed keywords or scopes, and the automatic response (`ANOMALY_ACTION`, `COMPROMISE_ACTION`, `AUTO_DISABLE_INBOX_RULES`) change what the person sees or what happens to accounts. Change them only on request, and say what the change hides. The management UI actions Revoke sessions, Block sign-in, Unblock sign-in, and Turn off or Turn on a rule change the tenant: rule 1 applies.
5. **Interactive scripts.** `install.ps1` asks questions: the region, the alert mailbox, the response permissions, "Continue?", and for `-Uninstall` the resource group name. If your shell cannot answer prompts, run `./install.ps1 -DryRun -Yes` with all parameters (read only), and show the plan to the person. After the person agrees, run the same command without `-DryRun`. Or ask the person to run the script in their own terminal and paste the output to you. From bash or zsh, start it with `pwsh ./install.ps1`.
6. **Commercial cloud only.** GCC, GCC High, DoD, and China clouds are not supported. Say so if the tenant is in one of them.

## Repository map

| Path | Content |
|---|---|
| `install.ps1` | Install, rerun to repair, update (`-Update`), check (`-Verify`), and remove (`-Uninstall`) with the Azure CLI. `./install.ps1 -Help` lists the commands and options; `Get-Help ./install.ps1 -Detailed` has the details |
| `function/function_app.py` | Timer trigger, HTTP endpoints, pipeline, checkpoints, `_DETECTORS` list |
| `function/compromise_detector.py` | 13 detectors. Each returns findings: `type`, `severity`, `user`, `description`, `ip`, `event`; `actor` (who made the change; `_run` adds it) and, for a change to an account or mailbox, `target` |
| `function/geo_monitor.py`, `function/responder.py` | Per-user country baseline; revoke or block (automatic, or from the user page) |
| `function/journal.py` | Findings journal (table `monitorfindings`, 90 days): incident context in emails, user page, weekly report |
| `function/mailbox_rules.py` | Inbox rules through Graph: list, assess, turn off or on |
| `function/onboarding.py` | Onboarding scan: audit history (7 days), inbox rule sweep, audit search (up to 180 days), starting-state report (timer `background_jobs`) |
| `function/audit_search.py` | Microsoft Graph audit log search: onboarding history and the user page audit log |
| `function/mail_access.py` | Counts of `MailItemsAccessed` and `Send` records per day (does the tenant log mail reads?), and the mail access check: mail read or sent from a risky IP that did not sign in as the user |
| `function/microsoft_nets.py`, `function/microsoft_nets.json` | IP ranges that only Microsoft 365's servers use (generated by `scripts/update_microsoft_nets.py`). The session and mail access checks skip records (not sign-ins) from them |
| `function/signin_networks.py`, `function/network_backfill.py` | Networks (/24, /48) of each user's successful sign-ins, with the first and last time. The MFA change and inbox rule checks read them. The backfill loads 30 days of past sign-ins once (timer `background_jobs`) |
| `function/session_monitor.py` | One Entra session seen from two countries, or moved to a risky IP in the same country (stolen cookie or token) |
| `function/ip_checker.py` | IP parsing, proxycheck.io, cache, dedup, queues |
| `function/proxycheck_quota.py` | proxycheck.io quota: level from each answer, usage count (with a key), warning email once per day |
| `function/o365_client.py` | Tokens, Management API fetch, audit subscriptions (`ensure_subscriptions`), SSRF guard |
| `function/identity.py` | Managed identity tokens: the client assertion for the app registration, and Table Storage |
| `function/alerting.py` | All emails: titles, steps ("What to do"), layout, reports, posture, recipients, tenant label |
| `function/config.py`, `function/settings.py` | Defaults from app settings; UI overrides and validation |
| `function/admin_api.py`, `function/admin_store.py`, `function/ui/` | Management UI (`/api/manage`): settings, users, mutes, alerts, history |
| `function/ui_access.py` | Who can open the management UI: the Monitor.Admin role, listed users, listed directory roles (Graph role assignments) |
| `function/webhook.py` | Alerts to a webhook: Slack, Microsoft Teams (Workflows), or JSON (`ALERT_DELIVERY`, `WEBHOOK_URL`, `WEBHOOK_FORMAT`) |
| `function/service_actors.py` | App consents by Microsoft's own services: the acting service principal's app belongs to a Microsoft tenant (Graph `appOwnerOrganizationId`). Not used for MFA or role changes |
| `function/version.py`, `function/updates.py` | The code version, and the daily check for a newer GitHub release (notify only: Overview and the weekly report) |
| `function/selftest.py`, `scripts/live-test.ps1` | Synthetic test for every alert type; live test on a test mailbox |
| `tests/` | Offline Python tests (`make test`). `conftest.py` blocks network access |
| `tests/install.Tests.ps1` | Pester tests of `install.ps1` with a fake `az` (`make test-install`). No Azure access |
| `.devcontainer/` | Dev container: pinned Python, PowerShell, Pester, Azure CLI, Node.js (`make docker-check`, VS Code "Reopen in Container") |
| `docs/` | Getting Started, How-To, Alert Triage, Architecture, Security, API Compatibility, KQL queries |

## Deploy

### 1. Check the prerequisites

| Check | Command or place | Expected |
|---|---|---|
| PowerShell | `pwsh --version` | 7.2 or later. Windows PowerShell 5.1 is not enough. Windows: `winget install --id Microsoft.PowerShell --source winget`. macOS: `brew install powershell` (not `--cask`) |
| Azure CLI | `az version` | `azure-cli` 2.60 or later. Windows: `winget install --id Microsoft.AzureCLI --source winget`. macOS: `brew install azure-cli`. Older version: `az upgrade` |
| Azure Cloud Shell (option) | https://shell.azure.com, PowerShell | Has PowerShell 7 and the Azure CLI, and is signed in. Use it if the person cannot install tools |
| Python | `python3 --version` | 3.12, only for local tests (`make setup`, `make test`). Not necessary to install |
| Azure subscription | `az account list --query "[].{name:name, tenant:tenantId, state:state}" -o table` | An `Enabled` subscription in the Microsoft 365 tenant, with the Owner role. None, a free trial, a CSP subscription, or another tenant: follow [Get an Azure subscription](docs/GETTING_STARTED.md#get-an-azure-subscription). The person does it in the portal: a pay-as-you-go sign-up with a card, or, if the organization has a Microsoft Customer Agreement, "Create a subscription" on its billing profile (Plan: Microsoft Azure Plan) |
| Azure region | `az functionapp list-flexconsumption-locations --query "[].name" -o tsv` | The region is in the list (Flex Consumption) |
| Subscription role | Azure Portal > Subscriptions > Access control | Owner, or Contributor + User Access Administrator |
| Entra ID role | Entra admin center > Roles | Global Administrator. Or Privileged Role Administrator plus Exchange Administrator (the default `-MailSendScope mailbox` signs in to Exchange Online). The script grants admin consent itself |
| Unified audit logging | Exchange Online PowerShell: `Get-AdminAuditLogConfig \| Format-List UnifiedAuditLogIngestionEnabled` | `True`. Off by default with Business Basic, Standard, and Premium licenses, and in enterprise trial tenants. If `False`: Microsoft Purview > Audit > Start recording user and admin activity |
| Alert mailbox | Microsoft 365 admin center | A licensed mailbox, or a shared mailbox (free, no license). It sends and receives the alerts. To read the alerts of a shared mailbox, add the person's own address in Settings > Email > Extra recipients |
| proxycheck.io key | https://proxycheck.io/dashboard/ | Optional. Free: 1,000 queries per day (100 without a key). The person enters it in the management UI after the install |

Not necessary: Azure Functions Core Tools, and Python (only for local tests).

### 2. Install

The person runs it in PowerShell 7:

```powershell
./install.ps1 -AdminEmail security@contoso.com -Location eastus
```

The script prints 9 numbered steps (`[n/9]`). In step 2 it shows the plan (resource group, Function App, alert mailbox, Mail.Send scope, Graph roles) and asks "Continue?". If a step fails, it prints `ERROR` and `Fix`. After the fix, run it again: each step checks what exists and continues. At the end it prints the management UI URL and the next steps. Without `-Yes`, it then waits up to 10 minutes for the first monitor run (the audit subscriptions start), runs the self-test, and asks if it should send test emails. With `-Yes`, it does not wait or ask: run `./install.ps1 -Verify` about 10 minutes later.

An assistant runs it in two calls:

```powershell
# 1. Preview. Read only; it needs an az login. Show the PLAN lines to the person.
./install.ps1 -DryRun -Yes -AdminEmail <alert mailbox> -Location <region> -ResponsePermissions yes
# 2. Only after the person says yes to that plan:
./install.ps1 -Yes -AdminEmail <alert mailbox> -Location <region> -ResponsePermissions yes
```

Before the preview, ask the person for:

- The alert mailbox and the region.
- The response permissions: `yes` grants them now (the actions stay off until the person turns them on in the management UI), `no` gives email only.
- The Mail.Send scope: `-MailSendScope mailbox` (default: the alert mailbox only, through the Exchange group `<name>-senders`; for the Exchange Online sign-in, the script shows a URL and a code, which the person opens in any browser, also on another computer; this works in SSH and Cloud Shell. The monitor sends a "Device code sign-in" alert for that sign-in: it is expected) or `tenant` (Graph `Mail.Send` for every mailbox). See [Limit Mail.Send](docs/HOW_TO.md#limit-mailsend-to-the-alert-mailbox).
- Other management UI admins: `-UiAdmins sam@contoso.com`. The person who runs the script gets the role automatically.

For a second tenant (an MSP or a fractional CISO with more than one customer), add `-Tenant <customer domain>`: the script signs in to that tenant, selects its subscription, and sets the Azure CLI back at the end. Each install is saved in `~/.m365-ato-monitor/tenants.json`; `./install.ps1 -List` shows them, `./install.ps1 -UpdateAll` updates each (rule 1: it changes each tenant). With `-Yes`, the script does not open a sign-in for a new tenant: the person runs `az login --tenant <domain>` first. The alert mailbox must be a mailbox of the tenant; the script stops before any change if it is not. Use `-SubscriptionId` if `az account show` shows the wrong subscription. `-Name` sets the base name of all resources (default `m365-ato-monitor`). Use the same `-Name` in each later command.

### 3. Check the result

| Check | Command | Expected |
|---|---|---|
| Health and detectors | `./install.ps1 -Verify` | Each `/api/status` check with `OK` or `WARN`, then each alert type `detected` and "Self-test passed". `o365_api_*` can fail for some minutes after the first install |
| Email path | `./install.ps1 -Verify -SendTestAlerts` (tell the person first) | `email sent` for each type; one `[SELF-TEST]` email per alert type in the alert mailbox |
| Real alerts | `scripts/live-test.ps1 -TestUser <test mailbox> -ExternalAddress <outside address>` (the person runs it; it changes the tenant) | Real alerts when Microsoft publishes the records: often within minutes, sometimes 1–2 hours later. See [How-To: Test the alerts](docs/HOW_TO.md#test-the-alerts) |
| Management UI | The URL that `install.ps1`, `./install.ps1 -Verify`, and `./install.ps1 -List` print: `https://<function app>.azurewebsites.net/api/manage`. Each alert email and report also links to it | Opens after Entra ID sign-in. The person who ran the script has the Monitor.Admin role. Other people: Settings > Management UI access |
| First audit content | Wait | The monitor starts the audit subscriptions on its first run. Microsoft takes up to 12 hours (often 12–24) to deliver the first content. A setup confirmation email arrives after the first content |
| Starting state | Wait | A "Starting state" email follows the first run: inbox rules of every mailbox, past audit records, and manual checks. Help the person triage each item with [Alert Triage](docs/TRIAGE.md) |

Tell the person: alerts arrive when Microsoft publishes the audit record, often within minutes and sometimes 1–2 hours or more after the event; new-country alerts start after 14 days unless home countries are set; add a mail rule so `[M365 Alert]` mail does not go to junk; enter the proxycheck.io key in Management UI > Settings > Suspicious sign-ins; a weekly report arrives each Monday, and a missing report means the monitor did not run.

Ask the person if they want a tenant name in subjects (they manage more than one tenant) or extra recipients (a ticket system or an outside security contact). Both are in Management UI > Settings > Email.

### Common problems

| Symptom | Cause | Fix |
|---|---|---|
| `Signed in as` shows the wrong account, tenant, or subscription | `az` is not logged in, or is logged in to another tenant | Add `-Tenant <domain>`. Or `az login --tenant <tenant ID>`, then `az account set --subscription <ID>`, or pass `-SubscriptionId`. Run the script again |
| `<address> is not in the tenant that the Azure CLI is signed in to` | The alert mailbox is in another tenant | Use the `Fix:` command (`-Tenant <domain>`). For an outside recipient: a mailbox of this tenant as the alert mailbox, the outside address in Settings > Email > Extra recipients |
| `The Exchange Online sign-in went to another tenant` | The browser used an account of another tenant | The person runs the script again and opens the URL in a private browser window, with an account of the tenant in the plan |
| `Exchange Online sign-in failed` with `AADSTS53003` or "blocked" | Conditional Access blocks the device code sign-in | Use `-MailSendScope tenant`, or allow the device code flow for that admin account for this step (the person decides) |
| A "Device code sign-in" alert for the admin at the time of `install.ps1` | The Exchange Online sign-in of `-MailSendScope mailbox` uses a device code | Expected. Confirm the time and the account with the person who ran the script |
| `The tenant has more than one subscription.` (with `-Yes`) | The script cannot ask | Ask the person which one; pass `-SubscriptionId` |
| `The Azure sign-in has expired`, `AADSTS700082`, or `does not exist in MSAL token cache` | The Azure CLI sign-in expired (90 days without use) | Without `-Yes`, the script opens the browser to sign in again. With `-Yes`, the person runs `az login --tenant <tenant ID>`, then the script again. `az logout` is not needed |
| `Azure CLI <version> is too old` | Azure CLI older than 2.60 | `az upgrade` |
| `Azure sign-in failed.`, or "No subscriptions found" | No Azure subscription in the tenant | [Get an Azure subscription](docs/GETTING_STARTED.md#get-an-azure-subscription) |
| "Free trial subscription is not supported for Flex Consumption" | A free trial subscription | Upgrade it to pay-as-you-go. Run the script again |
| `Region '<name>' does not offer Flex Consumption.` | No Flex Consumption in that region | Use a region from the `Fix:` line |
| `role assignment create failed`, `AuthorizationFailed` | The person is not Owner or User Access Administrator | Get the role, then run the script again |
| An admin consent step (`Grant ...`) fails, `Authorization_RequestDenied` | The person is not Global Administrator or Privileged Role Administrator | Get the role, then run the script again |
| `/api/status did not answer`, or `table_storage` FAILED right after the install | Role assignments take some minutes to apply | Wait 10 minutes, then run `./install.ps1 -Verify`. If it still fails, run `./install.ps1 -Update` |
| `azure_ad_token` FAILED | The federated credential or the managed identity is missing | `./install.ps1 -Update` |
| An email from `alert-<name>-code-deployed` | Expected after each install, rerun, and `-Update`. Otherwise someone with write access to the resource group deployed code | If no one ran `install.ps1`: find who has Contributor, Owner, or Website Contributor on the resource group, then run `./install.ps1 -Update` (rule 1). See [How-To](docs/HOW_TO.md#check-that-the-monitor-runs) |
| `Code deployment alert not set up` (WARN) | Azure refused the storage logs or the workspace transformation | The other alerts work. Run `./install.ps1 -Update` again (rule 1). If the warning stays, report the error text |
| "No run" email or no runs right after the first update that turns on Entra ID for Application Insights | The managed identity's Monitoring Metrics Publisher role did not apply yet. The host sends telemetry with it | Wait 15 minutes, then run `./install.ps1 -Verify`. If it still fails, run `./install.ps1 -Update` |
| `Code deployed. The host check did not pass yet` | The host starts after the storage role and setting changes. This takes some minutes | Wait 10 minutes, then run `./install.ps1 -Verify` |
| `AF20022` or `AF20023` in status or logs | No audit subscription yet | Wait. The monitor starts the subscriptions on its first run, checks them every 6 hours, and starts them at once after this error |
| `graph_api_token` FAILED, or "Email not sent" | No admin consent for `Mail.Send`, or the alert mailbox is not a licensed mailbox. With `-MailSendScope mailbox`: the mailbox is not in the group `<name>-senders`, or Exchange did not apply the grant yet (30 minutes to 2 hours) | `./install.ps1 -Update`, or change the alert mailbox in Management UI > Settings > Email. With `mailbox`: wait 2 hours, then run `./install.ps1` again (rule 1) |
| `MailboxNotEnabledForRESTAPI` ("alert email(s) wait in the outbox") | The alert mailbox has no Exchange Online mailbox (no license, for example an admin account) | A shared mailbox (free) or an Exchange Online license. Then `./install.ps1 -AdminEmail <mailbox>` (rule 1): it puts the mailbox into the group `<name>-senders` and moves the health alerts. Exchange applies it in 30 minutes to 2 hours; the outbox sends the queued alerts then. For a shared mailbox, add the person's address in Settings > Email > Extra recipients |
| `proxycheck_io` FAILED, `status=denied`, or the email "proxycheck.io quota is low" or "is used up" | Quota used or key not valid | Check the key and usage on the proxycheck.io dashboard. The person enters a new key in the management UI (rule 2). Overview > Monitor > IP lookups shows the state. Sign-in checks wait up to 26 hours; session and mail access checks skip records |
| "No login events found" for more than 48 hours | Unified audit logging off | Check audit logging. Run `./install.ps1 -Verify` |
| Turning on audit logging asks for `Enable-OrganizationCustomization` | A new ("dehydrated") tenant | The person runs `Enable-OrganizationCustomization` once in Exchange Online PowerShell (rule 1), then `Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true` again. It can take some minutes to several hours before the second command works |
| A change in the management UI (save, mute, revoke) fails with HTTP 403 and no message; pages load | The platform refused it before the code ran: the Function App's CORS list does not have its own origin, or (older UI) the request had no `Referer` | `./install.ps1 -Update` adds `https://<function app>.azurewebsites.net` to CORS and deploys the UI that sends a `Referer` to its own origin. A 403 with "Request refused" comes from the code: Application Insights has "Management UI request refused" with the Origin and Host. Or the person runs `az functionapp cors add -g <resource group> -n <function app> --allowed-origins https://<function app>.azurewebsites.net` (rule 1) |
| "The management UI is off: App Service Authentication is not detected" | The app does not see `WEBSITE_AUTH_ENABLED`. Microsoft does not document whether Flex Consumption sets it | `./install.ps1 -Update`. Alerts still work. Do not set `WEBSITE_AUTH_ENABLED` by hand |
| `az login` or the script hangs on macOS | Outbound firewall (LuLu, Little Snitch) blocks the Azure CLI binary | Allow the binary or pause the firewall |
| macOS asks "python wants to use … my_service_name in your keychain" | The Azure CLI keeps its tokens in the keychain when `core.encrypt_token_cache` is on (off by default on macOS) | The person selects Always Allow, or runs `az config set core.encrypt_token_cache=false`, then `az logout` and `az login` |

More: [Getting Started > Troubleshooting](docs/GETTING_STARTED.md#6-troubleshooting).

## Operate

| Task | Where |
|---|---|
| Detection settings, alert mailbox, extra recipients, webhook (Slack, Teams, JSON), tenant name in subjects, allowlists, keywords, sign-in email level, countries, automatic response, weekly report, proxycheck.io key | Management UI > Settings. Applies from the next run. A rerun of `install.ps1` does not revert it |
| Approve a country before travel | Management UI > Countries |
| Stop email for one expected medium alert for some days | Management UI > Mutes, or Alerts > Mute similar under the alert (only on request; rule 4) |
| Revoke sessions, block or unblock sign-in, turn an inbox rule off or on | Management UI > Users > the user (rule 1) |
| See everything one user did (sign-ins, mail reads and sends, rules, changes) for 7 to 180 days | Management UI > Users > the user > Audit log. The search takes 5 to 40 minutes, sometimes longer |
| Run the onboarding scan again | Management UI > Overview > Tools |
| Graph permissions for the response actions | `./install.ps1 -ResponsePermissions yes` or `no` (rule 1). `no` removes the roles |
| Mail.Send for the alert mailbox only (default for a new install) | `./install.ps1 -MailSendScope mailbox` on an existing install (rule 1). See [How-To](docs/HOW_TO.md#limit-mailsend-to-the-alert-mailbox) |
| Change the alert mailbox | With the mailbox scope: the person adds the new mailbox to the group `<name>-senders` (Microsoft 365 admin center > Teams & groups), waits up to 2 hours, then changes it in Management UI > Settings > Email |
| Management UI admins | Management UI > Settings > Management UI access: user names, or directory roles (Global Administrator and others). Or the Monitor.Admin role: `./install.ps1 -UiAdmins <upn>`, or Entra admin center > Enterprise applications > `<name>-admin-ui` > Users and groups. Give access only on request |
| Repair the Azure resources or the app registrations | `./install.ps1` (rerun; rule 1) |
| Deploy new code | `./install.ps1 -Update` or `make deploy` (rule 1). More than one tenant: `./install.ps1 -Tenant <domain> -Update`, or `./install.ps1 -UpdateAll` |
| See the installations on this computer, with the management UI link | `./install.ps1 -List` (read only) |
| A custom domain for the management UI | [How-To: Use a custom domain](docs/HOW_TO.md#use-a-custom-domain). The person does it in the portal (rule 1) |
| Remove the monitor | `./install.ps1 -Uninstall` (rule 3) |
| Read an alert | [Alert Triage](docs/TRIAGE.md). Each email has "What to do" steps, the other alerts for the user in 24 hours, and the raw audit record. Check the record before you call it a false positive |
| Mark an alert as checked | Management UI > Alerts (or Users > the user): the Triage list of the alert: Open, Investigating, Benign, or Resolved, with an optional note. On the user page, select several alerts with the boxes, then Set triage. A muted alert shows as Benign until an admin changes it. Alerts of a type that is off (for example failed sign-ins) are only on the user page. It changes only the list (the Alerts view shows open and investigating alerts first); later alerts still send email. History records it. Set Benign or Resolved only when the person decides it |
| Find past detections | [App Insights queries](docs/APP_INSIGHTS_QUERIES.md) |
| See the monitor's errors | `./scripts/errors.ps1` (read only; Azure CLI sign-in). `-Tenant <domain>` for another installation |

When the person asks "is this alert real?": follow [Alert Triage](docs/TRIAGE.md), including its section "For AI assistants". Read the audit record in the email, compare the source IP and country with the user's usual sign-ins, and ask whether the user or an admin made the change. The alert email for an admin-type change says to confirm first. Do not tell the person an alert is benign without that check.

## Develop

```bash
make docker-check   # build the dev container, run all linters and tests in it (needs Docker)
make check          # the same checks with the tools on this computer
make setup          # venv + dependencies (Python 3.12), for make check without the container
make test           # offline Python tests
make test-install   # Pester tests of install.ps1 with a fake az (pwsh, Pester 5)
make lint           # py_compile, pyflakes, node --check, PowerShell parser
```

Prefer the dev container (`.devcontainer/`): it has the pinned versions of Python, PowerShell, Pester, the Azure CLI, and Node.js. Run `make docker-check` before you push. Do not run `install.ps1` in the container: `az login` there uses the device code flow, which this monitor reports.

CI runs four checks on each pull request (`.github/workflows/ci.yml`): Python tests and lint, Dependency audit, PowerShell (syntax and the Pester tests of `install.ps1`), and Workflow security (zizmor). A fifth workflow (`.github/workflows/devcontainer.yml`) builds the dev container and runs `make check` in it when the container or its inputs change. A sixth (`.github/workflows/microsoft-nets.yml`) runs every month: it fails if `function/microsoft_nets.json` (Microsoft 365 server ranges: the Office 365 endpoints list minus all Azure service tags) is out of date, or if a hand-kept `INTERNAL_NETS` prefix (`function/microsoft_nets.py`) is in an Azure service tag. To fix it, run `python3 scripts/update_microsoft_nets.py`, commit the file, and deploy (rule 1). A seventh (`.github/workflows/release.yml`) runs when a commit to `main` changes `function/version.py`: it runs CI, then tags the commit `v<VERSION>` and publishes a GitHub release, which installed monitors report as "Update available". Keep them green.

### Add a detection

1. In `function/compromise_detector.py`, write a `_<name>_finding(event) -> Optional[dict]` that returns `_finding(type, severity, user, description, event)` or `None` (pass `target=` if the change applies to an account other than the actor's), and a public `detect_<name>(events)` that calls `_run(events, _<name>_finding)`. `_run` isolates records that fail to parse.
2. Add `detect_<name>` to the import and to `_DETECTORS` in `function/function_app.py`. A test fails if a public `detect_*` function is not registered.
3. In `function/alerting.py`, add the type to `_FINDING_TITLES`, `_FINDING_SHORT`, and `_COMPROMISE_STEPS`. If an admin or the user can make the change on purpose, add the type to `_CONFIRM_FIRST`.
4. Add tests in `tests/` with a record in the Management Activity API shape (see [API Compatibility](docs/API_COMPATIBILITY.md)): one that fires, one that does not.
5. Update the detection tables in `README.md` and `docs/ARCHITECTURE.md`.

Use the field names from a real record (Microsoft Purview > Audit > export) or from public rules for the same operation (Elastic `rules/integrations/o365`, Splunk `detections/cloud/o365_*`, Sigma `rules/cloud/m365`). Severity: high for actions that are rarely legitimate (external forwarding, audit off, federation, top admin roles); medium for actions that admins also do.

### Style

- Docs and email text: short, direct sentences in the style of ASD-STE100 Simplified Technical English. One instruction per sentence. No marketing language.
- Code reads tunable values as `config.X` at call time (the UI changes them at runtime).
- Do not add network calls to tests. `tests/conftest.py` blocks sockets. `tests/install.Tests.ps1` uses a fake `az`.

## Facts for answers

- Latency: Microsoft guarantees no time. Its documentation gives 60–90 minutes as typical for core services; in practice many records arrive within about 10 minutes, and some take 1–2 hours or more. Plus the 2-minute timer.
- Failed sign-ins (wrong password) from a suspicious IP, an automation client, or an attack tool send no email unless `LOGIN_ALERT_FAILED` is on. They are in the journal as "alert type off". A correct password stopped by MFA or Conditional Access always alerts.
- proxycheck.io quota: 100 lookups per day without a key, 1,000 with a free key. The monitor keeps a clean answer for 7 days (Settings > Advanced > Keep clean IP lookups, `IP_CACHE_DAYS`, 1–7) and a flagged answer (VPN, proxy, hosting, Tor) for 24 hours. When it is used up, sign-in and new-country checks wait up to 26 hours, session and mail access checks skip records, and account takeover alerts are sent without IP reputation. The monitor emails when the quota is low, used up, or refused (at most once per day for each).
- It does not prevent attacks. Optional response (off by default): revoke sessions or block sign-in after a high account-takeover alert or a new-country sign-in; turn off a malicious inbox rule. The same actions are buttons on the user page in the management UI. It never changes passwords.
- Reports: "Starting state" after the first run (inbox rules of all mailboxes; the last 7 days of audit content; older changes, up to 180 days, from the audit log search), weekly health report (Mondays), monthly report.
- Mutes hide medium alerts only, for 1–3650 days. A mute can name one network (ASN): it then hides only alerts from IPs in that network. High alerts are always sent.
- Licenses: works with Business Basic and higher, also in tenants with Entra ID P1 or P2. Needs no Entra ID P1/P2, Defender, Sentinel, or E5. Microsoft's own risk detection and response (Entra ID Protection risk policies and "users at risk" alerts) needs P2; Business Premium includes P1 only.
- Audit logging: off by default with Business Basic, Standard, and Premium licenses, and in enterprise trial tenants. Check it in every tenant before the install.
- Permissions: `ActivityFeed.Read` (Office 365 Management APIs). Graph application roles: always `User.ReadBasic.All`, `MailboxSettings.Read`, `AuditLogsQuery.Read.All`, `RoleManagement.Read.Directory` (directory roles for management UI access), and `Application.Read.All` (which tenant owns an acting app); `Mail.Send` only with `-MailSendScope tenant` (with `mailbox`, the default, Exchange Online RBAC for Applications grants "Application Mail.Send" for the members of the group `<name>-senders`); with the response permissions (the script asks; default yes) `User.RevokeSessions.All`, `User.EnableDisableAccount.All`, `User.Read.All`, and `MailboxSettings.ReadWrite` (replaces `MailboxSettings.Read`). The responses stay off until they are turned on in the management UI. Azure RBAC: Monitoring Reader on Application Insights and Monitoring Contributor on the action group (the monitor app); Storage Blob Data Owner, Storage Table Data Contributor, and Monitoring Metrics Publisher on Application Insights (the managed identity).
- Credential: a user-assigned managed identity, which is the only credential of the app registration (federated identity credential). No client secret, no storage key. Nothing expires or needs rotation.
- Webhook: optional (Management UI > Settings > Webhook). Alerts only; reports stay in email. With "Webhook only", a failed webhook sends the alert by email. Do not take the webhook URL in chat: it is a secret, and the person enters it in the management UI.
- Data: audit records are processed in memory; detections and summaries go to Application Insights in the person's subscription; one row per alert, with the alert's audit record (the same record as in the alert email), is kept for 90 days in Table Storage (findings journal). The proxycheck.io key is in Table Storage. IP addresses go to proxycheck.io. For the MFA and inbox rule checks, the networks (/24, /48) and the last 48 hours of sign-in IPs of each user are kept in Table Storage; a user's row is deleted after 90 days with no sign-in. Once a day, the update check asks the GitHub API for the latest release (no tenant data; Settings > Advanced > Check for updates).
- Platform: Azure Functions Flex Consumption (Linux, Python 3.12, 512 MB instance memory). The Linux Consumption retirement (30 September 2028) does not affect it.
- Cost: about $2–10 per month for a small tenant: the Function App $1–3 (the 2-minute timer), storage, Log Analytics ingestion, three log alert rules, and an activity log alert (no charge).
- Azure change alerts: Azure Monitor (not the app) emails the alert mailbox for each code deployment (`alert-<name>-code-deployed`, from the storage logs of the `deployments` container) and each Azure change to the monitor's resource group (`alert-<name>-azure-change`, activity log). Each install, rerun, and `-Update` sends one "code deployed" email. An unexpected one means someone with write access to the resource group changed the monitor: see [How-To: Check that the monitor runs](docs/HOW_TO.md#check-that-the-monitor-runs).
- Azure hardening: Application Insights accepts telemetry with Entra ID only (the managed identity has Monitoring Metrics Publisher); deployment with a user name and password (SCM, FTP) is off.
- One installation per tenant, in an Azure subscription of that tenant. `-Tenant <domain>` installs in, updates, checks, or removes from another tenant; `-List` and `-UpdateAll` work on the installations saved in `~/.m365-ato-monitor/tenants.json` (no secrets). With `-Tenant`, the alert subjects carry the organization name.
- Management UI access: the admin UI app does not require assignment, so any user of the tenant can sign in. The function allows only users with the Monitor.Admin role, the listed users, and the members of the listed directory roles (active, direct assignments). Everyone else gets HTTP 403.
- App consent records written by Microsoft's own services are not emailed: the acting service principal's app belongs to a Microsoft tenant (`f8cdef31-a31e-4b4a-93e4-5f571e91255a` or `72f988bf-86f1-41af-91ab-2d7cd011db47`). They are in the journal as "Microsoft service". This applies to app consents only: MFA method changes (written by the MFA service) and role changes (PIM) are not skipped as Microsoft service changes. An MFA method added by the user or by an admin sends email when the user or the admin had another alert in the 7 days before (then high), when the sign-in of the person who made the change (in the hour before) came from a network that they did not use before, or when the monitor saw no sign-in by that person. Otherwise it is in the journal as "Known sign-in" with no email. A person whose network history is shorter than 14 days also gets "Known sign-in" (no email) unless there was another alert. After an install or the update that adds it, the monitor loads 30 days of past sign-ins once (Graph audit search, `network_backfill.py`; Overview > Monitor > Past sign-ins loaded), so this period is short. Exchange and Windows service accounts are skipped by the detectors. A change that a person makes, also through a Microsoft app, still alerts.
- Permission grants that `install.ps1` makes to the monitor app are not emailed and not shown (not in Alerts, the user page, or the reports). Only the log has them ("Install grant"). The expected set follows the install's choices: Graph `Mail.Send` only with `-MailSendScope tenant`, the response roles only with `-ResponsePermissions yes`, and the Exchange role "Application Mail.Send" for the monitor app with `mailbox`, only in the scope `<name>-senders scope`. A grant from an earlier run with other choices (for example `-MailSendScope tenant`, then `mailbox`) also counts when the account, the roles, and the time match that run (app setting `INSTALL_GRANTS`, written by `install.ps1`; a change to it sends the Azure change alert). Any other grant to the monitor app still alerts, also the same Exchange role with no scope or another scope.
