# API Compatibility

The external APIs that the tool uses, the permissions, and the constraints. Reviewed: November 2026.

All Microsoft APIs below are generally available. The app authenticates with OAuth 2.0 client credentials (v2.0 token endpoint). The client credential is a client assertion. The assertion is a token of the Function App's user-assigned managed identity for the audience `api://AzureADTokenExchange`. The app registration trusts this token as a federated identity credential. Table Storage uses a managed identity token directly. There is no client secret. The app does not use basic auth.

Cloud: commercial only. The token endpoint (`login.microsoftonline.com`) and the Management API host (`manage.office.com`) are fixed in the code.

---

## Office 365 Management Activity API

The source of all audit data.

| Property | Value |
|---|---|
| Base URL | `https://manage.office.com/api/v1.0/{tenant}/activity/feed` |
| Resource (app ID) | `c5393580-f805-4401-95e8-94b7a6ef2fc2` (Office 365 Management APIs) |
| Permission | `ActivityFeed.Read` (Application) |
| Token scope | `https://manage.office.com/.default` |
| Content types | `Audit.AzureActiveDirectory`, `Audit.Exchange` |

Flow: `subscriptions/list` shows the subscriptions. `subscriptions/start` enables a content type. The function calls them itself: on the first run, every 6 hours, and at once after error `AF20022` or `AF20023`. `subscriptions/content` lists the blobs for a time window. The app downloads each `contentUri`. It sends the token only to `manage.office.com` (SSRF guard).

Window rules (Microsoft documentation):

- `startTime` and `endTime` select blobs by the time they became available: `startTime <= contentCreated < endTime`.
- The window is 24 hours or less.
- `startTime` is not more than 7 days in the past.

Record types:

| RecordType | Name | Use |
|---|---|---|
| 15 | AzureActiveDirectoryStsLogon | Sign-ins (eSTS): IP, user agent, `RequestType` |
| 9 | AzureActiveDirectoryAccountLogon | Sign-ins (legacy) |
| 8 | AzureActiveDirectory | Consents, app role assignments, MFA changes, role members, app credentials, domains |
| 1 | ExchangeAdmin | Inbox rules, `Set-Mailbox`, transport rules, mailbox and folder permissions, audit settings, mail protection policies, Exchange role assignments |
| 2 | ExchangeItem | `UpdateInboxRules` (Outlook and EWS rule changes) |

### Record formats

Sources, checked November 2026:

- Microsoft: the Management Activity API schema, Learn pages *Audit log activities*, *Mailbox auditing*, and *Audit log detailed properties*, the Exchange Online PowerShell reference (cmdlet parameter names), and the Microsoft Entra authentication error codes.
- Real records: the Elastic Microsoft 365 integration test data (382 records, 67 operations), Microsoft Sentinel samples, and `UpdateInboxRules` records from Splunk attack_data and SEKOIA intake-format tests. All detectors were run on these records. `tests/test_record_formats.py` has a test for each detail below.

Common fields:

| Field | Format | How the app reads it |
|---|---|---|
| `RecordType`, `UserType` | Int32 in the schema. Some records carry a string (`"15"`). | `config.record_type()`; string compare |
| `Target[].Type`, `Actor[].Type` (IdentityType) | 1 = Name, 2 = Other (IDs), 3 = PUID, 4 = SPN, 5 = UPN. Integer or string. | String compare |
| `Operation` | Learn sometimes uses another case than records (`Set company information.`) | Matched without case |
| `ResultStatus` | Exchange admin: `True`, `False`. Other workloads: `Succeeded`, `PartiallySucceeded`, `Failed`; Entra ID: `Success`, `Failure`. | A failed operation causes no compromise alert. User agent checks include failed sign-ins; a wrong password sends email only with `LOGIN_ALERT_FAILED`. |
| `ClientIP` | Exchange admin records add a port: `198.51.100.20:54321`, `[2001:db8::5]:443`. Empty or null for Entra ID admin activity. | `extract_ip` reads `ClientIP`, `ClientIPAddress` (mailbox records), `ActorIpAddress` (Entra ID), `ActorIP`, `ExtendedProperties[ClientIPAddress]`, and returns the first public address |
| `UserId` | A UPN, or `NT AUTHORITY\SYSTEM (...)`, `NT SERVICE\<service> (...)`, a service SID (`S-1-5-18`, or `S-1-5-80-...`, the SID form of `NT SERVICE\`), `Certificate` (a Microsoft service), or `ServicePrincipal_<id>` | Service accounts are skipped for permission changes. `Certificate` adding a Microsoft first-party app (app ID `xxxxxxxx-0000-0000-c000-000000000000` or `xxxxxxxx-0000-0ff1-ce00-000000000000`) to a role is skipped. For `ServicePrincipal_<object ID>`, the monitor reads the service principal's `appOwnerOrganizationId` (Graph, `Application.Read.All`): a Microsoft tenant (`f8cdef31-a31e-4b4a-93e4-5f571e91255a`, `72f988bf-86f1-41af-91ab-2d7cd011db47`) means a Microsoft service. For an app consent only, the finding is then journaled as "Microsoft service" without email. MFA method changes also have a Microsoft service as `UserId`. They are never skipped as a Microsoft service. They send email unless the person who made the change signed in from a known network and no one involved had another alert (see [Architecture](ARCHITECTURE.md)). For a service principal, the alert names it from `Actor` type 1 (for example `Azure MFA StrongAuthenticationService`). |

Operations:

| Operation | Fields |
|---|---|
| `UserLoggedIn`, `UserLoginFailed` | `ExtendedProperties`: `UserAgent` (`BAV2ROPC` is legacy authentication), `RequestType` (`Cmsi:Cmsi` is the device code flow; other values: `OAuth2:Authorize`, `Login:login`), `ResultStatusDetail`. Failure: `ErrorNumber` (AADSTS code; `ErrorCode` in the schema document) and `LogonError` (the code name, for example `UserStrongAuthClientAuthNRequiredInterrupt` = 50074). Some records have only `LogonError`. `config.LOGON_ERROR_CODES` maps the names. |
| `Consent to application.` | `ModifiedProperties[ConsentAction.Permissions].NewValue`: `[[... Scope: a b]] => [[... Scope: a b c]]; `. App name: `Target` type 1. |
| `Add app role assignment to service principal.` | `ModifiedProperties[AppRole.Value].NewValue` is the permission (for example `full_access_as_app`). App name: `ServicePrincipal.DisplayName`. |
| `Add OAuth2PermissionGrant.`, `Add delegated permission grant.` | Delegated grants. Scopes in a `ModifiedProperties` entry whose name contains `Scope` or `Permission`. |
| Exchange admin cmdlets | `Parameters`: one `{Name, Value}` per argument, with the cmdlet's parameter names (`BlindCopyTo`, `AccessRights`, `UnifiedAuditLogIngestionEnabled`, `AutoForwardingMode`, ...). `Identity` can be a path: `.../Microsoft Exchange Hosted Organizations/<tenant>/<name>`; the alert shows the last part. |
| `Set-Mailbox` | `ForwardingSmtpAddress` (`smtp:user@domain`), `ForwardingAddress`, `DeliverToMailboxAndForward`, `GrantSendOnBehalfTo`, `AuditEnabled`. An empty value removes forwarding. |
| `New-InboxRule`, `Set-InboxRule` | `Parameters` (cmdlet names). The rule name is `Name`, or the last part of `Identity` or `ObjectId` (`mailbox\rule`). |
| `UpdateInboxRules` (Outlook desktop) | Mailbox audit, on by default. Outlook on the web writes `New-InboxRule`/`Set-InboxRule` instead. `OperationProperties`: `RuleOperation` (`AddMailboxRule`, `ModifyMailboxRule`, `RemoveMailboxRule`), `RuleId`, `RuleState`, `RuleCondition`, `RuleName` (can have no `Value`), `RuleProvider`, `RuleActions` (JSON: `[{"ActionType":"Forward","Recipients":[...],"ForwardFlags":"..."}]`). `ActionType` `DeferAction` is a client-side rule with no details. A `Move` action has a folder ID, not a name. `ClientInfoString` `Client=MSExchangeRPC`. |
| `UpdateInboxRules` (EWS) | `OperationProperties`: `RuleOperation` (`Create`, ...), `Name`, `Actions` (`ForwardToRecipientsAction`, `RedirectToRecipientsAction`, `ForwardAsAttachmentToRecipientsAction`, `MoveToFolderAction`, `DeleteAction`, `MarkAsReadAction`), `Conditions`, `ServerRule` (JSON; recipients in `Actions[].Recipients[].Values[].Value`). `ClientInfoString` `Client=WebServices;<user agent>`. The detector reads addresses from the actions only, not from the conditions, and flags a rule made by a script (`python-requests` and other automation user agents). |
| `UpdateFolderPermissions` | Mailbox audit, on by default for owner, delegate, and admin. Older records: `ModifyFolderPermissions`, `AddFolderPermissions`. `Item.ParentFolder`: `Name`, `Path`, `MemberUpn` (`Everyone`, `Default`, `Anonymous`, or an address), `MemberRights` (`ReadAny, Visible, ...`). `MailboxOwnerUPN`, `ClientIPAddress`. |
| `Update user.` (MFA) | `ModifiedProperties[StrongAuthenticationMethod]` and `[StrongAuthenticationPhoneAppDetail]`: JSON lists (sometimes with `\r\n` formatting) in `OldValue` and `NewValue`. The detector compares the number of entries. The MFA service writes the record (`UserId` `ServicePrincipal_...`); the account is `ObjectId` or `Target` type 5. |
| Session ID (sign-ins) | `DeviceProperties`: `{"Name":"SessionId","Value":"<guid>"}`. On successful sign-ins; on failed sign-ins only for some errors (for example MFA interrupts). The unified audit log has interactive sign-ins only; refresh-token use is not in it. |
| Session ID (workload records) | Exchange: `SessionId`. Exchange, SharePoint, Teams: `AppAccessContext.AADSessionId` (with `UniqueTokenId`, `IssuedAtTime`). The same GUID as the sign-in. Missing on about half of records, for example Outlook desktop (`Client=MSExchangeRPC` has `SessionId` only), REST and EWS app access, and admin cmdlets. |
| `Update user.` (phone numbers) | `ModifiedProperties[StrongAuthenticationUserDetails]`: `[{"PhoneNumber":...,"AlternativePhoneNumber":...,"VoiceOnlyPhoneNumber":...}]`. Passkey, FIDO2, and Windows Hello registrations are not in the unified audit log. |
| `Add member to role.` | `ModifiedProperties[Role.DisplayName].NewValue` is the role. The member is the `Target` entry of type 5 (UPN) or `ObjectId`. |
| `Update application – Certificates and secrets management ` | En dash and a trailing space in real records. `ModifiedProperties[KeyDescription]`. App name: `Target` type 1 or `ExtendedProperties[targetName]`. |
| Domains | `Set domain authentication.`, `Set federation settings on domain.` (federation); `Add domain to company.`, `Verify domain.`, `Add verified domain.`, `Add unverified domain.` (domain added) |

`Disable Strong Authentication.` is confirmed by the Microsoft Learn password-spray playbook and by a real record, where `StrongAuthenticationRequirement` goes to `[]`.

Not confirmed in Microsoft documentation or in sample records: `Set-TransportRule` and `New-ManagementRoleAssignment` record examples (the parameter names are confirmed in the cmdlet reference), and the `UpdateInboxRules` `ActionType` names other than `Forward` and `DeferAction`. If one of these detections does not fire when you expect it to, compare with a record from Microsoft Purview > Audit.

Constraints:

- Unified audit logging must be on. Otherwise no content exists. See [Getting Started](GETTING_STARTED.md#unified-audit-logging).
- After a subscription starts, Microsoft documents up to 12 hours to deliver content. In practice it often takes 12–24 hours.
- Subscriptions are tenant-level. `./install.ps1 -Uninstall` does not stop them. They cost nothing, and a new installation uses them again.

---

## Microsoft Graph

Used to send email, to read inbox rules, and to search the audit log ([below](#microsoft-graph-audit-log-search)). Optional: UPN-to-object-ID lookup and the response actions.

| Property | Value |
|---|---|
| Endpoints | `POST /v1.0/users/{ADMIN_EMAIL}/sendMail`; `GET /v1.0/users` (inbox rule sweep); `GET /v1.0/users/{upn}/mailFolders/inbox/messageRules`; optional `GET /v1.0/users/{upn}?$select=id`; optional `PATCH /v1.0/users/{upn}` (`accountEnabled`) and `POST /v1.0/users/{upn}/revokeSignInSessions`; optional `PATCH /v1.0/users/{upn}/mailFolders/inbox/messageRules/{id}` (`isEnabled`) |
| Resource (app ID) | `00000003-0000-0000-c000-000000000000` |
| Permissions | Always `User.ReadBasic.All`, `MailboxSettings.Read`, `AuditLogsQuery.Read.All`, `RoleManagement.Read.Directory` (directory roles for management UI access: `GET /roleManagement/directory/roleAssignments`), and `Application.Read.All` (the tenant that owns an acting app: `GET /servicePrincipals/{id}?$select=appOwnerOrganizationId`); `Mail.Send` only with `-MailSendScope tenant`; with the response permissions `User.RevokeSessions.All`, `User.EnableDisableAccount.All`, `User.Read.All`, and `MailboxSettings.ReadWrite` (replaces `MailboxSettings.Read`). All Application |
| Token scope | `https://graph.microsoft.com/.default` |

Graph `Mail.Send` (Application) can send as any mailbox. The default (`-MailSendScope mailbox`) uses Exchange RBAC for Applications instead: [How-To](HOW_TO.md#limit-mailsend-to-the-alert-mailbox).

---

## Microsoft Graph audit log search

Used by the onboarding scan (history before the last 7 days) and the user page (audit log of one user). Module: `audit_search.py`.

| Item | Value |
|---|---|
| Endpoints | `POST /v1.0/security/auditLog/queries`; `GET /v1.0/security/auditLog/queries/{id}`; `GET /v1.0/security/auditLog/queries/{id}/records?$top=500`, then `@odata.nextLink` |
| Status | Generally available in v1.0 since October 2026 (Message Center MC1505599). Microsoft moved it back to beta once in April 2025 |
| Permission | `AuditLogsQuery.Read.All` (Application). The pair `AuditLogsQuery-Exchange.Read.All` and `AuditLogsQuery-Entra.Read.All` returns Exchange and Entra ID records only |
| Filters used | `filterStartDateTime`, `filterEndDateTime`, `operationFilters` (onboarding), `userPrincipalNameFilters` (user page) |
| Status values | `notStarted`, `running`, `succeeded`, `failed`, `cancelled` |
| Limits | At least 200 searches per tenant in 24 hours, 50 queued or running, 1,000,000 records per search (`isRecordCountLimitExceeded`). HTTP 429 when throttled |
| Time | Typically 4 to 40 minutes. Up to 48 hours for a broad search. Microsoft keeps a finished search for 30 days |
| Record | `auditData` is the audit record as a JSON object, with the Management Activity API fields (`CreationTime`, `Operation`, `UserId`, `Parameters`, ...) and an `@odata.type` key. Some types keep fields in `dynamicProperties`; the module merges them |
| Retention | Audit (Standard): 180 days (all Microsoft 365 Business plans). Audit (Premium, E5 users): 1 year |

Not checked against a live tenant yet: the record shape, the speed, and whether `GET /queries/{id}` accepts the scoped permissions.

## App Service Authentication (management UI)

| Property | Value |
|---|---|
| Provider | Entra ID (v2.0 endpoint), single tenant |
| App registration | `<name>-admin-ui`: app role `Monitor.Admin`, no assignment required, delegated `User.Read` (admin consent by `install.ps1`), ID token (implicit) |
| Redirect URI | `https://<function app>.azurewebsites.net/.auth/login/aad/callback` |
| Excluded paths | `/api/status`, `/api/health`, `/api/recent`, `/api/test`, `/api/selftest` (function keys), `/admin/*` (Functions host admin API) |
| Identity to the code | `X-MS-CLIENT-PRINCIPAL` header (claims, including `roles`). The code trusts it only if `WEBSITE_AUTH_ENABLED` is `true` |
| Flex Consumption | App Service Authentication is set through `config/authsettingsV2`. Microsoft does not document whether Flex Consumption sets `WEBSITE_AUTH_ENABLED`. If it is missing, the management UI stays off (fail closed) |

---

## Application Insights query API

Used by the monthly roll-up. It counts the monitor's own traces for 30 days.

| Property | Value |
|---|---|
| Endpoint | `POST https://api.applicationinsights.io/v1/apps/{appId}/query` |
| Authorization | Monitoring Reader (Azure RBAC) on the App Insights resource, for the app's service principal (`install.ps1` assigns it) |
| Token scope | `https://api.applicationinsights.io/.default` |
| Setting | `APP_INSIGHTS_APP_ID` |

The URL comes from configuration, not from an API response. If `APP_INSIGHTS_APP_ID` is not set, the roll-up logs an error and stops. The monitor is not affected.

---

## proxycheck.io v3

IP reputation for sign-in IPs and finding IPs. Checked November 2026.

| Property | Value |
|---|---|
| Endpoint | `POST https://proxycheck.io/v3/?p=1&key=<key>` with form field `ips=<a,b,c>` (up to 1,000 per request) |
| Key | Query string only. A POST to `/v3/` with no query string gets a 302 redirect to a lookup of the caller's own IP. |
| Quota | 100 queries/day without a key, 1,000/day with a free key. Paid plans add queries only. They add no fields: "we do not gatekeep features behind our paid plans" (pricing page). |
| Flags | None needed. v3 returns the full result. |

`ip_checker.from_v3` turns each result into the v2 keys that the rest of the code reads. An answer in the v2 shape (an older cache entry) passes unchanged.

| v3 field (real answers) | v2 key | Use |
|---|---|---|
| `detections.tor`, `compromised`, `proxy`, `vpn`, `anonymous`, `hosting` (booleans) | `type`: `TOR`, `Compromised Server`, `Proxy`, `VPN`, `Inference Engine`, `Hosting`, in this order. Else `network.type` (`Residential`, `Business`, `Wireless`) | Confidence. Tor, compromised: high. Proxy: medium, or high with attacks in `attack_history`. VPN, anonymous, hosting: medium |
| any of those except `hosting` | `proxy` (`yes`/`no`) | Flags |
| `detections.risk` (0–100) | `risk` | Risk score. Not at the top level, which the published spec says |
| `location.country_code`, `country_name`, `city_name`, `region_name` | `isocode`, `country`, `city`, `region` | Country baseline. The spec says `isocode` |
| `network.asn`, `provider`, `organisation`, `hostname` | the same names | Network, mutes, allowlists |
| `operator.name` | `operator` | Alert text only ("Service") |
| `attack_history` (counts by type, for example `login_attempt`) | `attacks` | Alert text only ("Attacks seen") |

v2 calls a cloud host (Azure, AWS) a VPN with risk 66. v3 calls it hosting with risk 33. Both are medium. A comparison of 322 IPs from two tenants, and 18 public VPN, Tor, and cloud IPs, gave the same confidence in v2 and v3 for each IP. A v3 `proxy` IP is medium, and high if `attack_history` has attacks. v2 gave high to SOCKS proxies only, and low to other proxies. v3 does not say which kind of proxy.

Response `status`:

| Status | HTTP | Meaning | App action |
|---|---|---|---|
| `ok` | 200 | Results returned | Use the results |
| `warning` | 200 | Results with a warning (for example within 10% of the quota) | Use the results, log the message |
| `denied` | 401, 403, 429 | Quota used, key not valid, or rate limit | Log a warning. Note the quota state. Cache a failure for 5 minutes. |
| `error` | 400 | No valid addresses | Log a warning |

A per-IP object with no `detections` and no `proxy` field is a failed lookup. The API returns each IP key as the client sent it, so the app sends canonical IPs.

---

## Platform lifecycle

Checked November 2026.

| Platform | Status | Effect on this tool |
|---|---|---|
| Azure Functions Flex Consumption (`FC1`) | Current. Linux only. Supports Python 3.10–3.14. Billing: $0.000026 per GB-s in most regions ($0.000037 in some) and $0.40 per million executions. Free grant per subscription and month: 100,000 GB-s and 250,000 executions, shared by all Flex Consumption apps in the subscription. Minimum billed execution: 1 second. Not in every region (`az functionapp list-flexconsumption-locations`) | The tool runs on Flex Consumption with 512 MB instance memory (about $1–3 per month). `install.ps1` checks the region |
| Flex Consumption limits | The host must start within 30 seconds. A deployment to a stopped app reports success, but the app starts with no functions (Azure/Azure-Functions issue 2670). Microsoft does not document whether the platform sets `WEBSITE_AUTH_ENABLED` | `install.ps1` starts the app before it deploys. The management UI fails closed without `WEBSITE_AUTH_ENABLED` |
| Python on Azure Functions | 3.11 support ends October 2027. 3.12 ends October 2028. Flex Consumption supports 3.10–3.14. | The tool runs on 3.12. Flex Consumption also offers 3.13 and later, so a later Python version needs no change of plan |
| Azure CLI | `az functionapp create --flexconsumption-location` and the Flex deployment storage flags. `install.ps1` needs 2.60 or later | The script stops with "too old" and the fix `az upgrade` |
| proxycheck.io | v3 is current (stable June 2026). v2 is "Legacy", supported "until 2035". Limits: 100 queries per day without a key, 1,000 with a free key. | The tool uses v3. |
| Application Insights query API (`/v1/apps/{appId}/query`) | Current. The `beta` path ended March 2026. `batch` ends March 2028. Entra ID authentication is required. | No change (`/v1`, single queries, Entra token). |
| Exchange Online application access policies | Replaced by RBAC for Applications. Microsoft will announce a deprecation later. | `install.ps1 -MailSendScope mailbox` uses RBAC for Applications: a management scope with `MemberOfGroup` (direct members only), and `Test-ServicePrincipalAuthorization` to check. Microsoft: changes apply in 30 minutes to 2 hours (cache). |

## iCloud Private Relay egress list

| Property | Value |
|---|---|
| URL | `GET https://mask-api.icloud.com/egress-ip-ranges.csv` (public, no key) |
| Format | One range per line: `prefix,country,region,city,` (IPv4 and IPv6). About 12 MB, 285,000 ranges; about 18,000 after adjacent ranges of one country are merged. |
| Use | With `PRIVATE_RELAY_TRUSTED`, a relay IP is not sent to proxycheck.io and gets the country from the list. Downloaded at most once a day per instance (1–2 seconds). |

## Licensing

These APIs work with Microsoft 365 Business Basic and higher. The tool needs no Entra ID P1/P2, Defender, or E5 license.

## Changes to watch

- The Management API content schema is additive. The parsers ignore unknown fields.
- If Microsoft adds a sign-in RecordType, add it to `LOGIN_RECORD_TYPES` in `function/config.py`.
- If Microsoft changes the `UpdateInboxRules` format, update `_update_inbox_rules_indicators` in `function/compromise_detector.py`.
- Microsoft renames Entra ID audit operations from time to time (for example the en dash in `Update application – Certificates and secrets management `). The app-credential detector matches the start and a fixed part of the name.
- The Graph audit log search is new in v1.0 (October 2026). If Microsoft moves it to beta again, change `_GRAPH` in `function/audit_search.py`. The onboarding report and the user page then say "not searched" or show the HTTP error until the fix.
- The Microsoft 365 docs name the search filter `serviceFilter` in one place and `serviceFilters` in another. The module does not use it.
