#Requires -Version 7.2
<#
.SYNOPSIS
    Install, update, check, or remove M365 ATO Monitor with the Azure CLI.

.DESCRIPTION
    One script for Windows, macOS, Linux, and Azure Cloud Shell. It needs
    PowerShell 7.2 or later and the Azure CLI. Nothing else.

    Install (and update; run it again at any time):
      - Resource group, storage account (no shared keys), user-assigned
        managed identity, Log Analytics, Application Insights.
      - Function App on the Flex Consumption plan (Python 3.12).
      - App registration for the monitor. Its credential is the managed
        identity (federated credential): there is no client secret.
      - Admin consent for the Graph and Office 365 Management API permissions.
      - App registration for the management UI sign-in, with the
        Monitor.Admin role for you.
      - Azure Monitor health alerts (no runs for 1 hour, repeated errors).
      - The function code.
    After the install, change settings in the management UI. You do not need
    this script again, except to deploy a new version (-Update) or to remove
    the monitor (-Uninstall).

    The person who runs it needs: Owner (or Contributor and User Access
    Administrator) on the subscription, and Global Administrator or
    Privileged Role Administrator in Entra ID (for admin consent). With
    -MailSendScope mailbox (the default), also Exchange Administrator, unless
    Global Administrator.

.PARAMETER AdminEmail
    The alert mailbox. A licensed or shared mailbox in the tenant of the
    installation. It sends and receives every email. The script stops if the
    address is not a mailbox of that tenant. The management UI can change it
    later. To get alerts at an outside address, add it in the management UI:
    Settings > Email > Extra recipients.

.PARAMETER Tenant
    Install in, update, check, or remove from this tenant: a domain of the
    tenant (contoso.com, contoso.onmicrosoft.com) or the tenant ID. Use it for
    a second tenant and after. The script signs in to that tenant if necessary,
    selects its subscription (it asks if there is more than one), and sets the
    Azure CLI back to your earlier subscription at the end. Without -Tenant,
    the script uses the tenant that the Azure CLI is signed in to; if it is
    not signed in, it signs in to the tenant of -AdminEmail.

.PARAMETER Name
    Base name for all resources. Default: m365-ato-monitor.

.PARAMETER Location
    Azure region with Flex Consumption, for example eastus or westeurope.

.PARAMETER ResponsePermissions
    yes: grant the Graph permissions for revoke sessions, block sign-in, and
    turn off inbox rules now. The actions stay off until you turn them on in
    the management UI. no: email only. ask (default): ask.

.PARAMETER MailSendScope
    mailbox (default): the app can send only as the alert mailbox. The script
    creates the mail-enabled security group <Name>-senders in Exchange Online,
    with the alert mailbox as its only member, and gives the app Mail.Send for
    the members of that group (Exchange RBAC for Applications). It installs the
    ExchangeOnlineManagement module if it is missing. For the Exchange Online
    sign-in, it shows a URL and a code: open the URL in any browser (also on
    another computer) and enter the code. To use another alert mailbox later, add it
    to the group, then change it in the management UI. tenant: Graph Mail.Send
    for every mailbox. A rerun keeps the current scope unless you give this
    parameter.

.PARAMETER UiAdmins
    More users who get the Monitor.Admin role. You get it automatically.

.PARAMETER UiSessionHours
    How long a management UI sign-in lasts, in hours (1 to 24). Without it, App
    Service Authentication keeps a sign-in for 8 hours. Blocking an admin or
    revoking the admin's sessions does not end a management UI sign-in: a shorter
    time limits that. Later runs (also -Update) keep the value. 0 keeps the
    current value.

.PARAMETER HostLogs
    full (default) or warnings. warnings: the Functions host logs only warnings
    and errors from its start-up and its own components, and sends no host metrics
    or performance counters. This is about 85% of the log volume. The monitor's
    own logs, the reports, and the health alerts do not change. Later runs (also
    -Update) keep the value.

.PARAMETER Update
    Deploy the code of this folder and repair the setup. Keeps all settings.

.PARAMETER Verify
    Show /api/status of the installed monitor, and run every detector on a
    synthetic record (no email).

.PARAMETER SendTestAlerts
    With -Verify: also send one labeled [SELF-TEST] email for each alert type.

.PARAMETER Uninstall
    Delete the resource group and both app registrations.

.PARAMETER List
    Show the installations on this computer (each install and update saves
    the tenant, subscription, name, and region in ~/.m365-ato-monitor; no
    secret).

.PARAMETER UpdateAll
    Run -Update for each saved installation, one after the other. It asks one
    time. A tenant whose sign-in has expired asks for a new sign-in (with -Yes,
    it is skipped and named in the summary).

.PARAMETER DryRun
    Show each change. Make no change. Reads still need an Azure CLI login.

.PARAMETER Yes
    Do not ask questions. Use the parameters and the defaults.

.PARAMETER Help
    Show a short summary of the commands and options (also --help).

.EXAMPLE
    ./install.ps1 -AdminEmail security@contoso.com -Location eastus
    ./install.ps1 -Tenant fabrikam.com -AdminEmail security@fabrikam.com -Location eastus
    ./install.ps1 -List
    ./install.ps1 -UpdateAll
    ./install.ps1 -Tenant fabrikam.com -Update
    ./install.ps1 -Verify
    ./install.ps1 -Verify -SendTestAlerts
    ./install.ps1 -Uninstall
#>
[CmdletBinding(DefaultParameterSetName = 'Install')]
param(
    [Parameter(ParameterSetName = 'Install')][string]$AdminEmail = '',
    [string]$Name = 'm365-ato-monitor',
    [Parameter(ParameterSetName = 'Install')][string]$Location = '',
    [string]$SubscriptionId = '',
    [string]$Tenant = '',
    [Parameter(ParameterSetName = 'Install')][ValidateSet('ask', 'yes', 'no')][string]$ResponsePermissions = 'ask',
    [Parameter(ParameterSetName = 'Install')][ArgumentCompleter({ param($c, $p, $word) 'mailbox', 'tenant' | Where-Object { $_ -like "$word*" } })][string]$MailSendScope = 'mailbox',
    [Parameter(ParameterSetName = 'Install')][string[]]$UiAdmins = @(),
    [Parameter(ParameterSetName = 'Install')][Parameter(ParameterSetName = 'Update')][ValidateRange(0, 24)][int]$UiSessionHours = 0,
    [Parameter(ParameterSetName = 'Install')][Parameter(ParameterSetName = 'Update')][ValidateSet('full', 'warnings')][string]$HostLogs,
    [Parameter(ParameterSetName = 'Update', Mandatory)][switch]$Update,
    [Parameter(ParameterSetName = 'Verify', Mandatory)][switch]$Verify,
    [Parameter(ParameterSetName = 'Verify')][switch]$SendTestAlerts,
    [Parameter(ParameterSetName = 'Uninstall', Mandatory)][switch]$Uninstall,
    [Parameter(ParameterSetName = 'List', Mandatory)][switch]$List,
    [Parameter(ParameterSetName = 'UpdateAll', Mandatory)][switch]$UpdateAll,
    [switch]$DryRun,
    [switch]$Yes,
    [Parameter(ParameterSetName = 'Help', Mandatory)][switch]$Help,
    # Anything else: --help, or a misspelled option. The script shows the usage.
    [Parameter(ValueFromRemainingArguments)][string[]]$Rest = @()
)

Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'
# Inside a function, $PSBoundParameters lists that function's parameters. Keep the script's.
$script:BoundKeys = @($PSBoundParameters.Keys)
# Invoke-Az checks the az exit code. A profile that sets this to $true would turn each
# "not found" check into an error.
$PSNativeCommandUseErrorActionPreference = $false

# -----------------------------------------------------------------------------
# Constants
# -----------------------------------------------------------------------------

$script:GraphAppId = '00000003-0000-0000-c000-000000000000'
$script:O365MgmtAppId = 'c5393580-f805-4401-95e8-94b7a6ef2fc2'
$script:AdminRoleId = '6c5d6f3e-2b1a-4c8e-9a7d-3f2e1b0c9d8a'   # Monitor.Admin app role (fixed)
# /admin/* is the Functions host admin API (it needs the host key). A redirect to sign-in there breaks
# key listing and portal tools on Flex.
$script:KeyEndpoints = @('/api/status', '/api/health', '/api/recent', '/api/test', '/api/selftest', '/admin/*')
$script:Graph = 'https://graph.microsoft.com/v1.0'
$script:MinAzVersion = [version]'2.60.0'   # Flex Consumption create flags
$script:Tag = 'm365-ato-monitor'

# Graph application roles. Base: always (list users, read inbox rules, search the
# audit log for the onboarding scan and the user page). Response: the buttons
# and automatic responses.
$script:GraphRolesBase = @('User.ReadBasic.All', 'MailboxSettings.Read', 'AuditLogsQuery.Read.All',
    'RoleManagement.Read.Directory', 'Application.Read.All')
$script:GraphRolesMail = @('Mail.Send')
$script:GraphRolesResponse = @('User.RevokeSessions.All', 'User.EnableDisableAccount.All', 'User.Read.All',
    'MailboxSettings.ReadWrite')

$script:Step = 0
$script:MailScopeNew = $false   # set by Install-Monitor: the Exchange Mail.Send scope was just made
$script:Confirmed = $false      # -UpdateAll asked one time: no "Continue?" for each installation
$script:Batch = $false          # -UpdateAll: no wait for the first run, no test emails
$script:PreviousSubscription = $null   # -Tenant switched the Azure CLI away from this subscription
$script:TenantName = ''
$script:TenantDomains = @()
$script:TenantDomain = ''
$script:Steps = 9
$script:RolesMade = @{}         # role assignments that this run made: "<role>|<scope>" -> time
$script:WorkspaceId = ''        # set by Set-Infrastructure
$script:GrantsMade = @()        # app roles that this run granted (Grant-AppRole)
# Azure operations on the monitor's resource group that send an alert email (Set-ChangeAlerts).
# Not the action group: the app changes its email when the alert mailbox changes in the UI.
$script:WatchedOperations = @(
    'Microsoft.Web/sites/write', 'Microsoft.Web/sites/delete', 'Microsoft.Web/sites/stop/action',
    'Microsoft.Web/sites/config/write', 'Microsoft.Web/sites/extensions/write',
    'Microsoft.Web/sites/basicPublishingCredentialsPolicies/write',
    'Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/write',
    'Microsoft.Authorization/roleAssignments/write', 'Microsoft.Storage/storageAccounts/write',
    'Microsoft.Insights/components/write', 'Microsoft.Insights/scheduledQueryRules/write',
    'Microsoft.Insights/scheduledQueryRules/delete', 'Microsoft.Insights/activityLogAlerts/write',
    'Microsoft.Insights/activityLogAlerts/delete', 'Microsoft.Insights/diagnosticSettings/write',
    'Microsoft.Insights/diagnosticSettings/delete', 'Microsoft.Insights/dataCollectionRules/write',
    'Microsoft.OperationalInsights/workspaces/write')

# -----------------------------------------------------------------------------
# Output
# -----------------------------------------------------------------------------

function Write-Step([string]$Text) {
    $script:Step++
    Write-Host ''
    Write-Host "[$($script:Step)/$($script:Steps)] $Text" -ForegroundColor Cyan
}
function Write-Ok([string]$Text) { Write-Host "  OK    $Text" -ForegroundColor Green }
function Write-Info([string]$Text) { Write-Host "        $Text" }
function Write-Warn2([string]$Text) { Write-Host "  WARN  $Text" -ForegroundColor Yellow }
function Write-Change([string]$Text) {
    if ($DryRun) { Write-Host "  PLAN  $Text" -ForegroundColor Magenta }
    else { Write-Host "  DO    $Text" -ForegroundColor White }
}

function Stop-Install([string]$Text, [string]$Fix = '') {
    Write-Host ''
    Write-Host "ERROR: $Text" -ForegroundColor Red
    if ($Fix) { Write-Host "Fix:   $Fix" -ForegroundColor Yellow }
    Write-Host 'Run the script again after the fix. Each step checks what exists and continues.'
    throw "install.ps1 stopped: $Text"
}

# -----------------------------------------------------------------------------
# Azure CLI wrappers
# -----------------------------------------------------------------------------

# Run az and return the parsed JSON (or $null). Throws with the az error text on failure.
function Invoke-Az {
    param([Parameter(Mandatory, ValueFromRemainingArguments)][string[]]$Arguments)
    # On Windows, az is a .cmd file. PowerShell passes an argument without spaces with no quotes,
    # and cmd.exe then reads ( ) & | < > ^ in it. Refuse them on every platform, so tests find them.
    foreach ($arg in $Arguments) {
        if ($arg -notmatch '\s' -and $arg -match '[()&|<>^]') { throw "Invoke-Az: az.cmd on Windows cannot take this argument: $arg" }
    }
    $errors = [System.Collections.Generic.List[string]]::new()
    $out = & az @Arguments --only-show-errors --output json 2>&1 | ForEach-Object {
        if ($_ -is [System.Management.Automation.ErrorRecord]) { $errors.Add($_.ToString()); return }
        $_
    }
    if ($LASTEXITCODE -ne 0) {
        $text = ($errors -join ' ').Trim()
        if (-not $text) { $text = ($out -join ' ').Trim() }
        throw "$(Get-AzLabel $Arguments) failed: $text"
    }
    $json = ($out -join "`n").Trim()
    # Return nothing (not $null) for no output: @(Invoke-Az ...) is then empty.
    if (-not $json) { return }
    try { return $json | ConvertFrom-Json -Depth 50 } catch { return $json }
}

# A short name for an az call in error messages: the command words, and for az rest the method and URL.
function Get-AzLabel([string[]]$Arguments) {
    $words = [System.Collections.Generic.List[string]]::new()
    foreach ($arg in $Arguments) { if ($arg -like '-*') { break }; $words.Add($arg) }
    if ($words.Count -and $words[0] -eq 'rest') {
        foreach ($option in '--method', '--url') {
            $i = [array]::IndexOf($Arguments, $option)
            if ($i -ge 0 -and $i + 1 -lt $Arguments.Count) { $words.Add(($Arguments[$i + 1] -split '\?')[0]) }
        }
    }
    return "az $($words -join ' ')"
}

# Errors that mean the az sign-in is expired or missing. Only a new "az login" helps.
$script:SignInPattern = 'AADSTS\d+|does not exist in MSAL token cache|invalid_grant|interaction_required|' +
    'Please run .?az login|Run .?az login'

# Errors that only mean "not replicated yet": a new identity, app, or role assignment takes
# seconds to minutes to appear everywhere in Entra ID and Azure.
$script:NotReadyPattern = 'PrincipalNotFound|does not exist in the directory|Request_ResourceNotFound|' +
    'ResourceNotFound|does not exist|AuthorizationPermissionMismatch|403|Forbidden|429|TooManyRequests|' +
    'valid application object|Permission being assigned was not found'
# Errors about the person who runs the script: retrying does not help.
$script:NeverRetryPattern = 'AuthorizationFailed|Authorization_RequestDenied|InvalidRoleDefinition|Insufficient privileges'

# A change. In -DryRun, print it and return $null. With -Retry, try again for up to 5 minutes
# while the error says that something new is not replicated yet.
function Invoke-AzChange {
    param([Parameter(Mandatory)][string]$What,
          [switch]$Retry,
          [Parameter(Mandatory, ValueFromRemainingArguments)][string[]]$Arguments)
    Write-Change $What
    if ($DryRun) { return $null }
    if (-not $Retry) { return Invoke-Az @Arguments }
    $deadline = (Get-Date).AddMinutes(5)
    while ($true) {
        try { return Invoke-Az @Arguments }
        catch {
            if ("$_" -match $script:NeverRetryPattern -or "$_" -notmatch $script:NotReadyPattern -or
                (Get-Date) -gt $deadline) { throw }
            Write-Info 'Not ready yet (new identities and role assignments take some minutes to apply). Next try in 15 seconds.'
            Start-Sleep -Seconds 15
        }
    }
}

# A request body goes through a file: JSON on a Windows command line breaks quoting.
function New-BodyFile($Object) {
    $path = Join-Path ([System.IO.Path]::GetTempPath()) ("m365atomon-" + [guid]::NewGuid().ToString('N') + '.json')
    $Object | ConvertTo-Json -Depth 50 -Compress | Set-Content -LiteralPath $path -Encoding utf8NoBOM
    return $path
}

# $Query goes through --uri-parameters: a URL with "&" breaks on Windows, where az is a .cmd file.
function Invoke-Rest {
    param([Parameter(Mandatory)][ValidateSet('GET', 'POST', 'PUT', 'PATCH', 'DELETE')][string]$Method,
          [Parameter(Mandatory)][string]$Url,
          $Body = $null,
          [hashtable]$Query = @{},
          [string]$What = '',
          [switch]$Retry)
    if ($Url -match '[&()]') { throw "Invoke-Rest: put query parameters in -Query, not in the URL (no & or parentheses): $Url" }
    $args2 = @('rest', '--method', $Method, '--url', $Url)
    if ($Query.Count) {
        $args2 += '--uri-parameters'
        $args2 += @($Query.GetEnumerator() | Sort-Object Key | ForEach-Object { "$($_.Key)=$($_.Value)" })
    }
    $file = $null
    if ($null -ne $Body) {
        $file = New-BodyFile $Body
        $args2 += @('--body', "@$file", '--headers', 'Content-Type=application/json')
    }
    try {
        if ($Method -eq 'GET') { return Invoke-Az @args2 }
        return Invoke-AzChange -What ($(if ($What) { $What } else { "$Method $Url" })) -Retry:$Retry @args2
    }
    finally { if ($file) { Remove-Item -LiteralPath $file -ErrorAction SilentlyContinue } }
}

# GET that returns $null for HTTP 404 instead of an error.
function Get-RestOrNull([string]$Url, [hashtable]$Query = @{}) {
    try { return Invoke-Rest -Method GET -Url $Url -Query $Query }
    catch { if ("$_" -match 'Not ?Found|404|ResourceNotFound|does not exist') { return $null }; throw }
}

function Get-Value($Object, [string]$Property) {
    if ($null -eq $Object) { return $null }
    $p = $Object.PSObject.Properties[$Property]
    if ($p) { return $p.Value } else { return $null }
}

# An object that this run created (or plans to create): it has no children yet, and a read of
# them right after the create can fail while Entra ID replicates.
function Set-New($Object) { if ($null -ne $Object) { $Object | Add-Member -NotePropertyName IsNew -NotePropertyValue $true -Force }; return $Object }
function Test-New($Object) { return [bool](Get-Value $Object 'IsNew') }

# True if each value in $Desired (hashtables, arrays, values) is the same in $Current (an object
# that az returned). Text compares without case: Azure can change the case of resource IDs.
function Test-Subset($Desired, $Current) {
    if ($Desired -is [System.Collections.IDictionary]) {
        if ($null -eq $Current) { return $false }
        foreach ($k in $Desired.Keys) {
            $value = if ($Current -is [System.Collections.IDictionary]) { $Current[$k] } else { Get-Value $Current $k }
            if (-not (Test-Subset $Desired[$k] $value)) { return $false }
        }
        return $true
    }
    if ($Desired -is [array]) {
        $have = @($Current)
        if ($have.Count -ne $Desired.Count) { return $false }
        for ($i = 0; $i -lt $Desired.Count; $i++) { if (-not (Test-Subset $Desired[$i] $have[$i])) { return $false } }
        return $true
    }
    return "$Desired" -eq "$Current"
}

# PUT $Body to an Azure resource only if the resource does not have it yet. A rerun then makes no
# change, so the alert on Azure changes (Set-ChangeAlerts) stays quiet.
function Set-ArmResource([string]$Url, [string]$ApiVersion, [hashtable]$Body, [string]$What) {
    $query = @{ 'api-version' = $ApiVersion }
    $current = if ($DryRun -and -not $script:Site) { $null } else { Get-RestOrNull $Url $query }
    if ($current -and (Test-Subset $Body $current)) { return $false }
    Invoke-Rest -Method PUT -Url $Url -Query $query -Body $Body -What $What -Retry | Out-Null
    return $true
}

# -----------------------------------------------------------------------------
# Names (the same for one subscription and base name, so a rerun finds them)
# -----------------------------------------------------------------------------

function Get-Names([string]$Subscription, [string]$Base) {
    $clean = ($Base.ToLowerInvariant() -replace '[^a-z0-9-]', '')
    if (-not $clean -or $clean.Length -gt 30) { Stop-Install "Name must be 1 to 30 letters, digits, or hyphens." }
    $sha = [System.Security.Cryptography.SHA256]::HashData([System.Text.Encoding]::UTF8.GetBytes("$Subscription/$clean"))
    $suffix = (-join ($sha[0..2] | ForEach-Object { $_.ToString('x2') }))
    $compact = ($clean -replace '-', '')
    $storage = ('st' + $compact)
    if ($storage.Length -gt 18) { $storage = $storage.Substring(0, 18) }
    return [ordered]@{
        Base          = $clean
        Suffix        = $suffix
        ResourceGroup = "rg-$clean"
        Identity      = "id-$clean"
        Storage       = "$storage$suffix"
        Workspace     = "log-$clean"
        AppInsights   = "appi-$clean"
        FunctionApp   = "func-$clean-$suffix"
        ActionGroup   = "ag-$clean"
        AlertNoRuns   = "alert-$clean-no-runs"
        AlertErrors   = "alert-$clean-errors"
        AlertDeploy   = "alert-$clean-code-deployed"
        AlertAzure    = "alert-$clean-azure-change"
        Transform     = "dcr-$clean-deploy-logs"
        BlobLogs      = "$clean-deploy-logs"
        AppReg        = $clean
        UiAppReg      = "$clean-admin-ui"
    }
}

# -----------------------------------------------------------------------------
# Preflight
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# Tenants: the installations on this computer, sign-in and subscription
# -----------------------------------------------------------------------------
# Each install and update saves one record per tenant in ~/.m365-ato-monitor/tenants.json:
# the tenant, the subscription, -Name, and the region. No secret. -List shows them;
# -UpdateAll and -Tenant use them.

function Get-StatePath {
    $root = if ($env:M365_ATO_MONITOR_HOME) { $env:M365_ATO_MONITOR_HOME } else { Join-Path $HOME '.m365-ato-monitor' }
    return Join-Path $root 'tenants.json'
}

function Read-TenantRecords {
    $path = Get-StatePath
    if (-not (Test-Path -LiteralPath $path)) { return @() }
    try { return @(Get-Content -Raw -LiteralPath $path | ConvertFrom-Json -Depth 10) }
    catch { Write-Warn2 "Cannot read $path. It is ignored."; return @() }
}

function Save-TenantRecord($Record) {
    if ($DryRun) { return }
    $path = Get-StatePath
    $records = @(Read-TenantRecords | Where-Object { $_.tenantId -ne $Record.tenantId })
    $records += $Record
    try {
        $null = New-Item -ItemType Directory -Force -Path (Split-Path -Parent $path)
        ConvertTo-Json -InputObject @($records) -Depth 10 | Set-Content -LiteralPath $path -Encoding utf8NoBOM
    }
    catch { Write-Warn2 "Cannot save the installation in ${path}: $_" }
}

function Remove-TenantRecord([string]$TenantId) {
    $path = Get-StatePath
    if ($DryRun -or -not (Test-Path -LiteralPath $path)) { return }
    $records = @(Read-TenantRecords | Where-Object { $_.tenantId -ne $TenantId })
    ConvertTo-Json -InputObject @($records) -Depth 10 | Set-Content -LiteralPath $path -Encoding utf8NoBOM
}

# The tenant ID for -Tenant: a tenant ID, a saved installation (domain or name), or a domain
# (looked up anonymously in the tenant's OpenID configuration).
function Resolve-TenantId([string]$Value) {
    $v = $Value.Trim()
    if ($v -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') { return $v.ToLowerInvariant() }
    $saved = @(Read-TenantRecords | Where-Object {
        $_.domain -eq $v -or $_.tenantName -eq $v -or "$($_.domain)" -like "$v.*" -or @($_.domains) -contains $v })
    if ($saved.Count -eq 1) { return "$($saved[0].tenantId)" }
    if ($v -notmatch '\.') {
        $known = (@(Read-TenantRecords | ForEach-Object { $_.domain }) -join ', ')
        Stop-Install "Unknown tenant '$v'." ("Use a domain of the tenant (contoso.com) or the tenant ID." +
            $(if ($known) { " Saved installations: $known." } else { '' }))
    }
    try {
        $cfg = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$v/v2.0/.well-known/openid-configuration" -TimeoutSec 20
        if ("$($cfg.issuer)" -match '/([0-9a-f]{8}-([0-9a-f]{4}-){3}[0-9a-f]{12})/') { return $Matches[1] }
    }
    catch { }
    Stop-Install "No Microsoft 365 tenant has the domain '$v'." 'Use a verified domain of the tenant, or the tenant ID (Entra admin center > Overview).'
}

# az login that leaves the choice of the subscription to this script.
function Invoke-AzLogin([string]$TenantArg) {
    $old = $env:AZURE_CORE_LOGIN_EXPERIENCE_V2
    $env:AZURE_CORE_LOGIN_EXPERIENCE_V2 = 'off'
    try {
        if ($TenantArg) { & az login --tenant $TenantArg --only-show-errors --output none }
        else { & az login --only-show-errors --output none }
        $code = $LASTEXITCODE
    }
    finally { $env:AZURE_CORE_LOGIN_EXPERIENCE_V2 = $old }
    return $code
}

function Get-TenantSubscriptions([string]$TenantId) {
    return @(Invoke-Az account list --all | Where-Object { $_.tenantId -eq $TenantId -and $_.state -eq 'Enabled' })
}

# -Tenant: select a subscription of that tenant in the Azure CLI. Remember the earlier one.
function Select-TenantSubscription([string]$TenantId, $Record) {
    $current = $null
    try { $current = Invoke-Az account show } catch { $current = $null }
    if ($current -and $current.tenantId -ne $TenantId -and -not $script:PreviousSubscription) {
        $script:PreviousSubscription = $current.id
    }
    $subs = @(Get-TenantSubscriptions $TenantId)
    if (-not $subs.Count) {
        if ($Yes) { Stop-Install "The Azure CLI is not signed in to tenant $TenantId." "az login --tenant $TenantId" }
        Write-Info "Sign in to tenant $TenantId in the browser window. Use an account of that tenant."
        if ((Invoke-AzLogin $TenantId) -ne 0) { Stop-Install 'Azure sign-in failed.' "az login --tenant $TenantId" }
        $subs = @(Get-TenantSubscriptions $TenantId)
    }
    if (-not $subs.Count) {
        Stop-Install "This account has no enabled Azure subscription in tenant $TenantId." `
            'docs/GETTING_STARTED.md#get-an-azure-subscription (the subscription must be in the same tenant as Microsoft 365)'
    }
    $want = if ($SubscriptionId) { $SubscriptionId } elseif ($Record) { "$($Record.subscriptionId)" } else { '' }
    $sub = if ($want) { $subs | Where-Object { $_.id -eq $want -or $_.name -eq $want } | Select-Object -First 1 }
           elseif ($subs.Count -eq 1) { $subs[0] }
           else { Read-SubscriptionChoice $subs }
    if (-not $sub) { Stop-Install "Subscription '$want' is not in tenant $TenantId." "Use one of: $(($subs | ForEach-Object { "$($_.name) ($($_.id))" }) -join ', ')" }
    & az account set --subscription $sub.id --only-show-errors
    if ($LASTEXITCODE) { Stop-Install "Cannot select subscription $($sub.id)." }
}

function Read-SubscriptionChoice($Subs) {
    $lines = @($Subs | ForEach-Object { "$($_.name) ($($_.id))" })
    if ($Yes) { Stop-Install 'The tenant has more than one subscription.' "Add -SubscriptionId with one of: $($lines -join ', ')" }
    Write-Info 'The tenant has more than one subscription:'
    for ($i = 0; $i -lt $lines.Count; $i++) { Write-Info "  $($i + 1). $($lines[$i])" }
    $n = 0
    $answer = Read-Host "Subscription for the monitor [1-$($lines.Count)]"
    if (-not [int]::TryParse($answer, [ref]$n) -or $n -lt 1 -or $n -gt $lines.Count) { throw 'Stopped: no subscription selected.' }
    return @($Subs)[$n - 1]
}

# After -Tenant: the Azure CLI goes back to the subscription that was selected before.
function Restore-AzSubscription {
    if (-not $script:PreviousSubscription) { return }
    & az account set --subscription $script:PreviousSubscription --only-show-errors 2>$null
    $script:PreviousSubscription = $null
}

# Name and domains of the signed-in tenant (Graph /organization). Empty if Graph refuses.
function Read-Organization {
    # -UpdateAll reuses this process: a failed lookup must not keep another tenant's domains.
    $script:TenantName = ''
    $script:TenantDomain = ''
    $script:TenantDomains = @()
    try {
        $org = @((Invoke-Rest -Method GET -Url "$($script:Graph)/organization" -Query @{ '$select' = 'displayName,verifiedDomains' }).value)[0]
    }
    catch { return }
    if (-not $org) { return }
    $script:TenantName = "$($org.displayName)"
    $domains = @($org.verifiedDomains)
    $script:TenantDomains = @($domains | ForEach-Object { "$($_.name)".ToLowerInvariant() })
    $default = @($domains | Where-Object { $_.isDefault }) + @($domains | Where-Object { $_.isInitial })
    $script:TenantDomain = if ($default.Count) { "$($default[0].name)" } else { '' }
}

function Get-TenantLabel {
    if ($script:TenantName) { return "$($script:TenantName) ($($script:TenantDomain), $($script:TenantId))" }
    return "$($script:TenantId)"
}

# The monitor sends as the alert mailbox: it must be a mailbox of this tenant.
function Test-AlertMailbox([string]$Email) {
    $domain = ($Email -split '@')[-1].ToLowerInvariant()
    $where = if ($script:TenantName) { "$($script:TenantName) ($($script:TenantDomain))" } else { "tenant $($script:TenantId)" }
    if ($script:TenantDomains.Count -and $domain -notin $script:TenantDomains) {
        Stop-Install ("$Email is not in the tenant that the Azure CLI is signed in to: $where. " +
            'The monitor sends every email as the alert mailbox, so it must be a mailbox of the tenant that you monitor.') `
            ("To install for the tenant of ${domain}: ./install.ps1 -Tenant $domain -AdminEmail $Email -Location <region>. " +
             'To get alerts at an outside address: use a mailbox of this tenant here, and add the outside address ' +
             'in the management UI (Settings > Email > Extra recipients).')
    }
    $e = $Email -replace "'", "''"
    $found = $null
    try {
        $found = @((Invoke-Rest -Method GET -Url "$($script:Graph)/users" -Query @{
            '$filter' = "mail eq '$e' or userPrincipalName eq '$e'"; '$select' = 'id,mail,userPrincipalName' }).value)
    }
    catch { Write-Warn2 "Cannot check the alert mailbox $Email in Entra ID. The install continues."; return }
    if (-not $found.Count) {
        Stop-Install "$where has no user or shared mailbox $Email." `
            'Use a licensed or shared mailbox of this tenant. A group or a contact cannot send email.'
    }
    $upn = @($found | Where-Object { "$($_.userPrincipalName)" -eq $Email })
    if (-not $upn.Count) {
        Write-Warn2 "The user principal name of $Email is $($found[0].userPrincipalName). If alert emails fail, use that name as the alert mailbox."
    }
}

function Test-Prerequisites {
    if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
        Stop-Install 'The Azure CLI (az) is not installed.' `
            'Windows: winget install Microsoft.AzureCLI. macOS: brew install azure-cli. Or use Azure Cloud Shell.'
    }
    $ver = Invoke-Az version
    $azVersion = [version](Get-Value $ver 'azure-cli')
    if ($azVersion -lt $script:MinAzVersion) {
        Stop-Install "Azure CLI $azVersion is too old. This script needs $($script:MinAzVersion) or later." 'az upgrade'
    }
    Write-Ok "Azure CLI $azVersion, PowerShell $($PSVersionTable.PSVersion)"

    $wantTenant = ''
    if ($Tenant) {
        $wantTenant = Resolve-TenantId $Tenant
        $record = @(Read-TenantRecords | Where-Object { $_.tenantId -eq $wantTenant }) | Select-Object -First 1
        Select-TenantSubscription $wantTenant $record
    }
    else {
        $account = $null
        try { $account = Invoke-Az account show } catch { $account = $null }
        if (-not $account) {
            # Not signed in: sign in to the tenant of the alert mailbox.
            $hint = if ($AdminEmail -match '@([^@\s]+)$') { $Matches[1] } else { '' }
            Write-Info ('Sign in to Azure in the browser window.' + $(if ($hint) { " Use an account of the tenant of $hint." } else { '' }))
            if ((Invoke-AzLogin $hint) -ne 0) {
                Stop-Install 'Azure sign-in failed.' ('If az says "No subscriptions found", the tenant has no Azure subscription: ' +
                    'docs/GETTING_STARTED.md#get-an-azure-subscription')
            }
        }
        if ($SubscriptionId) { & az account set --subscription $SubscriptionId --only-show-errors; if ($LASTEXITCODE) { Stop-Install "Cannot select subscription $SubscriptionId." } }
    }
    $account = Invoke-Az account show
    if ($wantTenant -and $account.tenantId -ne $wantTenant) { Stop-Install "The Azure CLI did not switch to tenant $wantTenant." "az login --tenant $wantTenant" }
    $script:TenantId = $account.tenantId
    $script:SubId = $account.id
    # "az account show" reads only the local profile. /me needs a valid token: an expired sign-in fails here.
    $me = $null
    try { $me = Get-Me }
    catch {
        if ("$_" -notmatch $script:SignInPattern) { throw }
        $fix = "az login --tenant $($script:TenantId)"
        if ($Yes) { Stop-Install 'The Azure sign-in has expired, or az has no token for this account.' $fix }
        Write-Info 'The Azure sign-in has expired. Sign in again in the browser window.'
        if ((Invoke-AzLogin $script:TenantId) -ne 0) { Stop-Install 'Azure sign-in failed.' $fix }
        & az account set --subscription $script:SubId --only-show-errors
        $account = Invoke-Az account show
        $script:TenantId = $account.tenantId
        $script:SubId = $account.id
        $me = Get-Me
    }
    $script:MeId = $me.id
    $script:MeUpn = $me.userPrincipalName
    Read-Organization
    Write-Ok "Signed in as $($script:MeUpn)"
    Write-Info "Tenant:       $(Get-TenantLabel)"
    Write-Info "Subscription: $($account.name) ($($script:SubId))"
}

function Get-Me {
    return Invoke-Rest -Method GET -Url "$($script:Graph)/me" -Query @{ '$select' = 'id,userPrincipalName,mail' }
}

function Confirm-Or-Stop([string]$Question) {
    if ($Yes -or $script:Confirmed) { return }
    $answer = Read-Host "$Question [y/N]"
    if ($answer -notmatch '^(y|yes)$') { throw 'Stopped by the user.' }
}

function Read-Default([string]$Question, [string]$Default) {
    if ($Yes) { return $Default }
    $answer = Read-Host "$Question$(if ($Default) { " [$Default]" })"
    if ([string]::IsNullOrWhiteSpace($answer)) { return $Default }
    return $answer.Trim()
}

function Register-Providers {
    foreach ($ns in 'Microsoft.Web', 'Microsoft.Storage', 'Microsoft.Insights', 'Microsoft.OperationalInsights',
        'Microsoft.ManagedIdentity') {
        $state = (Invoke-Az provider show --namespace $ns --query registrationState)
        if ($state -ne 'Registered') {
            Invoke-AzChange -What "Register resource provider $ns" provider register --namespace $ns --wait | Out-Null
        }
    }
}

# -----------------------------------------------------------------------------
# Entra ID: app registrations, permissions, admin consent
# -----------------------------------------------------------------------------

# A filter, not servicePrincipals(appId='...'): az.cmd on Windows cannot take the parentheses.
function Find-ServicePrincipal([string]$AppId, [string]$Select) {
    $r = Invoke-Rest -Method GET -Url "$($script:Graph)/servicePrincipals" -Query @{ '$filter' = "appId eq '$AppId'"; '$select' = $Select }
    return (@($r.value) | Select-Object -First 1)
}

function Get-ServicePrincipalByAppId([string]$AppId) {
    $sp = Find-ServicePrincipal $AppId 'id,appId,appRoles,oauth2PermissionScopes'
    if (-not $sp) { Stop-Install "No service principal for the Microsoft app $AppId in this tenant." 'Check that the tenant has Microsoft 365, then run the script again.' }
    return $sp
}

function Get-AppRoleId($ResourceSp, [string]$Value) {
    $role = @($ResourceSp.appRoles | Where-Object { $_.value -eq $Value -and $_.allowedMemberTypes -contains 'Application' })
    if ($role.Count -ne 1) { Stop-Install "App role $Value not found on $($ResourceSp.appId)." }
    return $role[0].id
}

function Find-Application([string]$DisplayName) {
    $r = Invoke-Rest -Method GET -Url "$($script:Graph)/applications" `
        -Query @{ '$filter' = "displayName eq '$DisplayName'"; '$select' = 'id,appId,displayName,tags,web' }
    $apps = @($r.value | Where-Object { @($_.tags) -contains $script:Tag })
    if ($apps.Count -gt 1) { Stop-Install "More than one app registration named '$DisplayName' has the tag $($script:Tag)." }
    if ($apps.Count -eq 1) { return $apps[0] }
    return $null
}

function Set-Application([string]$DisplayName, [hashtable]$Properties) {
    $existing = Find-Application $DisplayName
    $body = @{ displayName = $DisplayName; tags = @($script:Tag) } + $Properties
    if ($existing) {
        Invoke-Rest -Method PATCH -Url "$($script:Graph)/applications/$($existing.id)" -Body $body `
            -What "Update app registration $DisplayName" | Out-Null
        return $existing
    }
    $body.signInAudience = 'AzureADMyOrg'
    $created = Invoke-Rest -Method POST -Url "$($script:Graph)/applications" -Body $body -What "Create app registration $DisplayName"
    if ($DryRun) { return Set-New ([pscustomobject]@{ id = '00000000-0000-0000-0000-000000000000'; appId = '00000000-0000-0000-0000-000000000000' }) }
    return Set-New $created
}

# The tag WindowsAzureActiveDirectoryIntegratedApp puts the app in the default list of
# Entra admin center > Enterprise applications.
$script:SpTags = @('WindowsAzureActiveDirectoryIntegratedApp', $script:Tag)

function Set-ServicePrincipal([string]$AppId, [bool]$AssignmentRequired) {
    if ($DryRun -and $AppId -like '00000000*') {
        Write-Change 'Create the service principal of the new app registration'
        return Set-New ([pscustomobject]@{ id = '00000000-0000-0000-0000-000000000000' })
    }
    $sp = Find-ServicePrincipal $AppId 'id,appId,appRoleAssignmentRequired,tags'
    if (-not $sp) {
        # A new app registration can take some seconds to replicate: -Retry.
        $sp = Invoke-Rest -Method POST -Url "$($script:Graph)/servicePrincipals" `
            -Body @{ appId = $AppId; appRoleAssignmentRequired = $AssignmentRequired; tags = $script:SpTags } `
            -What "Create service principal for $AppId" -Retry
        if ($DryRun) { return Set-New ([pscustomobject]@{ id = '00000000-0000-0000-0000-000000000000' }) }
        return Set-New $sp
    }
    $tags = @(Get-Value $sp 'tags' | Where-Object { $_ })
    $missing = @($script:SpTags | Where-Object { $_ -notin $tags })
    if ($sp.appRoleAssignmentRequired -ne $AssignmentRequired -or $missing.Count) {
        Invoke-Rest -Method PATCH -Url "$($script:Graph)/servicePrincipals/$($sp.id)" `
            -Body @{ appRoleAssignmentRequired = $AssignmentRequired; tags = @($tags + $missing) } `
            -What "Update service principal $AppId" | Out-Null
    }
    return $sp
}

# Admin consent for one application permission = one app role assignment.
function Grant-AppRole([string]$ClientSpId, $ResourceSp, [string]$RoleValue, $Existing) {
    $roleId = Get-AppRoleId $ResourceSp $RoleValue
    if (@($Existing | Where-Object { $_.appRoleId -eq $roleId -and $_.resourceId -eq $ResourceSp.id }).Count) { return }
    Invoke-Rest -Method POST -Url "$($script:Graph)/servicePrincipals/$($ResourceSp.id)/appRoleAssignedTo" `
        -Body @{ principalId = $ClientSpId; resourceId = $ResourceSp.id; appRoleId = $roleId } `
        -What "Grant $RoleValue (admin consent)" -Retry | Out-Null
    $script:GrantsMade += [pscustomobject]@{ Sp = $ClientSpId; Role = $RoleValue }
}

# INSTALL_GRANTS: the grants that recent runs made to the monitor app, so that the monitor knows a
# grant record as the work of install.ps1 also after the choices changed (for example
# -MailSendScope tenant, then mailbox). Entries "<UTC time>;<account>;<role>,<role>", newest first,
# joined with "/"; at most 3, from the last 7 days. The monitor also checks the account and the time
# of the record. A change of this setting is an Azure change (alert-<name>-azure-change).
function New-InstallGrantsSetting([string]$Previous, [string[]]$Roles) {
    $entries = @("$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'));$($script:MeUpn);$($Roles -join ',')")
    foreach ($e in @("$Previous" -split '/' | Where-Object { $_ })) {
        $at = [datetime]::MinValue
        $ok = [datetime]::TryParse(($e -split ';')[0], [Globalization.CultureInfo]::InvariantCulture,
                                   [Globalization.DateTimeStyles]::AdjustToUniversal, [ref]$at)
        if ($ok -and $at -gt (Get-Date).ToUniversalTime().AddDays(-7)) { $entries += $e }
    }
    return ($entries | Select-Object -First 3) -join '/'
}

function Set-MonitorApp([string[]]$GraphRoles, [string]$IdentityPrincipalId, [string[]]$Keep = @()) {
    $graphSp = Get-ServicePrincipalByAppId $script:GraphAppId
    $o365Sp = Get-ServicePrincipalByAppId $script:O365MgmtAppId
    $access = @(
        @{ resourceAppId = $script:O365MgmtAppId
           resourceAccess = @(@{ id = (Get-AppRoleId $o365Sp 'ActivityFeed.Read'); type = 'Role' }) },
        @{ resourceAppId = $script:GraphAppId
           resourceAccess = @($GraphRoles | ForEach-Object { @{ id = (Get-AppRoleId $graphSp $_); type = 'Role' } }) }
    )
    $app = Set-Application $script:N.AppReg @{ requiredResourceAccess = $access }
    $sp = Set-ServicePrincipal $app.appId $false
    Write-Ok "Monitor app: $($app.appId)"

    # Federated credential: the managed identity is the app's only credential.
    $fics = @(if (Test-New $app) { @() } else {
        @((Invoke-Rest -Method GET -Url "$($script:Graph)/applications/$($app.id)/federatedIdentityCredentials").value) })
    $issuer = "https://login.microsoftonline.com/$($script:TenantId)/v2.0"
    $fic = @{ issuer = $issuer; subject = $IdentityPrincipalId; audiences = @('api://AzureADTokenExchange')
              description = 'The Function App managed identity. No client secret.' }
    if (-not @($fics | Where-Object { $_.subject -eq $IdentityPrincipalId -and $_.issuer -eq $issuer }).Count) {
        $named = @($fics | Where-Object { $_.name -eq 'function-app-managed-identity' }) | Select-Object -First 1
        if ($named) {
            # The managed identity was made again (for example, the resource group was deleted).
            Invoke-Rest -Method PATCH -Url "$($script:Graph)/applications/$($app.id)/federatedIdentityCredentials/$($named.id)" `
                -Body $fic -What 'Point the federated credential at the new managed identity' -Retry | Out-Null
        }
        else {
            Invoke-Rest -Method POST -Url "$($script:Graph)/applications/$($app.id)/federatedIdentityCredentials" `
                -Body ($fic + @{ name = 'function-app-managed-identity' }) `
                -What 'Add the managed identity as the federated credential' -Retry | Out-Null
        }
    }
    $secrets = @(if (Test-New $app) { @() } else {
        @((Invoke-Rest -Method GET -Url "$($script:Graph)/applications/$($app.id)" -Query @{ '$select' = 'passwordCredentials' }).passwordCredentials) })
    if ($secrets.Count) { Write-Warn2 "The app registration has $($secrets.Count) client secret(s). The monitor does not use them. Delete them: Entra admin center > App registrations > $($script:N.AppReg) > Certificates & secrets." }

    # Admin consent.
    $existing = @(if (Test-New $sp) { @() } else {
        @((Invoke-Rest -Method GET -Url "$($script:Graph)/servicePrincipals/$($sp.id)/appRoleAssignments").value) })
    Grant-AppRole $sp.id $o365Sp 'ActivityFeed.Read' $existing
    foreach ($role in $GraphRoles) { Grant-AppRole $sp.id $graphSp $role $existing }
    # Remove Graph roles that are no longer wanted. $Keep: remove later (Mail.Send, after the Exchange scope works).
    $wanted = @(@($GraphRoles) + @($Keep) | Where-Object { $_ } | ForEach-Object { Get-AppRoleId $graphSp $_ })
    foreach ($a in @($existing | Where-Object { $_.resourceId -eq $graphSp.id -and $_.appRoleId -notin $wanted })) {
        $match = @($graphSp.appRoles | Where-Object { $_.id -eq $a.appRoleId }) | Select-Object -First 1
        $value = if ($match) { $match.value } else { $a.appRoleId }
        Invoke-Rest -Method DELETE -Url "$($script:Graph)/servicePrincipals/$($sp.id)/appRoleAssignments/$($a.id)" `
            -What "Remove the Graph permission $value" | Out-Null
    }
    Write-Ok "Admin consent: ActivityFeed.Read, $($GraphRoles -join ', ')"
    return [pscustomobject]@{ App = $app; Sp = $sp }
}

function Remove-GraphAppRole([string]$SpId, [string[]]$Values) {
    $graphSp = Get-ServicePrincipalByAppId $script:GraphAppId
    $ids = @($Values | ForEach-Object { Get-AppRoleId $graphSp $_ })
    $assigned = @((Invoke-Rest -Method GET -Url "$($script:Graph)/servicePrincipals/$SpId/appRoleAssignments").value)
    foreach ($a in @($assigned | Where-Object { $_.resourceId -eq $graphSp.id -and $_.appRoleId -in $ids })) {
        $value = @($graphSp.appRoles | Where-Object { $_.id -eq $a.appRoleId })[0].value
        Invoke-Rest -Method DELETE -Url "$($script:Graph)/servicePrincipals/$SpId/appRoleAssignments/$($a.id)" `
            -What "Remove the tenant-wide Graph permission $value" | Out-Null
    }
}

# -----------------------------------------------------------------------------
# Mail.Send for the alert mailbox only (Exchange Online RBAC for Applications)
# -----------------------------------------------------------------------------
# The app gets the Exchange role "Application Mail.Send" in a management scope:
# the direct members of one mail-enabled security group. The alert mailbox is the
# member. To use another alert mailbox, an admin adds it to the group; the app
# cannot change the group or the scope. Exchange applies a change in 30 minutes
# to 2 hours. Graph and Exchange grants add up, so the tenant-wide Graph Mail.Send
# goes only after the Exchange grant works.

# Names that scripts/restrict-mail-send.ps1 used (one address). The group replaces them.
$script:OldScopeName = 'M365 ATO Monitor alert mailbox'
$script:OldAssignmentName = 'M365 ATO Monitor Mail.Send'

function Get-SendGroupName { return "$($script:N.Base)-senders" }

function Connect-Exchange {
    if (-not (Get-Module -ListAvailable -Name ExchangeOnlineManagement)) {
        Write-Change 'Install the PowerShell module ExchangeOnlineManagement (PowerShell Gallery, current user)'
        try { Install-Module -Name ExchangeOnlineManagement -Scope CurrentUser -Force -ErrorAction Stop }
        catch {
            Stop-Install "The module ExchangeOnlineManagement did not install: $_" `
                'Run: Install-Module ExchangeOnlineManagement -Scope CurrentUser. Or use -MailSendScope tenant.'
        }
    }
    Import-Module -Name ExchangeOnlineManagement -ErrorAction Stop
    # A device code: the script shows a URL and a code, and you choose the browser (also on another
    # computer). It works in SSH and Azure Cloud Shell. The code is valid for 15 minutes.
    Write-Info "Sign in to Exchange Online as $($script:MeUpn) or another Exchange Administrator or Global Administrator"
    Write-Info "of $(Get-TenantLabel): open the URL below in any browser and enter the code."
    Write-Info 'The monitor sends a "Device code sign-in" alert for this sign-in. That alert is expected.'
    try { $null = Connect-ExchangeOnline -Device -ShowBanner:$false -ErrorAction Stop }
    catch {
        $why = ("$_" -replace '\s+', ' ').Trim()
        $fix = if ($why -match 'AADSTS53003|AADSTS50105|blocked|Conditional Access') {
            'Your tenant can block the device code sign-in (Conditional Access). Use -MailSendScope tenant, or allow the device code flow for this account for this step.'
        } else { 'Run the script again. Enter the code within 15 minutes, with an Exchange Administrator or Global Administrator account.' }
        Stop-Install "Exchange Online sign-in failed: $why" $fix
    }
    # The browser can sign in with an account of another tenant. Then nothing must change there.
    $conn = @(Get-ConnectionInformation -ErrorAction SilentlyContinue) | Select-Object -Last 1
    $tid = "$(Get-Value $conn 'TenantID')".ToLowerInvariant()
    if ($tid -and $tid -ne "$($script:TenantId)".ToLowerInvariant()) {
        $null = Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
        Stop-Install "The Exchange Online sign-in went to another tenant ($tid), not $(Get-TenantLabel)." `
            "Run the script again. Sign in with an account of $($script:TenantDomain) (use a private browser window if the browser picks another account)."
    }
}

# True when Exchange shows Mail.Send for $Mailboxes[0], the mailbox the monitor sends as. Then the
# caller removes the Graph Mail.Send. Each mailbox in $Mailboxes becomes a member of the group.
function Set-MailSendGroup([string]$AppId, [string]$SpId, [string[]]$Mailboxes) {
    $group = Get-SendGroupName
    $scopeName = "$group scope"
    # The app ID is in the name: after a reinstall, the new app gets its own assignment.
    $assignment = "$group Mail.Send $($AppId.Substring(0, [Math]::Min(8, $AppId.Length)))"
    if ($DryRun) {
        Write-Change "Exchange Online: make the mail-enabled security group $group with $($Mailboxes -join ', ') as the member"
        Write-Change "Exchange Online: give the app 'Application Mail.Send' for the members of $group only"
        return $true
    }
    Connect-Exchange
    try {
        # The last address is the new alert mailbox: it must be a mailbox. An earlier one (set in the
        # management UI) without a mailbox cannot send, so it does not go into the group.
        $addresses = @(for ($i = 0; $i -lt $Mailboxes.Count; $i++) {
            $m = $Mailboxes[$i]
            $recipient = Get-Recipient -Identity $m -ErrorAction SilentlyContinue
            if ($recipient) { "$(@($recipient)[0].PrimarySmtpAddress)"; continue }
            if ($i -lt $Mailboxes.Count - 1) {
                Write-Warn2 "$m has no Exchange Online mailbox, so it does not go into the group $group."
                Write-Info "Set the alert mailbox to $($Mailboxes[-1]) in the management UI: Settings > Email."
                continue
            }
            Stop-Install "Exchange Online has no mailbox $m." `
                'Use a licensed mailbox or a shared mailbox (free, no license) as the alert mailbox: -AdminEmail <address>.'
        })
        $g = Get-DistributionGroup -Identity $group -ErrorAction SilentlyContinue
        if (-not $g) {
            Write-Change "Make the mail-enabled security group $group (hidden from the address list)"
            $g = New-DistributionGroup -Name $group -Alias $group -Type Security -Members $addresses `
                -MemberJoinRestriction Closed -MemberDepartRestriction Closed `
                -Notes 'M365 ATO Monitor sends alert email only as a member of this group. Add a new alert mailbox here before you change it in the management UI.'
        }
        if (-not (Get-Value @($g)[0] 'HiddenFromAddressListsEnabled')) {
            $null = Set-DistributionGroup -Identity $group -HiddenFromAddressListsEnabled $true
        }
        $members = @(Get-DistributionGroupMember -Identity $group -ResultSize Unlimited |
            ForEach-Object { "$($_.PrimarySmtpAddress)".ToLowerInvariant() })
        foreach ($address in $addresses) {
            if ($address.ToLowerInvariant() -notin $members) {
                Write-Change "Add $address to the group $group"
                $null = Add-DistributionGroupMember -Identity $group -Member $address -BypassSecurityGroupManagerCheck
            }
        }
        if (-not (Get-ServicePrincipal -Identity $SpId -ErrorAction SilentlyContinue)) {
            Write-Change 'Add the monitor app to Exchange Online'
            $null = New-ServicePrincipal -AppId $AppId -ObjectId $SpId -DisplayName $script:N.AppReg
        }
        $dn = "$(@($g)[0].DistinguishedName)"
        $filter = "MemberOfGroup -eq '$($dn -replace "'", "''")'"
        $scope = Get-ManagementScope -Identity $scopeName -ErrorAction SilentlyContinue
        if (-not $scope) {
            Write-Change "Make the management scope '$scopeName' (members of $group)"
            $null = New-ManagementScope -Name $scopeName -RecipientRestrictionFilter $filter
        }
        elseif ("$($scope.RecipientFilter)" -notmatch [regex]::Escape($dn)) {
            Write-Change "Set the management scope '$scopeName' to the members of $group"
            $null = Set-ManagementScope -Identity $scopeName -RecipientRestrictionFilter $filter
        }
        if (-not (Get-ManagementRoleAssignment -Identity $assignment -ErrorAction SilentlyContinue)) {
            Write-Change "Give the app 'Application Mail.Send' in the scope '$scopeName'"
            $null = New-ManagementRoleAssignment -Name $assignment -App $SpId -Role 'Application Mail.Send' `
                -CustomResourceScope $scopeName
        }
        # This test reads the role assignments directly, without the 30-minute to 2-hour cache.
        $ok = @(Test-ServicePrincipalAuthorization -Identity $SpId -Resource $addresses[0] |
            Where-Object { $_.RoleName -eq 'Application Mail.Send' -and $_.InScope })
        if (-not $ok.Count) {
            Write-Warn2 "Exchange Online does not show Mail.Send for $($addresses[0]) yet. The Graph permission Mail.Send stays (if any)."
            Write-Info 'Run the script again in some minutes to finish.'
            return $false
        }
        # The new grant works. Now remove the grants it replaces: an assignment of an earlier
        # installation (a deleted app), and the one-address scope of scripts/restrict-mail-send.ps1.
        $old = @(Get-ManagementRoleAssignment -Role 'Application Mail.Send' -ErrorAction SilentlyContinue |
            Where-Object { ("$($_.Name)" -like "$group Mail.Send*" -and "$($_.Name)" -ne $assignment) -or
                           "$($_.Name)" -eq $script:OldAssignmentName })
        foreach ($a in $old) {
            Write-Change "Remove the old role assignment '$($a.Name)'"
            $null = Remove-ManagementRoleAssignment -Identity "$($a.Name)" -Confirm:$false
        }
        if (Get-ManagementScope -Identity $script:OldScopeName -ErrorAction SilentlyContinue) {
            $null = Remove-ManagementScope -Identity $script:OldScopeName -Confirm:$false
        }
        Write-Ok "Mail.Send: only the members of $group ($($addresses -join ', ')). Exchange applies it in 30 minutes to 2 hours."
        return $true
    }
    finally { $null = Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue }
}

function Set-AdminUiApp([string]$HostName, [string[]]$Admins) {
    $graphSp = Get-ServicePrincipalByAppId $script:GraphAppId
    $userRead = @($graphSp.oauth2PermissionScopes | Where-Object { $_.value -eq 'User.Read' })[0].id
    # Keep the redirect URIs that someone added, for example for a custom domain (docs/HOW_TO.md).
    $known = @(Get-Value (Get-Value (Find-Application $script:N.UiAppReg) 'web') 'redirectUris')
    $redirects = @(@("https://$HostName/.auth/login/aad/callback") + $known | Where-Object { $_ } | Select-Object -Unique)
    $app = Set-Application $script:N.UiAppReg @{
        appRoles = @(@{ allowedMemberTypes = @('User'); id = $script:AdminRoleId; value = 'Monitor.Admin'
                        displayName = 'Monitor admin'; isEnabled = $true
                        description = 'Sign in to the M365 ATO Monitor management UI and change its settings' })
        web = @{ redirectUris = $redirects
                 implicitGrantSettings = @{ enableIdTokenIssuance = $true; enableAccessTokenIssuance = $false } }
        requiredResourceAccess = @(@{ resourceAppId = $script:GraphAppId
                                      resourceAccess = @(@{ id = $userRead; type = 'Scope' }) })
    }
    # No assignment required: any user of the tenant can sign in. The function decides who has access:
    # the Monitor.Admin role, or the users and directory roles in Settings > Management UI access.
    $sp = Set-ServicePrincipal $app.appId $false

    # Delegated User.Read for all users (sign-in only).
    $grants = @(if (Test-New $sp) { @() } else {
        @((Invoke-Rest -Method GET -Url "$($script:Graph)/oauth2PermissionGrants" -Query @{ '$filter' = "clientId eq '$($sp.id)'" }).value) })
    if (-not @($grants | Where-Object { $_.resourceId -eq $graphSp.id -and $_.consentType -eq 'AllPrincipals' }).Count) {
        Invoke-Rest -Method POST -Url "$($script:Graph)/oauth2PermissionGrants" `
            -Body @{ clientId = $sp.id; consentType = 'AllPrincipals'; resourceId = $graphSp.id; scope = 'User.Read' } `
            -What 'Grant User.Read to the management UI sign-in (admin consent)' -Retry | Out-Null
    }

    # Monitor.Admin for you and the -UiAdmins users.
    $assigned = @(if (Test-New $sp) { @() } else {
        @((Invoke-Rest -Method GET -Url "$($script:Graph)/servicePrincipals/$($sp.id)/appRoleAssignedTo").value) })
    $principals = @($script:MeId)
    foreach ($upn in $Admins) {
        # A filter, so that a guest UPN (#EXT#) needs no URL encoding.
        $found = Invoke-Rest -Method GET -Url "$($script:Graph)/users" `
            -Query @{ '$filter' = "userPrincipalName eq '$($upn.Trim().Replace("'", "''"))'"; '$select' = 'id' }
        $user = @($found.value) | Select-Object -First 1
        if ($user) { $principals += $user.id } else { Write-Warn2 "User $upn not found. No Monitor.Admin role for it." }
    }
    foreach ($id in ($principals | Select-Object -Unique)) {
        if (@($assigned | Where-Object { $_.principalId -eq $id -and $_.appRoleId -eq $script:AdminRoleId }).Count) { continue }
        Invoke-Rest -Method POST -Url "$($script:Graph)/servicePrincipals/$($sp.id)/appRoleAssignedTo" `
            -Body @{ principalId = $id; resourceId = $sp.id; appRoleId = $script:AdminRoleId } `
            -What "Give the Monitor.Admin role to $id" -Retry | Out-Null
    }
    Write-Ok "Management UI sign-in app: $($app.appId). More admins: Settings > Management UI access"
    return [pscustomobject]@{ App = $app; Sp = $sp }
}

# -----------------------------------------------------------------------------
# Azure resources
# -----------------------------------------------------------------------------

function Test-FlexLocation([string]$Loc, [switch]$Soft) {
    $norm = ($Loc -replace '\s', '').ToLowerInvariant()
    try { $locs = @(Invoke-Az functionapp list-flexconsumption-locations --query '[].name') }
    catch {
        # A new subscription: Microsoft.Web is not registered yet. Step 3 registers it, then checks again.
        if ($Soft -and "$_" -match 'MissingSubscriptionRegistration|not registered') {
            Write-Info 'Region check after the resource provider registration (step 3).'
            return $null
        }
        throw
    }
    if ($locs -notcontains $norm) {
        Stop-Install "Region '$Loc' does not offer Flex Consumption." "Use one of: $(($locs | Sort-Object) -join ', ')"
    }
    return $norm
}

function Get-ResourceOrNull([string[]]$ShowArgs) {
    try { return Invoke-Az @ShowArgs } catch {
        if ("$_" -match 'ResourceNotFound|ResourceGroupNotFound|not found|could not be found|NotFound') { return $null }
        throw
    }
}

function Set-RoleAssignment([string]$PrincipalId, [string]$Role, [string]$Scope, [string]$Label) {
    if ($DryRun -and $PrincipalId -like '00000000*') { Write-Change "Give $Label the role $Role"; return }
    # Not --assignee: az looks the principal up in Graph, which fails while a new one replicates.
    $existing = @(Invoke-Az role assignment list --scope $Scope --role $Role --query "[?principalId=='$PrincipalId'].id")
    if ($existing.Count) { return }
    Invoke-AzChange -What "Give $Label the role $Role" -Retry role assignment create --assignee-object-id $PrincipalId `
        --assignee-principal-type ServicePrincipal --role $Role --scope $Scope | Out-Null
    $script:RolesMade["$Role|$Scope"] = Get-Date
}

function Set-Infrastructure([string]$Loc) {
    $n = $script:N
    $tags = @("application=$($script:Tag)", "managed-by=install.ps1")

    if (-not (Get-ResourceOrNull @('group', 'show', '--name', $n.ResourceGroup))) {
        Invoke-AzChange -What "Create resource group $($n.ResourceGroup) in $Loc" group create --name $n.ResourceGroup `
            --location $Loc --tags @tags | Out-Null
    }

    $script:Uami = Get-ResourceOrNull @('identity', 'show', '--resource-group', $n.ResourceGroup, '--name', $n.Identity)
    if (-not $script:Uami) {
        $script:Uami = Invoke-AzChange -What "Create managed identity $($n.Identity)" identity create --resource-group $n.ResourceGroup `
            --name $n.Identity --location $Loc --tags @tags
        if ($DryRun) { $script:Uami = [pscustomobject]@{ id = "/subscriptions/$($script:SubId)/resourceGroups/$($n.ResourceGroup)/providers/Microsoft.ManagedIdentity/userAssignedIdentities/$($n.Identity)"; clientId = '00000000-0000-0000-0000-000000000000'; principalId = '00000000-0000-0000-0000-000000000000' } }
    }
    Write-Ok "Managed identity $($n.Identity)"

    $script:StorageId = "/subscriptions/$($script:SubId)/resourceGroups/$($n.ResourceGroup)/providers/Microsoft.Storage/storageAccounts/$($n.Storage)"
    if (-not (Get-ResourceOrNull @('storage', 'account', 'show', '--resource-group', $n.ResourceGroup, '--name', $n.Storage))) {
        # Shared keys stay on until the Function App uses the managed identity (Set-StorageKeysOff):
        # az functionapp create writes a key-based AzureWebJobsStorage.
        Invoke-AzChange -What "Create storage account $($n.Storage) (no public blobs)" storage account create `
            --resource-group $n.ResourceGroup --name $n.Storage --location $Loc --sku Standard_LRS --kind StorageV2 `
            --min-tls-version TLS1_2 --allow-blob-public-access false --allow-shared-key-access true `
            --https-only true --tags @tags | Out-Null
    }
    Write-Ok "Storage account $($n.Storage)"
    # The identity reaches storage with Entra ID: the host (blobs: timers, deployment package) and the
    # app's tables. Minimum roles from Microsoft's Flex Consumption guidance.
    foreach ($role in 'Storage Blob Data Owner', 'Storage Table Data Contributor') {
        Set-RoleAssignment $script:Uami.principalId $role $script:StorageId 'the managed identity'
    }

    $ws = Get-ResourceOrNull @('monitor', 'log-analytics', 'workspace', 'show', '--resource-group', $n.ResourceGroup, '--name', $n.Workspace)
    if (-not $ws) {
        $ws = Invoke-AzChange -What "Create Log Analytics workspace $($n.Workspace) (90 days)" monitor log-analytics workspace create `
            --resource-group $n.ResourceGroup --name $n.Workspace --location $Loc --retention-time 90 --tags @tags
    }
    $wsId = if ($ws) { $ws.id } else { "/subscriptions/$($script:SubId)/resourceGroups/$($n.ResourceGroup)/providers/Microsoft.OperationalInsights/workspaces/$($n.Workspace)" }

    $aiUrl = "https://management.azure.com/subscriptions/$($script:SubId)/resourceGroups/$($n.ResourceGroup)/providers/Microsoft.Insights/components/$($n.AppInsights)"
    $aiApi = @{ 'api-version' = '2020-02-02' }
    $script:Ai = Get-RestOrNull $aiUrl $aiApi
    if (-not $script:Ai) {
        $script:Ai = Invoke-Rest -Method PUT -Url $aiUrl -Query $aiApi -What "Create Application Insights $($n.AppInsights)" -Body @{
            location = $Loc; kind = 'web'; tags = @{ application = $script:Tag }
            properties = @{ Application_Type = 'web'; WorkspaceResourceId = $wsId; RetentionInDays = 90 } }
        if ($DryRun) { $script:Ai = [pscustomobject]@{ id = $aiUrl.Replace('https://management.azure.com', ''); properties = [pscustomobject]@{ ConnectionString = '(planned)'; AppId = '(planned)' } } }
    }
    Write-Ok "Application Insights $($n.AppInsights)"
    # The host sends telemetry with the identity (Set-AppInsightsEntraOnly). The role must apply
    # before the app uses the identity for telemetry: without it, the host does not start.
    Set-RoleAssignment $script:Uami.principalId 'Monitoring Metrics Publisher' $script:Ai.id 'the managed identity'
    $script:WorkspaceId = $wsId
}

# The site through ARM. For a Flex app, az functionapp show returns the raw ARM object too
# (properties.defaultHostName, properties.state), so read it the same way everywhere.
function Get-Site {
    $script:SiteId = "/subscriptions/$($script:SubId)/resourceGroups/$($script:N.ResourceGroup)/providers/Microsoft.Web/sites/$($script:N.FunctionApp)"
    return Get-RestOrNull "https://management.azure.com$($script:SiteId)" @{ 'api-version' = '2023-12-01' }
}

function Get-SiteProperty($Site, [string]$Property) { return Get-Value (Get-Value $Site 'properties') $Property }

# The alert mailbox that the running monitor uses: the management UI value, else the app setting.
# Read only (/api/status). Empty if the Function App does not exist or does not answer.
function Get-ActiveAlertMailbox {
    $site = Get-Site
    if (-not $site) { return '' }
    $script:HostName = Get-SiteProperty $site 'defaultHostName'
    if (-not $script:HostName) { $script:HostName = "$($script:N.FunctionApp).azurewebsites.net" }
    $value = "$(Get-Value (Get-Value (Get-Status -WaitSeconds 30 -Quiet) 'config') 'admin_email')"
    if ($value -match '^[^@\s]+@[^@\s]+$') { return $value }
    return ''
}

function Set-DeploymentContainer {
    # functionapp create reads the container that --deployment-storage-container-name names. It does not create it.
    $n = $script:N
    $url = "https://management.azure.com$($script:StorageId)/blobServices/default/containers/deployments"
    $api = @{ 'api-version' = '2023-05-01' }
    if (-not (Get-RestOrNull $url $api)) {
        Invoke-Rest -Method PUT -Url $url -Query $api -Body @{ properties = @{ publicAccess = 'None' } } `
            -What "Create blob container deployments in $($n.Storage) (the code package)" | Out-Null
    }
}

function Set-FunctionApp([string]$Loc) {
    $n = $script:N
    $script:Site = Get-Site
    if (-not $script:Site) {
        Set-DeploymentContainer
        # create needs shared keys on the storage account (it writes a key-based AzureWebJobsStorage).
        # They go off again after the app uses the identity.
        Set-StorageSharedKey $true
        Invoke-AzChange -What "Create Function App $($n.FunctionApp) (Flex Consumption, Python 3.12, 512 MB)" functionapp create `
            --resource-group $n.ResourceGroup --name $n.FunctionApp --flexconsumption-location $Loc --runtime python --runtime-version 3.12 `
            --instance-memory 512 --storage-account $n.Storage --deployment-storage-name $n.Storage `
            --deployment-storage-container-name deployments --deployment-storage-auth-type UserAssignedIdentity `
            --deployment-storage-auth-value $script:Uami.id --assign-identity $script:Uami.id `
            --app-insights $n.AppInsights --https-only true --tags "application=$($script:Tag)" | Out-Null
        if (-not $DryRun) { $script:Site = Get-Site }
    }
    $script:HostName = Get-SiteProperty $script:Site 'defaultHostName'
    if (-not $script:HostName) { $script:HostName = "$($n.FunctionApp).azurewebsites.net" }
    Write-Ok "Function App https://$($script:HostName)"
}

function Set-StorageSharedKey([bool]$Allowed) {
    $n = $script:N
    if (-not $DryRun) {
        $current = Invoke-Az storage account show --resource-group $n.ResourceGroup --name $n.Storage --query allowSharedKeyAccess
        if ($current -eq $Allowed) { return }
    }
    Invoke-AzChange -What "$(if ($Allowed) { 'Allow' } else { 'Turn off' }) shared key access on $($n.Storage)" storage account update `
        --resource-group $n.ResourceGroup --name $n.Storage --allow-shared-key-access $(if ($Allowed) { 'true' } else { 'false' }) | Out-Null
}

function Set-AppSettings([hashtable]$Settings) {
    $n = $script:N
    # Only the settings that change: a rerun with nothing new writes nothing (Set-ChangeAlerts).
    $current = if ($DryRun) { @{} } else { Get-ExistingSettings }
    $pairs = @($Settings.GetEnumerator() | Sort-Object Key |
        Where-Object { -not $current.ContainsKey($_.Key) -or "$($current[$_.Key])" -cne "$($_.Value)" } |
        ForEach-Object { "$($_.Key)=$($_.Value)" })
    if ($pairs.Count) {
        Invoke-AzChange -What "Set $($pairs.Count) app settings" functionapp config appsettings set --resource-group $n.ResourceGroup `
            --name $n.FunctionApp --settings @pairs | Out-Null
    }
    # The host reaches storage with the managed identity. Remove a key-based connection string.
    if (-not $DryRun) {
        $current = @(Invoke-Az functionapp config appsettings list --resource-group $n.ResourceGroup --name $n.FunctionApp --query '[].name')
        $drop = @($current | Where-Object { $_ -in @('AzureWebJobsStorage', 'DEPLOYMENT_STORAGE_CONNECTION_STRING') })
        if ($drop.Count) {
            Invoke-AzChange -What "Remove key-based settings: $($drop -join ', ')" functionapp config appsettings delete `
                --resource-group $n.ResourceGroup --name $n.FunctionApp --setting-names @drop | Out-Null
        }
    }
    # Everything uses the managed identity now. No storage key works after this.
    Set-StorageSharedKey $false
}

function Set-EasyAuth([string]$UiClientId) {
    $url = "https://management.azure.com$($script:SiteId)/config/authsettingsV2"
    $login = @{ tokenStore = @{ enabled = $false }; preserveUrlFragmentsForLogins = $true }
    if ($UiSessionHours -gt 0) {
        # How long a management UI sign-in lasts. Without it, App Service keeps a sign-in for 8 hours.
        $login.cookieExpiration = @{ convention = 'FixedTime'; timeToExpiration = ('{0:00}:00:00' -f $UiSessionHours) }
    }
    else {
        # A PUT replaces the whole configuration: keep a length that an earlier run set.
        $current = if ($DryRun -and -not $script:Site) { $null } else { Get-RestOrNull $url @{ 'api-version' = '2023-12-01' } }
        $keep = Get-Value (Get-Value (Get-Value $current 'properties') 'login') 'cookieExpiration'
        if ($keep) { $login.cookieExpiration = $keep }
    }
    $body = @{ properties = @{
        platform = @{ enabled = $true }
        globalValidation = @{ requireAuthentication = $true; unauthenticatedClientAction = 'RedirectToLoginPage'
                              redirectToProvider = 'azureactivedirectory'; excludedPaths = $script:KeyEndpoints }
        httpSettings = @{ requireHttps = $true }
        login = $login
        identityProviders = @{ azureActiveDirectory = @{
            enabled = $true
            registration = @{ clientId = $UiClientId; openIdIssuer = "https://login.microsoftonline.com/$($script:TenantId)/v2.0" }
            validation = @{ allowedAudiences = @($UiClientId) } } } } }
    $null = Set-ArmResource $url '2023-12-01' $body `
        'Turn on App Service Authentication for /api/manage (Entra ID)'
    Write-Ok 'Management UI sign-in: Entra ID, Monitor.Admin role'
}

# The management UI sends POST and PUT requests, and a browser adds an Origin header to them (also
# on the same site). The Functions host refuses (HTTP 403, no body) an origin that is not in the
# CORS list. Add the app's own origin. The function also checks that Origin is the app's own host.
function Set-Cors([string]$HostName) {
    if (-not $HostName) { return }
    $origin = "https://$HostName"
    $url = "https://management.azure.com$($script:SiteId)/config/web"
    $query = @{ 'api-version' = '2023-12-01' }
    $cfg = if ($DryRun -and -not $script:Site) { $null } else { Get-RestOrNull $url $query }
    $current = @(Get-Value (Get-Value (Get-Value $cfg 'properties') 'cors') 'allowedOrigins' | Where-Object { $_ })
    if ($origin -in $current) { Write-Ok "CORS: the management UI origin is allowed"; return }
    Invoke-Rest -Method PATCH -Url $url -Query $query -Body @{ properties = @{ cors = @{ allowedOrigins = @($current + $origin) } } } `
        -What "Allow $origin in CORS (the management UI sends changes from this origin)" -Retry | Out-Null
    if (-not $DryRun) { Write-Ok "CORS: $origin allowed" }
}

# Deployment with a user name and password (publish profile, FTP) off. az deploys to a Flex app
# with an Entra ID token (az functionapp deployment source config-zip), so it still works.
function Set-PublishingPasswordsOff {
    foreach ($kind in 'scm', 'ftp') {
        $url = "https://management.azure.com$($script:SiteId)/basicPublishingCredentialsPolicies/$kind"
        try {
            $policy = if ($DryRun -and -not $script:Site) { $null } else { Get-RestOrNull $url @{ 'api-version' = '2023-12-01' } }
            if ($policy -and -not (Get-Value (Get-Value $policy 'properties') 'allow')) { continue }
            if (-not $policy -and -not $DryRun) { continue }   # this plan has no such endpoint
            Invoke-Rest -Method PUT -Url $url -Query @{ 'api-version' = '2023-12-01' } -Body @{ properties = @{ allow = $false } } `
                -What "Turn off deployment with a user name and password ($($kind.ToUpperInvariant()))" | Out-Null
        }
        catch {
            # FTP: a plan without FTP can refuse the request. The deployment endpoint (scm) must not.
            if ($kind -eq 'scm') { Write-Warn2 "Deployment with a password not turned off: $(("$_" -replace '\s+', ' ').Trim())" }
        }
    }
    Write-Ok 'Deployment with a user name and password: off (deployments use Entra ID)'
}

# A role assignment can need some minutes before the service accepts it. Wait until a role that this
# run made is 5 minutes old.
function Wait-RoleApplied([string]$Role, [string]$Scope, [string]$Why) {
    $made = $script:RolesMade["$Role|$Scope"]
    if (-not $made -or $DryRun) { return }
    $wait = [int](300 - ((Get-Date) - $made).TotalSeconds)
    if ($wait -le 0) { return }
    Write-Info "Wait $wait seconds: the role '$Role' must apply first ($Why)."
    Start-Sleep -Seconds $wait
}

# Application Insights accepts telemetry only with Microsoft Entra ID (DisableLocalAuth). Before,
# anyone with the connection string could send telemetry, for example false "run completed" lines
# that hide an outage from the no-runs alert. The host sends with the managed identity
# (APPLICATIONINSIGHTS_AUTHENTICATION_STRING, Monitoring Metrics Publisher).
function Set-AppInsightsEntraOnly([string]$Loc) {
    $url = "https://management.azure.com$($script:Ai.id)"
    $query = @{ 'api-version' = '2020-02-02' }
    $ai = if ($DryRun -and -not (Get-Value (Get-Value $script:Ai 'properties') 'AppId')) { $null } else { Get-RestOrNull $url $query }
    $props = Get-Value $ai 'properties'
    if ((Get-Value $props 'DisableLocalAuth') -eq $true) { Write-Ok 'Application Insights: Entra ID only'; return }
    $keep = @{}
    foreach ($k in 'Application_Type', 'WorkspaceResourceId', 'RetentionInDays', 'IngestionMode', 'Flow_Type', 'Request_Source',
                   'SamplingPercentage', 'DisableIpMasking', 'publicNetworkAccessForIngestion', 'publicNetworkAccessForQuery') {
        $v = Get-Value $props $k
        if ($null -ne $v) { $keep[$k] = $v }
    }
    if (-not $keep['Application_Type']) { $keep['Application_Type'] = 'web' }
    $keep['DisableLocalAuth'] = $true
    $tags = @{ application = $script:Tag }
    $have = Get-Value $ai 'tags'
    if ($have) { foreach ($p in $have.PSObject.Properties) { $tags[$p.Name] = $p.Value } }
    Invoke-Rest -Method PUT -Url $url -Query $query -What 'Application Insights: accept telemetry with Entra ID only (local auth off)' `
        -Body @{ location = $(if ($ai) { $ai.location } else { $Loc }); kind = 'web'; tags = $tags; properties = $keep } | Out-Null
    Write-Ok 'Application Insights: Entra ID only'
}

# Two alerts to the action group (the alert mailbox), from Azure, outside the app:
#  - Azure changes: an activity log alert on the resource group ($script:WatchedOperations): app
#    settings, sign-in settings, identity credentials, role assignments, storage, alert rules.
#  - Code deployed: the storage account logs writes to the "deployments" container, where the code
#    package goes. A deployment through Kudu is not in the activity log. A workspace transformation
#    keeps only those rows, so the other blob writes of the host cost nothing in Log Analytics.
# The install itself sends one "code deployed" email (the deployment at the end).
function Set-ChangeAlerts([string]$AgId, [string]$Loc) {
    $n = $script:N
    $rg = "/subscriptions/$($script:SubId)/resourceGroups/$($n.ResourceGroup)"
    $ws = $script:WorkspaceId
    try {
        $dcrId = "$rg/providers/Microsoft.Insights/dataCollectionRules/$($n.Transform)"
        $keepKql = "source | where AccountName =~ '$($n.Storage)' and ObjectKey contains '/deployments/'"
        $null = Set-ArmResource "https://management.azure.com$dcrId" '2022-06-01' @{
            location = $Loc; kind = 'WorkspaceTransforms'; tags = @{ application = $script:Tag }
            properties = @{
                description = 'Keeps only the blob writes to the deployments container (code deployments of the monitor).'
                destinations = @{ logAnalytics = @(@{ workspaceResourceId = $ws; name = 'workspace' }) }
                dataFlows = @(@{ streams = @('Microsoft-Table-StorageBlobLogs'); destinations = @('workspace'); transformKql = $keepKql }) } } `
            'Keep only the code deployment rows of the storage logs (workspace transformation)'
        $wsUrl = "https://management.azure.com$ws"
        $wsNow = if ($DryRun) { $null } else { Get-RestOrNull $wsUrl @{ 'api-version' = '2022-10-01' } }
        if ("$(Get-Value (Get-Value $wsNow 'properties') 'defaultDataCollectionRuleResourceId')" -ne $dcrId) {
            Invoke-Rest -Method PATCH -Url $wsUrl -Query @{ 'api-version' = '2022-10-01' } `
                -Body @{ properties = @{ defaultDataCollectionRuleResourceId = $dcrId } } `
                -What "Use the transformation in the workspace $($n.Workspace)" -Retry | Out-Null
        }
        $null = Set-ArmResource "https://management.azure.com$($script:StorageId)/blobServices/default/providers/Microsoft.Insights/diagnosticSettings/$($n.BlobLogs)" '2021-05-01-preview' @{
            properties = @{ workspaceId = $ws; logs = @(@{ category = 'StorageWrite'; enabled = $true }) } } `
            "Send the blob write logs of $($n.Storage) to the workspace"
        $deployQuery = "StorageBlobLogs`n| where ingestion_time() > ago(15m)`n| where AccountName =~ '$($n.Storage)' and ObjectKey contains '/deployments/'" +
                       "`n| where OperationName !contains 'Lease'`n| summarize writes = count()"
        $null = Set-ArmResource "https://management.azure.com$rg/providers/Microsoft.Insights/scheduledQueryRules/$($n.AlertDeploy)" '2021-08-01' @{
            location = $Loc; kind = 'LogAlert'; tags = @{ application = $script:Tag }
            properties = @{ displayName = $n.AlertDeploy; severity = 2; enabled = $true; skipQueryValidation = $true
                            description = ('Code was deployed to the monitor. Expected after install.ps1 (an install, a rerun, or -Update). ' +
                                           'If no one ran it, someone with access to the resource group changed the code: check who, then run install.ps1 -Update.')
                            evaluationFrequency = 'PT15M'; windowSize = 'PT1H'; scopes = @($ws); autoMitigate = $false
                            criteria = @{ allOf = @(@{ query = $deployQuery; timeAggregation = 'Total'; metricMeasureColumn = 'writes'
                                                       operator = 'GreaterThanOrEqual'; threshold = 1
                                                       failingPeriods = @{ numberOfEvaluationPeriods = 1; minFailingPeriodsToAlert = 1 } }) }
                            actions = @{ actionGroups = @($AgId) } } } "Set the alert $($n.AlertDeploy) (code deployed)"
        Write-Ok 'Code deployment alert: an email when code is deployed to the monitor'
    }
    catch { Write-Warn2 "Code deployment alert not set up: $(("$_" -replace '\s+', ' ').Trim())" }
    $operations = @($script:WatchedOperations | ForEach-Object { @{ field = 'operationName'; equals = $_ } })
    $null = Set-ArmResource "https://management.azure.com$rg/providers/Microsoft.Insights/activityLogAlerts/$($n.AlertAzure)" '2020-10-01' @{
        location = 'Global'; tags = @{ application = $script:Tag }
        properties = @{ enabled = $true; scopes = @($rg)
                        description = ('A change to the Azure resources of the monitor: app settings, sign-in settings, identity credentials, ' +
                                       'role assignments, storage, or alert rules. Expected only when someone runs install.ps1 or changes them on purpose.')
                        condition = @{ allOf = @(@{ field = 'category'; equals = 'Administrative' }, @{ field = 'status'; equals = 'Succeeded' },
                                                 @{ anyOf = $operations }) }
                        actions = @{ actionGroups = @(@{ actionGroupId = $AgId }) } } } "Set the alert $($n.AlertAzure) (Azure changes to the monitor)"
    Write-Ok 'Azure change alert: an email when someone changes the monitor in Azure'
}

function Set-HealthAlerts([string]$Email, [string]$Loc) {
    $n = $script:N
    $rg = "/subscriptions/$($script:SubId)/resourceGroups/$($n.ResourceGroup)"
    $agId = "$rg/providers/Microsoft.Insights/actionGroups/$($n.ActionGroup)"
    $agUrl = "https://management.azure.com$agId"
    $agApi = @{ 'api-version' = '2023-01-01' }
    $ag = Get-RestOrNull $agUrl $agApi
    if ($ag -and (Test-Bound 'AdminEmail')) {
        # -AdminEmail on a rerun: move the receiver "admin" (made by the install) to the new address,
        # as the management UI does when the alert mailbox changes there. Other receivers stay.
        $receivers = @(Get-Value (Get-Value $ag 'properties') 'emailReceivers')
        $admin = $receivers | Where-Object { (Get-Value $_ 'name') -eq 'admin' } | Select-Object -First 1
        if ($admin -and "$(Get-Value $admin 'emailAddress')" -ne $Email) {
            $list = @(foreach ($r in $receivers) {
                @{ name = "$(Get-Value $r 'name')"; useCommonAlertSchema = [bool](Get-Value $r 'useCommonAlertSchema')
                   emailAddress = $(if ((Get-Value $r 'name') -eq 'admin') { $Email } else { "$(Get-Value $r 'emailAddress')" }) }
            })
            $props = Get-Value $ag 'properties'
            $keep = @{}
            foreach ($p in $props.PSObject.Properties) { $keep[$p.Name] = $p.Value }
            $keep.emailReceivers = $list
            $tags = Get-Value $ag 'tags'
            if (-not $tags) { $tags = @{} }
            Invoke-Rest -Method PUT -Url $agUrl -Query $agApi -What "Send the health alerts of $($n.ActionGroup) to $Email" -Body @{
                location = 'Global'; tags = $tags; properties = $keep } | Out-Null
        }
    }
    if (-not $ag) {
        # The app changes the email when the alert mailbox changes in the UI. A rerun keeps it.
        Invoke-Rest -Method PUT -Url $agUrl -Query $agApi -What "Create action group $($n.ActionGroup) (email $Email)" -Body @{
            location = 'Global'; tags = @{ application = $script:Tag }
            properties = @{ groupShortName = 'atomonitor'; enabled = $true
                            emailReceivers = @(@{ name = 'admin'; emailAddress = $Email; useCommonAlertSchema = $true }) } } | Out-Null
    }
    $rules = @(
        @{ Name = $n.AlertNoRuns; Severity = 1; Operator = 'LessThan'; Threshold = 1; Column = 'runs'
           Description = 'No audit_log_monitor run completed in 1 hour. Check /api/status (install.ps1 -Verify).'
           Query = "traces`n| where message startswith `"audit_log_monitor run completed`"`n| summarize runs = count()" },
        @{ Name = $n.AlertErrors; Severity = 2; Operator = 'GreaterThanOrEqual'; Threshold = 5; Column = 'errors'
           Description = '5 or more errors in 1 hour. Run the Errors query in docs/APP_INSIGHTS_QUERIES.md.'
           Query = "traces`n| where severityLevel >= 3`n| summarize errors = count()" }
    )
    foreach ($r in $rules) {
        $null = Set-ArmResource "https://management.azure.com$rg/providers/Microsoft.Insights/scheduledQueryRules/$($r.Name)" '2021-08-01' @{
            location = $Loc; kind = 'LogAlert'; tags = @{ application = $script:Tag }
            properties = @{ displayName = $r.Name; description = $r.Description; severity = $r.Severity; enabled = $true
                            evaluationFrequency = 'PT30M'; windowSize = 'PT1H'; scopes = @($script:Ai.id); autoMitigate = $true
                            criteria = @{ allOf = @(@{ query = $r.Query; timeAggregation = 'Total'; metricMeasureColumn = $r.Column
                                                       operator = $r.Operator; threshold = $r.Threshold
                                                       failingPeriods = @{ numberOfEvaluationPeriods = 1; minFailingPeriodsToAlert = 1 } }) }
                            actions = @{ actionGroups = @($agId) } } } "Set health alert $($r.Name)"
    }
    Write-Ok 'Health alerts: no runs for 1 hour, 5 or more errors in 1 hour'
    return $agId
}

# -----------------------------------------------------------------------------
# Code
# -----------------------------------------------------------------------------

# -HostLogs warnings: the host's start-up and component logs (most of the log volume) only from
# warnings up. The monitor's logs (category Function.<name>.User) stay at Information: the
# reports and the "no runs" alert read them. Function start and end lines stay too.
function Get-HostJson([string]$Path, [string]$Level) {
    $text = Get-Content -Raw -LiteralPath $Path
    if ($Level -ne 'warnings') { return $text }
    $json = $text | ConvertFrom-Json -AsHashtable
    if (-not $json.ContainsKey('logging')) { $json.logging = @{} }
    $json.logging.logLevel = [ordered]@{
        default = 'Information'; 'Host.Startup' = 'Warning'; 'Host.Aggregator' = 'Warning'; Microsoft = 'Warning'
    }
    if (-not $json.logging.ContainsKey('applicationInsights')) { $json.logging.applicationInsights = @{} }
    $json.logging.applicationInsights.enablePerformanceCountersCollection = $false
    return ($json | ConvertTo-Json -Depth 10)
}

function New-CodePackage([string]$HostLogLevel = 'full') {
    $src = Join-Path $PSScriptRoot 'function'
    if (-not (Test-Path (Join-Path $src 'function_app.py'))) { Stop-Install "function/function_app.py not found next to install.ps1." }
    $zip = Join-Path ([System.IO.Path]::GetTempPath()) "m365atomon-code-$([guid]::NewGuid().ToString('N')).zip"
    Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
    $archive = [System.IO.Compression.ZipFile]::Open($zip, 'Create')
    try {
        $root = (Resolve-Path $src).Path
        Get-ChildItem -LiteralPath $root -Recurse -File | Where-Object {
            $_.FullName -notmatch '[\\/](__pycache__|\.venv|\.python_packages)[\\/]' -and
            $_.Name -notin @('local.settings.json') -and $_.Extension -ne '.pyc'
        } | ForEach-Object {
            $rel = [System.IO.Path]::GetRelativePath($root, $_.FullName).Replace('\', '/')
            if ($rel -eq 'host.json') {
                $writer = [System.IO.StreamWriter]::new($archive.CreateEntry($rel).Open())
                try { $writer.Write((Get-HostJson $_.FullName $HostLogLevel)) } finally { $writer.Dispose() }
            }
            else { [System.IO.Compression.ZipFileExtensions]::CreateEntryFromFile($archive, $_.FullName, $rel) | Out-Null }
        }
    }
    finally { $archive.Dispose() }
    return $zip
}

function Publish-Code {
    $n = $script:N
    # A deployment to a stopped Flex app reports success, but the app starts with no functions
    # (Azure/Azure-Functions issue 2670). Start it first.
    if (-not $DryRun -and (Get-SiteProperty (Get-Site) 'state') -ne 'Running') {
        Invoke-AzChange -What 'Start the Function App' functionapp start --resource-group $n.ResourceGroup --name $n.FunctionApp | Out-Null
    }
    $zip = New-CodePackage $script:HostLogLevel
    try {
        Invoke-AzChange -What 'Deploy the function code (remote build installs requirements.txt)' -Retry functionapp deployment source config-zip `
            --resource-group $n.ResourceGroup --name $n.FunctionApp --src $zip --build-remote true --timeout 900 | Out-Null
    }
    catch {
        # After a Flex deployment, az checks the host. The host can need some minutes after the
        # storage role and setting changes of step 8. The code is deployed.
        if ("$_" -notmatch 'Deployment was successful|Failed to fetch host (key|url)') { throw }
        Write-Warn2 "Code deployed. The host check did not pass yet: $(("$_" -replace '\s+', ' ').Trim())"
        Write-Info 'Run ./install.ps1 -Verify in 10 minutes.'
        return
    }
    finally { Remove-Item -LiteralPath $zip -ErrorAction SilentlyContinue }
    Write-Ok 'Code deployed'
}

# The default function key, or $null. Only this key: the master key stays out of memory.
function Get-FunctionKey {
    try {
        $key = Invoke-Az functionapp keys list --resource-group $script:N.ResourceGroup --name $script:N.FunctionApp `
            --query functionKeys.default
    } catch { Write-Info "No function key: $(("$_" -replace '\s+', ' ').Trim())"; return $null }
    if ($key) { return "$key" } else { return $null }
}

# Read /api/status. Wait up to $WaitSeconds for the host to answer. Return the status, or $null.
function Get-Status([int]$WaitSeconds = 240, [switch]$Quiet) {
    $key = Get-FunctionKey
    if (-not $key) {
        if (-not $Quiet) { Write-Warn2 'No function key yet. Run ./install.ps1 -Verify in some minutes.' }
        return $null
    }
    $url = "https://$($script:HostName)/api/status"
    $deadline = (Get-Date).AddSeconds($WaitSeconds)
    while ($true) {
        $status = $null
        try {
            $r = Invoke-WebRequest -Uri $url -Headers @{ 'x-functions-key' = $key } -SkipHttpErrorCheck -TimeoutSec 60
            # 503 with JSON is the app's own answer (a check failed). A 503 page from the platform
            # (the host is starting) is not JSON: wait.
            if ($r.StatusCode -in 200, 503) { $status = $r.Content | ConvertFrom-Json }
        } catch { $status = $null }
        if ($status -and (Get-Value $status 'checks')) { return $status }
        if ((Get-Date) -gt $deadline) {
            if (-not $Quiet) { Write-Warn2 "/api/status did not answer. Run ./install.ps1 -Verify in some minutes." }
            return $null
        }
        if (-not $Quiet) { Write-Info 'Waiting for the Function App to start...' }
        Start-Sleep -Seconds 15
    }
}

function Write-Status($Status) {
    foreach ($c in $Status.checks.PSObject.Properties) {
        if ("$($c.Value)" -like 'ok*' -or "$($c.Value)" -like 'SKIPPED*') { Write-Ok "$($c.Name): $($c.Value)" }
        else { Write-Warn2 "$($c.Name): $($c.Value)" }
    }
}

# True while the audit subscriptions are not started (AF20022: none; AF20023: turned off).
# The first monitor run starts them, some minutes after the deploy.
function Test-FeedStarting($Status) {
    if (-not $Status) { return $false }
    return [bool]@($Status.checks.PSObject.Properties | Where-Object {
        $_.Name -like 'o365_api_*' -and "$($_.Value)" -match 'AF2002[23]' }).Count
}

# Print the checks of /api/status. Return the status, or $null.
function Show-Status([int]$WaitSeconds = 240) {
    if ($DryRun) { Write-Change 'Check /api/status'; return $null }
    $status = Get-Status $WaitSeconds
    if (-not $status) { return $null }
    Write-Status $status
    if (Test-FeedStarting $status) {
        Write-Info 'The audit subscriptions are not started yet. The first monitor run starts them.'
    }
    return $status
}

# Wait up to $Minutes for the first monitor run to start the audit subscriptions. Return the last status.
function Wait-AuditFeed($Status, [int]$Minutes = 10) {
    if (-not (Test-FeedStarting $Status)) { return $Status }
    Write-Info "Waiting up to $Minutes minutes for the first monitor run to start the audit subscriptions."
    Write-Info 'The install is complete. Press Ctrl+C to stop waiting, and run ./install.ps1 -Verify later.'
    $start = Get-Date
    $shown = 0
    while (((Get-Date) - $start).TotalMinutes -lt $Minutes) {
        Start-Sleep -Seconds 30
        $next = Get-Status 60 -Quiet
        if ($next) { $Status = $next }
        if (-not (Test-FeedStarting $Status)) { break }
        $elapsed = [int][math]::Floor(((Get-Date) - $start).TotalMinutes)
        if ($elapsed -gt $shown) { $shown = $elapsed; Write-Info "Still waiting: $elapsed of $Minutes minutes." }
    }
    Write-Status $Status
    return $Status
}

# After the install: wait for the audit feed, test each detection, and offer test emails.
function Complete-Install($Status, [string]$Email) {
    if ($DryRun -or -not $Status -or $script:Batch) { return }
    Write-Host ''
    Write-Host 'Check the first monitor run' -ForegroundColor Cyan
    if ($Yes) {
        if (Test-FeedStarting $Status) { Write-Info 'Run ./install.ps1 -Verify in about 10 minutes to check the audit feed.' }
        else { Write-Info 'Run ./install.ps1 -Verify to test each detection.' }
        return
    }
    $Status = Wait-AuditFeed $Status
    $passed = Invoke-SelfTest $false
    if (-not $passed -or $Status.status -ne 'healthy') {
        if (Test-FeedStarting $Status) {
            Write-Info 'The audit subscriptions are still not started. Check that unified audit logging is on'
            Write-Info '(README > Turn on audit logging). Then run ./install.ps1 -Verify.'
        }
        else { Write-Info 'Fix the warnings above, then run ./install.ps1 -Verify (docs/GETTING_STARTED.md#6-troubleshooting).' }
        return
    }
    if ($script:MailScopeNew) {
        # The test emails go without the outbox: they would fail now.
        Write-Info 'Exchange applies the new Mail.Send permission in 30 minutes to 2 hours. Until then, alert'
        Write-Info 'emails wait in the outbox, and the monitor sends them later. Send the test emails after 2 hours:'
        Write-Info '  ./install.ps1 -Verify -SendTestAlerts'
        return
    }
    $answer = Read-Host "Send one test email for each alert type to $Email now? [y/N]"
    if ($answer -match '^(y|yes)$') { $null = Invoke-SelfTest $true }
    else { Write-Info 'To send them later: ./install.ps1 -Verify -SendTestAlerts' }
}

# -----------------------------------------------------------------------------
# Main flows
# -----------------------------------------------------------------------------

# True if the person gave this script parameter (a rerun keeps the earlier choice otherwise).
function Test-Bound([string]$Name) { return $script:BoundKeys -contains $Name }

function Get-ExistingSettings {
    try {
        $list = Invoke-Az functionapp config appsettings list --resource-group $script:N.ResourceGroup --name $script:N.FunctionApp
        $h = @{}
        foreach ($s in @($list)) { $h[$s.name] = $s.value }
        return $h
    } catch { return @{} }
}

# -MailSendScope takes the word mailbox or tenant. The alert mailbox address goes in -AdminEmail.
function Test-MailSendScope {
    if ($MailSendScope -in 'mailbox', 'tenant') { return }
    if ($MailSendScope -match '@') {
        Stop-Install "-MailSendScope takes the word 'mailbox' or 'tenant', not an address. Give the alert mailbox with -AdminEmail." `
            "./install.ps1 -MailSendScope mailbox -AdminEmail $MailSendScope"
    }
    Stop-Install "-MailSendScope takes the word 'mailbox' (only the alert mailbox) or 'tenant' (every mailbox), not '$MailSendScope'." `
        './install.ps1 -MailSendScope mailbox'
}

function Install-Monitor {
    $isUpdate = [bool]$Update
    Test-MailSendScope
    $script:Step = 0
    $script:RolesMade = @{}   # per installation (-UpdateAll runs more than one)
    $script:GrantsMade = @()
    $script:Steps = 9
    Write-Step 'Check the tools and the Azure sign-in'
    Test-Prerequisites
    $script:N = Get-Names $script:SubId $Name
    $existingRg = Get-ResourceOrNull @('group', 'show', '--name', $script:N.ResourceGroup)
    $existing = if ($existingRg) { Get-ExistingSettings } else { @{} }
    if ($isUpdate -and -not $existingRg) { Stop-Install "No installation named '$Name' in this subscription." 'Run ./install.ps1 without -Update.' }
    # -HostLogs, else the value of the last run (app setting HOST_LOGS), else full.
    $script:HostLogLevel = if ($HostLogs) { $HostLogs } elseif ($existing['HOST_LOGS'] -eq 'warnings') { 'warnings' } else { 'full' }

    Write-Step 'Choose the settings'
    $loc = if ($existingRg) { $existingRg.location } else { $Location }
    if (-not $loc) { $loc = Read-Default 'Azure region (Flex Consumption)' 'eastus' }
    $checked = Test-FlexLocation $loc -Soft
    if ($checked) { $loc = $checked }
    $email = if ($AdminEmail) { $AdminEmail } elseif ($existing['ADMIN_EMAIL']) { $existing['ADMIN_EMAIL'] } else {
        Read-Default 'Alert mailbox (a licensed mailbox; it sends and receives the alerts)' $script:MeUpn }
    if ($email -notmatch '^[^@\s]+@[^@\s]+\.[A-Za-z]{2,}$') { Stop-Install "'$email' is not an email address." }
    # A change in the management UI is kept in Table Storage, not in the app setting, and wins over it.
    # $active is the alert mailbox that the running monitor uses; $fromUi is set if it is a UI change.
    # $shown is the one that is active after this run.
    $active = if ($existingRg) { Get-ActiveAlertMailbox } else { '' }
    $fromUi = if ($active -and $active -ne "$($existing['ADMIN_EMAIL'])") { $active } else { '' }
    $shown = if ($fromUi) { $fromUi } else { $email }
    Test-AlertMailbox $(if ($AdminEmail) { $email } else { $shown })
    $scope = if (Test-Bound 'MailSendScope') { $MailSendScope } elseif ($existing['MAIL_SEND_SCOPE']) { $existing['MAIL_SEND_SCOPE'] } else { $MailSendScope }
    # -Update deploys code; it does not sign in to Exchange Online. A rerun without -Update does.
    $exchangeStep = $scope -eq 'mailbox' -and -not $isUpdate
    $respond = switch ($ResponsePermissions) {
        'yes' { $true } 'no' { $false }
        default {
            if ($existing.ContainsKey('RESPONSE_PERMISSIONS')) { $existing['RESPONSE_PERMISSIONS'] -eq 'true' }
            elseif ($Yes) { $true }
            else { (Read-Default 'Grant the permissions for revoke sessions, block sign-in, and turn off inbox rules now? They stay off until you turn them on in the UI. (Y/n)' 'Y') -match '^(y|yes)$' }
        }
    }
    $graphRoles = @($script:GraphRolesBase)
    if ($scope -eq 'tenant') { $graphRoles += $script:GraphRolesMail }
    if ($respond) { $graphRoles += $script:GraphRolesResponse }
    $graphRoles = @($graphRoles | Select-Object -Unique)
    if ($respond) { $graphRoles = @($graphRoles | Where-Object { $_ -ne 'MailboxSettings.Read' }) }

    Write-Host ''
    Write-Host 'Plan' -ForegroundColor Cyan
    Write-Info "Tenant:          $(Get-TenantLabel)"
    Write-Info "Resource group:  $($script:N.ResourceGroup) ($loc)$(if ($existingRg) { ' - exists, will be checked and repaired' })"
    Write-Info "Function App:    $($script:N.FunctionApp) (Flex Consumption, Python 3.12)"
    if ($shown -ne $email) { Write-Info "Alert mailbox:   $shown (set in the management UI; it stays)" }
    else { Write-Info "Alert mailbox:   $email" }
    if ($AdminEmail -and $fromUi -and $fromUi -ne $AdminEmail) {
        Write-Warn2 ("The management UI set the alert mailbox to $fromUi. That value wins over -AdminEmail: " +
                     "the monitor keeps sending as $fromUi. To use $AdminEmail, change it in the management UI (Settings > Email).")
    }
    if ($scope -eq 'tenant') { Write-Info "Mail.Send:       every mailbox in the tenant (Graph). To limit it to $shown, add -MailSendScope mailbox (the word 'mailbox')" }
    else {
        Write-Info "Mail.Send:       the alert mailbox only: members of the Exchange group $(Get-SendGroupName)"
        if ($exchangeStep) {
            Write-Info '                 Needs the module ExchangeOnlineManagement (installed if missing) and an Exchange'
            Write-Info '                 Online sign-in: the script shows a URL and a code to enter in any browser.'
        }
    }
    Write-Info "Graph roles:     $($graphRoles -join ', ')"
    if ($DryRun) { Write-Info 'Dry run:         no change is made' }
    Confirm-Or-Stop 'Continue?'

    Write-Step 'Register the resource providers'
    Register-Providers
    Write-Ok 'Resource providers'
    if (-not $checked -and -not $DryRun) { $loc = Test-FlexLocation $loc }
    elseif (-not $checked) { $loc = ($loc -replace '\s', '').ToLowerInvariant() }

    Write-Step 'Create the Azure resources'
    Set-Infrastructure $loc

    Write-Step 'Create the Function App'
    Set-FunctionApp $loc

    Write-Step 'Create the app registrations and grant admin consent'
    $keep = @(if ($scope -eq 'mailbox') { $script:GraphRolesMail })
    $monitor = Set-MonitorApp $graphRoles $script:Uami.principalId -Keep $keep
    $script:MailScopeNew = $false
    # The group is in the app settings only after Exchange showed the grant.
    $sendGroup = "$($existing['MAIL_SEND_GROUP'])"
    if ($exchangeStep) {
        # The monitor sends as the active alert mailbox ($active, from the running monitor).
        $mailboxes = @($email)
        if ($active -and $active -ne $email) {
            Write-Info "The monitor sends as $active now. It stays in the group."
            $mailboxes = @($active, $email)
        }
        if (Set-MailSendGroup $monitor.App.appId $monitor.Sp.id $mailboxes) {
            if (-not (Test-New $monitor.Sp)) { Remove-GraphAppRole $monitor.Sp.id $script:GraphRolesMail }
            $script:MailScopeNew = -not $sendGroup
            $sendGroup = Get-SendGroupName
        }
    }
    elseif ($scope -eq 'mailbox' -and -not $sendGroup) {
        Write-Warn2 "Mail.Send is not limited to the alert mailbox yet. Run ./install.ps1 without -Update to finish."
    }
    # Until Exchange shows the grant, keep the earlier scope: the Graph Mail.Send stays in that case.
    $scopeSetting = if ($scope -eq 'mailbox' -and -not $sendGroup -and $existing['MAIL_SEND_SCOPE']) { $existing['MAIL_SEND_SCOPE'] } else { $scope }
    $ui = Set-AdminUiApp $script:HostName $UiAdmins
    Set-RoleAssignment $monitor.Sp.id 'Monitoring Reader' $script:Ai.id 'the monitor app'

    Write-Step 'Set up the health alerts'
    $agId = Set-HealthAlerts $email $loc
    Set-RoleAssignment $monitor.Sp.id 'Monitoring Contributor' $agId 'the monitor app'

    Write-Step 'Configure the Function App'
    $settings = @{
        AZURE_TENANT_ID = $script:TenantId
        AZURE_CLIENT_ID = $monitor.App.appId
        MONITOR_SP_ID = $monitor.Sp.id
        MANAGED_IDENTITY_CLIENT_ID = $script:Uami.clientId
        STORAGE_ACCOUNT_NAME = $script:N.Storage
        AzureWebJobsStorage__accountName = $script:N.Storage
        AzureWebJobsStorage__credential = 'managedidentity'
        AzureWebJobsStorage__clientId = $script:Uami.clientId
        APPLICATIONINSIGHTS_CONNECTION_STRING = $script:Ai.properties.ConnectionString
        APP_INSIGHTS_APP_ID = $script:Ai.properties.AppId
        ACTION_GROUP_ID = $agId
        ADMIN_UI_ENABLED = 'true'
        MONITOR_HOSTNAME = $script:HostName
        MAIL_SEND_SCOPE = $scopeSetting
        MAIL_SEND_GROUP = $(if ($scopeSetting -eq 'mailbox') { $sendGroup } else { '' })
        RESPONSE_PERMISSIONS = $(if ($respond) { 'true' } else { 'false' })
        APPLICATIONINSIGHTS_AUTHENTICATION_STRING = "Authorization=AAD;ClientId=$($script:Uami.clientId)"
        HOST_LOGS = $script:HostLogLevel
    }
    # The alert mailbox is a default. The UI overrides it; keep a UI change on a rerun.
    if (-not $existing['ADMIN_EMAIL'] -or $AdminEmail) { $settings.ADMIN_EMAIL = $email }
    $made = @($script:GrantsMade | Where-Object { $_.Sp -eq $monitor.Sp.id } | ForEach-Object { $_.Role } | Select-Object -Unique)
    if ($made.Count -and -not $DryRun) { $settings.INSTALL_GRANTS = New-InstallGrantsSetting $existing['INSTALL_GRANTS'] $made }
    # The verified domains count as internal (forwarding to a second domain is not "external").
    # Empty if Graph refused /organization: the setting keeps its value.
    if (@($script:TenantDomains).Count) { $settings.TENANT_DOMAINS = (@($script:TenantDomains) -join ',') }
    # More than one tenant (-Tenant): the organization name in the subjects, [M365 Alert][Contoso].
    if ($Tenant -and $script:TenantName -and -not $existing['TENANT_LABEL']) { $settings.TENANT_LABEL = $script:TenantName }
    Wait-RoleApplied 'Monitoring Metrics Publisher' $script:Ai.id 'the app sends telemetry with the managed identity'
    Set-AppSettings $settings
    Set-AppInsightsEntraOnly $loc
    Set-EasyAuth $ui.App.appId
    Set-Cors $script:HostName
    Set-PublishingPasswordsOff
    # Last: the changes above do not send an alert email on a first install.
    Set-ChangeAlerts $agId $loc

    Write-Step 'Deploy the code and check the status'
    Publish-Code
    $status = Show-Status

    Write-Host ''
    Write-Host 'Done.' -ForegroundColor Green
    Write-Info "Management UI: https://$($script:HostName)/api/manage"
    Write-Info 'Next:'
    Write-Info '  1. Open the management UI. Add a proxycheck.io key: Settings > Suspicious sign-ins.'
    Write-Info "  2. Add a mail rule so that '[M365 Alert]' mail does not go to junk."
    Write-Info '  3. Check that unified audit logging is on (docs/GETTING_STARTED.md).'
    if ($scope -eq 'mailbox') {
        Write-Info "  4. To use another alert mailbox later: add it to the Exchange group $(Get-SendGroupName)"
        Write-Info '     (Microsoft 365 admin center > Teams & groups > Active teams & groups), then change it'
        Write-Info '     in the management UI: Settings > Email.'
    }
    else { Write-Info "  4. Optional: limit Mail.Send to the alert mailbox ($email): ./install.ps1 -MailSendScope mailbox" }
    Write-Info 'The first audit content arrives after 12-24 hours. The "Starting state" report follows.'
    Save-TenantRecord ([pscustomobject]@{
        tenantId = $script:TenantId; tenantName = $script:TenantName; domain = $script:TenantDomain
        domains = @($script:TenantDomains); subscriptionId = $script:SubId; name = $Name; location = $loc
        functionApp = $script:N.FunctionApp; hostName = $script:HostName; adminEmail = $shown
        updated = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') })
    Complete-Install $status $email
}

function Test-Monitor {
    $script:Step = 0
    $script:Steps = 1
    Write-Step 'Check the monitor'
    Test-Prerequisites
    $script:N = Get-Names $script:SubId $Name
    $script:Site = Get-Site
    if (-not $script:Site) { Stop-Install "No Function App $($script:N.FunctionApp) in this subscription." }
    $script:HostName = Get-SiteProperty $script:Site 'defaultHostName'
    $null = Show-Status 60
    $send = [bool]$SendTestAlerts
    if ($send -and $DryRun) { Write-Change 'Send one test email for each alert type'; $send = $false }
    $null = Invoke-SelfTest $send
    Write-Info "Management UI: https://$($script:HostName)/api/manage"
}

# Run the self-test of each alert type. Return $true if it passed.
function Invoke-SelfTest([bool]$Send) {
    $key = Get-FunctionKey
    $uri = "https://$($script:HostName)/api/selftest?type=all$(if ($Send) { '&alert=true' })"
    try {
        $r = Invoke-WebRequest -Uri $uri -Headers @{ 'x-functions-key' = $key } -SkipHttpErrorCheck -TimeoutSec 120
        $result = $r.Content | ConvertFrom-Json
    } catch { Write-Warn2 "Self-test did not run: $_"; return $false }
    if (-not (Get-Value $result 'results')) { Write-Warn2 "Self-test did not run: HTTP $($r.StatusCode)"; return $false }
    foreach ($t in @($result.results)) {
        $mail = if ($Send) { if ($t.email_sent) { ', email sent' } else { ', email NOT sent' } } else { '' }
        if ($t.detected -ne $false) { Write-Ok "$($t.type): detected$mail" } else { Write-Warn2 "$($t.type): NOT detected$mail" }
    }
    if ($result.passed) { Write-Ok "Self-test passed$(if ($Send) { ': check the alert mailbox for [SELF-TEST] emails' })" }
    else { Write-Warn2 'Self-test failed. See the lines above and Application Insights.' }
    return [bool]$result.passed
}

function Remove-Monitor {
    $script:Step = 0
    $script:Steps = 2
    Write-Step 'Find the installation'
    Test-Prerequisites
    $script:N = Get-Names $script:SubId $Name
    $rg = Get-ResourceOrNull @('group', 'show', '--name', $script:N.ResourceGroup)
    $apps = @($script:N.AppReg, $script:N.UiAppReg | ForEach-Object { Find-Application $_ } | Where-Object { $_ })
    Write-Info "Resource group:    $(if ($rg) { $script:N.ResourceGroup } else { '(not found)' })"
    Write-Info "App registrations: $(if ($apps.Count) { ($apps.displayName -join ', ') } else { '(not found)' })"
    if (-not $rg -and -not $apps.Count) { Write-Ok 'Nothing to remove.'; return }

    Write-Step 'Remove'
    Write-Warn2 'This deletes the monitor, its settings, history, and alert journal. It cannot be undone.'
    if (-not $Yes) {
        $typed = Read-Host "Type the resource group name ($($script:N.ResourceGroup)) to confirm"
        if ($typed -ne $script:N.ResourceGroup) { throw 'Stopped: the name did not match.' }
    }
    foreach ($a in $apps) {
        Invoke-AzChange -What "Delete app registration $($a.displayName)" ad app delete --id $a.appId | Out-Null
    }
    if ($rg) {
        Invoke-AzChange -What "Delete resource group $($script:N.ResourceGroup) (runs in the background)" group delete `
            --name $script:N.ResourceGroup --yes --no-wait | Out-Null
    }
    Write-Ok 'Removed. The audit log subscriptions of the tenant stay; they cost nothing.'
    Remove-TenantRecord $script:TenantId
    $group = Get-SendGroupName
    Write-Info "If you used -MailSendScope mailbox, the Exchange Online group $group and its role assignment stay."
    Write-Info 'Remove them in Exchange Online PowerShell:'
    Write-Info "  Get-ManagementRoleAssignment -Role 'Application Mail.Send' | Where-Object Name -like '$group Mail.Send*' | Remove-ManagementRoleAssignment"
    Write-Info "  Remove-ManagementScope '$group scope'; Remove-DistributionGroup $group"
    Write-Info "  Remove-ServicePrincipal <the object ID of the deleted $($script:N.AppReg) app>"
    Write-Info 'Deleted app registrations stay in Entra ID > App registrations > Deleted applications for 30 days.'
}

# Columns of text. Format-Table prints nothing for these objects under Set-StrictMode.
function Write-Rows([object[]]$Rows, [string[]]$Columns) {
    $widths = @(foreach ($col in $Columns) {
        $len = @($Rows | ForEach-Object { "$($_[$col])".Length }) + $col.Length
        ($len | Measure-Object -Maximum).Maximum
    })
    $line = { param($values) (@(for ($i = 0; $i -lt $Columns.Count; $i++) { "$($values[$i])".PadRight($widths[$i]) }) -join '  ').TrimEnd() }
    Write-Host (& $line $Columns)
    Write-Host (& $line @($widths | ForEach-Object { '-' * $_ }))
    foreach ($r in $Rows) { Write-Host (& $line @($Columns | ForEach-Object { $r[$_] })) }
}

function Show-Installations {
    $records = @(Read-TenantRecords)
    if (-not $records.Count) {
        Write-Host 'No installation is saved on this computer. Each install and -Update saves one.'
        return
    }
    $rows = @($records | Sort-Object tenantName | ForEach-Object {
        # Records from before hostName was saved: the default host name of the Function App.
        $uiHost = if (Get-Value $_ 'hostName') { "$($_.hostName)" } else { "$($_.functionApp).azurewebsites.net" }
        @{ Tenant = "$($_.tenantName)"; Domain = "$($_.domain)"; 'Alert mailbox' = "$($_.adminEmail)"
           'Management UI' = "https://$uiHost/api/manage"
           Updated = if ($_.updated -is [datetime]) { $_.updated.ToUniversalTime().ToString('yyyy-MM-dd HH:mm') + ' UTC' } else { "$($_.updated)" } } })
    Write-Rows $rows @('Tenant', 'Domain', 'Alert mailbox', 'Management UI', 'Updated')
    Write-Host ''
    Write-Host 'Update one:  ./install.ps1 -Tenant <domain> -Update'
    Write-Host 'Update all:  ./install.ps1 -UpdateAll'
    Write-Host 'Check one:   ./install.ps1 -Tenant <domain> -Verify'
}

# -Update for each saved installation. One question at the start; a summary at the end.
function Update-AllInstallations {
    $records = @(Read-TenantRecords | Sort-Object tenantName)
    if (-not $records.Count) { Write-Host 'No installation is saved on this computer. Install or update one first.'; return }
    Write-Host "Update $($records.Count) installation(s) with the code in this folder:"
    $records | ForEach-Object { Write-Host "  $($_.tenantName) ($($_.domain))" }
    Confirm-Or-Stop 'Continue?'
    $script:Confirmed = $true
    $script:Batch = $true
    try {
        $results = foreach ($r in $records) {
            Write-Host ''
            Write-Host "=== $($r.tenantName) ($($r.domain)) ===" -ForegroundColor Cyan
            $Tenant = "$($r.tenantId)"; $Name = "$($r.name)"; $SubscriptionId = "$($r.subscriptionId)"
            $Update = $true; $AdminEmail = ''; $Location = ''
            $result = try { Install-Monitor; 'updated' }
                      catch { "FAILED: $(("$_" -replace '^install.ps1 stopped: ', ''))" }
            Restore-AzSubscription
            @{ Installation = "$($r.tenantName) ($($r.domain))"; Result = $result }
        }
    }
    finally { $script:Confirmed = $false; $script:Batch = $false }
    Write-Host ''
    Write-Rows @($results) @('Installation', 'Result')
    if (@($results | Where-Object { $_['Result'] -like 'FAILED*' }).Count) {
        Write-Host 'For a failed installation, run: ./install.ps1 -Tenant <domain> -Update'
    }
}

function Show-Usage {
    @'
M365 ATO Monitor installer. Needs PowerShell 7.2 or later and the Azure CLI 2.60 or later.

Install, or repair (run it again at any time):
  ./install.ps1 -AdminEmail <alert mailbox> -Location <region>
Install in another tenant:
  ./install.ps1 -Tenant <domain> -AdminEmail <alert mailbox> -Location <region>

Other actions:
  -Update                    Deploy the code of this folder. Keeps all settings.
  -UpdateAll                 -Update for each installation on this computer.
  -Verify                    Show the status and run the self-test (no email).
  -Verify -SendTestAlerts    Also send one [SELF-TEST] email for each alert type.
  -List                      Show the installations on this computer.
  -Uninstall                 Delete the resource group and the app registrations.

Options:
  -AdminEmail <address>      The alert mailbox. It sends and receives every email.
  -Location <region>         An Azure region with Flex Consumption, for example eastus.
  -Tenant <domain or ID>     The tenant. Default: the tenant of the Azure CLI sign-in.
  -SubscriptionId <ID>       The subscription. Default: the Azure CLI subscription.
  -Name <name>               The base name of the resources. Default: m365-ato-monitor.
  -MailSendScope <scope>     mailbox (default): the app sends only as the alert mailbox. It needs an
                             Exchange Online sign-in (a URL and a code). tenant: any mailbox.
                             Type the word mailbox or tenant, not an address.
  -ResponsePermissions <a>   ask (default), yes, or no: the permissions for revoke sessions,
                             block sign-in, and turn off inbox rules. They stay off until you
                             turn them on in the management UI.
  -UiAdmins <upn>,<upn>      More management UI admins. You get the role automatically.
  -UiSessionHours <1-24>     How long a management UI sign-in lasts. Default: 8 hours. Later runs
                             keep the value.
  -HostLogs <level>          full (default) or warnings: the Functions host logs only warnings
                             (about 85% less log volume). The monitor's own logs do not change.
                             Later runs keep the value.
  -DryRun                    Show each change. Make no change.
  -Yes                       Ask no questions.
  -Help                      Show this text. Details: Get-Help ./install.ps1 -Detailed
'@
}

# Run unless the file is dot-sourced (the tests load the functions only).
if ($MyInvocation.InvocationName -ne '.') {
    if ($Help -or $Rest.Count) {
        $asked = $Help -or ($Rest.Count -eq 1 -and $Rest[0] -in '--help', '-help', 'help', '/?', '-?', '/help')
        if (-not $asked) { Write-Host "Unknown option or value: $($Rest -join ' ')" -ForegroundColor Red; Write-Host '' }
        Write-Host (Show-Usage)
        exit $(if ($asked) { 0 } else { 1 })
    }
    try {
        if ($List) { Show-Installations }
        elseif ($UpdateAll) { Update-AllInstallations }
        elseif ($Uninstall) { Remove-Monitor }
        elseif ($Verify) { Test-Monitor }
        else { Install-Monitor }
    }
    catch {
        if ("$_" -notlike 'install.ps1 stopped:*' -and "$_" -notlike 'Stopped*') {
            Write-Host ''
            Write-Host "ERROR: $_" -ForegroundColor Red
            if ("$_" -match $script:SignInPattern) {
                $tenant = if ($script:TenantId) { " --tenant $($script:TenantId)" } else { '' }
                Write-Host "Fix:   The Azure sign-in has expired. Run: az login$tenant" -ForegroundColor Yellow
                Write-Host '       You do not need az logout first. Then run the script again.'
            }
            else { Write-Host 'Run the script again. Each step checks what exists and continues.' }
        }
        Restore-AzSubscription
        exit 1
    }
    Restore-AzSubscription
}
