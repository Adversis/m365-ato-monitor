#Requires -Version 7.1
<#
.SYNOPSIS
    Make real attacker-like changes on a test mailbox, then undo them, so that
    M365 ATO Monitor sends real alerts.

.DESCRIPTION
    Each test makes one change that an attacker makes after an account
    takeover (for example an inbox rule that forwards mail out). The script then
    undoes the change. The alert comes from the audit record of the change, so
    it arrives 1-2 hours later even though the change is already undone.

    Safety:
    - All changes are on -TestUser, a dedicated test mailbox. Do not use a
      person's mailbox or an admin account.
    - No mail goes to -ExternalAddress: the inbox rules match a subject that
      never occurs, and the mail flow rule is created turned off.
    - Mailbox forwarding is on for a few seconds. Mail that the test mailbox
      receives in that time is forwarded.
    - Every object has "M365-ATO-TEST" (or the subject marker "M365ATOTEST")
      in its name. -Cleanup finds and removes leftovers.

    Needs: PowerShell 7.1+, ExchangeOnlineManagement 3.x (Exchange admin), and
    for -IncludeEntra Microsoft.Graph.Authentication 2.x (Privileged Role
    Administrator and Application Administrator, or Global Administrator).

.PARAMETER TestUser
    UPN of the dedicated test mailbox.

.PARAMETER ExternalAddress
    An address outside your tenant. Use one you control.

.PARAMETER Tests
    Tests to run. Default: all. Names: InboxRuleForward, InboxRuleHidden,
    MailboxForwarding, MailFlowRule, MailboxFullAccess, InboxShared,
    AuditBypass, ExchangeRole, AttackToolSignIn, EntraRole, AppSecret,
    OAuthConsent. The last three need -IncludeEntra.

.PARAMETER IncludeEntra
    Also run the Entra ID tests (role member, app secret, OAuth consent).

.PARAMETER KeepMinutes
    Wait this many minutes before the undo step. Default 0 (undo at once).

.PARAMETER Cleanup
    Only remove leftovers of earlier runs on -TestUser. Makes no new changes.

.PARAMETER Force
    Do not ask for confirmation.

.EXAMPLE
    ./scripts/live-test.ps1 -TestUser ato-test@contoso.com -ExternalAddress me@gmail.com

.EXAMPLE
    ./scripts/live-test.ps1 -TestUser ato-test@contoso.com -ExternalAddress me@gmail.com -IncludeEntra

.EXAMPLE
    ./scripts/live-test.ps1 -TestUser ato-test@contoso.com -Cleanup -IncludeEntra
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$TestUser,
    [string]$ExternalAddress = "",
    [string[]]$Tests = @(),
    [switch]$IncludeEntra,
    [int]$KeepMinutes = 0,
    [switch]$Cleanup,
    [switch]$Force
)

$ErrorActionPreference = "Stop"
$Prefix = "M365-ATO-TEST"
$Marker = "M365ATOTEST" + (Get-Date).ToUniversalTime().ToString("yyyyMMddHHmmss")
$ExchangeTests = @("InboxRuleForward", "InboxRuleHidden", "MailboxForwarding", "MailFlowRule",
                   "MailboxFullAccess", "InboxShared", "AuditBypass", "ExchangeRole", "AttackToolSignIn")
$EntraTests = @("EntraRole", "AppSecret", "OAuthConsent")
$GraphAppId = "00000003-0000-0000-c000-000000000000"

function Write-Step($text) { Write-Host "`n== $text" -ForegroundColor Cyan }
function Write-OK($text) { Write-Host "  [OK]   $text" -ForegroundColor Green }
function Write-Bad($text) { Write-Host "  [FAIL] $text" -ForegroundColor Red }
function Write-Note($text) { Write-Host "  $text" }

# -----------------------------------------------------------------------------
# Checks
# -----------------------------------------------------------------------------

if (-not $Tests -or $Tests.Count -eq 0) {
    $Tests = $ExchangeTests + $(if ($IncludeEntra) { $EntraTests } else { @() })
}
$unknown = $Tests | Where-Object { $_ -notin ($ExchangeTests + $EntraTests) }
if ($unknown) { throw "Unknown test: $($unknown -join ', '). Known: $(($ExchangeTests + $EntraTests) -join ', ')" }
if (($Tests | Where-Object { $_ -in $EntraTests }) -and -not $IncludeEntra) {
    throw "The tests $($EntraTests -join ', ') need -IncludeEntra."
}
if (-not $Cleanup -and -not $ExternalAddress) { throw "Give -ExternalAddress (an address outside your tenant)." }
if ($ExternalAddress -and $ExternalAddress -notmatch '^[^@\s]+@[^@\s]+\.[^@\s]+$') { throw "-ExternalAddress is not an email address." }

if (-not (Get-Module -ListAvailable ExchangeOnlineManagement)) {
    throw "Install the module first: Install-Module ExchangeOnlineManagement -Scope CurrentUser"
}
if ($IncludeEntra -and -not (Get-Module -ListAvailable Microsoft.Graph.Authentication)) {
    throw "Install the module first: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser"
}

Write-Step "Connect to Exchange Online (sign in as an Exchange admin)"
Connect-ExchangeOnline -ShowBanner:$false
$admin = (Get-ConnectionInformation | Where-Object State -eq "Connected" | Select-Object -First 1).UserPrincipalName
$mailbox = Get-Mailbox -Identity $TestUser -ErrorAction SilentlyContinue
if (-not $mailbox) { throw "No mailbox found for $TestUser." }
if ($admin -and $TestUser -ieq $admin) { throw "Use a dedicated test mailbox, not the account you signed in with." }
$tenantDomains = (Get-AcceptedDomain).DomainName | ForEach-Object { "$_".ToLower() }
if ($ExternalAddress) {
    $externalDomain = $ExternalAddress.Split("@")[1].ToLower()
    if ($externalDomain -in $tenantDomains) {
        throw "$ExternalAddress is in an accepted domain of this tenant. Use an outside address, so the forwarding tests count as external."
    }
}
Write-OK "Signed in as $admin. Test mailbox: $TestUser"

if ($IncludeEntra) {
    Write-Step "Connect to Microsoft Graph"
    Connect-MgGraph -NoWelcome -Scopes @("RoleManagement.ReadWrite.Directory", "Application.ReadWrite.All",
        "DelegatedPermissionGrant.ReadWrite.All", "User.Read.All")
    $testUserId = (Invoke-MgGraphRequest -Method GET -Uri "/v1.0/users/$([uri]::EscapeDataString($TestUser))?`$select=id").id
    Write-OK "Microsoft Graph connected. Test user ID: $testUserId"
}

# -----------------------------------------------------------------------------
# Undo steps (also used by -Cleanup). Each one is safe to run more than once.
# -----------------------------------------------------------------------------

function Undo-InboxRules {
    Get-InboxRule -Mailbox $TestUser | Where-Object {
        $_.Name -like "$Prefix*" -or (("$($_.SubjectContainsWords)") -match "M365ATOTEST")
    } | ForEach-Object {
        Remove-InboxRule -Mailbox $TestUser -Identity $_.Identity -Confirm:$false
        Write-Note "removed inbox rule '$($_.Name)'"
    }
}

function Undo-MailboxForwarding {
    $mbx = Get-Mailbox -Identity $TestUser
    if ($mbx.ForwardingSmtpAddress) {
        if ($ExternalAddress -and "$($mbx.ForwardingSmtpAddress)" -notmatch [regex]::Escape($ExternalAddress)) {
            Write-Note "forwarding to $($mbx.ForwardingSmtpAddress) was not set by this script; left as it is"
            return
        }
        Set-Mailbox -Identity $TestUser -ForwardingSmtpAddress $null -DeliverToMailboxAndForward $false
        Write-Note "removed mailbox forwarding"
    }
}

function Undo-MailFlowRules {
    Get-TransportRule | Where-Object Name -like "$Prefix*" | ForEach-Object {
        Remove-TransportRule -Identity $_.Identity -Confirm:$false
        Write-Note "removed mail flow rule '$($_.Name)'"
    }
}

function Undo-FullAccess {
    if (-not $admin) { return }
    $perm = Get-MailboxPermission -Identity $TestUser -User $admin -ErrorAction SilentlyContinue |
        Where-Object { "$($_.AccessRights)" -match "FullAccess" -and -not $_.IsInherited }
    if ($perm) {
        Remove-MailboxPermission -Identity $TestUser -User $admin -AccessRights FullAccess -Confirm:$false
        Write-Note "removed Full Access for $admin"
    }
}

function Undo-InboxShared {
    $perm = Get-MailboxFolderPermission -Identity "$($TestUser):\Inbox" -User Default -ErrorAction SilentlyContinue
    if ($perm -and "$($perm.AccessRights)" -ne "None") {
        Set-MailboxFolderPermission -Identity "$($TestUser):\Inbox" -User Default -AccessRights None
        Write-Note "set Inbox permission for Default back to None"
    }
}

function Undo-AuditBypass {
    Set-MailboxAuditBypassAssociation -Identity $TestUser -AuditBypassEnabled $false
    Write-Note "audit bypass off"
}

function Undo-ExchangeRole {
    Get-ManagementRoleAssignment -RoleAssignee $TestUser -ErrorAction SilentlyContinue |
        Where-Object Name -like "$Prefix*" | ForEach-Object {
            Remove-ManagementRoleAssignment -Identity $_.Identity -Confirm:$false
            Write-Note "removed Exchange role assignment '$($_.Name)'"
        }
}

function Undo-Entra {
    if (-not $IncludeEntra) { return }
    $role = (Invoke-MgGraphRequest -Method GET -Uri "/v1.0/roleManagement/directory/roleDefinitions?`$filter=displayName eq 'Reports Reader'").value | Select-Object -First 1
    if ($role) {
        $assignments = (Invoke-MgGraphRequest -Method GET -Uri "/v1.0/roleManagement/directory/roleAssignments?`$filter=principalId eq '$testUserId' and roleDefinitionId eq '$($role.id)'").value
        foreach ($a in $assignments) {
            Invoke-MgGraphRequest -Method DELETE -Uri "/v1.0/roleManagement/directory/roleAssignments/$($a.id)" | Out-Null
            Write-Note "removed Reports Reader from $TestUser"
        }
    }
    $apps = (Invoke-MgGraphRequest -Method GET -Uri "/v1.0/applications?`$filter=startswith(displayName,'$Prefix')&`$select=id,appId,displayName").value
    foreach ($app in $apps) {
        $sps = (Invoke-MgGraphRequest -Method GET -Uri "/v1.0/servicePrincipals?`$filter=appId eq '$($app.appId)'&`$select=id").value
        foreach ($sp in $sps) {
            Invoke-MgGraphRequest -Method DELETE -Uri "/v1.0/servicePrincipals/$($sp.id)" | Out-Null
        }
        Invoke-MgGraphRequest -Method DELETE -Uri "/v1.0/applications/$($app.id)" | Out-Null
        Write-Note "deleted app '$($app.displayName)' and its consent"
    }
}

function Invoke-Cleanup {
    Write-Step "Undo"
    foreach ($step in @("Undo-InboxRules", "Undo-MailboxForwarding", "Undo-MailFlowRules", "Undo-FullAccess",
                        "Undo-InboxShared", "Undo-AuditBypass", "Undo-ExchangeRole", "Undo-Entra")) {
        try { & $step } catch { Write-Bad "$step : $($_.Exception.Message)" }
    }
    Write-OK "Undo complete"
}

if ($Cleanup) {
    Invoke-Cleanup
    Disconnect-ExchangeOnline -Confirm:$false
    return
}

# -----------------------------------------------------------------------------
# Tests
# -----------------------------------------------------------------------------

$expected = [ordered]@{
    InboxRuleForward  = "HIGH: Inbox rule - $TestUser (forwards externally)"
    InboxRuleHidden   = "HIGH: Inbox rule - $TestUser (name '.', 'invoice', mark as read, delete)"
    MailboxForwarding = "HIGH: Mailbox forwarding - $TestUser"
    MailFlowRule      = "HIGH: Mail flow rule - $admin (external BCC)"
    MailboxFullAccess = "MEDIUM: Mailbox access - $admin (Full Access)"
    InboxShared       = "MEDIUM: Mailbox access - $admin (Inbox shared with everyone)"
    AuditBypass       = "HIGH: Audit off - $admin"
    ExchangeRole      = "MEDIUM: Admin role - $admin (Exchange role)"
    AttackToolSignIn  = "HIGH: Attack tool sign-in - $TestUser (failed sign-in, user agent AADInternals). In Alerts as alert type off; an email only with Email failed sign-ins on"
    EntraRole         = "MEDIUM: Admin role - $admin (Reports Reader)"
    AppSecret         = "MEDIUM: App credential - $admin"
    OAuthConsent      = "HIGH: OAuth consent - $admin (Mail.Read)"
}

Write-Step "Plan"
Write-Note "Test mailbox:     $TestUser"
Write-Note "External address: $ExternalAddress (no mail is sent to it)"
Write-Note "Tests:            $($Tests -join ', ')"
Write-Note "Undo:             $(if ($KeepMinutes -gt 0) { "after $KeepMinutes minutes" } else { 'at once' })"
if (-not $Force) {
    $answer = Read-Host "Make these changes on $TestUser and then undo them? [y/N]"
    if ($answer -notmatch '^(y|yes)$') { Write-Note "Stopped. No changes made."; return }
}

$results = [ordered]@{}
function Invoke-Test($name, [scriptblock]$action) {
    if ($name -notin $Tests) { return }
    try {
        & $action
        $results[$name] = "done"
        Write-OK $name
    } catch {
        $results[$name] = "FAILED: $($_.Exception.Message)"
        Write-Bad "$name : $($_.Exception.Message)"
    }
}

Write-Step "Make the changes"

Invoke-Test "InboxRuleForward" {
    New-InboxRule -Mailbox $TestUser -Name "$Prefix forward $Marker" -SubjectContainsWords $Marker `
        -ForwardTo $ExternalAddress | Out-Null
}
Invoke-Test "InboxRuleHidden" {
    New-InboxRule -Mailbox $TestUser -Name "." -SubjectContainsWords "invoice $Marker" `
        -MarkAsRead $true -DeleteMessage $true | Out-Null
}
Invoke-Test "MailboxForwarding" {
    Set-Mailbox -Identity $TestUser -ForwardingSmtpAddress "smtp:$ExternalAddress" -DeliverToMailboxAndForward $true
}
Invoke-Test "MailFlowRule" {
    New-TransportRule -Name "$Prefix $Marker" -SubjectContainsWords $Marker -BlindCopyTo $ExternalAddress `
        -Enabled $false | Out-Null
}
Invoke-Test "MailboxFullAccess" {
    Add-MailboxPermission -Identity $TestUser -User $admin -AccessRights FullAccess -AutoMapping $false | Out-Null
}
Invoke-Test "InboxShared" {
    Set-MailboxFolderPermission -Identity "$($TestUser):\Inbox" -User Default -AccessRights Reviewer
}
Invoke-Test "AuditBypass" {
    Set-MailboxAuditBypassAssociation -Identity $TestUser -AuditBypassEnabled $true
}
Invoke-Test "ExchangeRole" {
    New-ManagementRoleAssignment -Name "$Prefix $Marker" -Role "View-Only Recipients" -User $TestUser | Out-Null
}
Invoke-Test "AttackToolSignIn" {
    # One failed password sign-in with an attack tool user agent. The password
    # is random, so the sign-in fails. Azure CLI public client ID.
    $tenantId = (Get-ConnectionInformation | Where-Object State -eq "Connected" | Select-Object -First 1).TenantID
    $form = @{
        grant_type = "password"; client_id = "04b07795-8ddb-461a-bbee-02f9e1bf7b46"
        scope = "https://graph.microsoft.com/.default"; username = $TestUser; password = [guid]::NewGuid().ToString()
    }
    $resp = Invoke-WebRequest -Method Post -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" `
        -Body $form -UserAgent "AADInternals" -SkipHttpErrorCheck
    if ([int]$resp.StatusCode -eq 200) { throw "The sign-in succeeded. Expected a failure." }
}
Invoke-Test "EntraRole" {
    $role = (Invoke-MgGraphRequest -Method GET -Uri "/v1.0/roleManagement/directory/roleDefinitions?`$filter=displayName eq 'Reports Reader'").value | Select-Object -First 1
    if (-not $role) { throw "Role 'Reports Reader' not found." }
    Invoke-MgGraphRequest -Method POST -Uri "/v1.0/roleManagement/directory/roleAssignments" -Body @{
        principalId = $testUserId; roleDefinitionId = $role.id; directoryScopeId = "/" } | Out-Null
}
$script:testApp = $null
function Get-TestApp {
    if (-not $script:testApp) {
        $script:testApp = Invoke-MgGraphRequest -Method POST -Uri "/v1.0/applications" -Body @{ displayName = "$Prefix $Marker" }
    }
    return $script:testApp
}
Invoke-Test "AppSecret" {
    $app = Get-TestApp
    # The response holds the secret. It is not printed or stored.
    Invoke-MgGraphRequest -Method POST -Uri "/v1.0/applications/$($app.id)/addPassword" -Body @{
        passwordCredential = @{ displayName = $Prefix } } | Out-Null
}
Invoke-Test "OAuthConsent" {
    $app = Get-TestApp
    $sp = Invoke-MgGraphRequest -Method POST -Uri "/v1.0/servicePrincipals" -Body @{ appId = $app.appId }
    $graphSp = (Invoke-MgGraphRequest -Method GET -Uri "/v1.0/servicePrincipals?`$filter=appId eq '$GraphAppId'&`$select=id").value | Select-Object -First 1
    Invoke-MgGraphRequest -Method POST -Uri "/v1.0/oauth2PermissionGrants" -Body @{
        clientId = $sp.id; consentType = "Principal"; principalId = $testUserId
        resourceId = $graphSp.id; scope = "Mail.Read" } | Out-Null
}

if ($KeepMinutes -gt 0) {
    Write-Step "Wait $KeepMinutes minutes before the undo step"
    Start-Sleep -Seconds ($KeepMinutes * 60)
}

Invoke-Cleanup

# -----------------------------------------------------------------------------
# Expected alerts
# -----------------------------------------------------------------------------

Write-Step "Expected alerts (1-2 hours from now, subject starts with [M365 Alert])"
foreach ($name in $results.Keys) {
    if ($results[$name] -eq "done") { Write-Note ("{0,-18} {1}" -f $name, $expected[$name]) }
    else { Write-Bad ("{0,-18} {1}" -f $name, $results[$name]) }
}

Write-Step "Tests you do by hand (they need the test user's sign-in)"
Write-Note "Device code sign-in:  az login --use-device-code --allow-no-subscriptions  (sign in as $TestUser)"
Write-Note "MFA method added:     as $TestUser, add a second method at https://mysignins.microsoft.com/security-info"
Write-Note "Outlook desktop rule: in Outlook desktop as $TestUser, create a rule that forwards to $ExternalAddress"
Write-Note "VPN or new country:   sign in as $TestUser through a VPN exit in another country"
Write-Note ""
Write-Note "If an alert does not arrive within 3 hours: run ./install.ps1 -Verify, then the Errors query in"
Write-Note "docs/APP_INSIGHTS_QUERIES.md, then search Microsoft Purview > Audit for the change."

Disconnect-ExchangeOnline -Confirm:$false
if ($IncludeEntra) { Disconnect-MgGraph | Out-Null }
