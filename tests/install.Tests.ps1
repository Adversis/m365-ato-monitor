# Pester 5 tests for install.ps1. A fake "az" function stands in for the Azure
# CLI: it simulates an empty subscription, records every call, and keeps the
# objects that the script creates. No network access, no Azure account.
#   pwsh -c "Invoke-Pester -Path tests/install.Tests.ps1 -Output Detailed"

BeforeAll {
    . (Join-Path $PSScriptRoot '..' 'install.ps1')
    $ErrorActionPreference = 'Stop'
    # The saved installations go to a temporary folder, not to ~/.m365-ato-monitor.
    $env:M365_ATO_MONITOR_HOME = Join-Path ([System.IO.Path]::GetTempPath()) "m365atomon-tests-$([guid]::NewGuid().ToString('N'))"
    $global:FabrikamId = '22222222-2222-4222-8222-222222222222'

    function New-FakeAzure {
        $global:Fake = [ordered]@{
            Calls = [System.Collections.Generic.List[object]]::new()
            Created = @{}
            AppCount = 0
            RoleCreates = 0
        }
    }

    function global:az {
        # install.ps1 turns on strict mode; the fake reads missing hashtable keys on purpose.
        Set-StrictMode -Off
        $ErrorActionPreference = 'Continue'
        $a = @($args | ForEach-Object { "$_" })
        $line = $a -join ' '
        $body = $null
        $i = [array]::IndexOf($a, '--body')
        if ($i -ge 0 -and $a[$i + 1].StartsWith('@')) { $body = Get-Content -Raw -LiteralPath $a[$i + 1].Substring(1) | ConvertFrom-Json -Depth 50 }
        $global:Fake.Calls.Add([pscustomobject]@{ Args = $a; Line = $line; Body = $body })
        $global:LASTEXITCODE = 0
        $c = $global:Fake.Created
        function NotFound { $global:LASTEXITCODE = 3; Write-Error 'ERROR: (ResourceNotFound) The resource was not found.' }
        function Fail([string]$Text) { $global:LASTEXITCODE = 1; Write-Error $Text }
        function Out([object]$o) { $o | ConvertTo-Json -Depth 20 -Compress }
        # The values after an option, up to the next option (Invoke-Az adds --only-show-errors).
        function Values([string]$Option) {
            $k = [array]::IndexOf($a, $Option)
            if ($k -lt 0) { return @() }
            @($a[($k + 1)..($a.Count - 1)] | ForEach-Object -Begin { $stop = $false } -Process {
                if ($stop -or $_ -like '--*') { $stop = $true } else { $_ } })
        }
        function Value([string]$Option) { @(Values $Option)[0] }
        foreach ($k in 'fics', 'assignments', 'grants', 'roles') { if ($null -eq $c[$k]) { $c[$k] = [System.Collections.Generic.List[object]]::new() } }
        # Two tenants. The CLI starts signed in to Contoso (tenant-1); "az login --tenant tenant-2" adds Fabrikam.
        if ($null -eq $c['accounts']) {
            $c.accounts = [System.Collections.Generic.List[object]]::new()
            if (-not $c.signedOut) { $c.accounts.Add(@{ id = 'sub-1'; name = 'Test subscription'; tenantId = 'tenant-1'; state = 'Enabled'; isDefault = $true }) }
        }
        $tenants = @{
            'tenant-1' = @{ name = 'Contoso'; domains = @('contoso.com', 'contoso.onmicrosoft.com')
                            subs = @(@{ id = 'sub-1'; name = 'Test subscription'; tenantId = 'tenant-1'; state = 'Enabled' }) }
            '22222222-2222-4222-8222-222222222222' = @{ name = 'Fabrikam'; domains = @('fabrikam.com', 'fabrikam.onmicrosoft.com')
                            subs = @(@{ id = 'sub-2'; name = 'Fabrikam subscription'; tenantId = '22222222-2222-4222-8222-222222222222'; state = 'Enabled' }) + @($c.extraFabrikamSubs | Where-Object { $_ }) }
        }
        $default = @($c.accounts | Where-Object { $_.isDefault }) | Select-Object -First 1
        function Use-Sub([string]$Id) { foreach ($x in $c.accounts) { $x.isDefault = ($x.id -eq $Id) } }

        $graphSp = @{ id = 'graph-sp'; appId = '00000003-0000-0000-c000-000000000000'
            appRoles = @('Mail.Send', 'User.ReadBasic.All', 'MailboxSettings.Read', 'MailboxSettings.ReadWrite',
                         'User.RevokeSessions.All', 'User.EnableDisableAccount.All', 'User.Read.All',
                         'AuditLogsQuery.Read.All', 'RoleManagement.Read.Directory', 'Application.Read.All') | ForEach-Object {
                @{ id = "role-$_"; value = $_; allowedMemberTypes = @('Application') } }
            oauth2PermissionScopes = @(@{ id = 'scope-user-read'; value = 'User.Read' }) }
        $o365Sp = @{ id = 'o365-sp'; appId = 'c5393580-f805-4401-95e8-94b7a6ef2fc2'
            appRoles = @(@{ id = 'role-ActivityFeed.Read'; value = 'ActivityFeed.Read'; allowedMemberTypes = @('Application') }) }

        switch -Regex ($line) {
            '^version' { return Out @{ 'azure-cli' = '2.70.0' } }
            '^login' {
                $c.loggedIn = $true
                $t = Value '--tenant'
                $t = if (-not $t) { 'tenant-1' } elseif ($t -match 'fabrikam') { '22222222-2222-4222-8222-222222222222' } elseif ($t -match 'contoso') { 'tenant-1' } else { $t }
                $c.loginTenants = @($c.loginTenants) + $t
                foreach ($sub in @($tenants[$t].subs)) {
                    if (-not ($c.accounts | Where-Object { $_.id -eq $sub.id })) { $c.accounts.Add(@{} + $sub + @{ isDefault = $false }) }
                }
                Use-Sub @($tenants[$t].subs)[0].id
                return
            }
            '^account show' {
                if (-not $default) { return Fail "ERROR: Please run 'az login' to setup account." }
                return Out @{ tenantId = $default.tenantId; id = $default.id; name = $default.name }
            }
            '^account list' { return Out @($c.accounts) }
            '^account set' {
                $want = Value '--subscription'
                if (-not ($c.accounts | Where-Object { $_.id -eq $want })) { return Fail "ERROR: The subscription of '$want' doesn't exist in cloud 'AzureCloud'." }
                Use-Sub $want
                return
            }
            '^provider show' {
                if ($c.webUnregistered -and (Value '--namespace') -eq 'Microsoft.Web') { return Out 'NotRegistered' }
                return Out 'Registered'
            }
            '^provider register' { if ((Value '--namespace') -eq 'Microsoft.Web') { $c.webUnregistered = $false }; return }
            '^functionapp list-flexconsumption-locations' {
                if ($c.webUnregistered) { return Fail "ERROR: (MissingSubscriptionRegistration) The subscription is not registered to use namespace 'Microsoft.Web'." }
                return Out @('eastus', 'westeurope')
            }
            '^group show' { if ($c.rg) { return Out @{ location = 'eastus' } } else { return NotFound } }
            '^group create' { $c.rg = $true; return Out @{} }
            '^group delete' { return }
            '^identity show' { if ($c.uami) { return Out $c.uami } else { return NotFound } }
            '^identity create' {
                $principal = if ($c.uamiPrincipal) { $c.uamiPrincipal } else { 'uami-principal' }
                $c.uami = @{ id = '/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/id'; clientId = 'uami-client'; principalId = $principal }
                return Out $c.uami
            }
            '^storage account show .*--query allowSharedKeyAccess' { return Out ([bool]$c.sharedKey) }
            '^storage account show' { if ($c.st) { return Out @{} } else { return NotFound } }
            '^storage account create' { $c.st = $true; $c.sharedKey = $line -match '--allow-shared-key-access true'; return Out @{} }
            '^storage account update' { $c.sharedKey = $line -match '--allow-shared-key-access true'; return Out @{} }
            '^role assignment list' {
                $want = if ((Value '--query') -match "principalId=='([^']+)'") { $Matches[1] } else { '' }
                return Out @($c.roles | Where-Object { $_.scope -eq (Value '--scope') -and $_.role -eq (Value '--role') -and $_.principalId -eq $want } |
                    ForEach-Object { $_.id })
            }
            '^role assignment create' {
                $global:Fake.RoleCreates++
                if ($c.roleError -and $global:Fake.RoleCreates -le $c.roleErrorTimes) { return Fail $c.roleError }
                $c.roles.Add(@{ id = "ra-$($c.roles.Count)"; scope = (Value '--scope'); role = (Value '--role'); principalId = (Value '--assignee-object-id') })
                return Out @{}
            }
            '^monitor log-analytics workspace show' { if ($c.ws) { return Out @{ id = '/subscriptions/sub-1/ws' } } else { return NotFound } }
            '^monitor log-analytics workspace create' { $c.ws = $true; return Out @{ id = '/subscriptions/sub-1/ws' } }
            '^functionapp create' {
                # Like az: the container that --deployment-storage-container-name names must exist.
                if (-not $c.container) { return Fail 'ERROR: (ContainerNotFound) The specified container does not exist.' }
                $c.func = $true
                $c.settings = [ordered]@{ AzureWebJobsStorage = 'DefaultEndpointsProtocol=x' }
                return Out @{}
            }
            '^functionapp start' { return Out @{} }
            '^functionapp config appsettings set' {
                foreach ($kv in (Values '--settings')) { $k, $v = $kv -split '=', 2; $c.settings[$k] = $v }
                return Out @()
            }
            '^functionapp config appsettings list .*--query \[\]\.name' { return Out @($c.settings.Keys) }
            '^functionapp config appsettings list' { return Out @($c.settings.GetEnumerator() | ForEach-Object { @{ name = $_.Key; value = $_.Value } }) }
            '^functionapp config appsettings delete' { foreach ($k in (Values '--setting-names')) { $c.settings.Remove($k) }; return Out @() }
            '^functionapp deployment source config-zip' { if ($c.zipError) { return Fail $c.zipError }; return Out @{} }
            '^functionapp keys list .*--query functionKeys\.default' { return Out 'fkey' }
            '^ad app delete' { return }
            '^rest' {
                $m = Value '--method'
                $u = Value '--url'
                $f = @($a | Where-Object { $_ -like '$filter=*' })[0]
                if ($u -match '/me$') {
                    # Like az after 90 days without use: account show works, a token request fails.
                    if ($c.signinExpired -and -not $c.loggedIn) {
                        return Fail ('ERROR: AADSTS700082: The refresh token has expired due to inactivity. Run the command ' +
                                     'below to authenticate interactively: az logout az login --tenant "tenant-1"')
                    }
                    return Out @{ id = 'me-id'; userPrincipalName = 'admin@contoso.com' }
                }
                if ($u -match '/organization$') {
                    $t = $tenants[$default.tenantId]
                    return Out @{ value = @(@{ displayName = $t.name
                        verifiedDomains = @($t.domains | ForEach-Object { @{ name = $_; isDefault = ($_ -notlike '*.onmicrosoft.com'); isInitial = ($_ -like '*.onmicrosoft.com') } }) }) }
                }
                if ($u -match '/users$' -and $m -eq 'GET') {
                    $mail = if ($f -match "mail eq '([^']+)'") { $Matches[1] } else { '' }
                    $domainOk = $tenants[$default.tenantId].domains -contains ($mail -split '@')[-1]
                    if ($domainOk -and $mail -notlike 'nobody@*') { return Out @{ value = @(@{ id = 'u-1'; mail = $mail; userPrincipalName = $mail }) } }
                    return Out @{ value = @() }
                }
                if ($u -match '/servicePrincipals$' -and $m -eq 'GET') {
                    if ($f -match "appId eq '00000003") { return Out @{ value = @($graphSp) } }
                    if ($f -match "appId eq 'c5393580") { return Out @{ value = @($o365Sp) } }
                    if ($f -match "appId eq '(app-\d)'" -and $c[$Matches[1]]) {
                        return Out @{ value = @(@{ id = "sp-$($Matches[1])"; appRoleAssignmentRequired = $c[$Matches[1]] -eq 'req'
                                                    tags = @('WindowsAzureActiveDirectoryIntegratedApp', 'm365-ato-monitor') }) }
                    }
                    return Out @{ value = @() }
                }
                if ($u -match '/servicePrincipals$' -and $m -eq 'POST') { $c[$body.appId] = $(if ($body.appRoleAssignmentRequired) { 'req' } else { 'opt' }); return Out @{ id = "sp-$($body.appId)" } }
                if ($u -match '/applications$' -and $m -eq 'GET') {
                    $want = if ($f -match "displayName eq '([^']+)'") { $Matches[1] } else { '' }
                    return Out @{ value = @(@($c.apps) | Where-Object { $_ -and $_.displayName -eq $want }) }
                }
                if ($u -match '/applications$' -and $m -eq 'POST') { $global:Fake.AppCount++; $n = $global:Fake.AppCount; $app = @{ id = "obj-$n"; appId = "app-$n"; displayName = $body.displayName; tags = $body.tags }; $c.apps = @($c.apps) + $app; return Out $app }
                if ($u -match '/applications/([^/]+)/federatedIdentityCredentials$') {
                    $obj = $Matches[1]
                    if ($m -eq 'GET') { return Out @{ value = @($c.fics | Where-Object { $_.app -eq $obj }) } }
                    $c.fics.Add(@{ id = "fic-$($c.fics.Count)"; app = $obj; name = $body.name; subject = $body.subject; issuer = $body.issuer })
                    return Out @{}
                }
                if ($u -match '/federatedIdentityCredentials/([^/]+)$' -and $m -eq 'PATCH') {
                    $id = $Matches[1]
                    foreach ($x in $c.fics) { if ($x.id -eq $id) { $x.subject = $body.subject; $x.issuer = $body.issuer } }
                    return Out @{}
                }
                if ($m -eq 'GET' -and $u -match '/applications/obj-\d$') { return Out @{ passwordCredentials = @() } }
                if ($u -match '/servicePrincipals/([^/]+)/appRoleAssignedTo$') {
                    $res = $Matches[1]
                    if ($m -eq 'GET') { return Out @{ value = @($c.assignments | Where-Object { $_.resourceId -eq $res }) } }
                    $c.assignments.Add(@{ id = "asg-$($c.assignments.Count)"; principalId = $body.principalId; resourceId = $body.resourceId; appRoleId = $body.appRoleId })
                    return Out @{}
                }
                if ($m -eq 'DELETE' -and $u -match '/servicePrincipals/[^/]+/appRoleAssignments/([^/]+)$') {
                    $gone = $Matches[1]
                    foreach ($x in @($c.assignments | Where-Object { $_.id -eq $gone })) { [void]$c.assignments.Remove($x) }
                    return Out @{}
                }
                if ($m -eq 'GET' -and $u -match '/servicePrincipals/([^/]+)/appRoleAssignments$') {
                    $sp = $Matches[1]
                    return Out @{ value = @($c.assignments | Where-Object { $_.principalId -eq $sp }) }
                }
                if ($u -match '/oauth2PermissionGrants$') {
                    if ($m -eq 'GET') {
                        $client = if ($f -match "clientId eq '([^']+)'") { $Matches[1] } else { '' }
                        return Out @{ value = @($c.grants | Where-Object { $_.clientId -eq $client }) }
                    }
                    $c.grants.Add(@{ clientId = $body.clientId; resourceId = $body.resourceId; consentType = $body.consentType })
                    return Out @{}
                }
                if ($u -match '/blobServices/default/containers/deployments$') {
                    if ($m -eq 'PUT') { $c.container = $true; return Out @{} }
                    if ($c.container) { return Out @{ name = 'deployments' } } else { return NotFound }
                }
                if ($u -match '/providers/Microsoft\.Web/sites/[^/]+$' -and $m -eq 'GET') {
                    # The raw ARM object, like az functionapp show for a Flex app.
                    if ($c.func) { return Out @{ properties = @{ defaultHostName = 'func-test.azurewebsites.net'; state = 'Running' } } }
                    return NotFound
                }
                if ($u -match '/components/[^/]+$') {
                    if ($m -eq 'PUT') { $c.ai = $true; if ($body.properties.DisableLocalAuth) { $c.aiEntraOnly = $true } }
                    $props = @{ ConnectionString = 'InstrumentationKey=k'; AppId = 'ai-app'; Application_Type = 'web'; WorkspaceResourceId = '/subscriptions/sub-1/ws' }
                    if ($c.aiEntraOnly) { $props.DisableLocalAuth = $true }
                    $ai = @{ id = '/subscriptions/sub-1/resourceGroups/rg/providers/Microsoft.Insights/components/appi'; location = 'eastus'; properties = $props }
                    if ($c.ai) { return Out $ai } else { return NotFound }
                }
                if ($u -match '/actionGroups/[^/]+$') {
                    if ($m -eq 'PUT') { $c.ag = $body; return Out @{} }
                    if ($c.ag) { return Out $c.ag } else { return NotFound }
                }
                # Resources that install.ps1 writes only when they differ (Set-ArmResource): keep what was written.
                if ($u -match '/(scheduledQueryRules|activityLogAlerts|diagnosticSettings|dataCollectionRules|basicPublishingCredentialsPolicies)/[^/]+$|/config/authsettingsV2$|/ws$') {
                    if ($null -eq $c['arm']) { $c.arm = @{} }
                    $key = $u.ToLowerInvariant()
                    if ($m -in 'PUT', 'PATCH') { $c.arm[$key] = $body; return Out $body }
                    if ($c.arm.ContainsKey($key)) { return Out $c.arm[$key] }
                    if ($u -match 'basicPublishingCredentialsPolicies') { return Out @{ properties = @{ allow = $true } } }   # the Azure default
                    if ($u -match '/ws$') { return Out @{ properties = @{} } }
                    return NotFound
                }
                if ($u -match '/config/web$') {
                    if ($m -eq 'PATCH') { $c.cors = @($body.properties.cors.allowedOrigins); return Out @{} }
                    return Out @{ properties = @{ cors = @{ allowedOrigins = @($c.cors | Where-Object { $_ }) } } }
                }
                if ($m -eq 'GET' -and $u -match 'management\.azure\.com') { return NotFound }
                if ($m -in 'POST', 'PUT', 'PATCH', 'DELETE') { return Out @{} }
                return Out @{ value = @() }
            }
            default { throw "fake az: no rule for: $line" }
        }
    }

    function Get-Calls([string]$Pattern) { @($global:Fake.Calls | Where-Object { $_.Line -match $Pattern }) }

    # A fake Exchange Online PowerShell: the cmdlets that install.ps1 uses for -MailSendScope mailbox.
    # Assignments: name -> service principal. Test-ServicePrincipalAuthorization is in scope only for an
    # assignment of that service principal and a member of the group.
    function New-FakeExchange([bool]$InScope = $true, [bool]$OldObjects = $false, [string]$OldAppAssignment = '') {
        $global:Exo = [ordered]@{ Calls = [System.Collections.Generic.List[string]]::new(); Group = $null
            Members = @(); Sp = $false; Scope = $null; Assignments = @{}; InScope = $InScope; OldScope = $OldObjects
            TenantId = 'tenant-1'; NoMailbox = @() }
        if ($OldObjects) { $global:Exo.Assignments['M365 ATO Monitor Mail.Send'] = 'sp-old' }
        if ($OldAppAssignment) { $global:Exo.Assignments[$OldAppAssignment] = 'sp-deleted-app' }
    }
    function global:Connect-ExchangeOnline { [CmdletBinding()] param([switch]$ShowBanner, [string]$UserPrincipalName, [switch]$Device)
        $global:Exo.Calls.Add("Connect-ExchangeOnline device=$Device $UserPrincipalName".TrimEnd()) }
    function global:Disconnect-ExchangeOnline { [CmdletBinding(SupportsShouldProcess)] param() $global:Exo.Calls.Add('Disconnect-ExchangeOnline') }
    function global:Get-ConnectionInformation { [CmdletBinding()] param() [pscustomobject]@{ TenantID = $global:Exo.TenantId } }
    function global:Get-Recipient { [CmdletBinding()] param([string]$Identity)
        if ($Identity -notin $global:Exo.NoMailbox) { [pscustomobject]@{ PrimarySmtpAddress = $Identity } } }
    function global:Get-DistributionGroup { [CmdletBinding()] param([string]$Identity) $global:Exo.Group }
    function global:New-DistributionGroup { [CmdletBinding()] param($Name, $Alias, $Type, $Members, $MemberJoinRestriction, $MemberDepartRestriction, $Notes)
        $global:Exo.Calls.Add("New-DistributionGroup $Name $Type")
        $global:Exo.Group = [pscustomobject]@{ Name = $Name; HiddenFromAddressListsEnabled = $false
            DistinguishedName = "CN=$Name,OU=contoso.onmicrosoft.com,DC=prod,DC=outlook,DC=com" }
        $global:Exo.Members = @($Members)
        $global:Exo.Group }
    function global:Set-DistributionGroup { [CmdletBinding()] param($Identity, $HiddenFromAddressListsEnabled)
        $global:Exo.Calls.Add("Set-DistributionGroup $Identity hidden=$HiddenFromAddressListsEnabled")
        $global:Exo.Group.HiddenFromAddressListsEnabled = $HiddenFromAddressListsEnabled }
    function global:Get-DistributionGroupMember { [CmdletBinding()] param($Identity, $ResultSize)
        $global:Exo.Members | ForEach-Object { [pscustomobject]@{ PrimarySmtpAddress = $_ } } }
    function global:Add-DistributionGroupMember { [CmdletBinding()] param($Identity, $Member, [switch]$BypassSecurityGroupManagerCheck)
        $global:Exo.Calls.Add("Add-DistributionGroupMember $Member"); $global:Exo.Members += $Member }
    function global:Get-ServicePrincipal { [CmdletBinding()] param($Identity) if ($global:Exo.Sp) { [pscustomobject]@{ Identity = $Identity } } }
    function global:New-ServicePrincipal { [CmdletBinding()] param($AppId, $ObjectId, $DisplayName)
        $global:Exo.Calls.Add("New-ServicePrincipal $AppId $ObjectId"); $global:Exo.Sp = $true }
    function global:Get-ManagementScope { [CmdletBinding()] param($Identity)
        if ($Identity -eq 'M365 ATO Monitor alert mailbox') { if ($global:Exo.OldScope) { [pscustomobject]@{ RecipientFilter = "PrimarySmtpAddress -eq 'old@contoso.com'" } } }
        elseif ($global:Exo.Scope) { [pscustomobject]@{ RecipientFilter = $global:Exo.Scope } } }
    function global:New-ManagementScope { [CmdletBinding()] param($Name, $RecipientRestrictionFilter)
        $global:Exo.Calls.Add("New-ManagementScope $Name | $RecipientRestrictionFilter"); $global:Exo.Scope = $RecipientRestrictionFilter }
    function global:Set-ManagementScope { [CmdletBinding()] param($Identity, $RecipientRestrictionFilter)
        $global:Exo.Calls.Add("Set-ManagementScope $Identity"); $global:Exo.Scope = $RecipientRestrictionFilter }
    function global:Get-ManagementRoleAssignment { [CmdletBinding()] param($Identity, $Role)
        foreach ($k in @($global:Exo.Assignments.Keys)) {
            if ((-not $Identity -or $k -eq $Identity) -and $global:Exo.Assignments[$k]) {
                [pscustomobject]@{ Name = $k; App = $global:Exo.Assignments[$k] } } } }
    function global:New-ManagementRoleAssignment { [CmdletBinding()] param($Name, $App, $Role, $CustomResourceScope)
        $global:Exo.Calls.Add("New-ManagementRoleAssignment $Name | $App | $Role | $CustomResourceScope"); $global:Exo.Assignments[$Name] = $App }
    function global:Remove-ManagementRoleAssignment { [CmdletBinding(SupportsShouldProcess)] param($Identity)
        $global:Exo.Calls.Add("Remove-ManagementRoleAssignment $Identity"); $global:Exo.Assignments.Remove($Identity) }
    function global:Remove-ManagementScope { [CmdletBinding(SupportsShouldProcess)] param($Identity)
        $global:Exo.Calls.Add("Remove-ManagementScope $Identity"); $global:Exo.OldScope = $false }
    function global:Test-ServicePrincipalAuthorization { [CmdletBinding()] param($Identity, $Resource)
        $assigned = @($global:Exo.Assignments.Values) -contains $Identity
        $member = @($global:Exo.Members) -contains $Resource
        [pscustomobject]@{ RoleName = 'Application Mail.Send'; InScope = ($global:Exo.InScope -and $assigned -and $member) } }
    function Get-ExoCalls([string]$Pattern) { @($global:Exo.Calls | Where-Object { $_ -match $Pattern }) }
    function Get-GraphRoles([string]$SpId) {
        @($global:Fake.Created.assignments | Where-Object { $_.principalId -eq $SpId -and $_.resourceId -eq 'graph-sp' } |
            ForEach-Object { $_.appRoleId -replace '^role-', '' })
    }
}

Describe 'Get-Names' {
    It 'is stable and valid for Azure' {
        $a = Get-Names 'sub-1' 'm365-ato-monitor'
        $b = Get-Names 'sub-1' 'm365-ato-monitor'
        $a.Storage | Should -Be $b.Storage
        $a.Storage | Should -Match '^[a-z0-9]{3,24}$'
        $a.FunctionApp | Should -Match '^func-m365-ato-monitor-[0-9a-f]{6}$'
        (Get-Names 'sub-2' 'm365-ato-monitor').Storage | Should -Not -Be $a.Storage
    }
}

Describe 'Invoke-Rest' {
    It 'refuses a URL with an ampersand (it breaks az.cmd on Windows)' {
        { Invoke-Rest -Method GET -Url 'https://graph.microsoft.com/v1.0/x?a=1&b=2' } | Should -Throw '*-Query*'
    }
}

Describe 'New-CodePackage' {
    It 'packs the function code without local settings or caches' {
        $zip = New-CodePackage
        try {
            Add-Type -AssemblyName System.IO.Compression.FileSystem
            $names = [System.IO.Compression.ZipFile]::OpenRead($zip).Entries.FullName
            $names | Should -Contain 'function_app.py'
            $names | Should -Contain 'host.json'
            $names | Should -Contain 'requirements.txt'
            $names | Should -Contain 'ui/app.js'
            ($names | Where-Object { $_ -match '__pycache__|local\.settings\.json$|\.pyc$' }) | Should -BeNullOrEmpty
        }
        finally { Remove-Item $zip -ErrorAction SilentlyContinue }
    }
}

Describe 'Help' {
    It 'lists every option of the script' {
        $common = [System.Management.Automation.PSCmdlet]::CommonParameters + [System.Management.Automation.PSCmdlet]::OptionalCommonParameters
        $names = (Get-Command (Join-Path $PSScriptRoot '..' 'install.ps1')).Parameters.Keys | Where-Object { $_ -notin $common -and $_ -ne 'Rest' }
        $text = Show-Usage
        foreach ($n in $names) { $text | Should -Match "-$n\b" -Because "-$n must be in the usage text" }
    }
    It 'shows the usage for -Help, --help, and an unknown option' {
        $script = Join-Path $PSScriptRoot '..' 'install.ps1'
        $out = pwsh -NoProfile -Command "& '$script' --help" 2>&1 | Out-String
        $LASTEXITCODE | Should -Be 0
        $out | Should -Match 'Install, or repair'
        $out = pwsh -NoProfile -Command "& '$script' -AdminEmial x@contoso.com" 2>&1 | Out-String
        $LASTEXITCODE | Should -Be 1
        $out | Should -Match 'Unknown option or value: -AdminEmial x@contoso.com'
    }
}

Describe 'INSTALL_GRANTS' {
    It 'keeps the 2 newest earlier entries of the last 7 days' {
        $script:MeUpn = 'admin@contoso.com'
        $recent = (Get-Date).ToUniversalTime().AddDays(-1).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $old = (Get-Date).ToUniversalTime().AddDays(-9).ToString('yyyy-MM-ddTHH:mm:ssZ')
        $prev = "$recent;a@contoso.com;Mail.Send/$old;b@contoso.com;Mail.Send/$recent;c@contoso.com;X/$recent;d@contoso.com;Y"
        $v = New-InstallGrantsSetting $prev @('Mail.Send', 'User.Read.All')
        $parts = $v -split '/'
        $parts.Count | Should -Be 3
        $parts[0] | Should -Match ';admin@contoso\.com;Mail\.Send,User\.Read\.All$'
        $v | Should -Not -Match 'b@contoso'
        $v | Should -Match 'a@contoso.*c@contoso'
        New-InstallGrantsSetting '' @('Mail.Send') | Should -Not -Match '/'
    }
}

Describe '-MailSendScope takes a word, not an address' {
    It 'names -AdminEmail when an address is given' {
        Mock Write-Host {}
        $MailSendScope = 'root@contoso.onmicrosoft.com'
        { Test-MailSendScope } | Should -Throw '*not an address. Give the alert mailbox with -AdminEmail*'
        Should -Invoke Write-Host -ParameterFilter { "$Object" -eq 'Fix:   ./install.ps1 -MailSendScope mailbox -AdminEmail root@contoso.onmicrosoft.com' }
    }
    It 'refuses another word and accepts mailbox and tenant in any case' {
        Mock Write-Host {}
        $MailSendScope = 'group'
        { Test-MailSendScope } | Should -Throw "*takes the word 'mailbox'*"
        foreach ($ok in 'mailbox', 'tenant', 'Mailbox') { $MailSendScope = $ok; { Test-MailSendScope } | Should -Not -Throw }
    }
}

Describe 'Install on an empty subscription' {
    BeforeAll {
        New-FakeAzure
        Mock Start-Sleep {}
        Mock Read-Host { 'y' }
        Mock Invoke-WebRequest { [pscustomobject]@{ StatusCode = 200; Content = '{"status":"healthy","checks":{"azure_ad_token":"ok"}}' } }
        $DryRun = $false; $Yes = $true; $Update = $false
        $AdminEmail = 'security@contoso.com'; $Location = 'eastus'; $Name = 'm365-ato-monitor'
        $ResponsePermissions = 'yes'; $MailSendScope = 'tenant'; $UiAdmins = @(); $SubscriptionId = ''
        Install-Monitor
    }

    It 'passes no short option and no cmd.exe special character to az (PowerShell binding, Windows az.cmd)' {
        foreach ($call in $global:Fake.Calls) {
            $call.Args | Where-Object { $_ -match '^-[A-Za-z]$' } | Should -BeNullOrEmpty -Because $call.Line
            $call.Args | Where-Object { $_ -notmatch '\s' -and $_ -match '[()&|<>^]' } | Should -BeNullOrEmpty -Because $call.Line
        }
    }

    It 'creates the deployment container before the Function App' {
        $order = [string[]]@($global:Fake.Calls.Line)
        $container = [array]::FindIndex($order, [Predicate[string]]{ param($l) $l -match '^rest --method PUT .*containers/deployments' })
        $create = [array]::FindIndex($order, [Predicate[string]]{ param($l) $l -match '^functionapp create' })
        $container | Should -BeGreaterOrEqual 0
        $create | Should -BeGreaterThan $container
    }

    It 'lists role assignments without --assignee (no Graph lookup of a new principal)' {
        $calls = @(Get-Calls '^role assignment list')
        $calls.Count | Should -BeGreaterThan 3
        foreach ($call in $calls) {
            $call.Args | Should -Not -Contain '--assignee'
            $call.Line | Should -Match "--query \[\?principalId=='[^']+'\]\.id"
        }
    }

    It 'tags the service principals for the Enterprise applications list' {
        $calls = @(Get-Calls '^rest --method POST --url \S+/servicePrincipals ')
        $calls.Count | Should -Be 2
        foreach ($call in $calls) {
            $call.Body.tags | Should -Contain 'WindowsAzureActiveDirectoryIntegratedApp'
        }
    }

    It 'turns shared keys off after the app uses the managed identity' {
        $st = Get-Calls '^storage account create'
        $st.Count | Should -Be 1
        $st[0].Line | Should -Match '--allow-blob-public-access false'
        $order = [string[]]@($global:Fake.Calls.Line)
        $off = [array]::FindLastIndex($order, [Predicate[string]]{ param($l) $l -match '^storage account update .*--allow-shared-key-access false' })
        $settings = [array]::FindIndex($order, [Predicate[string]]{ param($l) $l -match '^functionapp config appsettings set' })
        $create = [array]::FindIndex($order, [Predicate[string]]{ param($l) $l -match '^functionapp create' })
        $off | Should -BeGreaterThan $settings
        $settings | Should -BeGreaterThan $create
    }

    It 'gives the managed identity data roles on the storage account' {
        $roles = (Get-Calls '^role assignment create .*uami-principal').Line
        $roles -join "`n" | Should -Match 'Storage Blob Data Owner'
        $roles -join "`n" | Should -Match 'Storage Table Data Contributor'
        $roles -join "`n" | Should -Not -Match 'Queue'
    }

    It 'creates a Flex Consumption Python 3.12 app with the identity for deployment storage' {
        $f = Get-Calls '^functionapp create'
        $f.Count | Should -Be 1
        $f[0].Line | Should -Match '--flexconsumption-location eastus'
        $f[0].Line | Should -Match '--runtime python --runtime-version 3.12'
        $f[0].Line | Should -Match '--deployment-storage-auth-type UserAssignedIdentity'
    }

    It 'adds the managed identity as the only credential of the monitor app' {
        $fic = Get-Calls '^rest --method POST .*federatedIdentityCredentials'
        $fic.Count | Should -Be 1
        $fic[0].Body.subject | Should -Be 'uami-principal'
        $fic[0].Body.audiences | Should -Be @('api://AzureADTokenExchange')
        $fic[0].Body.issuer | Should -Be 'https://login.microsoftonline.com/tenant-1/v2.0'
        Get-Calls 'addPassword|credential reset' | Should -BeNullOrEmpty
    }

    It 'grants admin consent for each permission' {
        $grants = Get-Calls '^rest --method POST .*appRoleAssignedTo' | Where-Object { $_.Body.appRoleId -like 'role-*' }
        $roles = $grants.Body.appRoleId | ForEach-Object { $_ -replace '^role-', '' } | Sort-Object
        $roles | Should -Be (@('ActivityFeed.Read', 'Application.Read.All', 'AuditLogsQuery.Read.All', 'Mail.Send', 'MailboxSettings.ReadWrite',
                              'RoleManagement.Read.Directory', 'User.EnableDisableAccount.All', 'User.Read.All',
                              'User.ReadBasic.All', 'User.RevokeSessions.All') | Sort-Object)
    }

    It 'gives you the Monitor.Admin role; the function, not assignment, decides UI access' {
        $admin = Get-Calls '^rest --method POST .*appRoleAssignedTo' | Where-Object { $_.Body.appRoleId -eq '6c5d6f3e-2b1a-4c8e-9a7d-3f2e1b0c9d8a' }
        $admin.Body.principalId | Should -Be 'me-id'
        $created = Get-Calls '^rest --method POST --url \S+/servicePrincipals '
        @($created).Count | Should -Be 2
        @($created | Where-Object { $_.Body.appRoleAssignmentRequired }).Count | Should -Be 0
    }

    It 'allows the management UI origin in CORS (POST from the UI got HTTP 403 without it)' {
        $patch = @(Get-Calls '^rest --method PATCH --url \S+/config/web ')
        $patch.Count | Should -Be 1
        $patch[0].Body.properties.cors.allowedOrigins | Should -Contain 'https://func-test.azurewebsites.net'
    }

    It 'gives the function the service principal ID of the monitor app' {
        (Get-Calls '^functionapp config appsettings set')[0].Line | Should -Match 'MONITOR_SP_ID=sp-app-1'
    }

    It 'sets keyless app settings and removes the key-based connection string' {
        $set = (Get-Calls '^functionapp config appsettings set')[0].Line
        $set | Should -Match 'MANAGED_IDENTITY_CLIENT_ID=uami-client'
        $set | Should -Match 'AzureWebJobsStorage__credential=managedidentity'
        $set | Should -Match 'STORAGE_ACCOUNT_NAME='
        $set | Should -Match 'ADMIN_EMAIL=security@contoso.com'
        $set | Should -Match 'MONITOR_HOSTNAME=func-test.azurewebsites.net'
        $set | Should -Not -Match 'CLIENT_SECRET'
        (Get-Calls '^functionapp config appsettings delete')[0].Line | Should -Match 'AzureWebJobsStorage'
    }

    It 'turns on App Service Authentication with the script endpoints excluded' {
        $auth = Get-Calls '^rest --method PUT .*authsettingsV2'
        $auth.Count | Should -Be 1
        $auth[0].Body.properties.globalValidation.excludedPaths | Should -Contain '/api/status'
        $auth[0].Body.properties.globalValidation.excludedPaths | Should -Contain '/admin/*'
        $auth[0].Body.properties.globalValidation.requireAuthentication | Should -BeTrue
    }

    It 'creates the health alerts and deploys the code' {
        (Get-Calls '^rest --method PUT .*actionGroups').Count | Should -Be 1
        (Get-Calls '^rest --method PUT .*scheduledQueryRules').Count | Should -Be 3     # no runs, errors, code deployed
        (Get-Calls '^functionapp deployment source config-zip').Count | Should -Be 1
    }

    It 'writes the verified domains (TENANT_DOMAINS), so a second domain is internal' {
        $global:Fake.Created.settings['TENANT_DOMAINS'] -split ',' | Should -Contain 'contoso.com'
    }

    It 'records the grants of this run for the monitor (INSTALL_GRANTS)' {
        $v = $global:Fake.Created.settings['INSTALL_GRANTS']
        $v | Should -Match '^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ;admin@contoso\.com;'
        ($v -split ';')[2] -split ',' | Should -Contain 'Mail.Send'
        ($v -split ';')[2] -split ',' | Should -Contain 'ActivityFeed.Read'
        $v | Should -Not -Match 'User\.Read$'      # the admin UI app's delegated permission is not a grant to the monitor
    }

    It 'sends telemetry with the managed identity only, after its role applies' {
        $role = @(Get-Calls '^role assignment create .*uami-principal.*Monitoring Metrics Publisher')
        $role.Count | Should -Be 1
        $role[0].Line | Should -Match '--scope \S+/components/appi'
        Should -Invoke Start-Sleep -Scope Describe -ParameterFilter { $Seconds -ge 250 }
        $global:Fake.Created.settings['APPLICATIONINSIGHTS_AUTHENTICATION_STRING'] | Should -Be 'Authorization=AAD;ClientId=uami-client'
        $put = @(Get-Calls '^rest --method PUT --url \S+/components/appi ' | Where-Object { $_.Body.properties.DisableLocalAuth })
        $put.Count | Should -Be 1
        $put[0].Body.properties.WorkspaceResourceId | Should -Be '/subscriptions/sub-1/ws'
        $calls = @($global:Fake.Calls)
        $settings = [array]::FindIndex([string[]]$calls.Line, [Predicate[string]]{ param($l) $l -match '^functionapp config appsettings set' })
        $roleAt = [array]::FindIndex([string[]]$calls.Line, [Predicate[string]]{ param($l) $l -match '^role assignment create .*Monitoring Metrics Publisher' })
        $off = [array]::FindIndex($calls, [Predicate[object]]{ param($c) $c.Line -match '/components/' -and $c.Body -and $c.Body.properties.PSObject.Properties['DisableLocalAuth'] })
        $roleAt | Should -BeLessThan $settings
        $off | Should -BeGreaterThan $settings -Because 'local auth goes off after the app has the identity setting'
    }

    It 'turns off deployment with a user name and password' {
        foreach ($kind in 'scm', 'ftp') {
            $put = @(Get-Calls "^rest --method PUT --url \S+/basicPublishingCredentialsPolicies/$kind ")
            $put.Count | Should -Be 1
            $put[0].Body.properties.allow | Should -BeFalse
        }
    }

    It 'alerts on Azure changes to the monitor, set after the configuration changes' {
        $alert = @(Get-Calls '^rest --method PUT --url \S+/activityLogAlerts/alert-m365-ato-monitor-azure-change ')
        $alert.Count | Should -Be 1
        $p = $alert[0].Body.properties
        $p.scopes | Should -Be @('/subscriptions/sub-1/resourceGroups/rg-m365-ato-monitor')
        $p.actions.actionGroups[0].actionGroupId | Should -Match '/actionGroups/ag-m365-ato-monitor$'
        $ops = @(@($p.condition.allOf | Where-Object { $_.PSObject.Properties['anyOf'] })[0].anyOf | ForEach-Object { $_.equals })
        $ops | Should -Contain 'Microsoft.Web/sites/config/write'
        $ops | Should -Contain 'Microsoft.ManagedIdentity/userAssignedIdentities/federatedIdentityCredentials/write'
        $ops | Should -Contain 'Microsoft.Authorization/roleAssignments/write'
        $ops | Should -Not -Contain 'Microsoft.Insights/actionGroups/write'   # the app changes it with the alert mailbox
        $order = [string[]]@($global:Fake.Calls.Line)
        $at = [array]::FindIndex($order, [Predicate[string]]{ param($l) $l -match 'activityLogAlerts' -and $l -match '--method PUT' })
        $lastConfig = [array]::FindLastIndex($order, [Predicate[string]]{ param($l)
            $l -match '^functionapp config appsettings|^storage account update|--method (PUT|PATCH) --url \S+/(config/|components/|basicPublishing)' })
        $deploy = [array]::FindIndex($order, [Predicate[string]]{ param($l) $l -match '^functionapp deployment source config-zip' })
        $at | Should -BeGreaterThan $lastConfig
        $deploy | Should -BeGreaterThan $at
    }

    It 'alerts on a code deployment from the storage logs of the deployments container only' {
        $dcr = @(Get-Calls '^rest --method PUT --url \S+/dataCollectionRules/dcr-m365-ato-monitor-deploy-logs ')
        $dcr.Count | Should -Be 1
        $dcr[0].Body.kind | Should -Be 'WorkspaceTransforms'
        $dcr[0].Body.properties.dataFlows[0].streams | Should -Be @('Microsoft-Table-StorageBlobLogs')
        $dcr[0].Body.properties.dataFlows[0].transformKql | Should -Match "ObjectKey contains '/deployments/'"
        $link = @(Get-Calls '^rest --method PATCH --url \S+/sub-1/ws ')
        $link[0].Body.properties.defaultDataCollectionRuleResourceId | Should -Match '/dataCollectionRules/dcr-m365-ato-monitor-deploy-logs$'
        $diag = @(Get-Calls '^rest --method PUT --url \S+/blobServices/default/providers/Microsoft.Insights/diagnosticSettings/')
        $diag[0].Body.properties.logs.category | Should -Be @('StorageWrite')
        $rule = @(Get-Calls '^rest --method PUT --url \S+/scheduledQueryRules/alert-m365-ato-monitor-code-deployed ')
        $rule[0].Body.properties.criteria.allOf[0].query | Should -Match 'StorageBlobLogs'
        $rule[0].Body.properties.autoMitigate | Should -BeFalse        # no "resolved" email
        $rule[0].Body.properties.scopes | Should -Be @('/subscriptions/sub-1/ws')
    }
}

Describe 'Mail.Send for the alert mailbox (the default)' {
    BeforeAll {
        New-FakeAzure
        New-FakeExchange
        Mock Start-Sleep {}
        Mock Read-Host { 'y' }
        Mock Invoke-WebRequest { [pscustomobject]@{ StatusCode = 200; Content = '{"status":"healthy","checks":{"azure_ad_token":"ok"}}' } }
        Mock Get-Module { [pscustomobject]@{ Name = 'ExchangeOnlineManagement' } } -ParameterFilter { $Name -eq 'ExchangeOnlineManagement' }
        Mock Import-Module {} -ParameterFilter { $Name -eq 'ExchangeOnlineManagement' }
        Mock Install-Module {}
        Mock Test-Bound { $false }
        $DryRun = $false; $Yes = $true; $Update = $false
        $AdminEmail = 'security@contoso.com'; $Location = 'eastus'; $Name = 'm365-ato-monitor'
        $ResponsePermissions = 'no'; $MailSendScope = 'mailbox'; $UiAdmins = @(); $SubscriptionId = ''
        Install-Monitor
    }

    It 'is the default of -MailSendScope' {
        $ast = [System.Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot '..' 'install.ps1'), [ref]$null, [ref]$null)
        $p = $ast.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'MailSendScope' }
        $p.DefaultValue.Value | Should -Be 'mailbox'
    }

    It 'signs in to Exchange Online with a device code (a URL and a code; no browser opens)' {
        Get-ExoCalls '^Connect-ExchangeOnline device=True$' | Should -HaveCount 1
    }

    It 'makes a hidden mail-enabled security group with the alert mailbox as the member' {
        Get-ExoCalls '^New-DistributionGroup m365-ato-monitor-senders Security$' | Should -HaveCount 1
        Get-ExoCalls '^Set-DistributionGroup m365-ato-monitor-senders hidden=True$' | Should -HaveCount 1
        $global:Exo.Members | Should -Be @('security@contoso.com')
    }

    It 'gives the app Application Mail.Send for the members of the group only' {
        Get-ExoCalls '^New-ServicePrincipal app-1 sp-app-1$' | Should -HaveCount 1
        Get-ExoCalls "^New-ManagementScope m365-ato-monitor-senders scope \| MemberOfGroup -eq 'CN=m365-ato-monitor-senders," | Should -HaveCount 1
        Get-ExoCalls '^New-ManagementRoleAssignment m365-ato-monitor-senders Mail.Send app-1 \| sp-app-1 \| Application Mail.Send \| m365-ato-monitor-senders scope$' |
            Should -HaveCount 1
        Get-ExoCalls '^Disconnect-ExchangeOnline$' | Should -HaveCount 1
    }

    It 'grants no tenant-wide Graph Mail.Send' {
        $roles = Get-GraphRoles 'sp-app-1'
        $roles | Should -Contain 'User.ReadBasic.All'       # the list is read
        $roles | Should -Not -Contain 'Mail.Send'
    }

    It 'tells the function the scope and the group' {
        $global:Fake.Created.settings['MAIL_SEND_SCOPE'] | Should -Be 'mailbox'
        $global:Fake.Created.settings['MAIL_SEND_GROUP'] | Should -Be 'm365-ato-monitor-senders'
    }

    It 'does not sign in to Exchange Online with -Update' {
        $global:Exo.Calls.Clear()
        $Update = $true; $AdminEmail = ''
        Install-Monitor
        $global:Exo.Calls | Should -BeNullOrEmpty
        $global:Fake.Created.settings['MAIL_SEND_GROUP'] | Should -Be 'm365-ato-monitor-senders'
    }
}

Describe 'Change an install from tenant-wide to the alert mailbox' {
    BeforeAll {
        Mock Start-Sleep {}
        Mock Read-Host { 'y' }
        Mock Invoke-WebRequest { [pscustomobject]@{ StatusCode = 200; Content = '{"status":"healthy","checks":{"azure_ad_token":"ok"}}' } }
        Mock Get-Module { [pscustomobject]@{ Name = 'ExchangeOnlineManagement' } } -ParameterFilter { $Name -eq 'ExchangeOnlineManagement' }
        Mock Import-Module {} -ParameterFilter { $Name -eq 'ExchangeOnlineManagement' }
        Mock Install-Module {}
        $DryRun = $false; $Yes = $true; $Update = $false
        $AdminEmail = 'security@contoso.com'; $Location = 'eastus'; $Name = 'm365-ato-monitor'
        $ResponsePermissions = 'no'; $UiAdmins = @(); $SubscriptionId = ''
    }

    BeforeEach {
        New-FakeAzure
        $MailSendScope = 'tenant'
        Mock Test-Bound { $false }
        $AdminEmail = 'security@contoso.com'
    }

    It 'keeps the tenant-wide scope on a rerun without -MailSendScope' {
        New-FakeExchange
        Install-Monitor
        $MailSendScope = 'mailbox'          # the new default; the stored choice wins
        $AdminEmail = ''
        Install-Monitor
        $global:Exo.Calls | Should -BeNullOrEmpty
        Get-GraphRoles 'sp-app-1' | Should -Contain 'Mail.Send'
        $global:Fake.Created.settings['MAIL_SEND_SCOPE'] | Should -Be 'tenant'
    }

    It 'removes the Graph Mail.Send and the old one-address grant after Exchange shows the new grant' {
        New-FakeExchange -OldObjects $true
        Install-Monitor
        Get-GraphRoles 'sp-app-1' | Should -Contain 'Mail.Send'
        $MailSendScope = 'mailbox'
        Mock Test-Bound { $true } -ParameterFilter { $Name -eq 'MailSendScope' }
        Install-Monitor
        Get-GraphRoles 'sp-app-1' | Should -Not -Contain 'Mail.Send'
        Get-GraphRoles 'sp-app-1' | Should -Contain 'User.ReadBasic.All'
        $global:Fake.Created.settings['MAIL_SEND_SCOPE'] | Should -Be 'mailbox'
        Get-ExoCalls '^Remove-ManagementRoleAssignment M365 ATO Monitor Mail.Send$' | Should -HaveCount 1
        Get-ExoCalls '^Remove-ManagementScope M365 ATO Monitor alert mailbox$' | Should -HaveCount 1
    }

    It 'keeps the Graph Mail.Send, the old grant, and the tenant scope when Exchange does not show the grant' {
        New-FakeExchange -InScope $false -OldObjects $true
        Install-Monitor
        $MailSendScope = 'mailbox'
        Mock Test-Bound { $true } -ParameterFilter { $Name -eq 'MailSendScope' }
        Install-Monitor
        Get-GraphRoles 'sp-app-1' | Should -Contain 'Mail.Send'
        Get-ExoCalls '^Remove-' | Should -BeNullOrEmpty
        $global:Fake.Created.settings['MAIL_SEND_SCOPE'] | Should -Be 'tenant'
        $global:Fake.Created.settings['MAIL_SEND_GROUP'] | Should -BeNullOrEmpty
    }

    It 'puts the alert mailbox set in the management UI into the group' {
        New-FakeExchange
        Install-Monitor
        Mock Invoke-WebRequest { [pscustomobject]@{ StatusCode = 200
            Content = '{"status":"healthy","checks":{"azure_ad_token":"ok"},"config":{"admin_email":"alerts@contoso.com"}}' } }
        $MailSendScope = 'mailbox'; $AdminEmail = ''
        Mock Test-Bound { $true } -ParameterFilter { $Name -eq 'MailSendScope' }
        Install-Monitor
        $global:Exo.Members | Should -Contain 'alerts@contoso.com'
        Get-GraphRoles 'sp-app-1' | Should -Not -Contain 'Mail.Send'
    }

    It 'leaves out an earlier alert mailbox that has no mailbox, and moves the health alerts with -AdminEmail' {
        New-FakeExchange
        Install-Monitor
        $global:Exo.NoMailbox = @('root@contoso.onmicrosoft.com')
        Mock Invoke-WebRequest { [pscustomobject]@{ StatusCode = 200
            Content = '{"status":"healthy","checks":{"azure_ad_token":"ok"},"config":{"admin_email":"root@contoso.onmicrosoft.com"}}' } }
        $MailSendScope = 'mailbox'; $AdminEmail = 'alerts@contoso.com'
        Mock Test-Bound { $true } -ParameterFilter { $Name -in 'MailSendScope', 'AdminEmail' }
        $global:Fake.Calls.Clear()
        { Install-Monitor } | Should -Not -Throw
        $global:Exo.Members | Should -Be @('alerts@contoso.com')
        $global:Fake.Created.settings['ADMIN_EMAIL'] | Should -Be 'alerts@contoso.com'
        $ag = @(Get-Calls '^rest --method PUT --url \S+/actionGroups/')
        $ag.Count | Should -Be 1
        $ag[0].Body.properties.emailReceivers[0].emailAddress | Should -Be 'alerts@contoso.com'
    }

    It 'stops when the new alert mailbox has no mailbox' {
        New-FakeExchange
        Install-Monitor
        $global:Exo.NoMailbox = @('nobox@contoso.com')
        $MailSendScope = 'mailbox'; $AdminEmail = 'nobox@contoso.com'
        Mock Test-Bound { $true } -ParameterFilter { $Name -in 'MailSendScope', 'AdminEmail' }
        { Install-Monitor } | Should -Throw '*Exchange Online has no mailbox nobox@contoso.com*'
    }
}

Describe 'Alert mailbox set in the management UI' {
    BeforeAll {
        Mock Start-Sleep {}
        Mock Read-Host { 'y' }
        $DryRun = $false; $Yes = $true; $Update = $false
        $Location = 'eastus'; $Name = 'm365-ato-monitor'
        $ResponsePermissions = 'no'; $MailSendScope = 'tenant'; $UiAdmins = @(); $SubscriptionId = ''
    }

    BeforeEach {
        New-FakeAzure
        $AdminEmail = 'security@contoso.com'
        Mock Invoke-WebRequest { [pscustomobject]@{ StatusCode = 200; Content = '{"status":"healthy","checks":{"azure_ad_token":"ok"}}' } }
        Install-Monitor
        Mock Invoke-WebRequest { [pscustomobject]@{ StatusCode = 200
            Content = '{"status":"healthy","checks":{"azure_ad_token":"ok"},"config":{"admin_email":"alerts@contoso.com"}}' } }
        $global:Said = [System.Collections.Generic.List[string]]::new()
        Mock Write-Info { $global:Said.Add($Text) }
        Mock Write-Warn2 { $global:Said.Add("WARN $Text") }
    }

    It 'shows the UI value in the plan of -Update and keeps it' {
        $Update = $true; $AdminEmail = ''
        Install-Monitor
        $global:Said | Should -Contain 'Alert mailbox:   alerts@contoso.com (set in the management UI; it stays)'
        $global:Said | Where-Object { $_ -like 'WARN*management UI set*' } | Should -BeNullOrEmpty
        $global:Fake.Created.settings['ADMIN_EMAIL'] | Should -Be 'security@contoso.com'
    }

    It 'warns that the UI value wins over -AdminEmail' {
        $AdminEmail = 'soc@contoso.com'
        Mock Test-Bound { $true } -ParameterFilter { $Name -eq 'AdminEmail' }
        Install-Monitor
        $global:Said | Should -Contain 'Alert mailbox:   alerts@contoso.com (set in the management UI; it stays)'
        $global:Said | Where-Object { $_ -like 'WARN The management UI set the alert mailbox to alerts@contoso.com.*' } | Should -HaveCount 1
        $global:Fake.Created.settings['ADMIN_EMAIL'] | Should -Be 'soc@contoso.com'
    }

    It 'shows the new address of -AdminEmail when the UI did not change the mailbox' {
        Mock Invoke-WebRequest { [pscustomobject]@{ StatusCode = 200
            Content = '{"status":"healthy","checks":{"azure_ad_token":"ok"},"config":{"admin_email":"security@contoso.com"}}' } }
        $AdminEmail = 'soc@contoso.com'
        Mock Test-Bound { $true } -ParameterFilter { $Name -eq 'AdminEmail' }
        Install-Monitor
        $global:Said | Should -Contain 'Alert mailbox:   soc@contoso.com'
        $global:Said | Where-Object { $_ -like 'WARN*management UI set*' } | Should -BeNullOrEmpty
    }
}

Describe 'Health alert receivers on a mailbox change' {
    It 'keeps the other receivers, tags, and enabled state' {
        New-FakeAzure
        Mock Start-Sleep {}
        Mock Read-Host { 'y' }
        Mock Invoke-WebRequest { [pscustomobject]@{ StatusCode = 200; Content = '{"status":"healthy","checks":{"azure_ad_token":"ok"}}' } }
        $DryRun = $false; $Yes = $true; $Update = $false; $Tenant = ''
        $AdminEmail = 'security@contoso.com'; $Location = 'eastus'; $Name = 'm365-ato-monitor'
        $ResponsePermissions = 'no'; $MailSendScope = 'tenant'; $UiAdmins = @(); $SubscriptionId = ''
        Install-Monitor
        $ag = $global:Fake.Created.ag
        $ag.tags | Add-Member -NotePropertyName owner -NotePropertyValue 'on-call team'
        $ag.properties.enabled = $false
        $ag.properties.emailReceivers += [pscustomobject]@{ name = 'other'; emailAddress = 'other@contoso.com'; useCommonAlertSchema = $false }
        $ag.properties | Add-Member -NotePropertyName smsReceivers -NotePropertyValue @(
            [pscustomobject]@{ name = 'oncall'; countryCode = '1'; phoneNumber = '5550100' })
        $ag.properties | Add-Member -NotePropertyName webhookReceivers -NotePropertyValue @(
            [pscustomobject]@{ name = 'tickets'; serviceUri = 'https://tickets.example.test/hook'; useCommonAlertSchema = $true })
        $global:Fake.Calls.Clear()
        Mock Test-Bound { $true } -ParameterFilter { $Name -eq 'AdminEmail' }
        Set-HealthAlerts 'new@contoso.com' 'eastus'
        $put = @(Get-Calls '^rest --method PUT --url \S+/actionGroups/')
        $put | Should -HaveCount 1
        $body = $put[0].Body
        $body.properties.emailReceivers[0].emailAddress | Should -Be 'new@contoso.com'
        $body.properties.emailReceivers[1].emailAddress | Should -Be 'other@contoso.com'
        $body.properties.smsReceivers[0].phoneNumber | Should -Be '5550100'
        $body.properties.webhookReceivers[0].serviceUri | Should -Be 'https://tickets.example.test/hook'
        $body.properties.enabled | Should -BeFalse
        $body.tags.owner | Should -Be 'on-call team'
    }
}

Describe 'Organization metadata across tenants' {
    BeforeEach {
        $script:TenantId = 'next-tenant'
        $script:TenantName = 'Previous tenant'
        $script:TenantDomain = 'previous.example'
        $script:TenantDomains = @('previous.example')
    }

    It 'clears previous metadata when Graph refuses, and still checks the next mailbox' {
        Mock Invoke-Rest { throw 'Mock Graph 403' } -ParameterFilter { $Url -like '*/organization' }
        Mock Invoke-Rest { [pscustomobject]@{ value = @([pscustomobject]@{ userPrincipalName = 'security@next.example' }) } } `
            -ParameterFilter { $Url -like '*/users' }
        Read-Organization
        $script:TenantName | Should -BeNullOrEmpty
        $script:TenantDomain | Should -BeNullOrEmpty
        $script:TenantDomains | Should -BeNullOrEmpty
        { Test-AlertMailbox 'security@next.example' } | Should -Not -Throw
        Should -Invoke Invoke-Rest -Times 1 -Exactly -ParameterFilter { $Url -like '*/users' }
    }

    It 'clears previous metadata when the organization list is empty' {
        Mock Invoke-Rest { [pscustomobject]@{ value = @() } }
        Read-Organization
        $script:TenantName | Should -BeNullOrEmpty
        $script:TenantDomain | Should -BeNullOrEmpty
        $script:TenantDomains | Should -BeNullOrEmpty
    }

    It 'loads only the next organization after clearing the previous metadata' {
        Mock Invoke-Rest { [pscustomobject]@{ value = @([pscustomobject]@{
            displayName = 'Next tenant'; verifiedDomains = @([pscustomobject]@{
                name = 'next.example'; isDefault = $true; isInitial = $false }) }) } }
        Read-Organization
        $script:TenantName | Should -Be 'Next tenant'
        $script:TenantDomain | Should -Be 'next.example'
        $script:TenantDomains | Should -Be @('next.example')
    }
}

Describe 'Management UI sign-in app on a rerun' {
    BeforeAll {
        Mock Start-Sleep {}
        Mock Read-Host { 'y' }
        Mock Invoke-WebRequest { [pscustomobject]@{ StatusCode = 200; Content = '{"status":"healthy","checks":{"azure_ad_token":"ok"}}' } }
        $DryRun = $false; $Yes = $true; $Update = $false
        $AdminEmail = 'security@contoso.com'; $Location = 'eastus'; $Name = 'm365-ato-monitor'
        $ResponsePermissions = 'no'; $MailSendScope = 'tenant'; $UiAdmins = @(); $SubscriptionId = ''
    }

    It 'keeps a redirect URI that someone added, for example for a custom domain' {
        New-FakeAzure
        Install-Monitor
        $ui = @($global:Fake.Created.apps) | Where-Object { $_ -and $_.displayName -eq 'm365-ato-monitor-admin-ui' }
        $ui.web = @{ redirectUris = @('https://func-test.azurewebsites.net/.auth/login/aad/callback',
                                      'https://monitor.contoso.com/.auth/login/aad/callback') }
        $global:Fake.Calls.Clear()
        $AdminEmail = ''
        Install-Monitor
        $patch = @(Get-Calls '^rest --method PATCH --url \S+/applications/' | Where-Object { ($_.Body | ConvertTo-Json -Depth 6 -Compress) -match '"displayName":"m365-ato-monitor-admin-ui"' })
        $patch.Count | Should -Be 1
        $patch[0].Body.web.redirectUris | Should -Be @('https://func-test.azurewebsites.net/.auth/login/aad/callback',
                                                       'https://monitor.contoso.com/.auth/login/aad/callback')
    }
}

Describe 'Reinstall after an uninstall left the Exchange objects' {
    It 'gives the new app its own assignment and removes the one of the deleted app' {
        New-FakeAzure
        New-FakeExchange -OldAppAssignment 'm365-ato-monitor-senders Mail.Send oldapp00'
        Mock Start-Sleep {}
        Mock Read-Host { 'y' }
        Mock Invoke-WebRequest { [pscustomobject]@{ StatusCode = 200; Content = '{"status":"healthy","checks":{"azure_ad_token":"ok"}}' } }
        Mock Get-Module { [pscustomobject]@{ Name = 'ExchangeOnlineManagement' } } -ParameterFilter { $Name -eq 'ExchangeOnlineManagement' }
        Mock Import-Module {} -ParameterFilter { $Name -eq 'ExchangeOnlineManagement' }
        Mock Install-Module {}
        Mock Test-Bound { $false }
        $DryRun = $false; $Yes = $true; $Update = $false
        $AdminEmail = 'security@contoso.com'; $Location = 'eastus'; $Name = 'm365-ato-monitor'
        $ResponsePermissions = 'no'; $MailSendScope = 'mailbox'; $UiAdmins = @(); $SubscriptionId = ''
        Install-Monitor
        Get-ExoCalls '^New-ManagementRoleAssignment m365-ato-monitor-senders Mail.Send app-1 ' | Should -HaveCount 1
        Get-ExoCalls '^Remove-ManagementRoleAssignment m365-ato-monitor-senders Mail.Send oldapp00$' | Should -HaveCount 1
        $global:Fake.Created.settings['MAIL_SEND_GROUP'] | Should -Be 'm365-ato-monitor-senders'
    }
}

Describe 'The alert mailbox must be in the tenant' {
    BeforeEach {
        New-FakeAzure
        Mock Start-Sleep {}
        Mock Read-Host { 'y' }
        $DryRun = $false; $Yes = $true; $Update = $false; $Tenant = ''
        $Location = 'eastus'; $Name = 'm365-ato-monitor'
        $ResponsePermissions = 'no'; $MailSendScope = 'tenant'; $UiAdmins = @(); $SubscriptionId = ''
    }

    It 'stops before any change for a mailbox of another tenant, and names the -Tenant command' {
        $AdminEmail = 'security@fabrikam.com'
        { Install-Monitor } | Should -Throw '*security@fabrikam.com is not in the tenant*Contoso*'
        Get-Calls '^(group|identity|storage account|functionapp) create' | Should -BeNullOrEmpty
        Get-Calls '^rest --method (POST|PUT|PATCH)' | Should -BeNullOrEmpty
    }

    It 'stops for an address of the tenant that is not a mailbox' {
        $AdminEmail = 'nobody@contoso.com'
        { Install-Monitor } | Should -Throw '*has no user or shared mailbox nobody@contoso.com*'
    }

    It 'signs in to the tenant of the alert mailbox when the Azure CLI is not signed in' {
        $global:Fake.Created.signedOut = $true
        $AdminEmail = 'security@contoso.com'
        $Yes = $false
        Test-Prerequisites
        Get-Calls '^login --tenant contoso.com' | Should -HaveCount 1
        $script:TenantName | Should -Be 'Contoso'
    }
}

Describe 'A second tenant (-Tenant)' {
    BeforeAll {
        Mock Start-Sleep {}
        Mock Read-Host { 'y' }
        Mock Invoke-WebRequest { [pscustomobject]@{ StatusCode = 200; Content = '{"status":"healthy","checks":{"azure_ad_token":"ok"}}' } }
        Mock Invoke-RestMethod { [pscustomobject]@{ issuer = "https://login.microsoftonline.com/$($global:FabrikamId)/v2.0" } }
        Mock Test-Bound { $false }
        if (Test-Path $env:M365_ATO_MONITOR_HOME) { Remove-Item -Recurse -Force $env:M365_ATO_MONITOR_HOME }
        New-FakeAzure
        $DryRun = $false; $Yes = $true; $Update = $false
        $Location = 'eastus'; $Name = 'm365-ato-monitor'
        $ResponsePermissions = 'no'; $MailSendScope = 'tenant'; $UiAdmins = @(); $SubscriptionId = ''
        # The first tenant, as a single-tenant install: it is saved too.
        $Tenant = ''; $AdminEmail = 'security@contoso.com'
        Install-Monitor
        $global:Fake.Calls.Clear()
        $Tenant = 'fabrikam.com'; $AdminEmail = 'security@fabrikam.com'
        $Yes = $false                      # the sign-in to the new tenant asks (a browser window)
        Mock Complete-Install {}
        Install-Monitor
        $script:subDuring = (Invoke-Az account show).id
        Restore-AzSubscription
    }

    It 'signs in to the tenant, selects its subscription, and installs there' {
        Get-Calls "^login --tenant $($global:FabrikamId)" | Should -HaveCount 1
        $script:subDuring | Should -Be 'sub-2'
        $script:TenantId | Should -Be $global:FabrikamId
    }

    It 'sets the Azure CLI back to the earlier subscription' {
        (Invoke-Az account show).id | Should -Be 'sub-1'
    }

    It 'puts the organization name in the alert subjects' {
        $global:Fake.Created.settings['TENANT_LABEL'] | Should -Be 'Fabrikam'
    }

    It 'saves both installations, and -List shows them' {
        $records = @(Read-TenantRecords)
        @($records.tenantName) | Should -Be @('Contoso', 'Fabrikam')
        ($records | Where-Object tenantName -eq 'Fabrikam').subscriptionId | Should -Be 'sub-2'
        $out = Show-Installations 6>&1 | Out-String
        $out | Should -Match 'Fabrikam'
        $out | Should -Match 'Contoso'
        $out | Should -Match ([regex]::Escape('https://func-test.azurewebsites.net/api/manage'))
    }

    It 'finds a saved tenant by a short name, without a lookup' {
        Resolve-TenantId 'fabrikam' | Should -Be $global:FabrikamId
        Should -Invoke Invoke-RestMethod -Times 1 -Exactly -Scope Describe     # only the first install looked it up
    }

    It 'asks for the subscription when the tenant has more than one (-Yes: stops with the list)' {
        Remove-Item -Recurse -Force $env:M365_ATO_MONITOR_HOME
        New-FakeAzure
        $global:Fake.Created.extraFabrikamSubs = @(@{ id = 'sub-3'; name = 'Fabrikam dev'; tenantId = $global:FabrikamId; state = 'Enabled' })
        $null = Invoke-AzLogin 'fabrikam.com'                 # signed in to both tenants before
        & az account set --subscription sub-1
        $Tenant = 'fabrikam.com'; $Yes = $true
        { Test-Prerequisites } | Should -Throw '*more than one subscription*'
        Restore-AzSubscription
    }
}

Describe 'Update all installations' {
    It 'runs -Update for each saved installation and continues after a failure' {
        if (Test-Path $env:M365_ATO_MONITOR_HOME) { Remove-Item -Recurse -Force $env:M365_ATO_MONITOR_HOME }
        foreach ($r in @(@{ tenantId = 'tenant-1'; tenantName = 'Contoso'; domain = 'contoso.com'; subscriptionId = 'sub-1'; name = 'm365-ato-monitor' },
                         @{ tenantId = $global:FabrikamId; tenantName = 'Fabrikam'; domain = 'fabrikam.com'; subscriptionId = 'sub-2'; name = 'm365-ato-monitor' })) {
            Save-TenantRecord ([pscustomobject]$r)
        }
        $global:Updated = @()
        Mock Install-Monitor {
            $global:Updated += "$Tenant|$SubscriptionId|$([bool]$Update)"
            if ($Tenant -eq 'tenant-1') { throw 'install.ps1 stopped: The Azure sign-in has expired.' }
        }
        $DryRun = $false; $Yes = $true
        $out = Update-AllInstallations 6>&1 | Out-String
        $global:Updated | Should -Be @("tenant-1|sub-1|True", "$($global:FabrikamId)|sub-2|True")
        $out | Should -Match 'FAILED: The Azure sign-in has expired'
        $out | Should -Match 'updated'
        $script:Confirmed | Should -BeFalse
        $script:Batch | Should -BeFalse
    }
}

Describe 'Exchange Online sign-in in another tenant' {
    It 'stops before it changes anything in Exchange Online' {
        New-FakeAzure
        New-FakeExchange
        $global:Exo.TenantId = '99999999-9999-4999-8999-999999999999'
        Mock Start-Sleep {}
        Mock Read-Host { 'y' }
        Mock Get-Module { [pscustomobject]@{ Name = 'ExchangeOnlineManagement' } } -ParameterFilter { $Name -eq 'ExchangeOnlineManagement' }
        Mock Import-Module {} -ParameterFilter { $Name -eq 'ExchangeOnlineManagement' }
        Mock Test-Bound { $false }
        $DryRun = $false; $Yes = $true; $Update = $false; $Tenant = ''
        $AdminEmail = 'security@contoso.com'; $Location = 'eastus'; $Name = 'm365-ato-monitor'
        $ResponsePermissions = 'no'; $MailSendScope = 'mailbox'; $UiAdmins = @(); $SubscriptionId = ''
        { Install-Monitor } | Should -Throw '*sign-in went to another tenant*'
        Get-ExoCalls '^New-' | Should -BeNullOrEmpty
        Get-ExoCalls '^Disconnect-ExchangeOnline$' | Should -HaveCount 1
    }
}

Describe 'Dry run with the alert mailbox scope' {
    It 'does not sign in to Exchange Online and changes nothing there' {
        New-FakeAzure
        New-FakeExchange
        Mock Start-Sleep {}
        Mock Read-Host { 'y' }
        Mock Get-Module {} -ParameterFilter { $Name -eq 'ExchangeOnlineManagement' }
        Mock Install-Module {}
        $DryRun = $true; $Yes = $true; $Update = $false
        $AdminEmail = 'security@contoso.com'; $Location = 'eastus'; $Name = 'm365-ato-monitor'
        $ResponsePermissions = 'no'; $MailSendScope = 'mailbox'; $UiAdmins = @(); $SubscriptionId = ''
        Install-Monitor
        $global:Exo.Calls | Should -BeNullOrEmpty
        Should -Invoke Install-Module -Times 0
    }
}

Describe 'Dry run' {
    It 'makes no change' {
        New-FakeAzure
        Mock Start-Sleep {}
        $DryRun = $true; $Yes = $true; $Update = $false
        $AdminEmail = 'security@contoso.com'; $Location = 'eastus'; $Name = 'm365-ato-monitor'
        $ResponsePermissions = 'no'; $MailSendScope = 'tenant'; $UiAdmins = @(); $SubscriptionId = ''
        Install-Monitor
        $writes = $global:Fake.Calls | Where-Object {
            $_.Line -match ' create|delete|appsettings set|config-zip|provider register' -or
            $_.Line -match '^rest --method (POST|PUT|PATCH|DELETE)' }
        $writes | Should -BeNullOrEmpty
    }
}

Describe 'Uninstall' {
    It 'deletes both app registrations and the resource group after confirmation' {
        New-FakeAzure
        $global:Fake.Created.rg = $true
        $global:Fake.Created.apps = @(@{ id = 'obj-1'; appId = 'app-1'; displayName = 'm365-ato-monitor'; tags = @('m365-ato-monitor') },
                                       @{ id = 'obj-2'; appId = 'app-2'; displayName = 'm365-ato-monitor-admin-ui'; tags = @('m365-ato-monitor') })
        Mock Read-Host { 'rg-m365-ato-monitor' }
        $DryRun = $false; $Yes = $false; $Name = 'm365-ato-monitor'; $SubscriptionId = ''
        Remove-Monitor
        (Get-Calls '^ad app delete').Count | Should -Be 2
        (Get-Calls '^group delete --name rg-m365-ato-monitor').Count | Should -Be 1
    }

    It 'stops when the typed name does not match' {
        New-FakeAzure
        $global:Fake.Created.rg = $true
        Mock Read-Host { 'wrong' }
        $DryRun = $false; $Yes = $false; $Name = 'm365-ato-monitor'; $SubscriptionId = ''
        { Remove-Monitor } | Should -Throw '*did not match*'
        Get-Calls '^group delete' | Should -BeNullOrEmpty
    }
}

Describe 'Retry while new objects replicate' {
    BeforeEach { New-FakeAzure; Mock Start-Sleep {}; $DryRun = $false }

    It 'retries a role assignment while the new principal is not found' {
        $global:Fake.Created.roleError = "ERROR: (PrincipalNotFound) Principal p1 does not exist in the directory"
        $global:Fake.Created.roleErrorTimes = 2
        Set-RoleAssignment 'p1' 'Storage Table Data Contributor' '/subscriptions/sub-1/x' 'the managed identity'
        $global:Fake.RoleCreates | Should -Be 3
        Should -Invoke Start-Sleep -Times 2
    }

    It 'does not retry another error or a permission error of the person' {
        $global:Fake.Created.roleError = "ERROR: (InvalidRoleDefinitionName) The role is not valid"
        $global:Fake.Created.roleErrorTimes = 5
        { Set-RoleAssignment 'p1' 'Nope' '/subscriptions/sub-1/x' 'the managed identity' } | Should -Throw '*InvalidRoleDefinitionName*'
        $global:Fake.RoleCreates | Should -Be 1
        New-FakeAzure
        $global:Fake.Created.roleError = "ERROR: (AuthorizationFailed) The client does not have authorization (403 Forbidden)"
        $global:Fake.Created.roleErrorTimes = 5
        { Set-RoleAssignment 'p1' 'Storage Table Data Contributor' '/subscriptions/sub-1/x' 'the managed identity' } | Should -Throw '*AuthorizationFailed*'
        $global:Fake.RoleCreates | Should -Be 1
    }
}

Describe 'Invoke-Az' {
    It 'refuses an argument that az.cmd on Windows cannot take' {
        New-FakeAzure
        { Invoke-Az rest --method GET --url "https://graph.microsoft.com/v1.0/servicePrincipals(appId='x')" } | Should -Throw '*az.cmd*'
        $global:Fake.Calls.Count | Should -Be 0
    }
}

Describe 'Expired Azure sign-in' {
    BeforeEach {
        New-FakeAzure
        $global:Fake.Created.signinExpired = $true
        $DryRun = $false; $SubscriptionId = ''
    }

    It 'signs in again in the browser and continues' {
        $Yes = $false
        Test-Prerequisites
        @(Get-Calls '^login --tenant tenant-1').Count | Should -Be 1
        $script:MeUpn | Should -Be 'admin@contoso.com'
    }

    It 'stops with the az login command when it cannot ask (-Yes)' {
        $Yes = $true
        { Test-Prerequisites } | Should -Throw '*sign-in has expired*'
        @(Get-Calls '^login').Count | Should -Be 0
    }

    It 'names the failed call by method and URL' {
        { Get-Me } | Should -Throw 'az rest GET https://graph.microsoft.com/v1.0/me failed: *AADSTS700082*'
    }

    It 'matches the sign-in errors of az' {
        'ERROR: User ''a@b.com'' does not exist in MSAL token cache. Run `az login`.' | Should -Match $script:SignInPattern
        'ERROR: (ResourceNotFound) The resource was not found.' | Should -Not -Match $script:SignInPattern
    }
}

Describe 'After the install' {
    BeforeAll {
        $script:Pending = [pscustomobject]@{ status = 'unhealthy'; checks = [pscustomobject]@{
            azure_ad_token = 'ok'
            o365_api_aad = 'FAILED: RuntimeError: Listing Audit.AzureActiveDirectory content failed: HTTP 400 AF20023: The subscription was disabled.' } }
        $script:Healthy = [pscustomobject]@{ status = 'healthy'; checks = [pscustomobject]@{
            azure_ad_token = 'ok'; o365_api_aad = 'ok (0 content blobs in last 60 min)' } }
        $script:Broken = [pscustomobject]@{ status = 'unhealthy'; checks = [pscustomobject]@{
            graph_api_token = 'FAILED: no consent' } }
    }
    BeforeEach { Mock Start-Sleep {}; $DryRun = $false }

    It 'knows when the audit subscriptions are not started' {
        Test-FeedStarting $script:Pending | Should -BeTrue
        Test-FeedStarting $script:Healthy | Should -BeFalse
        Test-FeedStarting $null | Should -BeFalse
    }

    It 'waits until the first monitor run starts the subscriptions' {
        $script:StatusCalls = 0
        Mock Get-Status { $script:StatusCalls++; if ($script:StatusCalls -lt 3) { $script:Pending } else { $script:Healthy } }
        $result = Wait-AuditFeed $script:Pending
        $result.status | Should -Be 'healthy'
        $script:StatusCalls | Should -Be 3
    }

    It 'does not wait when the subscriptions run' {
        Mock Get-Status { $script:Healthy }
        (Wait-AuditFeed $script:Healthy).status | Should -Be 'healthy'
        Should -Invoke Get-Status -Times 0 -Exactly
    }

    It 'tests the detections, then asks before it sends test emails' {
        $Yes = $false
        Mock Wait-AuditFeed { $script:Healthy }
        Mock Invoke-SelfTest { $true }
        Mock Read-Host { 'y' }
        Complete-Install $script:Pending 'security@contoso.com'
        Should -Invoke Read-Host -Times 1 -Exactly
        Should -Invoke Invoke-SelfTest -Times 1 -Exactly -ParameterFilter { -not $Send }
        Should -Invoke Invoke-SelfTest -Times 1 -Exactly -ParameterFilter { $Send }
    }

    It 'sends no email when the answer is no' {
        $Yes = $false
        Mock Wait-AuditFeed { $script:Healthy }
        Mock Invoke-SelfTest { $true }
        Mock Read-Host { '' }
        Complete-Install $script:Healthy 'security@contoso.com'
        Should -Invoke Invoke-SelfTest -Times 0 -Exactly -ParameterFilter { $Send }
    }

    It 'does not offer test emails when a check fails' {
        $Yes = $false
        Mock Wait-AuditFeed { $script:Broken }
        Mock Invoke-SelfTest { $true }
        Mock Read-Host { 'y' }
        Complete-Install $script:Broken 'security@contoso.com'
        Should -Invoke Read-Host -Times 0 -Exactly
    }

    It 'does not wait or ask with -Yes' {
        $Yes = $true
        Mock Wait-AuditFeed { $script:Healthy }
        Mock Invoke-SelfTest { $true }
        Mock Read-Host { 'y' }
        Complete-Install $script:Pending 'security@contoso.com'
        Should -Invoke Wait-AuditFeed -Times 0 -Exactly
        Should -Invoke Read-Host -Times 0 -Exactly
    }
}

Describe 'Rerun after an install' {
    BeforeAll {
        New-FakeAzure
        Mock Start-Sleep {}
        Mock Read-Host { 'y' }
        Mock Invoke-WebRequest { [pscustomobject]@{ StatusCode = 200; Content = '{"status":"healthy","checks":{"azure_ad_token":"ok"}}' } }
        $DryRun = $false; $Yes = $true; $Update = $false
        $AdminEmail = 'security@contoso.com'; $Location = 'eastus'; $Name = 'm365-ato-monitor'
        $ResponsePermissions = 'yes'; $MailSendScope = 'tenant'; $UiAdmins = @(); $SubscriptionId = ''
        Install-Monitor
        $global:Fake.Calls.Clear()
        $AdminEmail = ''; $ResponsePermissions = 'ask'
        Install-Monitor
    }

    It 'creates nothing a second time' {
        Get-Calls '^(group|identity|storage account|monitor log-analytics workspace|functionapp) create' | Should -BeNullOrEmpty
        Get-Calls '^role assignment create' | Should -BeNullOrEmpty
        Get-Calls ('^rest --method (POST|PUT) --url \S*(/applications|/servicePrincipals|federatedIdentityCredentials|' +
                   'appRoleAssignedTo|oauth2PermissionGrants|containers/deployments|/components/|/actionGroups/)') | Should -BeNullOrEmpty
        Get-Calls '^rest --method DELETE' | Should -BeNullOrEmpty
        Get-Calls '^rest --method PATCH --url \S+/config/web ' | Should -BeNullOrEmpty   # CORS is already set
    }

    It 'changes nothing in Azure, so the Azure change alert sends no email' {
        Get-Calls ('^rest --method (PUT|PATCH) --url \S*(scheduledQueryRules|activityLogAlerts|diagnosticSettings|' +
                   'dataCollectionRules|basicPublishingCredentialsPolicies|authsettingsV2|/ws )') | Should -BeNullOrEmpty
        Get-Calls '^functionapp config appsettings (set|delete)' | Should -BeNullOrEmpty
        Get-Calls '^storage account update' | Should -BeNullOrEmpty
        Should -Invoke Start-Sleep -Scope Describe -ParameterFilter { $Seconds -ge 250 } -Times 1 -Exactly   # the first install only
    }

    It 'keeps the alert mailbox and the response permissions' {
        $global:Fake.Created.settings['RESPONSE_PERMISSIONS'] | Should -Be 'true'
        $global:Fake.Created.settings['ADMIN_EMAIL'] | Should -Be 'security@contoso.com'
    }
}

Describe 'Rerun after the managed identity was made again' {
    It 'points the federated credential at the new identity' {
        New-FakeAzure
        Mock Start-Sleep {}
        Mock Read-Host { 'y' }
        Mock Invoke-WebRequest { [pscustomobject]@{ StatusCode = 200; Content = '{"status":"healthy","checks":{"azure_ad_token":"ok"}}' } }
        $DryRun = $false; $Yes = $true; $Update = $false
        $AdminEmail = 'security@contoso.com'; $Location = 'eastus'; $Name = 'm365-ato-monitor'
        $ResponsePermissions = 'yes'; $MailSendScope = 'tenant'; $UiAdmins = @(); $SubscriptionId = ''
        Install-Monitor
        $global:Fake.Created.uami = $null
        $global:Fake.Created.uamiPrincipal = 'uami-principal-2'
        $global:Fake.Calls.Clear()
        Install-Monitor
        $patch = @(Get-Calls '^rest --method PATCH --url \S+/federatedIdentityCredentials/fic-0 ')
        $patch.Count | Should -Be 1
        $patch[0].Body.subject | Should -Be 'uami-principal-2'
        Get-Calls '^rest --method POST --url \S+/federatedIdentityCredentials ' | Should -BeNullOrEmpty
    }
}

Describe 'New subscription' {
    It 'checks the region after it registers Microsoft.Web' {
        New-FakeAzure
        $global:Fake.Created.webUnregistered = $true
        Mock Start-Sleep {}
        Mock Read-Host { 'y' }
        Mock Invoke-WebRequest { [pscustomobject]@{ StatusCode = 200; Content = '{"status":"healthy","checks":{"azure_ad_token":"ok"}}' } }
        $DryRun = $false; $Yes = $true; $Update = $false
        $AdminEmail = 'security@contoso.com'; $Location = 'eastus'; $Name = 'm365-ato-monitor'
        $ResponsePermissions = 'no'; $MailSendScope = 'tenant'; $UiAdmins = @(); $SubscriptionId = ''
        Install-Monitor
        $order = [string[]]@($global:Fake.Calls.Line)
        $register = [array]::FindIndex($order, [Predicate[string]]{ param($l) $l -match '^provider register --namespace Microsoft\.Web' })
        $check = [array]::FindLastIndex($order, [Predicate[string]]{ param($l) $l -match '^functionapp list-flexconsumption-locations' })
        $register | Should -BeGreaterOrEqual 0
        $check | Should -BeGreaterThan $register
        @(Get-Calls '^functionapp create').Count | Should -Be 1
    }
}

Describe 'Deploy and status' {
    It 'warns, and does not stop, when the host check fails after a good deployment' {
        New-FakeAzure
        $global:Fake.Created.zipError = 'ERROR: Deployment was successful but the app appears to be unhealthy. Please check the app logs.'
        Mock Start-Sleep {}
        Mock Read-Host { 'y' }
        Mock Invoke-WebRequest { [pscustomobject]@{ StatusCode = 200; Content = '{"status":"healthy","checks":{"azure_ad_token":"ok"}}' } }
        $DryRun = $false; $Yes = $true; $Update = $false
        $AdminEmail = 'security@contoso.com'; $Location = 'eastus'; $Name = 'm365-ato-monitor'
        $ResponsePermissions = 'no'; $MailSendScope = 'tenant'; $UiAdmins = @(); $SubscriptionId = ''
        { Install-Monitor } | Should -Not -Throw
        @(Get-Calls '^functionapp deployment source config-zip').Count | Should -Be 1
        Should -Invoke Invoke-WebRequest -Times 1
    }

    It 'stops for another deployment error' {
        New-FakeAzure
        $global:Fake.Created.zipError = 'ERROR: Remote build failed: pip install exited with code 1'
        Mock Start-Sleep {}
        Mock Read-Host { 'y' }
        $DryRun = $false; $Yes = $true; $Update = $false
        $AdminEmail = 'security@contoso.com'; $Location = 'eastus'; $Name = 'm365-ato-monitor'
        $ResponsePermissions = 'no'; $MailSendScope = 'tenant'; $UiAdmins = @(); $SubscriptionId = ''
        { Install-Monitor } | Should -Throw '*Remote build failed*'
    }

    It 'waits while the platform answers with a 503 page that is not JSON' {
        New-FakeAzure
        Mock Start-Sleep {}
        $global:WebCalls = 0
        Mock Invoke-WebRequest {
            $global:WebCalls++
            if ($global:WebCalls -eq 1) { return [pscustomobject]@{ StatusCode = 503; Content = '<html>Service Unavailable</html>' } }
            [pscustomobject]@{ StatusCode = 503; Content = '{"status":"unhealthy","checks":{"o365_api_audit_general":"FAILED: AF20022"}}' }
        }
        $DryRun = $false
        $script:N = Get-Names 'sub-1' 'm365-ato-monitor'
        $script:HostName = 'func-test.azurewebsites.net'
        { Show-Status 240 } | Should -Not -Throw
        $global:WebCalls | Should -Be 2
        Should -Invoke Start-Sleep -Times 1
    }
}

AfterAll {
    if ($env:M365_ATO_MONITOR_HOME -and (Test-Path $env:M365_ATO_MONITOR_HOME)) { Remove-Item -Recurse -Force $env:M365_ATO_MONITOR_HOME }
    $env:M365_ATO_MONITOR_HOME = $null
}
