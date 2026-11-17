#Requires -Version 7.1
<#
.SYNOPSIS
    Show the monitor's errors from Application Insights. Read only.

.DESCRIPTION
    Runs the "Errors" query of docs/APP_INSIGHTS_QUERIES.md (traces with
    severity Error or Critical) through Azure Resource Manager, with your
    Azure CLI sign-in. It changes nothing and needs no function key. You need
    read access to the monitor's resource group (Reader, Monitoring Reader, or
    Owner).

    The script finds the installation from ~/.m365-ato-monitor/tenants.json
    (written by install.ps1): -Tenant, or the saved installation in the
    tenant that the Azure CLI is signed in to. Else it uses -Name and the
    current subscription.

    The output first counts the errors by message, then lists the newest.

.PARAMETER Hours
    How far back to look. Default 24. 1 to 720 (30 days).

.PARAMETER Tenant
    A saved installation: its domain, tenant name, or tenant ID (see
    ./install.ps1 -List). The Azure CLI must be signed in to that tenant.

.PARAMETER Name
    The base name of the resources (install.ps1 -Name). Default: the saved
    installation's name, else m365-ato-monitor.

.PARAMETER SubscriptionId
    The subscription of the monitor. Default: the saved installation's, else
    the current one (az account show).

.PARAMETER Warnings
    Include warnings (severity 2).

.PARAMETER Top
    How many of the newest messages to list. Default 50.

.PARAMETER Full
    Show the whole message (with the stack trace) instead of the first line.

.PARAMETER All
    Also show the host's "Exception encountered while listening to EventStream"
    errors. Azure logs one when it stops an instance (scale-in or recycle).

.PARAMETER Kql
    Run this query instead (for example another query from
    docs/APP_INSIGHTS_QUERIES.md). -Hours, -Warnings, and -Top do not apply.

.EXAMPLE
    ./scripts/errors.ps1

.EXAMPLE
    ./scripts/errors.ps1 -Tenant contoso.com -Hours 72 -Full

.EXAMPLE
    ./scripts/errors.ps1 -Kql 'traces | where message startswith "Compromise indicator" | take 20'
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 720)][int]$Hours = 24,
    [string]$Tenant,
    [string]$Name,
    [string]$SubscriptionId,
    [switch]$Warnings,
    [ValidateRange(1, 1000)][int]$Top = 50,
    [switch]$Full,
    [switch]$All,
    [string]$Kql
)

$ErrorActionPreference = 'Stop'

function Stop-Script([string]$Message, [string]$Fix = '') {
    Write-Host "ERROR: $Message" -ForegroundColor Red
    if ($Fix) { Write-Host "Fix: $Fix" }
    exit 1
}

function Invoke-Az([string[]]$Arguments) {
    $out = & az @Arguments 2>&1
    if ($LASTEXITCODE -ne 0) { throw (($out | Out-String).Trim()) }
    return ($out | Where-Object { $_ -is [string] }) -join "`n"
}

if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    Stop-Script 'The Azure CLI (az) is not installed.' 'Install it: see AGENTS.md > Deploy > Check the prerequisites.'
}
try { $account = Invoke-Az @('account', 'show', '-o', 'json') | ConvertFrom-Json }
catch { Stop-Script 'The Azure CLI is not signed in.' 'Run: az login --tenant <your tenant domain>' }

# The saved installation (install.ps1 writes it).
$root = if ($env:M365_ATO_MONITOR_HOME) { $env:M365_ATO_MONITOR_HOME } else { Join-Path $HOME '.m365-ato-monitor' }
$statePath = Join-Path $root 'tenants.json'
$records = @()
if (Test-Path -LiteralPath $statePath) {
    try { $records = @(Get-Content -Raw -LiteralPath $statePath | ConvertFrom-Json -Depth 10) } catch { }
}
$saved = $null
if ($Tenant) {
    $t = $Tenant.Trim().ToLowerInvariant()
    $match = @($records | Where-Object { "$($_.tenantId)" -eq $t -or "$($_.domain)" -eq $t -or "$($_.tenantName)".ToLowerInvariant() -eq $t -or @($_.domains) -contains $t })
    if ($match.Count -ne 1) {
        Stop-Script "No saved installation for '$Tenant'." "Use a domain that ./install.ps1 -List shows, or pass -Name and -SubscriptionId."
    }
    $saved = $match[0]
    if ("$($saved.tenantId)" -ne "$($account.tenantId)") {
        Stop-Script "The Azure CLI is signed in to another tenant." "Run: az login --tenant $($saved.domain)"
    }
}
else {
    $match = @($records | Where-Object { "$($_.tenantId)" -eq "$($account.tenantId)" })
    if ($match.Count -eq 1) { $saved = $match[0] }
}

$sub = if ($SubscriptionId) { $SubscriptionId } elseif ($saved) { "$($saved.subscriptionId)" } else { "$($account.id)" }
$base = if ($Name) { $Name } elseif ($saved -and $saved.name) { "$($saved.name)" } else { 'm365-ato-monitor' }
$clean = ($base.ToLowerInvariant() -replace '[^a-z0-9-]', '')
if (-not $clean) { Stop-Script "Name '$base' is not valid." }
# The same names as install.ps1 (Get-Names).
$resourceGroup = "rg-$clean"
$appInsights = "appi-$clean"
$label = if ($saved) { "$($saved.domain) ($resourceGroup)" } else { $resourceGroup }

$minLevel = if ($Warnings) { 2 } else { 3 }
$query = if ($Kql) { $Kql } else {
@"
traces
| where timestamp > ago(${Hours}h)
| where severityLevel >= $minLevel
| extend host_stop = tostring(customDimensions.Category) == "Microsoft.Azure.WebJobs.Script.Grpc.FunctionRpcService"
    and message == "Exception encountered while listening to EventStream"
| project timestamp, severityLevel, message, host_stop
| order by timestamp desc
"@
}

$url = "https://management.azure.com/subscriptions/$sub/resourceGroups/$resourceGroup/providers/" +
       "Microsoft.Insights/components/$appInsights/query?api-version=2018-04-20"
$bodyFile = New-TemporaryFile
try {
    @{ query = $query } | ConvertTo-Json -Compress | Set-Content -LiteralPath $bodyFile -Encoding utf8NoBOM
    Write-Host "Querying $appInsights in $label, subscription $sub ..." -ForegroundColor DarkGray
    $result = Invoke-Az @('rest', '--method', 'post', '--url', $url, '--body', "@$bodyFile",
                          '--headers', 'Content-Type=application/json', '-o', 'json') | ConvertFrom-Json -Depth 20
}
catch {
    $text = "$_"
    if ($text -match 'ResourceNotFound|ResourceGroupNotFound|could not be found') {
        Stop-Script "Application Insights $appInsights was not found in $resourceGroup." 'Pass -Tenant, -Name, or -SubscriptionId (./install.ps1 -List shows the installations).'
    }
    if ($text -match 'AuthorizationFailed|Forbidden|403') {
        Stop-Script 'Access denied.' "Your account needs Reader or Monitoring Reader on $resourceGroup."
    }
    Stop-Script "The query failed: $text"
}
finally { Remove-Item -LiteralPath $bodyFile -ErrorAction SilentlyContinue }

$table = @($result.tables)[0]
$columns = @($table.columns | ForEach-Object { $_.name })
$rows = foreach ($r in @($table.rows)) {
    $o = [ordered]@{}
    for ($i = 0; $i -lt $columns.Count; $i++) { $o[$columns[$i]] = $r[$i] }
    [pscustomobject]$o
}
$rows = @($rows)

if ($Kql) {
    if (-not $rows.Count) { Write-Host 'No rows.'; exit 0 }
    $rows | Format-List
    exit 0
}

# The Functions host logs this error when Azure stops an instance (scale-in or recycle): the
# worker's connection closes during "Stopping JobHost". It is not an error of the monitor.
$hostStops = @($rows | Where-Object { $_.host_stop -eq $true })
if (-not $All) { $rows = @($rows | Where-Object { $_.host_stop -ne $true }) }
$what = if ($Warnings) { 'errors and warnings' } else { 'errors' }
if ($hostStops.Count -and -not $All) {
    Write-Host ("Not shown: $($hostStops.Count) 'Exception encountered while listening to EventStream' " +
                "(the Functions host when Azure stops an instance; -All shows them).") -ForegroundColor DarkGray
}
if (-not $rows.Count) {
    Write-Host "No $what in the last $Hours hours." -ForegroundColor Green
    exit 0
}

$level = @{ 2 = 'Warning'; 3 = 'Error'; 4 = 'Critical' }
function Get-FirstLine([string]$Text) { (($Text -split "`r?`n")[0]).Trim() }

Write-Host ""
Write-Host "$($rows.Count) $what in the last $Hours hours, by message:" -ForegroundColor Yellow
$rows | Group-Object { Get-FirstLine $_.message } | Sort-Object Count -Descending | ForEach-Object {
    $newest = ($_.Group | Sort-Object timestamp -Descending | Select-Object -First 1).timestamp
    [pscustomobject]@{ Count = $_.Count; Newest = ([datetime]$newest).ToUniversalTime().ToString('yyyy-MM-dd HH:mm'); Message = $_.Name }
} | Format-Table -AutoSize -Wrap

Write-Host "Newest $([Math]::Min($Top, $rows.Count)) (UTC):" -ForegroundColor Yellow
foreach ($r in ($rows | Select-Object -First $Top)) {
    $when = ([datetime]$r.timestamp).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss')
    $sev = $level[[int]$r.severityLevel] ?? "$($r.severityLevel)"
    $text = if ($Full) { "$($r.message)" } else { Get-FirstLine $r.message }
    Write-Host "$when  $sev  $text"
}
