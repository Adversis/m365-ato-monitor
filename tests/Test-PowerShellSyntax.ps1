# Parse every .ps1 file in the repository. Exit 1 on a syntax error.
$failed = $false
$root = Split-Path -Parent $PSScriptRoot
foreach ($file in Get-ChildItem -Path $root -Recurse -Filter *.ps1 | Where-Object { $_.FullName -notmatch '[\\/]\.git[\\/]' }) {
    $errors = $null
    $null = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$null, [ref]$errors)
    foreach ($e in $errors) {
        Write-Output "::error file=$($file.FullName),line=$($e.Extent.StartLineNumber)::$($e.Message)"
        $failed = $true
    }
    Write-Output "$($file.Name): $(if ($errors.Count) { 'ERRORS' } else { 'syntax OK' })"
}
if ($failed) { exit 1 }
