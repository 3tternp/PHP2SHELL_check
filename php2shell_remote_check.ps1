<#
.SYNOPSIS
  Authenticated Windows/IIS PHP patch-status checks over PowerShell remoting.
.DESCRIPTION
  Sends the local php2shell_check.ps1 through Invoke-Command -FilePath to each
  authorized Windows host. No HTTP/exploit probe and no file write to targets.
  Remoting must already be configured by the system administrator.
.EXAMPLE
  .\php2shell_remote_check.ps1 -ComputerName WEB01,WEB02
.EXAMPLE
  .\php2shell_remote_check.ps1 -ComputerList .\windows_hosts.txt -UseSSL
.NOTES
  Exit 0 all assessed upstream fixed; 1 any below threshold; 2 vendor review;
       3 unknown/remoting failure; 4 no PHP found on checked hosts.
  Requires Windows PowerShell 5.1 or PowerShell 7+ and the sibling host checker.
#>
[CmdletBinding()]
param(
    [string[]]$ComputerName,
    [string]$ComputerList,
    [string]$CheckerPath = (Join-Path $PSScriptRoot 'php2shell_check.ps1'),
    [pscredential]$Credential,
    [switch]$UseSSL
)
$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $CheckerPath -PathType Leaf)) {
    Write-Error "Local host checker not found: $CheckerPath"
    exit 3
}
$targets = New-Object 'System.Collections.Generic.List[string]'
foreach ($name in @($ComputerName)) {
    if (-not [string]::IsNullOrWhiteSpace($name)) { $targets.Add($name.Trim()) }
}
if ($ComputerList) {
    try {
        foreach ($name in @(Get-Content -LiteralPath $ComputerList -ErrorAction Stop)) {
            $trimmed = $name.Trim()
            if ($trimmed -and -not $trimmed.StartsWith('#')) { $targets.Add($trimmed) }
        }
    } catch {
        Write-Error "Could not read computer list: $($_.Exception.Message)"
        exit 3
    }
}
if ($targets.Count -eq 0) {
    Write-Error 'Provide -ComputerName or -ComputerList.'
    exit 3
}

$counts = @{ Fixed = 0; Below = 0; Review = 0; Unknown = 0; NoPhp = 0 }
Write-Output ('=' * 72)
Write-Output '🛡️  PHP2SHELL Check  🔎  |  Remote Windows / IIS fleet'
Write-Output '🔒 Authenticated PowerShell remoting | read-only checks on target hosts'
Write-Output ('=' * 72)
foreach ($computer in $targets) {
    Write-Output "`nREMOTE_TARGET: $computer"
    $params = @{
        ComputerName = $computer; FilePath = $CheckerPath; ErrorAction = 'Stop'
        ArgumentList = @('', $false, $true) # PhpBin, AsJson, NoExit by position
    }
    if ($Credential) { $params.Credential = $Credential }
    if ($UseSSL) { $params.UseSSL = $true }
    try {
        # FilePath sends the local checker source to the remote session.
        # It runs with the remote session account's privileges. The checker
        # prints its status/exit code without exiting the remote runspace.
        $lines = @(Invoke-Command @params)
        foreach ($line in $lines) { Write-Output "$line" }
        $summaryLines = @($lines | Where-Object { "$_" -match '^OVERALL EXIT CODE: ([0-4])\b' })
        if ($summaryLines.Count -eq 0) { throw 'Checker did not return its summary; verify remote execution and permissions.' }
        $code = [int]([regex]::Match("$($summaryLines[-1])",'^OVERALL EXIT CODE: ([0-4])\b').Groups[1].Value)
        switch ($code) {
            0 { $counts.Fixed++; $label = 'PATCHED_UPSTREAM_VERSIONS_ASSESSED' }
            1 { $counts.Below++; $label = 'BELOW_FIXED_VERSION' }
            2 { $counts.Review++; $label = 'REVIEW_VENDOR_BACKPORT' }
            3 { $counts.Unknown++; $label = 'UNKNOWN' }
            4 { $counts.NoPhp++; $label = 'NO_PHP_FOUND' }
        }
        Write-Output "REMOTE_SUMMARY | $computer | $label | checker_exit=$code"
    } catch {
        $counts.Unknown++
        Write-Output "REMOTE_SUMMARY | $computer | REMOTE_UNKNOWN_OR_TRANSPORT_FAILURE | $($_.Exception.Message)"
    }
}
Write-Output "`nFLEET_SUMMARY | fixed=$($counts.Fixed) below=$($counts.Below) vendor_review=$($counts.Review) unknown=$($counts.Unknown) no_php=$($counts.NoPhp)"
Write-Output 'Confirm web SAPI, backport evidence, and worker restart on each host before closing.'
if ($counts.Below -gt 0) { exit 1 }
elseif ($counts.Unknown -gt 0) { exit 3 }
elseif ($counts.Review -gt 0) { exit 2 }
elseif ($counts.NoPhp -gt 0) { exit 4 }
else { exit 0 }
