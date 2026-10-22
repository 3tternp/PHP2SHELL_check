<#
.SYNOPSIS
  Read-only PHP2Shell patch-status inventory for Windows / IIS.
.DESCRIPTION
  Checks local PHP binary versions with -v and records IIS FastCGI bindings and
  running PHP processes. A vendor backport, service mapping, or worker restart
  cannot be proven from a version string alone. No network or exploit probe.
.PARAMETER PhpBin
  Check one executable path instead of discovery. An IIS site may use another.
.PARAMETER AsJson
  Emit one JSON object containing results, warnings and the overall exit code.
.PARAMETER NoExit
  Internal remoting option: return output without ending the remote runspace.
.NOTES
  Exit 0 = all assessed upstream-fixed; 1 = below fixed; 2 = vendor review;
       3 = incomplete/unknown; 4 = no PHP binary found. See companion playbook.
  Compatible with Windows PowerShell 5.1 and PowerShell 7+.
#>
[CmdletBinding()]
param(
    [string]$PhpBin,
    [switch]$AsJson,
    [switch]$NoExit
)

$ErrorActionPreference = 'Stop'
$fixed = @{ '8.2' = 35; '8.3' = 36; '8.4' = 27; '8.5' = 12 }
$items = @{}
$warnings = New-Object 'System.Collections.Generic.List[string]'
$incomplete = $false

function Add-Candidate {
    param([string]$Path, [string]$Evidence)
    if ([string]::IsNullOrWhiteSpace($Path)) { return }
    try {
        $file = Get-Item -LiteralPath $Path -ErrorAction Stop
        if ($file.PSIsContainer) { throw 'path is a directory' }
        $key = $file.FullName.ToLowerInvariant()
        if (-not $script:items.ContainsKey($key)) {
            $script:items[$key] = [pscustomobject]@{ Path = $file.FullName; Evidence = @($Evidence) }
        } elseif ($script:items[$key].Evidence -notcontains $Evidence) {
            $script:items[$key].Evidence = @($script:items[$key].Evidence) + @($Evidence)
        }
    } catch {
        $script:warnings.Add("Candidate unavailable [$Evidence]: $Path")
        if ($Evidence -like 'IIS_FASTCGI*' -or $Evidence -eq 'EXPLICIT_PATH') { $script:incomplete = $true }
    }
}

if ($PhpBin) {
    Add-Candidate -Path $PhpBin -Evidence 'EXPLICIT_PATH'
} else {
    foreach ($name in @('php.exe','php-cgi.exe')) {
        try {
            foreach ($cmd in @(Get-Command $name -All -ErrorAction SilentlyContinue)) {
                if ($cmd -and $cmd.Source) { Add-Candidate -Path $cmd.Source -Evidence 'PATH' }
            }
        } catch { }
    }

    # Bounded roots. -Recurse is used only under familiar PHP install directories.
    $patterns = @('C:\PHP*','C:\xampp\php*','C:\wamp*\bin\php\*',
                  'C:\Program Files\PHP*','C:\Program Files (x86)\PHP*')
    foreach ($pattern in $patterns) {
        foreach ($root in @(Get-Item -Path $pattern -ErrorAction SilentlyContinue)) {
            if (-not $root.PSIsContainer) { continue }
            foreach ($name in @('php.exe','php-cgi.exe')) {
                try {
                    Get-ChildItem -LiteralPath $root.FullName -Filter $name -File -Recurse -ErrorAction Stop |
                        ForEach-Object { Add-Candidate -Path $_.FullName -Evidence 'DISCOVERED' }
                } catch {
                    $warnings.Add("Could not fully scan install root: $($root.FullName)")
                    $incomplete = $true
                }
            }
        }
    }
}

# Read IIS binding even with -PhpBin to flag a different active FastCGI binary.
$appHost = Join-Path $env:windir 'System32\inetsrv\config\applicationHost.config'
if (Test-Path -LiteralPath $appHost) {
    try {
        [xml]$config = Get-Content -LiteralPath $appHost -Raw -ErrorAction Stop
        foreach ($node in @($config.SelectNodes('//system.webServer/fastCgi/application'))) {
            if ($node.fullPath -match '(?i)php(?:-cgi)?\.exe$') {
                if ($PhpBin) {
                    $resolved = $null
                    try { $resolved = (Get-Item -LiteralPath $node.fullPath -ErrorAction Stop).FullName }
                    catch { $warnings.Add("IIS FastCGI binding unavailable: $($node.fullPath)"); $incomplete = $true }
                    if ($resolved -and $items.Count -gt 0 -and $items.Values.Path -notcontains $resolved) {
                        $warnings.Add("IIS uses another PHP binary: $resolved (run without -PhpBin)")
                        $incomplete = $true
                    }
                } else { Add-Candidate -Path $node.fullPath -Evidence 'IIS_FASTCGI' }
            }
        }
    } catch {
        $warnings.Add('IIS applicationHost.config could not be read or parsed; run elevated and verify bindings manually.')
        $incomplete = $true
    }
}

try {
    foreach ($proc in @(Get-CimInstance Win32_Process -Filter "Name='php.exe' OR Name='php-cgi.exe'" -ErrorAction Stop)) {
        if ([string]::IsNullOrEmpty($proc.ExecutablePath)) {
            $warnings.Add("Running PHP PID $($proc.ProcessId) path unavailable; rerun elevated.")
            $incomplete = $true
        } elseif ($PhpBin) {
            if ($items.Values.Path -notcontains $proc.ExecutablePath) {
                $warnings.Add("Running PHP PID $($proc.ProcessId) uses another path: $($proc.ExecutablePath)")
                $incomplete = $true
            } else { Add-Candidate -Path $proc.ExecutablePath -Evidence 'RUNNING_PROCESS' }
        } else { Add-Candidate -Path $proc.ExecutablePath -Evidence 'RUNNING_PROCESS' }
    }
} catch { $warnings.Add('Could not query running PHP processes; verify service processes manually.'); $incomplete = $true }

$results = New-Object 'System.Collections.Generic.List[object]'
foreach ($candidate in @($items.Values | Sort-Object Path)) {
    $version = $null; $branch = $null; $status = 'UNKNOWN'; $required = $null
    try {
        $raw = & $candidate.Path -v 2>$null
        if ($LASTEXITCODE -ne 0) { throw "PHP -v exited $LASTEXITCODE" }
        $line = "$(($raw | Select-Object -First 1))"
        if ($line -notmatch 'PHP\s+(\d+)\.(\d+)\.(\d+)') { throw 'Unrecognized PHP -v output' }
        $major = [int]$Matches[1]; $minor = [int]$Matches[2]; $patch = [int]$Matches[3]
        $version = "$major.$minor.$patch"; $branch = "$major.$minor"
        if ($fixed.ContainsKey($branch)) {
            $required = "$branch.$($fixed[$branch])"
            if ($patch -ge $fixed[$branch]) { $status = 'PATCHED_UPSTREAM_VERSION' }
            else { $status = 'BELOW_FIXED_VERSION' }
        } else { $status = 'REVIEW_VENDOR_BACKPORT' }
    } catch { $warnings.Add("Version check failed for $($candidate.Path): $($_.Exception.Message)") }
    $results.Add([pscustomobject]@{
        Status = $status; Path = $candidate.Path; Version = $version
        Required = $required; Evidence = @($candidate.Evidence)
    })
}

if ($results.Count -eq 0) { $exitCode = if ($incomplete) { 3 } else { 4 } }
elseif (@($results | Where-Object Status -eq 'BELOW_FIXED_VERSION').Count -gt 0) { $exitCode = 1 }
elseif ($incomplete -or @($results | Where-Object Status -eq 'UNKNOWN').Count -gt 0) { $exitCode = 3 }
elseif (@($results | Where-Object Status -eq 'REVIEW_VENDOR_BACKPORT').Count -gt 0) { $exitCode = 2 }
else { $exitCode = 0 }

$output = [pscustomobject]@{
    Host = $env:COMPUTERNAME; CheckedAtUtc = (Get-Date).ToUniversalTime().ToString('o')
    Cves = @('CVE-2026-109618','CVE-2026-109619')
    Results = @($results.ToArray()); Warnings = @($warnings.ToArray())
    ExitCode = $exitCode
    Scope = 'Local executable versions and IIS FastCGI registration; confirm vendor backport, application mapping, and running worker build manually.'
}
if ($AsJson) { $output | ConvertTo-Json -Depth 6 }
else {
    Write-Output ('=' * 72)
    Write-Output '🛡️  PHP2SHELL Check  🔎'
    Write-Output ('=' * 72)
    Write-Output "📍 Host: $($output.Host)  |  🕒 Checked (UTC): $($output.CheckedAtUtc)"
    Write-Output '🔒 Read-only patch-status inventory | CVE-2026-109618 / CVE-2026-109619'
    Write-Output ('-' * 72)
    foreach ($entry in $output.Results) {
        Write-Output "$($entry.Status) | $($entry.Path) | PHP $($entry.Version) | required $($entry.Required) | $($entry.Evidence -join ',')"
    }
    foreach ($warning in $output.Warnings) { Write-Output "WARNING | $warning" }
    Write-Output "OVERALL EXIT CODE: $exitCode | $($output.Scope)"
}
if ($NoExit) { return }
exit $exitCode
