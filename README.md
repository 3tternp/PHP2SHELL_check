# 🛡️ PHP2SHELL Check 🔎

> **🐧 Linux** · **🪟 Windows / IIS** · **🌐 Remote URL hints** · **🔒 Read-only PHP checks**

---

Read-only checks for **CVE-2026-109618** and **CVE-2026-109619**. Host scripts inventory PHP executables and compare versions with the first upstream releases that fix both vulnerabilities. The URL script checks only version hints disclosed in HTTP headers.

> **A version result is an inventory finding, not proof that a website is safe.** Confirm the PHP runtime serving each site, any vendor backport, and that web workers have restarted after updating. The URL checker sends a normal HEAD or GET request; none of these scripts attempts exploitation.

## 📦 Files

| File | Platform | What it checks |
| --- | --- | --- |
| [`php2shell_check.sh`](php2shell_check.sh) | Linux | Common PHP CLI, FPM and CGI paths, symlinks, and best-effort running-process paths under `/proc`. |
| [`php2shell_check.ps1`](php2shell_check.ps1) | Windows / IIS | PHP on `PATH`, common installation directories, IIS FastCGI application registrations, and running PHP processes. Supports JSON output. |
| [`php2shell_remote_check.sh`](php2shell_remote_check.sh) | Linux SSH fleet | Runs the Linux host checker through authenticated SSH on specified hosts and summarizes results. |
| [`php2shell_remote_check.ps1`](php2shell_remote_check.ps1) | Windows WinRM fleet | Runs the Windows host checker through PowerShell remoting on specified computers and summarizes results. |
| [`php2shell_url_check.py`](php2shell_url_check.py) | HTTP(S) URL | Passively inspects `X-Powered-By` and `Server` version hints; cannot establish the actual serving PHP build or exploitability. |

## ✅ Fixed upstream releases

| PHP branch | First fixed version |
| --- | --- |
| 8.5 | 8.5.12 |
| 8.4 | 8.4.27 |
| 8.3 | 8.3.36 |
| 8.2 | 8.2.35 |
| 8.1 and earlier | No supported upstream release. Verify a vendor/source backport or migrate. |

A Linux distribution or long-term support vendor may backport the fixes while retaining an older upstream version string. The scripts therefore flag versions below the upstream threshold for **package-level review** rather than asserting that every such build is vulnerable.

### Console banner

The local scripts and remote wrappers display the same banner in their normal text output (the remote wrappers add the fleet label):

```text
========================================================================
🛡️  PHP2SHELL Check  🔎
========================================================================
📍 Host: web-server-01  |  🕒 Checked (UTC): 2026-10-22T09:00:00Z
🔒 Read-only patch-status inventory | CVE-2026-109618 / CVE-2026-109619
------------------------------------------------------------------------
```

Windows `-AsJson` and the URL checker's `--json` emit machine-readable JSON without the decorative banner.

## ⚙️ Requirements

- Linux: Bash, `find`, `readlink`, and permission to execute the selected local PHP binaries. Access to `/proc` improves running-process visibility. GNU `readlink -f` is used.
- Windows: Windows PowerShell 5.1 or PowerShell 7+, with permission to execute the selected PHP binaries. Run from an elevated session when IIS configuration or process information is access restricted.
- Remote Linux: OpenSSH client, SSH access to each target, configured authentication and a trusted host key in `known_hosts`.
- Remote Windows: PowerShell remoting already enabled for authorized accounts. Use your environment's approved WinRM authentication and transport settings.
- Remote URL: Python 3.8+ with standard library only and network access to the authorized endpoint. TLS certificates are validated; redirects are not followed.
- Run scripts only on systems you administer or are authorized to assess. They execute candidate PHP binaries with the `-v` argument and do not change PHP settings.

## 🚀 Usage

### Linux

```bash
chmod +x ./php2shell_check.sh
./php2shell_check.sh
printf 'Exit code: %s\n' "$?"
```

To check one known executable:

```bash
PHP_BIN=/usr/sbin/php-fpm8.4 ./php2shell_check.sh
```

Run the script **inside each relevant container/runtime namespace** as well as on the host. The host scan cannot inventory every container filesystem. If PHP uses Apache `mod_php`, identify its loaded module and package separately; it is not a standalone `php` process.

### Windows / IIS

From PowerShell in the directory containing the script:

```powershell
.\php2shell_check.ps1
$LASTEXITCODE
```

To check one executable or collect JSON:

```powershell
.\php2shell_check.ps1 -PhpBin 'C:\PHP\php-cgi.exe'
.\php2shell_check.ps1 -AsJson | Out-File .\php2shell_status.json -Encoding utf8
$LASTEXITCODE
```

`-PhpBin` narrows the executable version check. The Windows script still checks IIS registration and running processes for another path, reporting a scope warning when it sees one. The IIS configuration may require elevation. Follow your organization's PowerShell execution policy when running the script.

### Remote Linux fleet over SSH

Keep `php2shell_remote_check.sh` and `php2shell_check.sh` in the same directory. The remote wrapper streams the local checker to each Linux host over authenticated SSH; it does not copy a file to the target.

```bash
chmod +x ./php2shell_remote_check.sh
./php2shell_remote_check.sh --host socuser@web01.example.com --host socuser@web02.example.com
printf 'Fleet exit code: %s\n' "$?"
```

For a host list, use one SSH target or configured SSH alias per line. Blank lines and `#` comments are ignored:

```bash
./php2shell_remote_check.sh --hosts-file linux_hosts.txt
./php2shell_remote_check.sh --host web01 --port 2222 --identity ~/.ssh/php_audit_key
```

The wrapper uses noninteractive SSH and strict host-key verification. Arrange trusted SSH keys/host keys in advance; do not disable verification to make a check pass. Run the checker separately inside each relevant container. A remote transport failure is reported as `REMOTE_UNKNOWN_OR_TRANSPORT_FAILURE`, not as a clean result.

### Remote Windows / IIS fleet over PowerShell remoting

Keep `php2shell_remote_check.ps1` and `php2shell_check.ps1` in the same directory. The wrapper uses `Invoke-Command -FilePath` to send the local checker to each authorized remote Windows host. PowerShell remoting must already be configured; the script does not enable it.

```powershell
.\php2shell_remote_check.ps1 -ComputerName WEB01,WEB02
$LASTEXITCODE
```

You can use a file with one computer name per line, or supply approved credentials and SSL transport as required by your environment:

```powershell
.\php2shell_remote_check.ps1 -ComputerList .\windows_hosts.txt -UseSSL
.\php2shell_remote_check.ps1 -ComputerName WEB01 -Credential (Get-Credential)
```

Do not put passwords in the host list or command line. Run with a remote account that can inspect the IIS FastCGI mapping and PHP processes; inaccessible paths are assessment gaps. A remoting error is reported as unknown.

### Remote URL inspection (no host credentials)

Use this when you can reach a site but cannot yet run the host checker. It makes one ordinary `HEAD` request per URL and examines only explicit PHP versions in the `X-Powered-By` and `Server` response headers. Supply the final URL explicitly; redirects are not followed. Use only URLs you are authorized to assess.

```bash
python3 ./php2shell_url_check.py --url https://app.example.com/ --url https://portal.example.com/
python3 ./php2shell_url_check.py --urls-file authorized_urls.txt --json > url_results.json
```

If the server rejects `HEAD` with HTTP 405, rerun using `--method GET`. A GET response body is neither read nor parsed. The URL list uses one URL per line; blank lines and lines starting with `#` are ignored. Avoid sensitive query strings; the tool omits queries from its output but still sends them to the server.

| URL status | Meaning |
| --- | --- |
| `BELOW_FIXED_VERSION_DISCLOSED` | An HTTP header explicitly advertises a PHP version below the upstream threshold. Investigate the actual runtime and vendor backports. |
| `AT_OR_ABOVE_FIXED_VERSION_DISCLOSED` | A header advertises a version at or above the threshold. This is a hint, **not** confirmation that the site is patched. |
| `REVIEW_VENDOR_BACKPORT` | A version was disclosed on a branch outside the listed thresholds. Verify the vendor fix. |
| `VERSION_NOT_DISCLOSED` / `CONFLICTING_VERSION_HINTS` | Header evidence cannot establish a single PHP version. |
| `REDIRECT_UNDETERMINED` / `METHOD_NOT_ALLOWED` / `HTTP_ERROR_UNDETERMINED` / `REQUEST_FAILED` | The check did not get usable version evidence. Follow the stated action or inspect the host. |

URL checker exit codes: `0` only means every checked endpoint disclosed a version at or above the threshold; `1` means at least one below-threshold hint; `2` means missing/conflicting version hints; `3` means a request/HTTP/redirect/method failure; `4` means another branch needs backport review. For mixed results, priority is `1`, `3`, `4`, `2`, then `0`. Inspect each row. A proxy, load balancer, CDN, or arbitrary header can supply a misleading version. Many sites disclose no version at all. **Use the authenticated host scripts and package evidence to verify patch status.**

## 🔎 Interpret the results

| Status | Meaning | Action |
| --- | --- | --- |
| `PATCHED_UPSTREAM_VERSION` | The assessed executable reports a version at or above its branch's first fixed upstream release. | Confirm this executable serves the site, restart/recycle workers, and verify the active build. |
| `BELOW_FIXED_VERSION` | The assessed executable reports a lower version on a supported branch. | Update or obtain a vendor advisory/package changelog explicitly covering both CVEs. |
| `REVIEW_VENDOR_BACKPORT` | The branch is outside the supported upstream thresholds used by the script. | Verify a vendor/source fix for both CVEs and plan migration. |
| `UNKNOWN` | The executable version could not be read. | Check permissions/path and rerun. |
| `UNKNOWN_RUNNING_PROCESS` | On Linux, a PHP process still points to a replaced/deleted executable. | Restart/recycle the service and verify again. |
| `NO_PHP_FOUND` | No candidate executable was found in the scanned locations. | Check custom paths, containers, managed hosting and `mod_php` manually. |

On Linux, `RUNNING_PROCESS` means the executable path was observed under `/proc`; `DISCOVERED_ONLY` means the file was found but was not observed running. This does not establish which application uses the binary.

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Every executable assessed meets an upstream fixed-version threshold, with no reported assessment gap. Service-level confirmation is still required. |
| `1` | At least one assessed executable is below its branch's fixed upstream version. |
| `2` | No below-threshold result, but an older/other branch requires vendor backport review. |
| `3` | The assessment is incomplete or a version could not be determined. |
| `4` | No PHP executable was found by discovery. |

For mixed results, the overall code favors `1`, then `3`, then `2`; review **every result row and warning**. In particular, exit `0` does not prove that every web-facing SAPI, container or vendor package is patched.

Remote wrappers use the same codes for a fleet: `1` if any host reports a below-threshold version, otherwise `3` for any unknown/transport failure, otherwise `2` for vendor review, otherwise `4` if any host found no PHP, or `0` when all hosts checked return `0`. Review each `REMOTE_SUMMARY` row; mixed `0` and `4` still requires scope validation.

## 🧾 Close a patch finding

1. Map each website, FPM pool, IIS FastCGI binding, `mod_php` installation, container, or managed service to its **actual serving PHP runtime**.
2. For a version below the upstream threshold, verify the installed vendor package release and advisory/changelog explicitly naming **both CVEs**, or install a fixed upstream release.
3. Restart or recycle serving workers after patching. Confirm no old executable remains loaded and the site uses the intended build.
4. Rerun the appropriate script from the relevant host/container and retain its output with the change ticket, package evidence, runtime mapping, and restart timestamp.
5. If patching is delayed, track temporary controls and monitoring separately. A workaround does not make the script report a patched state.

## ⚠️ Limitations and validation

- The host checks inspect local executable versions. The URL checker inspects selected HTTP response headers. None tests whether either vulnerability is exploitable or establishes that an environment has been compromised.
- PHP CLI settings may differ from PHP-FPM, Apache `mod_php`, CGI and IIS configurations. The scripts intentionally do **not** use interim mitigation settings to declare a host patched.
- Discovery is best effort. Custom launchers, inaccessible process paths, multiple PHP installations, containers and hosted platforms may require additional inventory.
- The local Bash checker was syntax-checked with mock version fixtures. The SSH wrapper was checked with simulated remote results and transport failures. The PowerShell host checker and WinRM wrapper have not been run on a live Windows/IIS environment; validate both on representative systems before fleet rollout.
- The authenticated remote scripts run the local checker on their targets. The URL script cannot determine patch status from a website URL alone. All checks still require service mapping, vendor evidence, and worker-restart verification above.

## 📚 References

- [PHP project security release and guidance](https://www.php.net/archive/2026.php#2026-10-21-5)
- [CVE-2026-109618 PHP advisory](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w)
- [CVE-2026-109619 PHP advisory](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)
- [PHP supported versions](https://www.php.net/supported-versions.php)

Reviewed 22 October 2026.
