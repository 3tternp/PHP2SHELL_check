#!/usr/bin/env bash
# Authenticated Linux fleet inventory over SSH. No HTTP/exploit probing.
# Executes the sibling php2shell_check.sh on each remote host through stdin.
set -uo pipefail

usage() {
  cat <<'HELP'
Usage: ./php2shell_remote_check.sh --host user@server [--host user@server ...]
       ./php2shell_remote_check.sh --hosts-file hosts.txt
Options:
  --host HOST        SSH target or configured alias; may repeat
  --hosts-file FILE  One SSH target per line; blank lines and # comments ignored
  --checker FILE     Local host checker (default: sibling php2shell_check.sh)
  --port N           SSH port, 1-65535 (default: 22)
  --identity FILE    SSH private key path (optional; agent/config also supported)
  --help             Show this help
SSH uses BatchMode and strict known-host verification; configure authentication
and known_hosts before running. No files are written on the target.
Exit: 0 all fixed-version checks; 1 any below threshold; 2 backport review;
      3 unknown/SSH failure; 4 no PHP found on every checked host.
HELP
}

targets=(); hosts_file=''; port=22; identity=''
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
checker="$script_dir/php2shell_check.sh"
while (($#)); do
  case "$1" in
    --host) (($# >= 2)) || { usage >&2; exit 3; }; targets+=("$2"); shift 2 ;;
    --hosts-file) (($# >= 2)) || { usage >&2; exit 3; }; hosts_file="$2"; shift 2 ;;
    --checker) (($# >= 2)) || { usage >&2; exit 3; }; checker="$2"; shift 2 ;;
    --port) (($# >= 2)) || { usage >&2; exit 3; }; port="$2"; shift 2 ;;
    --identity) (($# >= 2)) || { usage >&2; exit 3; }; identity="$2"; shift 2 ;;
    --help) usage; exit 0 ;;
    *) printf 'Unknown argument: %s\n' "$1" >&2; usage >&2; exit 3 ;;
  esac
done
[[ "$port" =~ ^[0-9]+$ ]] && ((10#$port >= 1 && 10#$port <= 65535)) || { printf 'Invalid SSH port.\n' >&2; exit 3; }
[[ -r "$checker" ]] || { printf 'Cannot read local checker: %s\n' "$checker" >&2; exit 3; }
if [[ -n "$hosts_file" ]]; then
  [[ -r "$hosts_file" ]] || { printf 'Cannot read hosts file: %s\n' "$hosts_file" >&2; exit 3; }
  while IFS= read -r host || [[ -n "$host" ]]; do
    host="${host%$'\r'}"
    [[ -z "$host" || "$host" =~ ^[[:space:]]*# ]] && continue
    targets+=("$host")
  done < "$hosts_file"
fi
((${#targets[@]} > 0)) || { printf 'No SSH targets supplied.\n' >&2; usage >&2; exit 3; }
if [[ -n "$identity" && ! -r "$identity" ]]; then printf 'Cannot read identity file.\n' >&2; exit 3; fi
command -v ssh >/dev/null 2>&1 || { printf 'OpenSSH client not found.\n' >&2; exit 3; }

ssh_args=(-T -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=10 -p "$port")
[[ -z "$identity" ]] || ssh_args+=(-i "$identity")
below=0; review=0; unknown=0; no_php=0; fixed=0
printf '%s\n' '========================================================================'
printf '%s\n' '🛡️  PHP2SHELL Check  🔎  |  Remote Linux fleet'
printf '%s\n' '🔒 Authenticated SSH | read-only local version checks on target hosts'
printf '%s\n' '========================================================================'
for host in "${targets[@]}"; do
  # Validate names before passing them to ssh; leading hyphens/options and
  # whitespace are deliberately disallowed. Use ~/.ssh/config for complex names.
  if [[ "$host" == -* || ! "$host" =~ ^[A-Za-z0-9_.:@-]+$ ]]; then
    printf 'REMOTE_UNKNOWN | invalid target: %s\n' "$host" >&2
    unknown=$((unknown+1)); continue
  fi
  printf '\nREMOTE_TARGET: %s\n' "$host"
  ssh "${ssh_args[@]}" "$host" 'bash -s' < "$checker"
  rc=$?
  case "$rc" in
    0) fixed=$((fixed+1)); label='PATCHED_UPSTREAM_VERSIONS_ASSESSED' ;;
    1) below=$((below+1)); label='BELOW_FIXED_VERSION' ;;
    2) review=$((review+1)); label='REVIEW_VENDOR_BACKPORT' ;;
    4) no_php=$((no_php+1)); label='NO_PHP_FOUND' ;;
    *) unknown=$((unknown+1)); label="REMOTE_UNKNOWN_OR_TRANSPORT_FAILURE ($rc)" ;;
  esac
  printf 'REMOTE_SUMMARY | %s | %s | checker_exit=%s\n' "$host" "$label" "$rc"
done
printf '\nFLEET_SUMMARY | fixed=%s below=%s vendor_review=%s unknown=%s no_php=%s\n' "$fixed" "$below" "$review" "$unknown" "$no_php"
printf '%s\n' 'Confirm web SAPI, backport evidence, and worker restart on each host before closing.'
if ((below > 0)); then exit 1
elif ((unknown > 0)); then exit 3
elif ((review > 0)); then exit 2
elif ((no_php > 0)); then exit 4
else exit 0
fi
