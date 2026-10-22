#!/usr/bin/env bash
# PHP2Shell patch-status inventory for CVE-2026-109618 and CVE-2026-109619.
# Read only. Runs candidate PHP binaries with -v; does not probe a web endpoint.
# PHP_BIN=/absolute/path/to/php[-fpm] limits assessment to one binary.
# Exit: 0 all assessed upstream-fixed; 1 any below fixed; 2 vendor/backport review;
#       3 assessment incomplete; 4 no PHP binary found. See playbook for scope.
set -uo pipefail

fixed_patch() {
  case "$1" in 8.5) printf '12';; 8.4) printf '27';; 8.3) printf '36';; 8.2) printf '35';; *) return 1;; esac
}

contains_path() {
  local item
  for item in "${bins[@]}"; do [[ "$item" == "$1" ]] && return 0; done
  return 1
}

add_binary() {
  local item="$1" resolved
  [[ -f "$item" && -x "$item" ]] || return 0
  local name="${item##*/}"
  if [[ -z "${PHP_BIN:-}" ]]; then
    [[ "$name" =~ ^php([0-9]+(\.[0-9]+)?)?$|^php-(fpm|cgi)([0-9]+(\.[0-9]+)?)?$|^php[0-9]+\.[0-9]+-(fpm|cgi)$ ]] || return 0
  fi
  resolved="$(readlink -f -- "$item" 2>/dev/null)" || return 0
  [[ -n "$resolved" ]] || return 0
  contains_path "$resolved" || bins+=("$resolved")
}

printf '%s\n' '========================================================================'
printf '%s\n' '🛡️  PHP2SHELL Check  🔎'
printf '%s\n' '========================================================================'
printf '📍 Host: %s  |  🕒 Checked (UTC): %s\n' "$(hostname 2>/dev/null || printf unknown)" "$(date -u +%FT%TZ)"
printf '%s\n' '🔒 Read-only patch-status inventory | CVE-2026-109618 / CVE-2026-109619'
printf '%s\n' '------------------------------------------------------------------------'

bins=(); running=(); deleted=0; count_fixed=0; count_below=0; count_review=0; count_unknown=0
if [[ -n "${PHP_BIN:-}" ]]; then
  add_binary "$PHP_BIN"
  if ((${#bins[@]} == 0)); then
    printf 'UNKNOWN: PHP_BIN does not resolve to an executable file: %s\n' "$PHP_BIN" >&2
    exit 3
  fi
else
  # Include symlinks as well as regular files, and paths outside standard installs
  # when a PHP executable is observed as a running process.
  for dir in /usr/bin /usr/local/bin /usr/sbin /usr/local/sbin /opt/plesk/php/*/bin /opt/*/bin; do
    [[ -d "$dir" ]] || continue
    while IFS= read -r -d '' item; do add_binary "$item"; done < <(
      find "$dir" -maxdepth 1 \( -type f -o -type l \) \
        \( -name 'php' -o -name 'php[0-9]*' -o -name 'php-fpm*' -o -name 'php-cgi*' \) -print0 2>/dev/null)
  done
fi

# /proc is a best-effort indicator of what is currently executing. It cannot
# identify PHP loaded as an Apache module or every container/namespace.
if [[ -d /proc ]]; then
  for proc in /proc/[0-9]*/exe; do
    [[ -e "$proc" ]] || continue
    target="$(readlink -- "$proc" 2>/dev/null)" || continue
    name="${target##*/}"; name="${name% (deleted)}"
    case "$name" in php|php[0-9]*|php-fpm*|php-cgi*) ;; *) continue;; esac
    if [[ "$target" == *' (deleted)' ]]; then
      deleted=$((deleted+1)); continue
    fi
    resolved="$(readlink -f -- "$proc" 2>/dev/null)" || continue
    if [[ -n "${PHP_BIN:-}" ]]; then
      [[ "${bins[0]}" == "$resolved" ]] && running+=("$resolved")
    else
      running+=("$resolved")
      add_binary "$resolved"
    fi
  done
fi

if ((${#bins[@]} == 0)); then
  printf 'NO_PHP_FOUND: no candidate PHP executable found in scanned locations. This does not prove the host does not serve PHP.\n'
  exit 4
fi

for bin in "${bins[@]}"; do
  observed='DISCOVERED_ONLY'
  for item in "${running[@]}"; do [[ "$item" == "$bin" ]] && observed='RUNNING_PROCESS' && break; done
  raw="$("$bin" -v 2>/dev/null)"; rc=$?
  first="${raw%%$'\n'*}"
  if ((rc != 0)) || [[ ! "$first" =~ PHP[[:space:]]+([0-9]+)\.([0-9]+)\.([0-9]+) ]]; then
    printf 'UNKNOWN | %s | %s | version unavailable (exit %s)\n' "$observed" "$bin" "$rc"
    count_unknown=$((count_unknown+1)); continue
  fi
  major="${BASH_REMATCH[1]}"; minor="${BASH_REMATCH[2]}"; patch="${BASH_REMATCH[3]}"
  branch="$major.$minor"; version="$major.$minor.$patch"
  if fixed="$(fixed_patch "$branch")"; then
    if ((10#$patch >= 10#$fixed)); then
      printf 'PATCHED_UPSTREAM_VERSION | %s | %s | PHP %s | >= %s.%s\n' "$observed" "$bin" "$version" "$branch" "$fixed"
      count_fixed=$((count_fixed+1))
    else
      printf 'BELOW_FIXED_VERSION | %s | %s | PHP %s | upstream fix %s.%s; check vendor backport\n' "$observed" "$bin" "$version" "$branch" "$fixed"
      count_below=$((count_below+1))
    fi
  else
    printf 'REVIEW_VENDOR_BACKPORT | %s | %s | PHP %s | no upstream fix threshold for branch; verify vendor evidence or migrate\n' "$observed" "$bin" "$version"
    count_review=$((count_review+1))
  fi
done

if ((deleted > 0)); then
  printf 'UNKNOWN_RUNNING_PROCESS: %s PHP process(es) use a deleted/replaced executable; restart/recycle and verify the active service.\n' "$deleted"
  count_unknown=$((count_unknown+1))
fi
printf 'SUMMARY: fixed=%s below=%s vendor_review=%s unknown=%s assessed=%s\n' "$count_fixed" "$count_below" "$count_review" "$count_unknown" "${#bins[@]}"
printf 'SCOPE: CLI/FPM/CGI binary version only. Confirm each web-facing SAPI, package backports, containers, and worker restart manually; mod_php is not visible as a PHP executable.\n'
if ((count_below > 0)); then exit 1
elif ((count_unknown > 0)); then exit 3
elif ((count_review > 0)); then exit 2
else exit 0
fi
