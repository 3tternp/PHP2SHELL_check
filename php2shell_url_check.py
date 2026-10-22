#!/usr/bin/env python3
"""Passive PHP2SHELL version-hint check for authorized HTTP(S) endpoints.

This does not test exploitability or prove the version of the serving PHP runtime.
"""

import argparse
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request


FIXED = {(8, 5): 12, (8, 4): 27, (8, 3): 36, (8, 2): 35}
VERSION = re.compile(r"\bPHP[/ ](\d+)\.(\d+)\.(\d+)(?!\d)", re.IGNORECASE)
AGENT = "PHP2SHELL-Check/1.0 (passive version inventory)"


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def target_url(raw):
    parsed = urllib.parse.urlsplit(raw.strip())
    if parsed.scheme.lower() not in ("http", "https") or not parsed.hostname:
        raise ValueError("expected an absolute http:// or https:// URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("URL credentials are not allowed")
    try:
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("invalid port") from exc
    # Fragments are never sent; omit them. Keep the query for the request but
    # never include it in output (it may contain a token).
    request_url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", parsed.query, ""))
    display_url = urllib.parse.urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))
    return request_url, display_url


def assess(headers):
    # Headers can describe a proxy or a stale configuration, so these are hints.
    hints = []
    for key in ("X-Powered-By", "Server"):
        for value in headers.get_all(key, []):
            hints.extend(tuple(map(int, match)) for match in VERSION.findall(value))
    versions = sorted(set(hints))
    if not versions:
        return "VERSION_NOT_DISCLOSED", None, "No explicit PHP version in selected response headers"
    if len(versions) != 1:
        return "CONFLICTING_VERSION_HINTS", None, "Multiple distinct PHP versions disclosed"
    version = versions[0]
    shown = ".".join(map(str, version))
    branch = version[:2]
    if branch not in FIXED:
        return "REVIEW_VENDOR_BACKPORT", shown, "Branch outside upstream thresholds; verify vendor package"
    if version[2] < FIXED[branch]:
        return "BELOW_FIXED_VERSION_DISCLOSED", shown, "Disclosed version below upstream threshold; verify serving runtime and backports"
    return "AT_OR_ABOVE_FIXED_VERSION_DISCLOSED", shown, "Version hint meets upstream threshold; verify actual runtime"


def check(raw, opener, method, timeout):
    request_url, display_url = target_url(raw)
    result = {"url": display_url, "method": method, "status": None, "http_status": None, "php_version_hint": None, "note": None}
    request = urllib.request.Request(request_url, method=method, headers={"User-Agent": AGENT})
    try:
        with opener.open(request, timeout=timeout) as response:
            result["http_status"] = response.status
            result["status"], result["php_version_hint"], result["note"] = assess(response.headers)
    except urllib.error.HTTPError as exc:
        result["http_status"] = exc.code
        if 300 <= exc.code < 400:
            result["status"] = "REDIRECT_UNDETERMINED"
            result["note"] = "Redirect was not followed; supply the final URL explicitly"
        elif exc.code == 405 and method == "HEAD":
            result["status"] = "METHOD_NOT_ALLOWED"
            result["note"] = "HEAD rejected; rerun with --method GET"
        else:
            result["status"] = "HTTP_ERROR_UNDETERMINED"
            result["note"] = "HTTP error; serving PHP version not assessed"
        exc.close()
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        result["status"] = "REQUEST_FAILED"
        result["note"] = "Connection, timeout, or TLS validation failed: " + type(exc).__name__
    return result


def main():
    parser = argparse.ArgumentParser(description="Passive PHP2SHELL HTTP version-hint inventory; no exploit requests")
    parser.add_argument("--url", action="append", default=[], help="Authorized HTTP(S) URL; repeatable")
    parser.add_argument("--urls-file", help="One authorized URL per line; # comments and blank lines ignored")
    parser.add_argument("--method", choices=("HEAD", "GET"), default="HEAD", help="GET is useful if HEAD returns 405")
    parser.add_argument("--timeout", type=float, default=8.0, help="Per-request timeout in seconds (1–60)")
    parser.add_argument("--json", action="store_true", help="Print JSON without banner")
    args = parser.parse_args()
    if not 1 <= args.timeout <= 60:
        parser.error("--timeout must be between 1 and 60 seconds")
    urls = list(args.url)
    if args.urls_file:
        try:
            with open(args.urls_file, encoding="utf-8") as source:
                urls += [line.strip() for line in source if line.strip() and not line.lstrip().startswith("#")]
        except OSError as exc:
            parser.error("could not read --urls-file: " + str(exc))
    if not urls:
        parser.error("provide --url and/or --urls-file")
    for raw in urls:
        try:
            target_url(raw)
        except ValueError as exc:
            parser.error("invalid target URL: " + str(exc))

    opener = urllib.request.build_opener(NoRedirect(), urllib.request.ProxyHandler({}))
    # Respect system certificate validation. Do not automatically use ambient
    # proxy settings, which could leak target URLs outside the intended path.
    results = [check(raw, opener, args.method, args.timeout) for raw in urls]
    if args.json:
        print(json.dumps({"checks": results}, indent=2))
    else:
        print("🛡️  PHP2SHELL Check  🔎  |  passive URL inspection")
        for item in results:
            print("{url}  {status}  HTTP={http_status}  PHP={php_version_hint}".format(**item))
            print("  " + item["note"])
    statuses = {item["status"] for item in results}
    if "BELOW_FIXED_VERSION_DISCLOSED" in statuses:
        return 1
    if statuses & {"REQUEST_FAILED", "REDIRECT_UNDETERMINED", "METHOD_NOT_ALLOWED", "HTTP_ERROR_UNDETERMINED"}:
        return 3
    if "REVIEW_VENDOR_BACKPORT" in statuses:
        return 4
    if statuses & {"VERSION_NOT_DISCLOSED", "CONFLICTING_VERSION_HINTS"}:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
