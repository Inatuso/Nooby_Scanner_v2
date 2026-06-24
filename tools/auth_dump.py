#!/usr/bin/env python3
"""Login diagnostic dumper for the JSON-API services (ThousandEyes, Schneider).

Hits a real appliance, primes the session, then sends the login exactly the way
the scanner does -- and prints the full request and response (status, headers,
body) for every step. Use this to see WHY a login is rejected on real hardware,
then we calibrate try_login from the output.

Usage:
    python tools/auth_dump.py thousandeyes 10.0.0.50
    python tools/auth_dump.py schneider   10.0.0.60 --user Administrator --pass Gateway

Credentials default to the matching data/creds file; --user/--pass override.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ROOT = Path(__file__).resolve().parent.parent
CREDS_DIR = ROOT / "creds"

# (prime_path, auth_path, csrf_cookie_substr, csrf_header)
PROFILES = {
    "thousandeyes": ("/login?redirect=%2Fadvanced", "/api/login", "csrf", "x-csrftoken"),
    "schneider":    ("/",                            "/rs/login",  None,   None),
}
CREDS_FILE = {"thousandeyes": "thousandeyes.creds.json", "schneider": "schneider.creds.json"}

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
LINE = "-" * 72


def first_cred(service: str):
    try:
        data = json.loads((CREDS_DIR / CREDS_FILE[service]).read_text(encoding="utf-8"))
        return data[0]["username"], data[0]["password"]
    except Exception:
        return "admin", "admin"


def dump_response(label: str, r: requests.Response) -> None:
    print(f"\n{LINE}\n{label}: {r.request.method} {r.url}  ->  HTTP {r.status_code}")
    print("  request headers:")
    for k, v in r.request.headers.items():
        print(f"    {k}: {v}")
    if r.request.body:
        body = r.request.body
        if isinstance(body, bytes):
            body = body.decode("utf-8", "replace")
        print(f"  request body: {body}")
    print("  response headers:")
    for k, v in r.headers.items():
        print(f"    {k}: {v}")
    text = r.text or ""
    print(f"  response body ({len(text)} bytes):")
    print("    " + (text[:1500].replace("\n", "\n    ")) + ("...[truncated]" if len(text) > 1500 else ""))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("service", choices=sorted(PROFILES))
    ap.add_argument("host", help="IP or host (no scheme)")
    ap.add_argument("--scheme", default="https", choices=["https", "http"])
    ap.add_argument("--port", type=int, default=None, help="override port (default 443/80)")
    ap.add_argument("--user", default=None)
    ap.add_argument("--pass", dest="pwd", default=None)
    a = ap.parse_args()

    prime_path, auth_path, csrf_sub, csrf_hdr = PROFILES[a.service]
    user, pwd = first_cred(a.service)
    if a.user is not None:
        user = a.user
    if a.pwd is not None:
        pwd = a.pwd

    base = f"{a.scheme}://{a.host}" + (f":{a.port}" if a.port else "")
    s = requests.Session()
    s.headers["User-Agent"] = UA

    print(f"Target   : {base}")
    print(f"Service  : {a.service}")
    print(f"Creds    : {user} / {pwd}")
    print(f"Prime    : {prime_path}")
    print(f"Auth POST: {auth_path}")

    rp = s.get(base + prime_path, timeout=10, verify=False)
    dump_response("PRIME", rp)
    print(f"\n  cookies after prime: {dict(s.cookies)}")

    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/plain, */*",
        "Origin": base,
        "Referer": base + prime_path,
        "X-Requested-With": "XMLHttpRequest",
    }
    if csrf_sub:
        for name, val in s.cookies.items():
            if csrf_sub.lower() in name.lower():
                headers[csrf_hdr] = val
                print(f"\n  CSRF: sending {csrf_hdr}={val}  (from cookie '{name}')")
                break
        else:
            print(f"\n  CSRF: no cookie containing '{csrf_sub}' found -> none sent "
                  f"(token may live in page HTML instead)")

    payload = {"username": user, "password": pwd}
    rl = s.post(base + auth_path, json=payload, headers=headers,
                timeout=10, verify=False, allow_redirects=False)
    dump_response("LOGIN", rl)
    print(f"\n  cookies after login: {dict(s.cookies)}")
    print(f"\n{LINE}\nVERDICT: login returned HTTP {rl.status_code} "
          f"({'looks OK' if rl.status_code in (200, 201, 204) else 'rejected'})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
