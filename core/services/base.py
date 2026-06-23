"""Base class for HTTP web-service probes (iLO, SATO, Zebra, …).

Carried over from the original unified web scanner, with two changes so it
plugs into the fused runner:
  * it emits the shared ``core.result.ScanResult`` (superset shape);
  * ``scan()`` takes a ``port`` argument (ignored — web probes auto-try 443/80)
    so every probe in the tool has the same ``scan(ip, port, check_auth)`` call.
"""

from __future__ import annotations

import json
import logging
import re
import socket
import time
from pathlib import Path

import requests
import urllib3

from ..result import ScanResult

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class Service:
    """Subclass and override the class attributes (and optionally try_login / detect)."""

    name: str = ""
    kind: str = "web"
    creds_filename: str = ""
    patterns: re.Pattern = re.compile("")
    config_path: str = "/"
    requires_auth: bool = True   # False = no login (detection alone is the result)
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    ports: tuple = (443, 80)
    timeout: int = 10
    max_creds: int = 2

    def __init__(self, data_dir: Path):
        self.creds_path = data_dir / self.creds_filename

    # -- runner plumbing ----------------------------------------------------

    def target_ports(self) -> list[int | None]:
        """Web probes try 443/80 internally → one logical job per host."""
        return [None]

    # -- low-level helpers --------------------------------------------------

    def _port_open(self, ip: str, port: int) -> bool:
        try:
            with socket.create_connection((ip, port), timeout=5):
                return True
        except OSError:
            return False

    def _fetch(self, url: str, session: requests.Session, **kw) -> requests.Response | None:
        try:
            return session.get(url, timeout=self.timeout, verify=False, allow_redirects=True, **kw)
        except requests.RequestException:
            return None

    def _matches(self, response: requests.Response | None) -> bool:
        if response is None:
            return False
        if self.patterns.search(response.text):
            return True
        headers_str = " ".join(f"{k}: {v}" for k, v in response.headers.items())
        return bool(self.patterns.search(headers_str))

    def _load_creds(self) -> list:
        try:
            with open(self.creds_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            logging.warning("[%s] Could not load %s: %s", self.name, self.creds_path, e)
            return []

    def _make_session(self) -> requests.Session:
        s = requests.Session()
        s.headers["User-Agent"] = self.user_agent
        return s

    # -- evidence-based form login -----------------------------------------
    #
    # A login is only reported as successful when there is POSITIVE proof of a
    # session: either a redirect to a non-login page, or a session cookie that
    # the server set on the POST response. A bare 200 that just re-renders the
    # page is treated as a FAILURE. This deliberately errs toward false
    # negatives (safer for a security tool than crying wolf).

    def _login_proof(self, response: requests.Response | None,
                     cookies_before: set[str],
                     fail_markers: re.Pattern | None) -> bool:
        if response is None:
            return False
        sc = response.status_code
        if sc >= 400:                                  # 401/403/404/5xx -> not in
            return False
        body = response.text or ""
        if fail_markers and fail_markers.search(body):  # explicit error/login form
            return False
        if 300 <= sc < 400:                            # redirect away from login?
            loc = response.headers.get("Location", "").lower()
            return bool(loc) and "login" not in loc
        new_cookies = set(response.cookies.keys()) - cookies_before
        return bool(new_cookies)                       # 200 + fresh session cookie

    def _form_login(self, base_url: str, session: requests.Session, *,
                    auth_path: str, build_payload, prime_path: str = "/",
                    fail_markers: re.Pattern | None = None,
                    extra_headers: dict | None = None):
        """Shared flow: prime the page, POST creds, require login proof."""
        creds = self._load_creds()
        base = base_url.rstrip("/")
        self._fetch(base + prime_path, session)        # prime cookies
        cookies_before = set(session.cookies.keys())

        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": base,
            "Referer": base + prime_path,
            "Accept": "*/*",
        }
        if extra_headers:
            headers.update(extra_headers)

        for cred in creds[:self.max_creds]:
            payload = build_payload(cred)
            logging.info("  [%s] Trying %s on %s", self.name,
                         cred.get("username") or cred.get("password") or "<empty>", base + auth_path)
            try:
                r = session.post(base + auth_path, data=payload, headers=headers,
                                 timeout=self.timeout, verify=False, allow_redirects=False)
            except Exception as e:
                logging.debug("  POST failed: %s", e)
                time.sleep(1)
                continue
            if self._login_proof(r, cookies_before, fail_markers):
                return True, cred.get("username", ""), cred.get("password", "")
            time.sleep(1)
        return False, None, None

    def _json_login(self, base_url: str, session: requests.Session, *,
                    auth_path: str, build_payload, prime_path: str = "/",
                    csrf_cookie: str | None = None, csrf_header: str = "X-CSRFToken",
                    fail_markers: re.Pattern | None = None,
                    extra_headers: dict | None = None):
        """Login flow for JSON APIs (e.g. ThousandEyes, Schneider Link 150).

        These appliances answer the login with a real status code (200 on
        success, 401/403 on bad creds), so a clean 200 without an error body is
        the success signal. Optionally echoes a CSRF token taken from a cookie.
        """
        creds = self._load_creds()
        base = base_url.rstrip("/")
        self._fetch(base + prime_path, session)          # prime: get session + CSRF cookie

        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/plain, */*",
            "Origin": base,
            "Referer": base + prime_path,
            "X-Requested-With": "XMLHttpRequest",
        }
        if extra_headers:
            headers.update(extra_headers)
        if csrf_cookie:
            for name, val in session.cookies.items():
                if csrf_cookie.lower() in name.lower():
                    headers[csrf_header] = val
                    break

        for cred in creds[:self.max_creds]:
            logging.info("  [%s] Trying %s on %s", self.name,
                         cred.get("username") or "<empty>", base + auth_path)
            try:
                r = session.post(base + auth_path, json=build_payload(cred), headers=headers,
                                 timeout=self.timeout, verify=False, allow_redirects=False)
            except Exception as e:
                logging.debug("  POST failed: %s", e)
                time.sleep(1)
                continue
            if r is not None and r.status_code in (200, 201, 204):
                body = r.text or ""
                if not (fail_markers and fail_markers.search(body)):
                    return True, cred.get("username", ""), cred.get("password", "")
            time.sleep(1)
        return False, None, None

    # -- overridable steps --------------------------------------------------

    def detect(self, base_url: str, session: requests.Session) -> bool:
        """Default: regex match on root, fallback probe on config_path."""
        response = self._fetch(base_url, session)
        if self._matches(response):
            return True
        probe = self._fetch(base_url.rstrip("/") + self.config_path, session)
        return self._matches(probe)

    def try_login(self, base_url: str, session: requests.Session) -> tuple[bool, str | None, str | None]:
        """Default: HTTP Basic Auth against config_path, success if 200 + pattern match."""
        creds = self._load_creds()
        target_url = base_url.rstrip("/") + self.config_path
        for cred in creds[:self.max_creds]:
            user = cred["username"]
            pwd  = cred["password"]
            logging.info("  [%s] Trying %s:%s on %s", self.name, user, pwd or "<empty>", target_url)
            r = self._fetch(target_url, session, auth=(user, pwd))
            if r is not None and r.status_code == 200 and self._matches(r):
                return True, user, pwd
        return False, None, None

    # -- entry point --------------------------------------------------------

    def scan(self, ip: str, port: int | None = None, check_auth: bool = False) -> ScanResult:
        port_443 = 443 in self.ports and self._port_open(ip, 443)
        port_80  = 80  in self.ports and self._port_open(ip, 80)

        if not port_443 and not port_80:
            return ScanResult(ip=ip, service=self.name, detected=False, url=None,
                              error="no open web ports")

        session = self._make_session()
        chosen_port = 443 if port_443 else 80
        url = f"https://{ip}" if port_443 else f"http://{ip}"
        probe = self._fetch(url, session)
        if probe is None and url.startswith("https://") and port_80:
            chosen_port = 80
            url = f"http://{ip}"
            probe = self._fetch(url, session)
        if probe is None:
            return ScanResult(ip=ip, service=self.name, detected=False, url=url,
                              port=chosen_port, error="HTTP request failed")

        try:
            detected = self.detect(url, session)
        except Exception as e:
            return ScanResult(ip=ip, service=self.name, detected=False, url=url,
                              port=chosen_port, error=f"detect error: {e}")

        if not detected:
            return ScanResult(ip=ip, service=self.name, detected=False, url=url,
                              port=chosen_port, error=None)

        # Services like CiscoVoIP expose data with no login — detection IS the
        # result, so don't attempt (or report) an auth step for them.
        if not self.requires_auth:
            return ScanResult(
                ip=ip, service=self.name, detected=True, url=url, port=chosen_port,
                auth_applicable=False, security="exposed (no auth)", error=None,
            )

        auth_success, u, p = False, None, None
        if check_auth:
            try:
                auth_success, u, p = self.try_login(url, session)
            except Exception as e:
                return ScanResult(ip=ip, service=self.name, detected=True, url=url,
                                  port=chosen_port, error=f"auth error: {e}")

        return ScanResult(
            ip=ip, service=self.name, detected=True, url=url, port=chosen_port,
            auth_success=auth_success,
            winner=(u, p) if auth_success else None,
            security="default-creds" if auth_success else None,
            error=None,
        )
