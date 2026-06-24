import re

from .base import Service


class ThousandEyesService(Service):
    name = "ThousandEyes"
    creds_filename = "thousandeyes.creds.json"
    # Real markers from the appliance: the "Appliance Access" page title and the
    # __Secure-tevasid session cookie (seen in the Set-Cookie header).
    patterns = re.compile(
        r"ThousandEyes|thousandeyes\.com|teva-version|te-brand|tevasid|Appliance Access",
        re.IGNORECASE,
    )
    config_path = "/login?redirect=%2Fadvanced"

    # Login is a JSON POST to /api/login (Content-Type: application/json). The
    # CSRF token is NOT a cookie: the appliance returns a rotating token in the
    # X-Newcsrftoken response header, which must be echoed back as x-csrftoken.
    # Sending no token gets a flat 403 Forbidden.
    _AUTH_PATH = "/api/login"
    # Match real failure text only. A bare "error" key is NOT a failure marker:
    # a success body can legitimately carry "error":null / "errorCode":0, which
    # used to be misread as a failed login.
    _FAIL_MARKERS = re.compile(
        r'invalid\s+(?:user|password|cred)|unauthor|incorrect|login failed|'
        r'access denied|"error"\s*:\s*"[^"]', re.IGNORECASE)

    def try_login(self, base_url, session):
        return self._json_login(
            base_url, session,
            auth_path=self._AUTH_PATH,
            prime_path=self.config_path,
            build_payload=lambda c: {"username": c["username"], "password": c["password"]},
            csrf_resp_header="X-Newcsrftoken", csrf_header="x-csrftoken",
            fail_markers=self._FAIL_MARKERS,
        )
