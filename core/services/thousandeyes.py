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

    # Login is a JSON POST to /api/login (Content-Type: application/json) with a
    # CSRF token echoed in the x-csrftoken header — not a form post.
    _AUTH_PATH = "/api/login"
    _FAIL_MARKERS = re.compile(r'invalid|unauthor|incorrect|"error"|denied', re.IGNORECASE)

    def try_login(self, base_url, session):
        return self._json_login(
            base_url, session,
            auth_path=self._AUTH_PATH,
            prime_path=self.config_path,
            build_payload=lambda c: {"username": c["username"], "password": c["password"]},
            csrf_cookie="csrf", csrf_header="x-csrftoken",
            fail_markers=self._FAIL_MARKERS,
        )
