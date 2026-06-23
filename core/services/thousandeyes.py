import re

from .base import Service


class ThousandEyesService(Service):
    name = "ThousandEyes"
    creds_filename = "thousandeyes.creds.json"
    # "Virtual Appliance" dropped — far too generic. Keep brand-specific markers.
    patterns = re.compile(
        r"ThousandEyes|teva-version|te-brand|thousandeyes\.com",
        re.IGNORECASE,
    )
    config_path = "/login?redirect=%2Fadvanced"

    # The login form posts to "api/login" relative to /login → /api/login
    _AUTH_PATH = "/api/login"
    # Login form still rendered / error returned -> auth failed.
    _FAIL_MARKERS = re.compile(
        r'type="password"|form-horizontal|name="username"|invalid|unauthor|incorrect',
        re.IGNORECASE,
    )

    def try_login(self, base_url, session):
        return self._form_login(
            base_url, session,
            auth_path=self._AUTH_PATH,
            prime_path=self.config_path,
            build_payload=lambda c: {"username": c["username"], "password": c["password"]},
            fail_markers=self._FAIL_MARKERS,
        )
