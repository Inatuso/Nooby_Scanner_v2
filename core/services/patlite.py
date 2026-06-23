import re

from .base import Service


class PatliteService(Service):
    name = "PATLITE"
    creds_filename = "patlite.creds.json"
    patterns = re.compile(
        r"PATLITE|LA6 Setup Tool|set_lang\.cgi|change_lang",
        re.IGNORECASE,
    )
    config_path = "/"

    # Password-only login form posts to login.cgi
    _AUTH_PATH = "/login.cgi"
    # Still showing the password field / error -> auth failed.
    _FAIL_MARKERS = re.compile(
        r'name="password"|login\.cgi|invalid|incorrect|denied',
        re.IGNORECASE,
    )

    def try_login(self, base_url, session):
        # PATLITE login is password-only; report the matching username for context.
        return self._form_login(
            base_url, session,
            auth_path=self._AUTH_PATH,
            prime_path="/",
            build_payload=lambda c: {"password": c["password"]},
            fail_markers=self._FAIL_MARKERS,
        )
