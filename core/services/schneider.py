import re

from .base import Service


class SchneiderService(Service):
    name = "Schneider"
    creds_filename = "schneider.creds.json"
    # "icon-motor" dropped — too generic. Keep vendor-specific markers.
    patterns = re.compile(
        r"Schneider Electric|Link 150|login-error-account|/rs/login",
        re.IGNORECASE,
    )
    config_path = "/"

    _AUTH_PATH = "/rs/login"
    # Login form still present / explicit error -> auth failed.
    _FAIL_MARKERS = re.compile(
        r'login-error-account|id="login-form"|type="password"|invalid|incorrect',
        re.IGNORECASE,
    )

    def try_login(self, base_url, session):
        return self._form_login(
            base_url, session,
            auth_path=self._AUTH_PATH,
            prime_path="/",
            build_payload=lambda c: {"username": c["username"], "password": c["password"]},
            fail_markers=self._FAIL_MARKERS,
        )
