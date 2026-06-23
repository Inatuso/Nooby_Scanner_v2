import re

from .base import Service


class CrestronService(Service):
    name = "Crestron"
    creds_filename = "crestron.creds.json"
    # Specific vendor strings only. "Device Administration" alone was too
    # generic and matched unrelated appliances (false positives).
    patterns = re.compile(
        r"Crestron Electronics|crestron\.com|/userlogin\.html|CrestronSecureWebSocket",
        re.IGNORECASE,
    )
    config_path = "/userlogin.html"

    _AUTH_PATH = "/userlogin.html"
    # Still on the login page / explicit denial -> auth failed.
    _FAIL_MARKERS = re.compile(
        r'name="login"|name="passwd"|userlogin\.html|invalid|incorrect|denied',
        re.IGNORECASE,
    )

    def try_login(self, base_url, session):
        return self._form_login(
            base_url, session,
            auth_path=self._AUTH_PATH,
            prime_path=self.config_path,
            build_payload=lambda c: {"login": c["username"], "passwd": c["password"]},
            fail_markers=self._FAIL_MARKERS,
            extra_headers={"X-Requested-With": "XMLHttpRequest"},
        )
