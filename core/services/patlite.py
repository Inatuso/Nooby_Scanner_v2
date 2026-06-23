import logging
import re
import time

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

    # If the response still shows the password field, auth failed.
    _LOGIN_MARKERS = re.compile(
        r'name="password"|login\.cgi',
        re.IGNORECASE,
    )

    def try_login(self, base_url, session):
        creds = self._load_creds()
        base = base_url.rstrip("/")
        auth_url = base + self._AUTH_PATH

        # Prime the session by visiting the root page
        self._fetch(base + "/", session)

        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin":       base,
            "Referer":      base + "/",
        }

        for cred in creds[:self.max_creds]:
            pwd = cred["password"]   # PATLITE login is password-only
            payload = {"password": pwd}

            logging.info("  [%s] Trying password=%s on %s",
                         self.name, pwd or "<empty>", auth_url)

            try:
                r = session.post(auth_url, data=payload, headers=headers,
                                 timeout=self.timeout, verify=False, allow_redirects=True)
            except Exception as e:
                logging.debug("  POST failed: %s", e)
                time.sleep(2)
                continue

            # Success: 2xx/3xx AND we're no longer on the login page
            if r.status_code < 400 and not self._LOGIN_MARKERS.search(r.text):
                return True, cred["username"], pwd

            time.sleep(2)

        return False, None, None
