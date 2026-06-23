import logging
import re
import time

from .base import Service


class CrestronService(Service):
    name = "Crestron"
    creds_filename = "crestron.creds.json"
    patterns = re.compile(
        r"CRESTRON|Crestron Electronics|crestron\.com|Device Administration",
        re.IGNORECASE,
    )
    config_path = "/userlogin.html"

    # The form posts (via AJAX) back to /userlogin.html with login / passwd fields
    _AUTH_PATH = "/userlogin.html"

    def try_login(self, base_url, session):
        creds = self._load_creds()
        base = base_url.rstrip("/")
        login_url = base + self.config_path
        auth_url  = base + self._AUTH_PATH

        # Prime the session by visiting the login page
        self._fetch(login_url, session)

        headers = {
            "Content-Type":     "application/x-www-form-urlencoded; charset=UTF-8",
            "X-Requested-With": "XMLHttpRequest",
            "Origin":           base,
            "Referer":          login_url,
            "Accept":           "*/*",
        }

        for cred in creds[:self.max_creds]:
            user = cred["username"]
            pwd  = cred["password"]
            payload = {"login": user, "passwd": pwd}

            logging.info("  [%s] Trying %s:%s on %s",
                         self.name, user or "<empty>", pwd or "<empty>", auth_url)

            try:
                r = session.post(auth_url, data=payload, headers=headers,
                                 timeout=self.timeout, verify=False, allow_redirects=False)
            except Exception as e:
                logging.debug("  POST failed: %s", e)
                time.sleep(2)
                continue

            # The page returns 403 on bad creds, 200 (+ redirect header) on success.
            if r.status_code == 200 or (300 <= r.status_code < 400):
                return True, user, pwd

            time.sleep(2)

        return False, None, None
