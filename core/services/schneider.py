import logging
import re
import time

from .base import Service


class SchneiderService(Service):
    name = "Schneider"
    creds_filename = "schneider.creds.json"
    patterns = re.compile(
        r"Schneider Electric|Link 150|login-error-account|icon-motor",
        re.IGNORECASE,
    )
    config_path = "/"

    # The login form posts to /rs/login
    _AUTH_PATH = "/rs/login"

    # If the response still shows the login form, auth failed.
    _LOGIN_MARKERS = re.compile(
        r'login-error-account|id="login-form"|type="password"',
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
            "Accept":       "*/*",
        }

        for cred in creds[:self.max_creds]:
            user = cred["username"]
            pwd  = cred["password"]
            payload = {"username": user, "password": pwd}

            logging.info("  [%s] Trying %s:%s on %s",
                         self.name, user or "<empty>", pwd or "<empty>", auth_url)

            try:
                r = session.post(auth_url, data=payload, headers=headers,
                                 timeout=self.timeout, verify=False, allow_redirects=True)
            except Exception as e:
                logging.debug("  POST failed: %s", e)
                time.sleep(2)
                continue

            # Success: 2xx/3xx AND response no longer shows the login form
            if r.status_code < 400 and not self._LOGIN_MARKERS.search(r.text):
                return True, user, pwd

            time.sleep(2)

        return False, None, None
