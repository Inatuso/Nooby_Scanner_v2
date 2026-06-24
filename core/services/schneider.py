import re

from .base import Service


class SchneiderService(Service):
    name = "Schneider"
    creds_filename = "schneider.creds.json"
    # "icon-motor" and the request path "/rs/login" dropped (the path is echoed
    # in 404s -> false positives). Vendor-specific content markers only.
    patterns = re.compile(
        r"Schneider Electric|Link 150|login-error-account",
        re.IGNORECASE,
    )
    config_path = "/"

    # Link 150 posts JSON to /rs/login (Content-Type: application/json),
    # NOT form-encoded — that was why valid creds were reported as failed.
    _AUTH_PATH = "/rs/login"
    # Real failure text only. "error":null / errorCode:0 in a success body must
    # NOT count as a failure, so a bare "error" key is no longer a marker.
    _FAIL_MARKERS = re.compile(
        r'login-error-account|invalid\s+(?:user|password|cred)|incorrect|'
        r'access denied|"error"\s*:\s*"[^"]', re.IGNORECASE)

    def try_login(self, base_url, session):
        return self._json_login(
            base_url, session,
            auth_path=self._AUTH_PATH,
            prime_path="/",
            build_payload=lambda c: {"username": c["username"], "password": c["password"]},
            fail_markers=self._FAIL_MARKERS,
        )
