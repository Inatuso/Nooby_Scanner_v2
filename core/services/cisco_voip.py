import re

from .base import Service


class CiscoVoIPService(Service):
    name = "CiscoVoIP"
    creds_filename = "cisco_voip.creds.json"
    # Device-specific markers only. The old patterns matched the request URL
    # tokens ("CGI/Java/Serviceability", "device.statistics") which the box may
    # echo back, and a bare 12-hex run — both caused false positives. Require
    # something only a Cisco phone serves.
    patterns = re.compile(
        r"Cisco IP Phone|Cisco Unified IP Phone|Cisco Systems Inc\. IP Phone|"
        r"\bSEP[0-9A-F]{12}\b|name=\"phoneName\"",
        re.IGNORECASE,
    )
    config_path = "/CGI/Java/Serviceability?adapter=device.statistics.device"
    requires_auth = False   # device-info page is unauthenticated — finding it is the result

    def detect(self, base_url, session):
        # Require a genuine phone marker on the device-info page (or the root) —
        # a plain 200 from some random web server is NOT a detection.
        for url in (base_url.rstrip("/") + self.config_path, base_url):
            if self._matches(self._fetch(url, session)):
                return True
        return False

    # No credentials — the device-information page is served without auth.
    def try_login(self, base_url, session):
        return False, None, None
