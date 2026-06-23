import re

from .base import Service


class CiscoVoIPService(Service):
    name = "CiscoVoIP"
    creds_filename = "cisco_voip.creds.json"
    patterns = re.compile(
        r"Cisco IP Phone|CGI/Java/Serviceability|device\.statistics|SEP[0-9A-F]{12}",
        re.IGNORECASE,
    )
    # Unauthenticated device-info endpoint exposed by Cisco IP phones
    config_path = "/CGI/Java/Serviceability?adapter=device.statistics.device"

    # No credentials — the device-information page is served without auth.
    def try_login(self, base_url, session):
        return False, None, None
