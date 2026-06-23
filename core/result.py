"""The single result shape shared by every probe (web, VNC, RDP, SSH).

The two original projects each had their own ``ScanResult``; this is the
superset that covers all of them so the runner, reporter, history and HTML
report can stay probe-agnostic.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ScanResult:
    ip:           str
    service:      str
    detected:     bool = False           # the probe positively identified the service
    port:         int | None = None      # concrete port the hit was on (None for web auto 443/80)
    url:          str | None = None      # http(s)://ip , vnc://ip:port , rdp://ip:port …
    auth_success: bool = False
    winner:       tuple | None = None    # (username/label, password) on success
    error:        str | None = None      # unreachable / protocol / auth error
    proto:        str | None = None      # RFB version, SSH banner, RDP selected protocol
    security:     str | None = None      # none | vncauth | NLA | TLS | RDP | open …
    info:         str | None = None      # freeform extra (banner text, note)
    # filled in by the runner so checkpoint/resume can dedupe jobs
    key:          str = field(default="", compare=False)

    @property
    def is_finding(self) -> bool:
        """True when this row is worth showing in a report (service found)."""
        return self.detected

    @property
    def severity(self) -> str:
        """Coarse severity used to colour the HTML report and console."""
        if self.auth_success or self.security in ("none", "open"):
            return "critical"
        if self.detected:
            return "warning"
        if self.error:
            return "error"
        return "info"
