"""SSH probe — is TCP/22 open and is it really speaking SSH?

An SSH server sends its identification banner ("SSH-2.0-OpenSSH_9.6\r\n")
immediately on connect, so detection is reliable and needs no credentials.
We do NOT attempt authentication (that would be brute force — out of scope).
"""

from __future__ import annotations

import socket

from ..result import ScanResult

DEFAULT_PORT = 22


class SSHProbe:
    name = "SSH"
    kind = "ssh"

    def __init__(self, ports: list[int] | None = None, timeout: float = 6.0):
        self.ports = ports or [DEFAULT_PORT]
        self.timeout = timeout

    def target_ports(self) -> list[int]:
        return self.ports

    def scan(self, ip: str, port: int | None = None, check_auth: bool = False) -> ScanResult:
        port = port or DEFAULT_PORT
        res = ScanResult(ip=ip, service=self.name, port=port, url=f"ssh://{ip}:{port}")

        try:
            with socket.create_connection((ip, port), self.timeout) as sock:
                sock.settimeout(self.timeout)
                try:
                    banner = sock.recv(256).decode("latin-1", "replace").strip()
                except (socket.timeout, OSError):
                    banner = ""
        except (ConnectionError, socket.timeout, OSError):
            return res                                    # port closed / filtered

        # Port is open. Confirm it's SSH from the banner.
        res.port = port
        if banner.startswith("SSH-"):
            res.detected = True
            res.proto = banner.split("-", 2)[1] if "-" in banner else None
            res.security = "open-port"
            res.info = banner
        else:
            # Open but not SSH (or no banner) — still useful to know the port is up.
            res.detected = True
            res.security = "open-port"
            res.info = banner or "TCP open, no SSH banner"
            res.error = None if banner else "open but no SSH banner"
        return res
