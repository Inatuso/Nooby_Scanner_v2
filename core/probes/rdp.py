"""RDP probe — is TCP/3389 open, and what security layer does it require?

Detection sends the standard X.224 Connection Request with an RDP Negotiation
Request (MS-RDPBCGR) and parses the server's Negotiation Response. That tells
us not just "port open" but also whether the server enforces NLA/CredSSP, plain
TLS, or legacy standard RDP security — handy context for a recap. No credentials
are tried (RDP auth would be brute force — out of scope).
"""

from __future__ import annotations

import socket
import struct

from ..result import ScanResult

DEFAULT_PORT = 3389

# RDP Negotiation Request requestedProtocols flags we advertise.
_PROTO_SSL = 0x01
_PROTO_HYBRID = 0x02
_REQUESTED = _PROTO_SSL | _PROTO_HYBRID

# selectedProtocol values in the Negotiation Response.
_SECURITY = {
    0x00000000: "Standard RDP",
    0x00000001: "TLS",
    0x00000002: "CredSSP (NLA)",
    0x00000008: "RDSTLS",
    0x00000010: "CredSSP-EX (NLA)",
}


def _build_negotiation_request() -> bytes:
    # RDP_NEG_REQ: type=0x01, flags=0x00, length=0x0008 (LE), requestedProtocols (LE)
    neg_req = struct.pack("<BBHI", 0x01, 0x00, 0x0008, _REQUESTED)
    # X.224 Connection Request (CR): LI, 0xE0, DST-REF(2), SRC-REF(2), class(1)
    x224 = bytes([6 + len(neg_req), 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00]) + neg_req
    # TPKT header: version=3, reserved=0, total length (BE)
    tpkt = struct.pack(">BBH", 0x03, 0x00, 4 + len(x224))
    return tpkt + x224


def _parse_negotiation_response(data: bytes) -> tuple[bool, str | None, str | None]:
    """Return (is_rdp, security_label, note) from a server response."""
    if len(data) < 5 or data[0] != 0x03:                  # not a TPKT frame
        return False, None, None
    # X.224 data starts at offset 4; fixed CC header is 7 bytes (LI + code + 4 refs + class).
    x224 = data[4:]
    if len(x224) < 2 or x224[1] != 0xD0:                  # 0xD0 = X.224 Connection Confirm
        return True, "Standard RDP", "RDP (no negotiation response)"
    neg = x224[7:]
    if len(neg) < 8:
        return True, "Standard RDP", "RDP (no negotiation data)"
    neg_type = neg[0]
    if neg_type == 0x02:                                  # RDP_NEG_RSP
        (selected,) = struct.unpack("<I", neg[4:8])
        return True, _SECURITY.get(selected, f"protocol 0x{selected:x}"), None
    if neg_type == 0x03:                                  # RDP_NEG_FAILURE
        (code,) = struct.unpack("<I", neg[4:8])
        return True, "negotiation refused", f"server requires stronger security (code {code})"
    return True, "Standard RDP", None


class RDPProbe:
    name = "RDP"
    kind = "rdp"

    def __init__(self, ports: list[int] | None = None, timeout: float = 6.0):
        self.ports = ports or [DEFAULT_PORT]
        self.timeout = timeout

    def target_ports(self) -> list[int]:
        return self.ports

    def scan(self, ip: str, port: int | None = None, check_auth: bool = False) -> ScanResult:
        port = port or DEFAULT_PORT
        res = ScanResult(ip=ip, service=self.name, port=port, url=f"rdp://{ip}:{port}")

        try:
            with socket.create_connection((ip, port), self.timeout) as sock:
                sock.settimeout(self.timeout)
                try:
                    sock.sendall(_build_negotiation_request())
                    data = sock.recv(512)
                except (socket.timeout, OSError):
                    data = b""
        except (ConnectionError, socket.timeout, OSError):
            return res                                    # port closed / filtered

        # Port is open at this point.
        is_rdp, security, note = _parse_negotiation_response(data)
        res.detected = True
        if is_rdp:
            res.proto = "RDP"
            res.security = security or "open-port"
            res.info = note
        else:
            res.security = "open-port"
            res.info = "TCP open, no RDP negotiation response"
        return res
