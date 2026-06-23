"""VNC / RFB probe — detection + classic VNC-Authentication password test.

Ported from the standalone VNC scanner, with the reliability fixes for the
"works the first time, then the service looks down on the next scan" bug:

  WHY IT BROKE
  ------------
  The old code opened a *throwaway* connection just to read the security types,
  abandoned it mid-handshake, then opened *more* connections to try passwords.
  Many VNC servers (RealVNC especially) treat a connection that is dropped
  mid-handshake as a failed/!abandoned session and briefly black-list the
  source after a couple of those ("too many security failures"). They also keep
  the half-open session reserved until it times out. So the immediate second
  scan hit a server that was still holding/blocking the previous session and
  reported it as down.

  THE FIX
  -------
   * ONE connection does detection *and* the first password — we no longer burn
     an extra connection per host just to fingerprint it.
   * Every socket is shut down with ``shutdown(SHUT_RDWR)`` before close, so the
     server is told the session is over immediately instead of waiting for its
     own timeout (this is the "session not deconnected" the user suspected).
   * Connects are retried with a short back-off, so a host that is briefly
     cooling down from the previous attempt isn't misreported as down.
   * A small cooldown is inserted between the per-password reconnects.
"""

from __future__ import annotations

import socket
import struct
import time
from typing import Optional

from cryptography.hazmat.primitives.ciphers import Cipher, modes

try:  # cryptography >= 43 moved single/triple DES into the "decrepit" module
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
except ImportError:  # older versions
    from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES

from ..result import ScanResult

DEFAULT_PORT = 5900
SEC_NONE = 1     # no authentication -> server is wide open
SEC_VNCAUTH = 2  # classic DES challenge/response, password only

CONNECT_RETRIES = 2          # extra attempts when a connect is refused/filtered
RETRY_BACKOFF = 0.6          # seconds between connect attempts
AUTH_COOLDOWN = 0.5          # seconds between per-password reconnects


class ProtoError(Exception):
    """Host accepted TCP but did not behave like an RFB server."""


# --------------------------------------------------------------------------- #
# Low-level RFB helpers
# --------------------------------------------------------------------------- #
def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ProtoError("connection closed mid-handshake")
        buf.extend(chunk)
    return bytes(buf)


def _read_reason(sock: socket.socket) -> str:
    try:
        (length,) = struct.unpack(">I", _recv_exact(sock, 4))
        return _recv_exact(sock, length).decode("latin-1", "replace").strip()
    except Exception:
        return ""


def _handshake_version(sock: socket.socket) -> tuple[tuple[int, int], tuple[int, int]]:
    """Exchange RFB banners. Returns (negotiated, server) as (major, minor)."""
    banner = _recv_exact(sock, 12)                # e.g. b"RFB 003.008\n"
    if not banner.startswith(b"RFB ") or banner[7:8] != b"." or banner[11:12] != b"\n":
        raise ProtoError("not an RFB service")
    try:
        server = (int(banner[4:7]), int(banner[8:11]))
    except ValueError:
        raise ProtoError("malformed RFB version banner")

    if server >= (3, 8):
        ours = (3, 8)
    elif server >= (3, 7):
        ours = (3, 7)
    else:
        ours = (3, 3)
    sock.sendall(b"RFB %03d.%03d\n" % ours)
    return ours, server


def _read_sectypes(sock: socket.socket, version: tuple[int, int]) -> list[int]:
    """Read the security types offered, using the *negotiated* version."""
    if version >= (3, 7):
        count = _recv_exact(sock, 1)[0]
        if count == 0:
            raise ProtoError(_read_reason(sock) or "server offered no security types")
        return list(_recv_exact(sock, count))
    # RFB 3.3: server dictates a single type as uint32.
    (sectype,) = struct.unpack(">I", _recv_exact(sock, 4))
    if sectype == 0:
        raise ProtoError(_read_reason(sock) or "server rejected connection")
    return [sectype]


# --------------------------------------------------------------------------- #
# VNC Authentication (DES challenge/response)
# --------------------------------------------------------------------------- #
def _reverse_bits(byte: int) -> int:
    return int(f"{byte:08b}"[::-1], 2)


def _vnc_key(password: str) -> bytes:
    raw = password.encode("latin-1", "ignore")[:8].ljust(8, b"\x00")
    return bytes(_reverse_bits(b) for b in raw)


def _vnc_response(challenge: bytes, password: str) -> bytes:
    # TripleDES with K1=K2=K3 is plain single DES, which is what VNC-Auth uses.
    cipher = Cipher(TripleDES(_vnc_key(password) * 3), modes.ECB())
    enc = cipher.encryptor()
    return enc.update(challenge) + enc.finalize()


def _auth_on_socket(sock: socket.socket, version: tuple[int, int], password: str) -> bool:
    """Finish VNC-Auth on an already-open socket whose sectypes were just read.

    For 3.7+ the client must announce the chosen security type first; for 3.3
    the server already committed to it and the challenge follows immediately.
    """
    if version >= (3, 7):
        sock.sendall(bytes([SEC_VNCAUTH]))
    challenge = _recv_exact(sock, 16)
    sock.sendall(_vnc_response(challenge, password))
    (result,) = struct.unpack(">I", _recv_exact(sock, 4))
    return result == 0


# --------------------------------------------------------------------------- #
# Connection management
# --------------------------------------------------------------------------- #
def _connect(ip: str, port: int, timeout: float) -> Optional[socket.socket]:
    """Connect with a short retry/back-off so a host that is briefly cooling
    down from the previous probe is not misreported as down."""
    last: Exception | None = None
    for attempt in range(CONNECT_RETRIES + 1):
        try:
            sock = socket.create_connection((ip, port), timeout)
            sock.settimeout(timeout)
            return sock
        except (ConnectionError, socket.timeout, OSError) as exc:
            last = exc
            if attempt < CONNECT_RETRIES:
                time.sleep(RETRY_BACKOFF)
    return None


def _close(sock: socket.socket | None) -> None:
    """Tell the server the session is over *now* (FIN), then close."""
    if sock is None:
        return
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


# --------------------------------------------------------------------------- #
# Probe class (runner interface)
# --------------------------------------------------------------------------- #
class VNCProbe:
    name = "VNC"
    kind = "vnc"

    def __init__(self, passwords: list[str] | None = None, ports: list[int] | None = None,
                 timeout: float = 6.0):
        self.passwords = passwords or []
        self.ports = ports or [DEFAULT_PORT]
        self.timeout = timeout

    def target_ports(self) -> list[int]:
        return self.ports

    def scan(self, ip: str, port: int | None = None, check_auth: bool = False) -> ScanResult:
        port = port or DEFAULT_PORT
        res = ScanResult(ip=ip, service=self.name, port=port, url=f"vnc://{ip}:{port}")

        sock = _connect(ip, port, self.timeout)
        if sock is None:
            return res                                    # down / filtered -> clean miss

        remaining: list[str] = []
        try:
            version, server = _handshake_version(sock)
            types = _read_sectypes(sock, version)
            res.detected = True
            res.proto = f"{server[0]}.{server[1]}"

            if SEC_NONE in types:                         # no password needed at all
                res.security = "none"
                res.auth_success = True
                res.winner = ("(no auth)", "")
                return res

            if SEC_VNCAUTH not in types:
                res.security = "unsupported"
                res.error = f"security types {types} not supported"
                return res

            res.security = "vncauth"
            if not check_auth or not self.passwords:
                return res

            # Reuse THIS connection for the first password (no extra connect).
            first, remaining = self.passwords[0], self.passwords[1:]
            if _auth_on_socket(sock, version, first):
                res.auth_success = True
                res.winner = ("password", first)
                return res
        except ProtoError as exc:
            res.error = str(exc)
            return res
        except (ConnectionError, socket.timeout, OSError):
            # If we already fingerprinted it, keep detected=True; just no auth.
            if not res.detected:
                return res
            res.error = "connection dropped during handshake"
            return res
        finally:
            _close(sock)

        # Remaining passwords: a fresh, gracefully-closed connection each, with
        # a small cooldown so we don't trip the server's failure throttle.
        for pw in remaining:
            time.sleep(AUTH_COOLDOWN)
            sock = _connect(ip, port, self.timeout)
            if sock is None:
                res.error = "connection refused during auth (rate-limited?)"
                break
            try:
                version, _ = _handshake_version(sock)
                types = _read_sectypes(sock, version)
                if SEC_VNCAUTH not in types:
                    break
                if _auth_on_socket(sock, version, pw):
                    res.auth_success = True
                    res.winner = ("password", pw)
                    break
            except ProtoError as exc:
                res.error = str(exc)
                break
            except (ConnectionError, socket.timeout, OSError):
                res.error = "connection dropped during auth (rate-limited?)"
                break
            finally:
                _close(sock)

        return res
