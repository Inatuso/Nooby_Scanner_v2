"""Assemble the set of probes to run from the user's selection + options.

A "probe" is anything with ``name``, ``kind``, ``target_ports()`` and
``scan(ip, port, check_auth)`` — the 10 web services plus VNC, RDP, SSH.
"""

from __future__ import annotations

from pathlib import Path

from .probes import RDPProbe, SSHProbe, VNCProbe
from .services import WEB_SERVICES

# Logical groups offered in the menu / --probes flag.
WEB_NAMES = [cls.name for cls in WEB_SERVICES]
EXTRA_NAMES = ["VNC", "RDP", "SSH"]
ALL_NAMES = WEB_NAMES + EXTRA_NAMES

GROUPS = {
    "all": ALL_NAMES,
    "web": WEB_NAMES,
    "extra": EXTRA_NAMES,
}


def resolve_selection(spec: str | None) -> list[str]:
    """Turn a comma-separated spec ('all', 'web', 'vnc,rdp', 'ilo,sato') into
    a concrete, de-duplicated list of probe names. Empty/None -> all."""
    if not spec:
        return list(ALL_NAMES)
    by_lower = {n.lower(): n for n in ALL_NAMES}
    picked: list[str] = []
    for tok in (t.strip().lower() for t in spec.split(",") if t.strip()):
        if tok in GROUPS:
            for n in GROUPS[tok]:
                if n not in picked:
                    picked.append(n)
        elif tok in by_lower:
            n = by_lower[tok]
            if n not in picked:
                picked.append(n)
        else:
            raise ValueError(
                f"Unknown probe {tok!r}. Options: {', '.join(ALL_NAMES)} "
                f"or groups {', '.join(GROUPS)}"
            )
    return picked


def build_probes(
    names: list[str],
    *,
    data_dir: Path,
    vnc_passwords: list[str] | None = None,
    vnc_ports: list[int] | None = None,
    rdp_ports: list[int] | None = None,
    ssh_ports: list[int] | None = None,
    timeout: float = 6.0,
) -> list:
    """Instantiate the probe objects for the chosen names."""
    web_by_name = {cls.name: cls for cls in WEB_SERVICES}
    probes: list = []
    for name in names:
        if name in web_by_name:
            probes.append(web_by_name[name](data_dir))
        elif name == "VNC":
            probes.append(VNCProbe(passwords=vnc_passwords, ports=vnc_ports, timeout=timeout))
        elif name == "RDP":
            probes.append(RDPProbe(ports=rdp_ports, timeout=timeout))
        elif name == "SSH":
            probes.append(SSHProbe(ports=ssh_ports, timeout=timeout))
    return probes
