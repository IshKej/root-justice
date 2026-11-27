"""Safe Local Host Audit: detect unauthorized Artex listeners (:8787, :8788) or containers."""

from __future__ import annotations

import socket
from typing import Dict, List


ARTEX_DEFAULT_PORTS = (8787, 8788)


def check_local_ports(ports: tuple[int, ...] = ARTEX_DEFAULT_PORTS, host: str = "127.0.0.1") -> List[Dict[str, object]]:
    """Read-only TCP connect check for default Artex Web UI (:8787) and MITM Proxy (:8788) ports."""
    findings: List[Dict[str, object]] = []
    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.4)
            is_open = sock.connect_ex((host, port)) == 0
        findings.append(
            {
                "host": host,
                "port": port,
                "listening": is_open,
                "service_guess": "ARTEX Web UI" if port == 8787 else "ARTEX MITM Proxy",
            }
        )
    return findings
