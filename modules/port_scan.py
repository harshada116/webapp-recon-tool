"""
port_scan.py
------------
Optional lightweight TCP connect-scan of a curated list of commonly
security-relevant ports. This deliberately avoids raw-socket SYN scanning
(which requires elevated privileges and looks like an attack) in favor of
a polite, opt-in TCP-connect scan of a small, well-known port set.

This feature is OFF by default in the web UI and must be explicitly
enabled by the operator, since port scanning may be restricted by the
target's acceptable-use policy or local law even when the rest of the
recon is purely passive/public.
"""

from __future__ import annotations

import concurrent.futures
import socket
from typing import Any, Dict, List

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
}


def _check_port(hostname: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((hostname, port), timeout=timeout):
            return True
    except OSError:
        return False


def scan_common_ports(hostname: str, timeout: float = 1.5, max_workers: int = 20) -> Dict[str, Any]:
    open_ports: List[Dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(_check_port, hostname, port, timeout): (port, service)
            for port, service in COMMON_PORTS.items()
        }
        for fut in concurrent.futures.as_completed(futures):
            port, service = futures[fut]
            if fut.result():
                open_ports.append({"port": port, "service": service})

    open_ports.sort(key=lambda p: p["port"])
    return {
        "ports_checked": len(COMMON_PORTS),
        "open_ports": open_ports,
    }
