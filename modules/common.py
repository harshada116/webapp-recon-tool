"""
common.py
---------
Shared helpers used across every recon module:
  * target normalization (accepts a bare domain or a full URL)
  * an SSRF guard that refuses to enumerate private/internal addresses,
    since this tool is meant for reconnaissance against a target the
    operator is authorized to assess -- not as a pivot into internal infra.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass
from urllib.parse import urlparse

USER_AGENT = "WebAppReconTool/1.0 (+authorized security assessment)"
DEFAULT_TIMEOUT = 8


class InvalidTargetError(ValueError):
    pass


@dataclass
class Target:
    raw: str
    hostname: str
    scheme: str
    base_url: str


def normalize_target(raw: str) -> Target:
    raw = raw.strip()
    if not raw:
        raise InvalidTargetError("Target must not be empty.")

    if "://" not in raw:
        raw = "https://" + raw

    parsed = urlparse(raw)
    if not parsed.hostname:
        raise InvalidTargetError(f"Could not parse hostname from '{raw}'.")

    hostname = parsed.hostname.lower()
    scheme = parsed.scheme if parsed.scheme in ("http", "https") else "https"
    base_url = f"{scheme}://{hostname}"
    return Target(raw=raw, hostname=hostname, scheme=scheme, base_url=base_url)


def assert_public_host(hostname: str) -> None:
    """Raise InvalidTargetError if hostname resolves to a private/internal IP."""
    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        raise InvalidTargetError(f"Could not resolve host '{hostname}': {exc}") from exc

    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            raise InvalidTargetError(
                f"'{hostname}' resolves to a private/internal address and cannot be scanned."
            )
