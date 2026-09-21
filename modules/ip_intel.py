"""
ip_intel.py
-----------
Resolves the target's IP addresses and looks up who owns the surrounding
netblock, using public registry data (RDAP) plus reverse DNS.

This is what fills in the "netblock owner / hosting company / hosting
country" fields of the site-report dashboard. It is entirely passive with
respect to the target: the only host contacted is the RDAP bootstrap
service (a public WHOIS-over-HTTP endpoint run by the RIRs), and reverse
DNS goes to the configured resolver.

Fails soft like every other module -- RDAP endpoints rate-limit, and some
allocations return sparse records.
"""

from __future__ import annotations

import socket
from typing import Any, Dict, List, Optional

import requests

from .common import USER_AGENT, DEFAULT_TIMEOUT

RDAP_BOOTSTRAP = "https://rdap.org/ip/{ip}"


def resolve_addresses(hostname: str) -> Dict[str, List[str]]:
    """Return the A/AAAA addresses the hostname currently resolves to."""
    ipv4: List[str] = []
    ipv6: List[str] = []
    try:
        for family, _type, _proto, _canon, sockaddr in socket.getaddrinfo(hostname, None):
            addr = sockaddr[0]
            if family == socket.AF_INET and addr not in ipv4:
                ipv4.append(addr)
            elif family == socket.AF_INET6 and addr not in ipv6:
                ipv6.append(addr)
    except socket.gaierror:
        pass
    return {"ipv4": ipv4, "ipv6": ipv6}


def reverse_dns(ip: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return None


def _entity_name(entity: Dict[str, Any]) -> Optional[str]:
    """Pull a human-readable name out of an RDAP entity's jCard."""
    vcard = entity.get("vcardArray")
    if isinstance(vcard, list) and len(vcard) == 2 and isinstance(vcard[1], list):
        for field in vcard[1]:
            # each field is [name, params, type, value]
            if isinstance(field, list) and len(field) >= 4 and field[0] == "fn":
                value = field[3]
                if isinstance(value, str) and value.strip():
                    return value.strip()
    handle = entity.get("handle")
    return str(handle) if handle else None


def parse_rdap(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Reduce an RDAP IP-network response to the fields the dashboard shows.

    Split out from the HTTP call so it can be unit-tested against a fixture
    without network access.
    """
    start = payload.get("startAddress")
    end = payload.get("endAddress")
    netblock_range = f"{start} - {end}" if start and end else None

    # Prefer the entity that registered the block; fall back to any named one.
    owner = None
    abuse_email = None
    for entity in payload.get("entities", []) or []:
        roles = [r.lower() for r in (entity.get("roles") or [])]
        name = _entity_name(entity)
        if name and owner is None and ("registrant" in roles or "administrative" in roles):
            owner = name
        if "abuse" in roles and abuse_email is None:
            for sub in [entity] + list(entity.get("entities") or []):
                vcard = sub.get("vcardArray")
                if isinstance(vcard, list) and len(vcard) == 2:
                    for field in vcard[1]:
                        if isinstance(field, list) and len(field) >= 4 and field[0] == "email":
                            abuse_email = field[3]
                            break
        if name and owner is None:
            owner = name

    return {
        "netblock_owner": owner or payload.get("name"),
        "netblock_name": payload.get("name"),
        "netblock_range": netblock_range,
        "cidr": _cidr_from(payload),
        "ip_country": payload.get("country"),
        "rdap_handle": payload.get("handle"),
        "registry": (payload.get("port43") or "").strip() or None,
        "abuse_contact": abuse_email,
    }


def _cidr_from(payload: Dict[str, Any]) -> Optional[str]:
    for item in payload.get("cidr0_cidrs", []) or []:
        prefix = item.get("v4prefix") or item.get("v6prefix")
        length = item.get("length")
        if prefix and length is not None:
            return f"{prefix}/{length}"
    return None


def rdap_lookup(ip: str, timeout: int = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    try:
        resp = requests.get(
            RDAP_BOOTSTRAP.format(ip=ip),
            timeout=timeout,
            headers={"User-Agent": USER_AGENT, "Accept": "application/rdap+json"},
        )
    except requests.RequestException as exc:
        return {"error": f"RDAP lookup failed: {exc}"}

    if resp.status_code != 200:
        return {"error": f"RDAP lookup returned HTTP {resp.status_code} for {ip}"}

    try:
        return parse_rdap(resp.json())
    except ValueError as exc:
        return {"error": f"RDAP response was not valid JSON: {exc}"}


def lookup(hostname: str) -> Dict[str, Any]:
    addresses = resolve_addresses(hostname)
    primary_ip = addresses["ipv4"][0] if addresses["ipv4"] else (
        addresses["ipv6"][0] if addresses["ipv6"] else None
    )
    if not primary_ip:
        return {"error": f"Could not resolve any IP address for '{hostname}'."}

    info: Dict[str, Any] = {
        "primary_ip": primary_ip,
        "ipv4_addresses": addresses["ipv4"],
        "ipv6_addresses": addresses["ipv6"],
        "reverse_dns": reverse_dns(primary_ip),
    }
    info.update(rdap_lookup(primary_ip))
    return info
