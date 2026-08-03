"""
subdomain_enum.py
------------------
Passive subdomain discovery via certificate-transparency logs
(crt.sh) plus a small built-in wordlist for active DNS brute-forcing
of common subdomain names. Only passive/lightweight active checks are
performed -- no aggressive brute forcing -- to stay a good network citizen
and avoid tripping IDS/rate-limits on the target.
"""

from __future__ import annotations

import concurrent.futures
from typing import Dict, List, Set

import requests

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2", "cpanel",
    "api", "dev", "staging", "test", "admin", "portal", "vpn", "app",
    "blog", "shop", "static", "cdn", "m", "beta", "docs", "support",
]


def crtsh_lookup(hostname: str, timeout: int = 10) -> Set[str]:
    """Query crt.sh certificate-transparency search for subdomains."""
    found: Set[str] = set()
    try:
        resp = requests.get(
            f"https://crt.sh/?q=%.{hostname}&output=json",
            timeout=timeout,
            headers={"User-Agent": "WebAppReconTool/1.0"},
        )
        if resp.status_code == 200:
            for entry in resp.json():
                name_value = entry.get("name_value", "")
                for name in name_value.split("\n"):
                    name = name.strip().lstrip("*.")
                    if name.endswith(hostname):
                        found.add(name)
    except (requests.RequestException, ValueError):
        pass  # crt.sh is best-effort; ignore failures silently
    return found


def _resolves(fqdn: str) -> bool:
    import socket
    try:
        socket.getaddrinfo(fqdn, None)
        return True
    except socket.gaierror:
        return False


def bruteforce_common(hostname: str, wordlist: List[str] = None) -> Set[str]:
    wordlist = wordlist or COMMON_SUBDOMAINS
    candidates = [f"{word}.{hostname}" for word in wordlist]
    found: Set[str] = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
        futures = {pool.submit(_resolves, c): c for c in candidates}
        for fut in concurrent.futures.as_completed(futures):
            if fut.result():
                found.add(futures[fut])
    return found


def enumerate_subdomains(hostname: str) -> Dict[str, List[str]]:
    passive = crtsh_lookup(hostname)
    active = bruteforce_common(hostname)
    combined = sorted(passive | active)
    return {
        "passive_ct_logs": sorted(passive),
        "active_bruteforce": sorted(active),
        "combined_unique": combined,
        "total_found": len(combined),
    }
