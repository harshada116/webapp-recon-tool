"""
dns_enum.py
-----------
Enumerates common DNS record types for the target domain using dnspython.
"""

from __future__ import annotations

from typing import Any, Dict, List

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA"]


def enumerate_records(hostname: str) -> Dict[str, Any]:
    try:
        import dns.resolver
    except ImportError:
        return {"error": "dnspython is not installed. Run: pip install dnspython"}

    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5

    results: Dict[str, List[str]] = {}
    for rtype in RECORD_TYPES:
        try:
            answers = resolver.resolve(hostname, rtype)
            results[rtype] = [answer.to_text() for answer in answers]
        except dns.resolver.NoAnswer:
            results[rtype] = []
        except dns.resolver.NXDOMAIN:
            return {"error": f"Domain '{hostname}' does not exist (NXDOMAIN)."}
        except Exception as exc:  # timeouts, no nameservers, etc.
            results[rtype] = [f"lookup error: {exc}"]

    return results
