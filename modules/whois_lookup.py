"""
whois_lookup.py
----------------
Wraps python-whois to retrieve public registration data for a domain.
Fails soft (returns an 'error' field) since many TLDs/registrars rate-limit
or block WHOIS queries.
"""

from __future__ import annotations

from typing import Any, Dict


def lookup(hostname: str) -> Dict[str, Any]:
    try:
        import whois  # python-whois
    except ImportError:
        return {"error": "python-whois is not installed. Run: pip install python-whois"}

    # Reduce to the registrable domain (best-effort: last two labels) since
    # WHOIS operates on the registered domain, not a full subdomain.
    labels = hostname.split(".")
    domain = ".".join(labels[-2:]) if len(labels) >= 2 else hostname

    try:
        w = whois.whois(domain)
    except Exception as exc:  # whois raises many different exception types
        return {"error": f"WHOIS lookup failed: {exc}", "domain": domain}

    def _fmt(value):
        if isinstance(value, list):
            return [str(v) for v in value]
        return str(value) if value is not None else None

    return {
        "domain": domain,
        "registrar": _fmt(w.get("registrar")),
        "creation_date": _fmt(w.get("creation_date")),
        "expiration_date": _fmt(w.get("expiration_date")),
        "updated_date": _fmt(w.get("updated_date")),
        "name_servers": _fmt(w.get("name_servers")),
        "status": _fmt(w.get("status")),
        "emails": _fmt(w.get("emails")),
        "org": _fmt(w.get("org")),
        "country": _fmt(w.get("country")),
    }
