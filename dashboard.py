"""
dashboard.py
------------
Condenses a full ReconResult into a "site report" summary: the handful of
facts an analyst wants at a glance (who hosts it, where, on what stack,
how healthy the certificate is) plus a short list of passive observations.

This module is deliberately pure -- it performs no network access and only
reshapes data already collected by the recon modules -- so the whole
dashboard can be unit-tested against fixture dictionaries.

Structure returned by build_dashboard():

    {
      "site": str, "hostname": str, "generated_at": str,
      "cards":     [{"label","value","note","tone"}],       # at-a-glance tiles
      "sections":  [{"title", "rows": [(label, value), ...]}],
      "technology":[{"category", "items": [str, ...]}],
      "findings":  [{"severity","title","detail"}],
      "history":   [{...}],                                  # past observations
    }

Tones/severities are plain strings ("good", "warn", "bad", "neutral") so the
renderer decides how to colour them.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

# Headers whose absence is worth noting on a recon summary. This is a light
# hygiene check on data already collected -- not a substitute for a dedicated
# header-security analyzer.
SECURITY_HEADERS = [
    ("strict-transport-security", "HSTS"),
    ("content-security-policy", "Content-Security-Policy"),
    ("x-content-type-options", "X-Content-Type-Options"),
    ("x-frame-options", "X-Frame-Options"),
    ("referrer-policy", "Referrer-Policy"),
]

# robots.txt entries that commonly point at interesting areas.
INTERESTING_PATH_HINTS = re.compile(
    r"admin|backup|config|private|internal|staging|dev|test|db|sql|log|secret|\.git",
    re.IGNORECASE,
)

SENSITIVE_PORTS = {21, 23, 445, 3306, 3389, 5432, 6379, 27017}


def _mod(result, name: str) -> Dict[str, Any]:
    """Return a module's data, or {} if it is missing or errored out."""
    data = (result.modules or {}).get(name)
    if not isinstance(data, dict) or data.get("error"):
        return {}
    return data


def _first(values, default=None):
    if isinstance(values, (list, tuple)):
        return values[0] if values else default
    return values if values else default


def _shorten_date(value: Optional[str]) -> Optional[str]:
    """WHOIS dates arrive as 'YYYY-MM-DD HH:MM:SS' strings (or lists of them)."""
    value = _first(value)
    if not value:
        return None
    text = str(value)
    match = re.match(r"(\d{4}-\d{2}-\d{2})", text)
    return match.group(1) if match else text


# ---------------------------------------------------------------- summary


def _dns_admin(dns: Dict[str, Any]) -> Optional[str]:
    """The SOA RNAME field is the DNS administrator contact."""
    soa = _first(dns.get("SOA"))
    if not soa:
        return None
    parts = str(soa).split()
    if len(parts) < 2:
        return None
    rname = parts[1].rstrip(".")
    # SOA RNAME encodes '@' as the first unescaped dot: admin.example.com
    local, _, domain = rname.partition(".")
    return f"{local}@{domain}" if domain else rname


def _nameserver_organisation(dns: Dict[str, Any], whois: Dict[str, Any]) -> Optional[str]:
    ns = _first(dns.get("NS")) or _first(whois.get("name_servers"))
    if not ns:
        return None
    labels = str(ns).rstrip(".").lower().split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else str(ns)


def build_sections(result) -> List[Dict[str, Any]]:
    whois = _mod(result, "whois")
    dns = _mod(result, "dns")
    ip = _mod(result, "ip_intel")
    ssl = _mod(result, "ssl")
    headers = _mod(result, "http_headers")
    robots = _mod(result, "robots_txt")
    sitemap = _mod(result, "sitemap")
    subdomains = _mod(result, "subdomains")

    background = [
        ("Site", result.base_url),
        ("Domain", whois.get("domain") or result.hostname),
        ("Registrar", _first(whois.get("registrar"))),
        ("Registrant organisation", _first(whois.get("org"))),
        ("Registrant country", _first(whois.get("country"))),
        ("Domain registered", _shorten_date(whois.get("creation_date"))),
        ("Domain expires", _shorten_date(whois.get("expiration_date"))),
        ("Domain last updated", _shorten_date(whois.get("updated_date"))),
        ("Domain status", _first(whois.get("status"))),
    ]

    network = [
        ("IP address", ip.get("primary_ip") or _first(dns.get("A"))),
        ("IPv6 address", _first(ip.get("ipv6_addresses")) or _first(dns.get("AAAA"))),
        ("Reverse DNS", ip.get("reverse_dns")),
        ("Netblock owner", ip.get("netblock_owner")),
        ("Netblock range", ip.get("cidr") or ip.get("netblock_range")),
        ("Hosting country", ip.get("ip_country")),
        ("Registry", ip.get("registry")),
        ("Abuse contact", ip.get("abuse_contact")),
        ("Nameservers", ", ".join(str(n).rstrip(".") for n in (dns.get("NS") or [])) or None),
        ("Nameserver organisation", _nameserver_organisation(dns, whois)),
        ("DNS admin", _dns_admin(dns)),
        ("Mail servers", ", ".join(str(m) for m in (dns.get("MX") or [])) or None),
    ]

    tls = [
        ("Subject common name", ssl.get("subject_common_name")),
        ("Issuer", ssl.get("issuer")),
        ("Issued", ssl.get("issued")),
        ("Expires", ssl.get("expires")),
        ("Days until expiry", ssl.get("days_until_expiry")),
        ("TLS protocol", ssl.get("tls_protocol")),
        ("Cipher suite", ssl.get("cipher_suite")),
        ("Serial number", ssl.get("serial_number")),
        ("Alternative names", len(ssl.get("subject_alt_names") or []) or None),
        ("CAA records", ", ".join(dns.get("CAA") or []) or "none published"),
    ]

    crawl = [
        ("Final URL", headers.get("final_url")),
        ("HTTP status", headers.get("status_code")),
        ("Server header", headers.get("server")),
        ("Powered by", headers.get("powered_by")),
        ("robots.txt", "present" if robots.get("found") else "not found"),
        ("Disallowed paths", len(robots.get("disallowed_paths") or []) or None),
        ("sitemap.xml", sitemap.get("url") if sitemap.get("found") else "not found"),
        ("Sitemap entries", sitemap.get("entry_count")),
        ("Subdomains discovered", subdomains.get("total_found")),
    ]

    return [
        {"title": "Background", "rows": _clean(background)},
        {"title": "Network", "rows": _clean(network)},
        {"title": "SSL/TLS certificate", "rows": _clean(tls)},
        {"title": "Crawling & content", "rows": _clean(crawl)},
    ]


def _clean(rows: List[Tuple[str, Any]]) -> List[Tuple[str, str]]:
    """Drop empty rows and stringify values for rendering."""
    cleaned = []
    for label, value in rows:
        if value is None or value == "" or value == []:
            continue
        cleaned.append((label, str(value)))
    return cleaned


# ------------------------------------------------------------------ cards


def build_cards(result) -> List[Dict[str, Any]]:
    ip = _mod(result, "ip_intel")
    ssl = _mod(result, "ssl")
    tech = _mod(result, "technology")
    subdomains = _mod(result, "subdomains")
    headers = _mod(result, "http_headers")
    ports = _mod(result, "port_scan")

    cards: List[Dict[str, Any]] = []

    cards.append({
        "label": "Hosted by",
        "value": ip.get("netblock_owner") or "unknown",
        "note": ip.get("ip_country") or "",
        "tone": "neutral",
    })
    cards.append({
        "label": "IP address",
        "value": ip.get("primary_ip") or "unknown",
        "note": ip.get("reverse_dns") or "",
        "tone": "neutral",
    })

    days = ssl.get("days_until_expiry")
    if days is None:
        cards.append({"label": "Certificate", "value": "unknown", "note": "no TLS data", "tone": "warn"})
    else:
        tone = "bad" if days < 0 else "warn" if days < 30 else "good"
        label = "expired" if days < 0 else f"{days} days left"
        cards.append({
            "label": "Certificate",
            "value": label,
            "note": ssl.get("issuer") or "",
            "tone": tone,
        })

    protocol = ssl.get("tls_protocol")
    if protocol:
        modern = protocol in ("TLSv1.2", "TLSv1.3")
        cards.append({
            "label": "TLS protocol",
            "value": protocol,
            "note": "modern" if modern else "outdated",
            "tone": "good" if modern else "bad",
        })

    server = tech.get("server_header") or headers.get("server")
    if server:
        cards.append({
            "label": "Web server",
            "value": server,
            "note": "version disclosed" if re.search(r"\d+\.\d+", server) else "",
            "tone": "warn" if re.search(r"\d+\.\d+", server) else "neutral",
        })

    detected = tech.get("detected_technologies") or []
    if detected:
        cards.append({
            "label": "Technologies",
            "value": str(len(detected)),
            "note": ", ".join(sorted({d.get("category", "") for d in detected}))[:60],
            "tone": "neutral",
        })

    if subdomains.get("total_found") is not None:
        cards.append({
            "label": "Subdomains",
            "value": str(subdomains.get("total_found")),
            "note": f"{len(subdomains.get('passive_ct_logs') or [])} from CT logs",
            "tone": "neutral",
        })

    if ports:
        open_ports = ports.get("open_ports") or []
        risky = [p for p in open_ports if p.get("port") in SENSITIVE_PORTS]
        cards.append({
            "label": "Open ports",
            "value": str(len(open_ports)),
            "note": f"{len(risky)} sensitive" if risky else f"of {ports.get('ports_checked', 0)} checked",
            "tone": "bad" if risky else "neutral",
        })

    return cards


# ------------------------------------------------------------- technology


def build_technology(result) -> List[Dict[str, Any]]:
    """Group fingerprinted technologies by category, Netcraft-style."""
    tech = _mod(result, "technology")
    grouped: Dict[str, List[str]] = {}
    for item in tech.get("detected_technologies") or []:
        category = item.get("category") or "Other"
        name = item.get("technology")
        if name and name not in grouped.setdefault(category, []):
            grouped[category].append(name)

    # Header-derived facts the signature table does not itself emit.
    server = tech.get("server_header")
    if server:
        grouped.setdefault("Web Server", [])
        if server not in grouped["Web Server"]:
            grouped["Web Server"].append(server)
    powered_by = tech.get("powered_by_header")
    if powered_by:
        grouped.setdefault("Language/Runtime", [])
        if powered_by not in grouped["Language/Runtime"]:
            grouped["Language/Runtime"].append(powered_by)

    return [{"category": c, "items": sorted(v)} for c, v in sorted(grouped.items())]


# --------------------------------------------------------------- findings


def build_findings(result) -> List[Dict[str, str]]:
    """Passive observations drawn from data already collected.

    These are pointers for an analyst, not vulnerability confirmations --
    nothing here is verified against the target beyond the initial scan.
    """
    findings: List[Dict[str, str]] = []
    ssl = _mod(result, "ssl")
    dns = _mod(result, "dns")
    headers = _mod(result, "http_headers")
    robots = _mod(result, "robots_txt")
    ports = _mod(result, "port_scan")
    tech = _mod(result, "technology")

    days = ssl.get("days_until_expiry")
    if isinstance(days, int):
        if days < 0:
            findings.append({
                "severity": "bad",
                "title": "TLS certificate has expired",
                "detail": f"Expired {abs(days)} days ago ({ssl.get('expires')}).",
            })
        elif days < 30:
            findings.append({
                "severity": "warn",
                "title": "TLS certificate expires soon",
                "detail": f"{days} days remaining ({ssl.get('expires')}).",
            })

    protocol = ssl.get("tls_protocol")
    if protocol and protocol not in ("TLSv1.2", "TLSv1.3"):
        findings.append({
            "severity": "bad",
            "title": f"Negotiated an outdated TLS protocol ({protocol})",
            "detail": "TLS 1.0/1.1 are deprecated and no longer considered secure.",
        })

    if dns and not dns.get("CAA"):
        findings.append({
            "severity": "warn",
            "title": "No CAA records published",
            "detail": "Any certificate authority may issue certificates for this domain.",
        })

    header_map = {k.lower(): v for k, v in (headers.get("headers") or {}).items()}
    missing = [label for key, label in SECURITY_HEADERS if key not in header_map]
    if missing:
        findings.append({
            "severity": "warn",
            "title": f"{len(missing)} security header(s) not set",
            "detail": ", ".join(missing) + ". Pair with a dedicated header analyzer for severity ratings.",
        })

    server = tech.get("server_header") or headers.get("server")
    if server and re.search(r"\d+\.\d+", str(server)):
        findings.append({
            "severity": "warn",
            "title": "Web server discloses its version",
            "detail": f"Server header: {server}. Version banners make CVE matching trivial for an attacker.",
        })

    powered_by = headers.get("powered_by")
    if powered_by:
        findings.append({
            "severity": "warn",
            "title": "X-Powered-By header discloses the runtime",
            "detail": str(powered_by),
        })

    interesting = [p for p in (robots.get("disallowed_paths") or []) if INTERESTING_PATH_HINTS.search(p)]
    if interesting:
        findings.append({
            "severity": "warn",
            "title": f"robots.txt hides {len(interesting)} interesting path(s)",
            "detail": ", ".join(interesting[:8]),
        })

    risky_ports = [p for p in (ports.get("open_ports") or []) if p.get("port") in SENSITIVE_PORTS]
    if risky_ports:
        findings.append({
            "severity": "bad",
            "title": "Sensitive service ports reachable from the internet",
            "detail": ", ".join(f"{p['port']}/{p.get('service', '?')}" for p in risky_ports),
        })

    if not findings:
        findings.append({
            "severity": "good",
            "title": "No passive observations flagged",
            "detail": "Nothing in the collected data stood out. This is not a clean bill of health -- "
                      "the scan is passive and shallow by design.",
        })

    return findings


# ------------------------------------------------------- observation/history


def observation_from(result) -> Dict[str, Any]:
    """The subset of a scan worth storing to build a hosting-history table."""
    ip = _mod(result, "ip_intel")
    ssl = _mod(result, "ssl")
    tech = _mod(result, "technology")
    headers = _mod(result, "http_headers")
    return {
        "ip": ip.get("primary_ip") or _first(_mod(result, "dns").get("A")),
        "netblock_owner": ip.get("netblock_owner"),
        "hosting_country": ip.get("ip_country"),
        "web_server": tech.get("server_header") or headers.get("server"),
        "tls_issuer": ssl.get("issuer"),
    }


# ------------------------------------------------------------------ build


def build_dashboard(result, history: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    if result.error:
        return {
            "site": result.target,
            "hostname": result.hostname,
            "generated_at": result.generated_at,
            "error": result.error,
            "cards": [], "sections": [], "technology": [], "findings": [], "history": [],
        }

    return {
        "site": result.base_url or result.target,
        "hostname": result.hostname,
        "generated_at": result.generated_at,
        "cards": build_cards(result),
        "sections": build_sections(result),
        "technology": build_technology(result),
        "findings": build_findings(result),
        "history": list(reversed(history or [])),
    }
