"""
tech_fingerprint.py
--------------------
Lightweight, dependency-free technology fingerprinting based on response
headers, cookies, and simple HTML/body signatures. This is intentionally
conservative (pattern-matching well-known signatures) rather than shipping
a large third-party fingerprint database, keeping it easy to audit and
extend.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List

import requests

from .common import USER_AGENT, DEFAULT_TIMEOUT

# (Technology name, category) -> list of (source, regex) signatures.
# source is one of: "header:<Name>", "cookie", "html"
SIGNATURES = [
    ("WordPress", "CMS", [("html", r"wp-content|wp-includes"), ("header:link", r"wp-json")]),
    ("Drupal", "CMS", [("html", r"Drupal\.settings|sites/all/modules")]),
    ("Joomla", "CMS", [("html", r"/media/jui/|Joomla!")]),
    ("Shopify", "E-commerce", [("html", r"cdn\.shopify\.com"), ("header:x-shopid", r".*")]),
    ("Magento", "E-commerce", [("html", r"Mage\.Cookies|/skin/frontend/")]),
    ("React", "JS Framework", [("html", r"data-reactroot|__REACT_DEVTOOLS")]),
    ("Vue.js", "JS Framework", [("html", r"data-v-app|__vue__")]),
    ("Angular", "JS Framework", [("html", r"ng-version=|ng-app")]),
    ("jQuery", "JS Library", [("html", r"jquery(\.min)?\.js")]),
    ("Bootstrap", "CSS Framework", [("html", r"bootstrap(\.min)?\.css")]),
    ("Nginx", "Web Server", [("header:server", r"nginx")]),
    ("Apache", "Web Server", [("header:server", r"apache")]),
    ("Microsoft IIS", "Web Server", [("header:server", r"iis")]),
    ("LiteSpeed", "Web Server", [("header:server", r"litespeed")]),
    ("PHP", "Language/Runtime", [("header:x-powered-by", r"php")]),
    ("ASP.NET", "Language/Runtime", [("header:x-powered-by", r"asp\.net"), ("header:x-aspnet-version", r".*")]),
    ("Express", "Language/Runtime", [("header:x-powered-by", r"express")]),
    ("Cloudflare", "CDN/WAF", [("header:server", r"cloudflare"), ("header:cf-ray", r".*")]),
    ("Amazon CloudFront", "CDN", [("header:via", r"cloudfront"), ("header:x-amz-cf-id", r".*")]),
    ("Fastly", "CDN", [("header:x-served-by", r"cache-"), ("header:via", r"fastly")]),
    ("Akamai", "CDN", [("header:server", r"akamaighost")]),
    ("Google Analytics", "Analytics", [("html", r"www\.google-analytics\.com|gtag\(")]),
    ("Google Tag Manager", "Analytics", [("html", r"googletagmanager\.com")]),
    ("reCAPTCHA", "Security/Bot Mitigation", [("html", r"www\.google\.com/recaptcha")]),
    ("Laravel", "PHP Framework", [("cookie", r"laravel_session")]),
    ("Django", "Python Framework", [("cookie", r"csrftoken|django")]),
    ("Ruby on Rails", "Ruby Framework", [("header:x-powered-by", r"rails|phusion")]),
    ("Varnish", "Cache", [("header:x-varnish", r".*"), ("header:via", r"varnish")]),
]


def fingerprint(base_url: str) -> Dict[str, Any]:
    try:
        resp = requests.get(base_url, timeout=DEFAULT_TIMEOUT, headers={"User-Agent": USER_AGENT})
    except requests.RequestException as exc:
        return {"error": f"Request failed: {exc}"}

    headers_lower = {k.lower(): v for k, v in resp.headers.items()}
    cookie_names = "; ".join(resp.headers.get("Set-Cookie", "").split(","))
    body = resp.text[:200_000] if resp.text else ""  # cap size for performance

    detected: List[Dict[str, str]] = []
    for name, category, sigs in SIGNATURES:
        for source, pattern in sigs:
            haystack = ""
            if source == "html":
                haystack = body
            elif source == "cookie":
                haystack = cookie_names
            elif source.startswith("header:"):
                header_name = source.split(":", 1)[1]
                haystack = headers_lower.get(header_name, "")
            if haystack and re.search(pattern, haystack, re.IGNORECASE):
                detected.append({"technology": name, "category": category})
                break  # one match per technology is enough

    return {
        "detected_technologies": detected,
        "server_header": resp.headers.get("Server"),
        "powered_by_header": resp.headers.get("X-Powered-By"),
        "status_code": resp.status_code,
    }
