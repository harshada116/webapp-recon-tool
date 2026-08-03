"""
robots_sitemap.py
------------------
Fetches and parses robots.txt (disallowed paths, sitemap references) and
attempts to discover/parse sitemap.xml.
"""

from __future__ import annotations

from typing import Any, Dict, List
from urllib.parse import urljoin

import requests
from xml.etree import ElementTree

from .common import USER_AGENT, DEFAULT_TIMEOUT

COMMON_SITEMAP_PATHS = ["/sitemap.xml", "/sitemap_index.xml"]


def analyze_robots_txt(base_url: str) -> Dict[str, Any]:
    url = urljoin(base_url, "/robots.txt")
    try:
        resp = requests.get(url, timeout=DEFAULT_TIMEOUT, headers={"User-Agent": USER_AGENT})
    except requests.RequestException as exc:
        return {"found": False, "error": f"Request failed: {exc}", "url": url}

    if resp.status_code != 200:
        return {"found": False, "status_code": resp.status_code, "url": url}

    disallowed, allowed, sitemaps, user_agents = [], [], [], []
    for line in resp.text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        lower = line.lower()
        if lower.startswith("disallow:"):
            disallowed.append(line.split(":", 1)[1].strip())
        elif lower.startswith("allow:"):
            allowed.append(line.split(":", 1)[1].strip())
        elif lower.startswith("sitemap:"):
            sitemaps.append(line.split(":", 1)[1].strip())
        elif lower.startswith("user-agent:"):
            user_agents.append(line.split(":", 1)[1].strip())

    return {
        "found": True,
        "url": url,
        "user_agents": user_agents,
        "disallowed_paths": disallowed,
        "allowed_paths": allowed,
        "sitemaps_referenced": sitemaps,
        "raw_length_bytes": len(resp.content),
    }


def discover_sitemap(base_url: str, robots_result: Dict[str, Any] | None = None) -> Dict[str, Any]:
    candidates: List[str] = []
    if robots_result and robots_result.get("sitemaps_referenced"):
        candidates.extend(robots_result["sitemaps_referenced"])
    candidates.extend(urljoin(base_url, p) for p in COMMON_SITEMAP_PATHS)

    seen = set()
    for url in candidates:
        if url in seen:
            continue
        seen.add(url)
        try:
            resp = requests.get(url, timeout=DEFAULT_TIMEOUT, headers={"User-Agent": USER_AGENT})
        except requests.RequestException:
            continue
        if resp.status_code != 200 or not resp.content:
            continue

        url_count = None
        try:
            root = ElementTree.fromstring(resp.content)
            tag = root.tag.lower()
            if tag.endswith("urlset"):
                url_count = len(root)
            elif tag.endswith("sitemapindex"):
                url_count = len(root)  # count of child sitemaps
        except ElementTree.ParseError:
            pass

        return {
            "found": True,
            "url": url,
            "status_code": resp.status_code,
            "entry_count": url_count,
            "size_bytes": len(resp.content),
        }

    return {"found": False, "checked": list(seen)}
