"""
http_headers.py
----------------
Simple HTTP response header collector, reused by the recon report as raw
evidence (separate from the deep header-security analysis performed by
Project 1's header_analyzer, which can be run against the same target for
a full security assessment).
"""

from __future__ import annotations

from typing import Any, Dict

import requests

from .common import USER_AGENT, DEFAULT_TIMEOUT


def collect_headers(base_url: str) -> Dict[str, Any]:
    try:
        resp = requests.get(
            base_url,
            timeout=DEFAULT_TIMEOUT,
            headers={"User-Agent": USER_AGENT},
            allow_redirects=True,
        )
    except requests.RequestException as exc:
        return {"error": f"Request failed: {exc}"}

    return {
        "final_url": resp.url,
        "status_code": resp.status_code,
        "headers": dict(resp.headers),
        "server": resp.headers.get("Server"),
        "powered_by": resp.headers.get("X-Powered-By"),
    }
