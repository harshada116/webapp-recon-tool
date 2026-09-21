"""
recon.py
--------
Orchestrates the individual reconnaissance modules against a target and
assembles a single ReconResult. Each module failure is isolated so one
broken lookup (e.g. WHOIS rate-limited) does not abort the whole scan.
"""

from __future__ import annotations

import datetime
import os
import time
import traceback
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from modules.common import Target, normalize_target, assert_public_host, InvalidTargetError
from modules import (
    whois_lookup,
    ip_intel,
    dns_enum,
    subdomain_enum,
    ssl_info,
    http_headers,
    robots_sitemap,
    tech_fingerprint,
    screenshot as screenshot_module,
    port_scan,
)

SCREENSHOTS_DIR = os.path.join(os.path.dirname(__file__), "static", "screenshots")


@dataclass
class ReconResult:
    target: str
    hostname: str
    base_url: str
    generated_at: str
    error: Optional[str] = None
    modules: Dict[str, Any] = field(default_factory=dict)
    timings: Dict[str, float] = field(default_factory=dict)


def _run_module(result: ReconResult, name: str, func, *args, **kwargs):
    start = time.time()
    try:
        result.modules[name] = func(*args, **kwargs)
    except Exception as exc:  # noqa: BLE001 - isolate module failures
        result.modules[name] = {"error": f"{name} failed: {exc}"}
        result.modules[name]["_traceback"] = traceback.format_exc(limit=3)
    result.timings[name] = round(time.time() - start, 2)


def run_recon(
    raw_target: str,
    enable_port_scan: bool = False,
    enable_screenshot: bool = True,
    enable_subdomains: bool = True,
) -> ReconResult:
    try:
        target: Target = normalize_target(raw_target)
        assert_public_host(target.hostname)
    except InvalidTargetError as exc:
        return ReconResult(
            target=raw_target,
            hostname="",
            base_url="",
            generated_at=datetime.datetime.utcnow().isoformat(),
            error=str(exc),
        )

    result = ReconResult(
        target=raw_target,
        hostname=target.hostname,
        base_url=target.base_url,
        generated_at=datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
    )

    _run_module(result, "whois", whois_lookup.lookup, target.hostname)
    _run_module(result, "ip_intel", ip_intel.lookup, target.hostname)
    _run_module(result, "dns", dns_enum.enumerate_records, target.hostname)
    if enable_subdomains:
        _run_module(result, "subdomains", subdomain_enum.enumerate_subdomains, target.hostname)
    _run_module(result, "ssl", ssl_info.get_certificate_info, target.hostname)
    _run_module(result, "http_headers", http_headers.collect_headers, target.base_url)

    robots_result = None
    _run_module(result, "robots_txt", robots_sitemap.analyze_robots_txt, target.base_url)
    robots_result = result.modules.get("robots_txt")
    _run_module(result, "sitemap", robots_sitemap.discover_sitemap, target.base_url, robots_result)

    _run_module(result, "technology", tech_fingerprint.fingerprint, target.base_url)

    if enable_screenshot:
        screenshot_path = os.path.join(SCREENSHOTS_DIR, f"{target.hostname}.png")
        _run_module(result, "screenshot", screenshot_module.capture, target.base_url, screenshot_path)

    if enable_port_scan:
        _run_module(result, "port_scan", port_scan.scan_common_ports, target.hostname)

    return result
