"""
test_recon.py
-------------
Unit tests for the recon orchestrator and shared validation helpers, using
mocks so no real network access is required.

Run:
    cd recon_tool
    python -m unittest test_recon.py -v
"""

import unittest
from unittest.mock import patch

from modules.common import normalize_target, InvalidTargetError
import recon


class TestNormalizeTarget(unittest.TestCase):
    def test_bare_domain_gets_https_scheme(self):
        t = normalize_target("example.com")
        self.assertEqual(t.scheme, "https")
        self.assertEqual(t.hostname, "example.com")
        self.assertEqual(t.base_url, "https://example.com")

    def test_full_url_preserved(self):
        t = normalize_target("http://example.com/path")
        self.assertEqual(t.scheme, "http")
        self.assertEqual(t.hostname, "example.com")

    def test_empty_target_raises(self):
        with self.assertRaises(InvalidTargetError):
            normalize_target("   ")


class TestRunRecon(unittest.TestCase):
    @patch("recon.assert_public_host", return_value=None)
    @patch("recon.whois_lookup.lookup", return_value={"domain": "example.com"})
    @patch("recon.dns_enum.enumerate_records", return_value={"A": ["93.184.216.34"]})
    @patch("recon.subdomain_enum.enumerate_subdomains", return_value={"combined_unique": []})
    @patch("recon.ssl_info.get_certificate_info", return_value={"subject_common_name": "example.com"})
    @patch("recon.http_headers.collect_headers", return_value={"status_code": 200})
    @patch("recon.robots_sitemap.analyze_robots_txt", return_value={"found": False})
    @patch("recon.robots_sitemap.discover_sitemap", return_value={"found": False})
    @patch("recon.tech_fingerprint.fingerprint", return_value={"detected_technologies": []})
    def test_run_recon_assembles_all_modules(self, *_mocks):
        result = recon.run_recon(
            "example.com",
            enable_port_scan=False,
            enable_screenshot=False,
            enable_subdomains=True,
        )
        self.assertIsNone(result.error)
        self.assertEqual(result.hostname, "example.com")
        expected_modules = {
            "whois", "dns", "subdomains", "ssl", "http_headers",
            "robots_txt", "sitemap", "technology",
        }
        self.assertTrue(expected_modules.issubset(result.modules.keys()))

    @patch("recon.assert_public_host", side_effect=InvalidTargetError("private host"))
    def test_run_recon_rejects_private_target(self, _mock):
        result = recon.run_recon("http://192.168.1.1")
        self.assertIsNotNone(result.error)
        self.assertEqual(result.modules, {})

    @patch("recon.assert_public_host", return_value=None)
    @patch("recon.whois_lookup.lookup", side_effect=RuntimeError("boom"))
    @patch("recon.dns_enum.enumerate_records", return_value={})
    @patch("recon.subdomain_enum.enumerate_subdomains", return_value={})
    @patch("recon.ssl_info.get_certificate_info", return_value={})
    @patch("recon.http_headers.collect_headers", return_value={})
    @patch("recon.robots_sitemap.analyze_robots_txt", return_value={})
    @patch("recon.robots_sitemap.discover_sitemap", return_value={})
    @patch("recon.tech_fingerprint.fingerprint", return_value={})
    def test_one_module_failure_does_not_abort_scan(self, *_mocks):
        result = recon.run_recon("example.com", enable_screenshot=False)
        self.assertIn("error", result.modules["whois"])
        # other modules should still have run
        self.assertIn("dns", result.modules)


if __name__ == "__main__":
    unittest.main()
