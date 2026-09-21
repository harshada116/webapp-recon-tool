"""
test_recon.py
-------------
Unit tests for the recon orchestrator and shared validation helpers, using
mocks so no real network access is required.

Run:
    cd recon_tool
    python -m unittest test_recon.py -v
"""

import os
import shutil
import tempfile
import unittest
from unittest.mock import patch

from modules.common import normalize_target, InvalidTargetError
from modules import ip_intel
import dashboard
import history_store
import recon
import report_generator


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
    @patch("recon.ip_intel.lookup", return_value={"primary_ip": "93.184.216.34"})
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
            "whois", "ip_intel", "dns", "subdomains", "ssl", "http_headers",
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
    @patch("recon.ip_intel.lookup", return_value={})
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



class _FakeResult:
    """Minimal stand-in for ReconResult for pure dashboard tests."""

    def __init__(self, modules, error=None):
        self.target = "example.com"
        self.hostname = "example.com"
        self.base_url = "https://example.com"
        self.generated_at = "2026-01-01 00:00 UTC"
        self.error = error
        self.modules = modules
        self.timings = {}


def _sample_modules(**overrides):
    modules = {
        "whois": {
            "domain": "example.com",
            "registrar": "Example Registrar, Inc.",
            "creation_date": "1995-08-14 04:00:00",
            "expiration_date": ["2026-08-13 04:00:00"],
            "org": "Example Org",
            "country": "US",
        },
        "ip_intel": {
            "primary_ip": "93.184.216.34",
            "ipv4_addresses": ["93.184.216.34"],
            "ipv6_addresses": [],
            "reverse_dns": "edge.example.com",
            "netblock_owner": "Example Hosting BV",
            "cidr": "93.184.216.0/24",
            "ip_country": "NL",
        },
        "dns": {
            "A": ["93.184.216.34"],
            "NS": ["ns1.provider.net.", "ns2.provider.net."],
            "MX": ["10 mail.example.com."],
            "SOA": ["ns1.provider.net. hostmaster.example.com. 2024 7200 3600 120960 3600"],
            "CAA": [],
        },
        "ssl": {
            "subject_common_name": "example.com",
            "issuer": "Example CA",
            "expires": "Mar  1 00:00:00 2026 GMT",
            "days_until_expiry": 12,
            "tls_protocol": "TLSv1.3",
            "subject_alt_names": ["example.com", "www.example.com"],
        },
        "http_headers": {
            "status_code": 200,
            "final_url": "https://example.com/",
            "server": "nginx/1.18.0",
            "powered_by": "PHP/8.1.2",
            "headers": {"Server": "nginx/1.18.0", "Content-Security-Policy": "default-src 'self'"},
        },
        "technology": {
            "detected_technologies": [
                {"technology": "WordPress", "category": "CMS"},
                {"technology": "Nginx", "category": "Web Server"},
            ],
            "server_header": "nginx/1.18.0",
        },
        "robots_txt": {"found": True, "disallowed_paths": ["/admin/", "/images/"]},
        "sitemap": {"found": True, "url": "https://example.com/sitemap.xml", "entry_count": 42},
        "subdomains": {"total_found": 3, "passive_ct_logs": ["www.example.com"]},
    }
    modules.update(overrides)
    return modules


class TestDashboard(unittest.TestCase):
    def setUp(self):
        self.dash = dashboard.build_dashboard(_FakeResult(_sample_modules()))

    def _rows(self, title):
        section = next(s for s in self.dash["sections"] if s["title"] == title)
        return dict(section["rows"])

    def test_sections_present(self):
        titles = [s["title"] for s in self.dash["sections"]]
        self.assertEqual(
            titles, ["Background", "Network", "SSL/TLS certificate", "Crawling & content"]
        )

    def test_network_section_uses_ip_intel(self):
        rows = self._rows("Network")
        self.assertEqual(rows["Netblock owner"], "Example Hosting BV")
        self.assertEqual(rows["Hosting country"], "NL")
        self.assertEqual(rows["Reverse DNS"], "edge.example.com")

    def test_dns_admin_derived_from_soa(self):
        self.assertEqual(self._rows("Network")["DNS admin"], "hostmaster@example.com")

    def test_nameserver_organisation_reduced_to_registrable_domain(self):
        self.assertEqual(self._rows("Network")["Nameserver organisation"], "provider.net")

    def test_whois_dates_shortened(self):
        rows = self._rows("Background")
        self.assertEqual(rows["Domain registered"], "1995-08-14")
        self.assertEqual(rows["Domain expires"], "2026-08-13")

    def test_empty_rows_are_dropped(self):
        result = _FakeResult(_sample_modules(whois={"error": "rate limited"}))
        dash = dashboard.build_dashboard(result)
        background = dict(next(s for s in dash["sections"] if s["title"] == "Background")["rows"])
        self.assertNotIn("Registrar", background)
        self.assertIn("Site", background)

    def test_cards_flag_expiring_certificate(self):
        card = next(c for c in self.dash["cards"] if c["label"] == "Certificate")
        self.assertEqual(card["tone"], "warn")
        self.assertIn("12 days", card["value"])

    def test_technology_grouped_by_category(self):
        groups = {g["category"]: g["items"] for g in self.dash["technology"]}
        self.assertEqual(groups["CMS"], ["WordPress"])
        self.assertIn("Nginx", groups["Web Server"])

    def test_findings_flag_missing_caa_and_version_disclosure(self):
        titles = " | ".join(f["title"] for f in self.dash["findings"])
        self.assertIn("No CAA records published", titles)
        self.assertIn("discloses its version", titles)
        self.assertIn("X-Powered-By", titles)

    def test_findings_flag_interesting_robots_paths(self):
        detail = next(
            f for f in self.dash["findings"] if "robots.txt" in f["title"]
        )["detail"]
        self.assertIn("/admin/", detail)
        self.assertNotIn("/images/", detail)

    def test_clean_scan_reports_no_findings(self):
        clean = _sample_modules(
            dns={"A": ["1.2.3.4"], "CAA": ['0 issue "letsencrypt.org"']},
            ssl={"days_until_expiry": 200, "tls_protocol": "TLSv1.3"},
            http_headers={
                "server": "nginx",
                "headers": {
                    "Strict-Transport-Security": "max-age=63072000",
                    "Content-Security-Policy": "default-src 'self'",
                    "X-Content-Type-Options": "nosniff",
                    "X-Frame-Options": "DENY",
                    "Referrer-Policy": "no-referrer",
                },
            },
            technology={"detected_technologies": [], "server_header": "nginx"},
            robots_txt={"found": True, "disallowed_paths": ["/images/"]},
        )
        dash = dashboard.build_dashboard(_FakeResult(clean))
        self.assertEqual([f["severity"] for f in dash["findings"]], ["good"])

    def test_failed_scan_short_circuits(self):
        dash = dashboard.build_dashboard(_FakeResult({}, error="private address"))
        self.assertEqual(dash["error"], "private address")
        self.assertEqual(dash["cards"], [])

    def test_module_errors_do_not_raise(self):
        broken = {key: {"error": "failed"} for key in _sample_modules()}
        dash = dashboard.build_dashboard(_FakeResult(broken))
        self.assertTrue(dash["sections"])  # still renders, just sparse

    def test_dashboard_renders_to_html(self):
        html_out = report_generator.render_dashboard(self.dash)
        self.assertIn("Example Hosting BV", html_out)
        self.assertIn("dash-card", html_out)

    def test_rendered_dashboard_escapes_hostile_target_data(self):
        hostile = _sample_modules(
            ip_intel={"primary_ip": "1.2.3.4", "netblock_owner": "<script>alert(1)</script>"}
        )
        html_out = report_generator.render_dashboard(
            dashboard.build_dashboard(_FakeResult(hostile))
        )
        self.assertNotIn("<script>", html_out)
        self.assertIn("&lt;script&gt;", html_out)


class TestHistoryStore(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.mkdtemp()
        self.path = os.path.join(self._tmp, "history.json")

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_first_observation_creates_entry(self):
        entries = history_store.record_observation(
            "example.com", {"ip": "1.2.3.4", "web_server": "nginx"}, path=self.path
        )
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["ip"], "1.2.3.4")
        self.assertEqual(entries[0]["scans"], 1)

    def test_unchanged_rescan_updates_existing_entry(self):
        obs = {"ip": "1.2.3.4", "web_server": "nginx"}
        history_store.record_observation("example.com", obs, path=self.path)
        entries = history_store.record_observation("example.com", obs, path=self.path)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["scans"], 2)

    def test_changed_host_appends_new_row(self):
        history_store.record_observation("example.com", {"ip": "1.2.3.4"}, path=self.path)
        entries = history_store.record_observation("example.com", {"ip": "5.6.7.8"}, path=self.path)
        self.assertEqual([e["ip"] for e in entries], ["1.2.3.4", "5.6.7.8"])

    def test_hostname_is_case_insensitive(self):
        history_store.record_observation("Example.COM", {"ip": "1.2.3.4"}, path=self.path)
        self.assertEqual(len(history_store.load_history("example.com", path=self.path)), 1)

    def test_corrupt_history_file_does_not_break_scan(self):
        with open(self.path, "w", encoding="utf-8") as fh:
            fh.write("{not json")
        entries = history_store.record_observation("example.com", {"ip": "1.2.3.4"}, path=self.path)
        self.assertEqual(len(entries), 1)


class TestIpIntelParsing(unittest.TestCase):
    RDAP_FIXTURE = {
        "handle": "NET-93-184-216-0-1",
        "name": "EXAMPLE-NET",
        "startAddress": "93.184.216.0",
        "endAddress": "93.184.216.255",
        "country": "NL",
        "port43": "whois.ripe.net",
        "cidr0_cidrs": [{"v4prefix": "93.184.216.0", "length": 24}],
        "entities": [
            {
                "handle": "EH-1",
                "roles": ["registrant"],
                "vcardArray": ["vcard", [["version", {}, "text", "4.0"],
                                          ["fn", {}, "text", "Example Hosting BV"]]],
            },
            {
                "handle": "AB-1",
                "roles": ["abuse"],
                "vcardArray": ["vcard", [["fn", {}, "text", "Abuse Desk"],
                                          ["email", {}, "text", "abuse@example-hosting.nl"]]],
            },
        ],
    }

    def test_parse_rdap_extracts_owner_and_range(self):
        parsed = ip_intel.parse_rdap(self.RDAP_FIXTURE)
        self.assertEqual(parsed["netblock_owner"], "Example Hosting BV")
        self.assertEqual(parsed["cidr"], "93.184.216.0/24")
        self.assertEqual(parsed["netblock_range"], "93.184.216.0 - 93.184.216.255")
        self.assertEqual(parsed["ip_country"], "NL")
        self.assertEqual(parsed["abuse_contact"], "abuse@example-hosting.nl")

    def test_parse_rdap_tolerates_sparse_record(self):
        parsed = ip_intel.parse_rdap({"name": "SOME-NET"})
        self.assertEqual(parsed["netblock_owner"], "SOME-NET")
        self.assertIsNone(parsed["cidr"])
        self.assertIsNone(parsed["netblock_range"])


if __name__ == "__main__":
    unittest.main()
