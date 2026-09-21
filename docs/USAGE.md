# Usage

1. Open the app (`http://127.0.0.1:5001` locally, or your deployed URL).
2. Enter a target and choose which optional modules to run:
   - **Subdomain enumeration** (on by default) — passive crt.sh lookup +
     small built-in wordlist brute force.
   - **Screenshot capture** (on by default) — requires Chrome/Chromium;
     shows an error in its own section if unavailable, without
     affecting the rest of the report.
   - **Open port scan** (off by default) — a polite TCP-connect scan of
     ~19 commonly relevant ports. Enable only when you're certain port
     scanning the target is within your authorization.
3. Click **Run Recon**. Each module runs independently; if one fails
   (e.g. a WHOIS rate limit, a DNS timeout) its section shows the error
   while the rest of the report is still populated normally.
4. Read the **site report dashboard** at the top: at-a-glance tiles
   (hosting org, IP, certificate health, TLS version, web server, open
   ports), then Background / Network / SSL / Crawling panels, the
   technology breakdown, passive observations, and hosting history.
   **Open site report dashboard** gives the same summary on its own page
   (`/dashboard/<report_id>`), which is the view to screenshot or print.
5. Review the full module output below it: WHOIS, DNS records, subdomains, SSL/TLS
   certificate, HTTP headers, robots.txt, sitemap.xml, detected
   technologies, screenshot, and (if enabled) open ports.
6. Use **Download HTML Report** / **Download PDF Report** to save the
   full findings.

## What each section tells you

| Section | What to look for |
|---|---|
| Dashboard → Observations | Passive flags only (expiring cert, no CAA, missing security headers, version disclosure, interesting robots.txt paths, sensitive open ports). Nothing here is verified against the target — treat each as a lead to confirm, not a finding to report. |
| Dashboard → Hosting history | Only what *this tool* has seen. It starts empty; re-scan a host over time and any change of IP, netblock owner, web server or certificate issuer becomes a new row. Useful for spotting a migration between providers or an unexpected CA change. |
| IP & Netblock | Who actually owns the address space (often a CDN or cloud provider rather than the organisation), the hosting country, and the abuse contact to use for responsible disclosure. |
| WHOIS | Registrar, creation/expiry dates (a domain expiring soon is worth flagging), name servers, registrant org. |
| DNS | Unexpected `A`/`MX` records, missing `CAA` (means any CA can issue a cert for the domain), stray `TXT` records leaking SPF/verification tokens. |
| Subdomains | Forgotten staging/dev/admin subdomains — often the weakest link in an otherwise hardened main site. |
| SSL/TLS | Certificate expiry, issuer, and whether the negotiated protocol is modern (TLS 1.2+). |
| HTTP Headers | Raw evidence — pair with a dedicated header-security analyzer for a full severity-rated assessment. |
| robots.txt / sitemap.xml | Disallowed paths often hint at sensitive areas (`/admin`, `/backup`); sitemap entry counts give a sense of site size. |
| Technology | Framework/CMS/CDN fingerprint — useful for knowing which CVEs might apply. |
| Screenshot | Quick visual confirmation you're looking at the right site, and a snapshot for the report. |
| Open Ports | Anything beyond 80/443 open publicly is worth a closer look. |

## Programmatic / scripted use

`recon.py` has no Flask dependency, so you can use it directly:

```python
from recon import run_recon

result = run_recon(
    "example.com",
    enable_port_scan=False,
    enable_screenshot=False,
    enable_subdomains=True,
)
print(result.modules["dns"])
print(result.modules["technology"])
```

## Legal / ethical reminder

Only run this tool against targets you own or have explicit written
authorization to test. Subdomain brute forcing and port scanning
generate real traffic to the target and third parties (DNS resolvers,
crt.sh); disable those options if you are unsure they're in scope.
