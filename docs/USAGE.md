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
4. Review the report sections: WHOIS, DNS records, subdomains, SSL/TLS
   certificate, HTTP headers, robots.txt, sitemap.xml, detected
   technologies, screenshot, and (if enabled) open ports.
5. Use **Download HTML Report** / **Download PDF Report** to save the
   full findings.

## What each section tells you

| Section | What to look for |
|---|---|
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
