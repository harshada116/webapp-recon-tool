# Web Application Reconnaissance Tool

A reconnaissance tool that collects publicly available information about a
target web application:

- WHOIS lookup
- DNS record enumeration
- Subdomain enumeration (certificate-transparency logs + wordlist)
- SSL/TLS certificate information
- HTTP response header collection
- robots.txt analysis
- sitemap.xml discovery
- Technology fingerprinting (web server, framework, CMS, CDN, etc.)
- Screenshot capture of the target website
- Open port scanning (optional, off by default)

Generates a professional report in **HTML** and **PDF** formats.

> ⚠️ Use only against systems you own or are explicitly authorized to
> assess. Subdomain brute-forcing and port scanning generate real traffic
> to the target and, in the case of subdomain lookups, to third parties
> (crt.sh, DNS resolvers).

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open `http://127.0.0.1:5001`, enter a target, click **Run Recon**.

See [`docs/SETUP.md`](docs/SETUP.md) for full install/deploy instructions,
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for design notes, and
[`docs/USAGE.md`](docs/USAGE.md) for how to use the tool and interpret
results.

## Running tests

```bash
python -m unittest test_recon.py -v
```

## Project layout

```
webapp-recon-tool/
├── modules/              one module per recon technique
│   ├── common.py          target normalization + SSRF guard
│   ├── whois_lookup.py
│   ├── dns_enum.py
│   ├── subdomain_enum.py
│   ├── ssl_info.py
│   ├── http_headers.py
│   ├── robots_sitemap.py
│   ├── tech_fingerprint.py
│   ├── screenshot.py      optional (Selenium + Chrome)
│   └── port_scan.py       optional, off by default
├── recon.py               orchestrator (isolates per-module failures)
├── report_generator.py    generic dict/list → HTML/PDF report rendering
├── app.py                  Flask web UI
├── templates/, static/
├── test_recon.py          unit tests (mocked, no network required)
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── docs/
```
