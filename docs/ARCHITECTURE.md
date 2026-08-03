# Architecture

## Design principles

- **Fail-soft, not fail-fast.** Every external lookup (WHOIS, DNS, TLS,
  HTTP, screenshot, port scan) is isolated so one failing/rate-limited
  service does not abort the whole scan. Failures surface as an `error`
  field in that module's result rather than an exception bubbling to
  the UI.
- **Safe by default (SSRF guard).** Before contacting any target,
  `modules/common.py::assert_public_host()` resolves the hostname and
  rejects private/loopback/link-local/reserved/multicast IP ranges. This
  stops the tool from being turned into an internal network scanner.
- **One module per technique, orchestrated centrally.** Each recon
  technique lives in its own file under `modules/`, with no dependency
  on the others. `recon.py` is the only place that knows about all of
  them, wiring them together and handling failures uniformly.
- **Generic report rendering.** Rather than a bespoke HTML template per
  module, `report_generator.py` renders any dict/list of
  JSON-serializable values into tables automatically. Adding a new
  recon module requires no report changes.
- **Optional/heavy dependencies degrade gracefully.** PDF export
  (WeasyPrint) and screenshot capture (Selenium + Chrome) are only
  imported when used; if unavailable, that module reports a clear error
  instead of crashing the whole scan.

## Data flow

```
Browser ─▶ Flask app.py ─▶ recon.run_recon(target, flags)
                              │
                              ├─ modules/common.py   normalize + SSRF guard
                              │
                              ├─ modules/whois_lookup.py
                              ├─ modules/dns_enum.py
                              ├─ modules/subdomain_enum.py   (crt.sh + wordlist)
                              ├─ modules/ssl_info.py
                              ├─ modules/http_headers.py
                              ├─ modules/robots_sitemap.py
                              ├─ modules/tech_fingerprint.py
                              ├─ modules/screenshot.py        (optional)
                              └─ modules/port_scan.py         (opt-in)
                                        │
                                        ▼
                              ReconResult.modules{name: dict}
                                        │
                     ┌──────────────────┼───────────────────┐
                     ▼                                       ▼
             templates/index.html                  report_generator.py
             (generic dict/list → table renderer)   (same generic renderer,
                                                       full HTML page / PDF)
```

`recon.py::_run_module` wraps every module call in a try/except and
records timing, so `ReconResult.modules` always has an entry per
requested module — either real data or `{"error": "..."}`. One flaky
dependency (e.g. WHOIS rate limit) never prevents the rest of the report
from being generated.

`report_generator.py` uses **generic** dict/list-to-HTML-table
rendering (`_render_value` / `_render_dict` / `_render_dict_list`)
instead of per-module templates, so a module's output just needs to be
JSON-serializable to appear correctly in the report.

## Module notes

| Module | Approach |
|---|---|
| `whois_lookup.py` | Wraps `python-whois`; reduces to the registrable domain before querying. |
| `dns_enum.py` | Queries A, AAAA, MX, NS, TXT, CNAME, SOA, CAA via `dnspython`. |
| `subdomain_enum.py` | **Passive:** crt.sh certificate-transparency search. **Active:** resolves a small fixed wordlist concurrently. Both are combined and deduped. |
| `ssl_info.py` | Opens a raw TLS socket, reads the peer certificate: subject, issuer, validity window, SANs, negotiated protocol/cipher. |
| `http_headers.py` | Simple raw header collection (evidence-gathering, not deep header-security analysis). |
| `robots_sitemap.py` | Parses `robots.txt` line-by-line, then discovers/parses `sitemap.xml` from referenced or common paths. |
| `tech_fingerprint.py` | Small, auditable regex signature table (headers/cookies/HTML body) rather than an opaque third-party fingerprint database. |
| `screenshot.py` | Headless Selenium + Chrome; returns a clear error if unavailable instead of failing the whole scan. |
| `port_scan.py` | TCP-connect scan (no raw sockets, no root required) of ~19 well-known ports; off by default in the UI. |

## Security considerations in the code itself

- Outbound requests set a descriptive `User-Agent`.
- Network timeouts are set on every external call.
- The Flask `secret_key` is read from an environment variable with a
  random fallback — set `RECON_TOOL_SECRET_KEY` explicitly for any
  multi-worker or non-local deployment.
- Report HTML output is escaped via `html.escape()` everywhere
  remote/user data is interpolated, to prevent stored-XSS in the
  generated report itself (a malicious target could otherwise embed
  script tags in its WHOIS data, headers, etc.).
- Port scanning is TCP-connect only and off by default in the UI.
- Subdomain enumeration favors a passive source (crt.sh) and a small,
  fixed wordlist rather than large/aggressive brute-force lists.
