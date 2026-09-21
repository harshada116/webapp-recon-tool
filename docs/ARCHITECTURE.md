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
- **Summary is derived, never collected twice.** `dashboard.py` is a pure
  function over an existing `ReconResult` -- it performs no network access
  and only reshapes what the modules already gathered. That keeps the
  site-report dashboard fully unit-testable against fixture dicts, and
  means a module failing only thins the summary rather than breaking it.
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
                              ├─ modules/ip_intel.py          (reverse DNS + RDAP)
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
                                        ▼
                              dashboard.build_dashboard()  ◀── history_store.py
                              (pure; cards/sections/tech/     (reports/history.json)
                               findings/history)
                                        │
                     ┌──────────────────┼───────────────────┐
                     ▼                                       ▼
             templates/index.html                  report_generator.py
             templates/dashboard.html               render_dashboard() +
             (dashboard + generic tables)           generic renderer →
                                                       full HTML page / PDF
```

## Site-report dashboard

`dashboard.py` turns a `ReconResult` into the summary shown above the raw
module output, modelled on the layout of a Netcraft site report:

| Piece | Source |
|---|---|
| At-a-glance cards | Hosting org, IP, certificate expiry, TLS version, web server, tech count, subdomain count, open ports. Each carries a `tone` (`good`/`warn`/`bad`/`neutral`); the renderer decides the colour. |
| Background panel | WHOIS: registrar, registrant org/country, registration/expiry dates. |
| Network panel | `ip_intel` + DNS: IP/IPv6, reverse DNS, netblock owner and range, hosting country, nameservers, nameserver organisation, DNS admin (derived from the SOA RNAME), MX. |
| SSL/TLS panel | Certificate subject/issuer/validity/protocol, plus whether CAA records exist. |
| Crawling panel | Final URL, status, server headers, robots.txt/sitemap presence, subdomain count. |
| Site technology | `tech_fingerprint` output regrouped by category into chips. |
| Observations | Passive flags derived from collected data only (expiring cert, legacy TLS, absent CAA, missing security headers, version disclosure, interesting robots.txt paths, sensitive open ports). Nothing is re-probed or verified against the target. |
| Hosting history | `history_store.py` (see below). |

Rendering lives in `report_generator.render_dashboard()` rather than in a
Jinja template so the web UI, the downloadable HTML report and the PDF all
use one implementation; `DASHBOARD_CSS` is likewise a single constant that
`templates/*.html` inline alongside `static/style.css`. Every value passes
through `html.escape()`, so hostile data from a target (a `<script>` tag in
a WHOIS org name, say) cannot break out into the report.

## Hosting history

Netcraft can show years of history because it crawls continuously. This
tool only knows what it has observed itself, so `history_store.py` keeps a
small JSON file (`reports/history.json`) of per-host observations: IP,
netblock owner, hosting country, web server, certificate issuer. A re-scan
that matches the previous observation bumps `last_seen`/`scans` instead of
appending, so the table reads as a change log rather than a scan log. The
file is best-effort: a corrupt or unwritable history never fails a scan.
For multi-worker deployments, replace it with a real datastore -- concurrent
writers can race.

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
| `ip_intel.py` | Resolves A/AAAA, does a reverse-DNS PTR lookup, then queries the public RDAP bootstrap service for netblock owner, CIDR, country and abuse contact. Passive w.r.t. the target -- only the RIR endpoint is contacted. `parse_rdap()` is split from the HTTP call so it is testable offline. |
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
