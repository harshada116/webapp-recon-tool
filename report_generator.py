"""
report_generator.py (Recon Tool)
---------------------------------
Renders a ReconResult into a self-contained HTML report, and optionally a
PDF via WeasyPrint. Generic helpers turn arbitrary dict/list module output
into readable tables without needing bespoke rendering code per module.
"""

from __future__ import annotations

import html
import os
from typing import Any

from recon import ReconResult

MODULE_TITLES = {
    "whois": "WHOIS Lookup",
    "ip_intel": "IP & Netblock Intelligence",
    "dns": "DNS Record Enumeration",
    "subdomains": "Subdomain Enumeration",
    "ssl": "SSL/TLS Certificate",
    "http_headers": "HTTP Response Headers",
    "robots_txt": "robots.txt Analysis",
    "sitemap": "sitemap.xml Discovery",
    "technology": "Technology Fingerprinting",
    "screenshot": "Screenshot",
    "port_scan": "Open Port Scan",
}


def _esc(v) -> str:
    return html.escape(str(v)) if v is not None else ""


def _render_value(value: Any) -> str:
    if value is None:
        return "<em>none</em>"
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, (list, tuple)):
        if not value:
            return "<em>none</em>"
        if all(isinstance(v, dict) for v in value):
            return _render_dict_list(value)
        items = "".join(f"<li>{_esc(v)}</li>" for v in value)
        return f"<ul class='val-list'>{items}</ul>"
    if isinstance(value, dict):
        return _render_dict(value)
    return _esc(value)


def _render_dict(d: dict) -> str:
    rows = "".join(
        f"<tr><th>{_esc(k)}</th><td>{_render_value(v)}</td></tr>"
        for k, v in d.items()
        if not str(k).startswith("_")
    )
    return f"<table class='kv'>{rows}</table>"


def _render_dict_list(items: list) -> str:
    if not items:
        return "<em>none</em>"
    keys = list(items[0].keys())
    header = "".join(f"<th>{_esc(k)}</th>" for k in keys)
    rows = "".join(
        "<tr>" + "".join(f"<td>{_render_value(row.get(k))}</td>" for k in keys) + "</tr>"
        for row in items
    )
    return f"<table class='grid'><thead><tr>{header}</tr></thead><tbody>{rows}</tbody></table>"


def _module_section(module_key: str, data: Any) -> str:
    title = MODULE_TITLES.get(module_key, module_key.replace("_", " ").title())
    if isinstance(data, dict) and data.get("error"):
        body = f"<p class='error'>{_esc(data['error'])}</p>"
    else:
        body = _render_value(data)
    return f"""
    <section class="module">
      <h2>{_esc(title)}</h2>
      {body}
    </section>
    """


# --------------------------------------------------------------- dashboard
#
# The dashboard CSS lives here rather than in static/style.css because the
# same markup has to render in three places: the web UI, the downloadable
# standalone HTML report, and the PDF. Keeping one copy avoids the three
# drifting apart; the web UI pulls it in via DASHBOARD_CSS too.

DASHBOARD_CSS = """
.dash { margin-bottom: 20px; }
.dash-head { display:flex; justify-content:space-between; align-items:baseline;
  flex-wrap:wrap; gap:8px; margin-bottom:12px; }
.dash-head h2 { font-size:18px; margin:0; }
.dash-head .dash-meta { font-size:12px; color:#6b7280; }
.dash-cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(170px,1fr));
  gap:10px; margin-bottom:18px; }
.dash-card { background:#fff; border:1px solid #e5e7eb; border-left-width:4px;
  border-radius:8px; padding:10px 12px; }
.dash-card .c-label { font-size:11px; text-transform:uppercase; letter-spacing:.04em;
  color:#6b7280; margin-bottom:4px; }
.dash-card .c-value { font-size:16px; font-weight:600; word-break:break-word; }
.dash-card .c-note { font-size:11.5px; color:#6b7280; margin-top:3px; word-break:break-word; }
.dash-card.good { border-left-color:#16a34a; }
.dash-card.warn { border-left-color:#d97706; }
.dash-card.bad  { border-left-color:#dc2626; }
.dash-card.neutral { border-left-color:#7c3aed; }
.dash-grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(320px,1fr)); gap:14px; }
.dash-panel { background:#fff; border:1px solid #e5e7eb; border-radius:8px; padding:14px 16px; }
.dash-panel h3 { font-size:13px; text-transform:uppercase; letter-spacing:.04em;
  color:#374151; margin:0 0 10px; }
.dash-panel table.kv th { width:170px; }
.tech-group { margin-bottom:10px; }
.tech-group .tech-cat { font-size:11.5px; color:#6b7280; margin-bottom:4px; }
.chip { display:inline-block; background:#f3f4f6; border:1px solid #e5e7eb;
  border-radius:999px; padding:2px 10px; font-size:12px; margin:0 4px 4px 0; }
ul.findings { list-style:none; margin:0; padding:0; }
ul.findings li { border-left:3px solid #e5e7eb; padding:4px 0 6px 10px; margin-bottom:8px; }
ul.findings li.good { border-left-color:#16a34a; }
ul.findings li.warn { border-left-color:#d97706; }
ul.findings li.bad  { border-left-color:#dc2626; }
ul.findings .f-title { font-size:13px; font-weight:600; }
ul.findings .f-detail { font-size:12px; color:#4b5563; }
.dash-note { font-size:11.5px; color:#6b7280; margin-top:6px; }
@media print { .dash-cards, .dash-grid { break-inside: avoid; } }
"""


def _dash_cards(cards: list) -> str:
    if not cards:
        return ""
    tiles = "".join(
        f"""<div class="dash-card {_esc(c.get('tone', 'neutral'))}">
              <div class="c-label">{_esc(c.get('label'))}</div>
              <div class="c-value">{_esc(c.get('value'))}</div>
              <div class="c-note">{_esc(c.get('note'))}</div>
            </div>"""
        for c in cards
    )
    return f'<div class="dash-cards">{tiles}</div>'


def _dash_panel(title: str, body: str) -> str:
    return f'<div class="dash-panel"><h3>{_esc(title)}</h3>{body}</div>'


def _dash_rows(rows: list) -> str:
    if not rows:
        return "<p class='dash-note'>No data collected.</p>"
    body = "".join(
        f"<tr><th>{_esc(label)}</th><td>{_esc(value)}</td></tr>" for label, value in rows
    )
    return f"<table class='kv'>{body}</table>"


def _dash_technology(groups: list) -> str:
    if not groups:
        return "<p class='dash-note'>No technologies fingerprinted.</p>"
    out = []
    for group in groups:
        chips = "".join(f"<span class='chip'>{_esc(i)}</span>" for i in group.get("items", []))
        out.append(
            f"<div class='tech-group'><div class='tech-cat'>{_esc(group.get('category'))}</div>{chips}</div>"
        )
    return "".join(out)


def _dash_findings(findings: list) -> str:
    if not findings:
        return ""
    items = "".join(
        f"""<li class="{_esc(f.get('severity', 'warn'))}">
              <div class="f-title">{_esc(f.get('title'))}</div>
              <div class="f-detail">{_esc(f.get('detail'))}</div>
            </li>"""
        for f in findings
    )
    return (
        f"<ul class='findings'>{items}</ul>"
        "<p class='dash-note'>Passive observations from collected data only &mdash; "
        "nothing here has been verified against the target.</p>"
    )


def _dash_history(history: list) -> str:
    if not history:
        return (
            "<p class='dash-note'>No previous scans recorded for this host yet. "
            "Re-scan it later and any change of IP, netblock owner, web server or "
            "certificate issuer will appear here.</p>"
        )
    rows = "".join(
        "<tr>"
        f"<td>{_esc(h.get('first_seen'))}</td>"
        f"<td>{_esc(h.get('last_seen'))}</td>"
        f"<td>{_esc(h.get('ip'))}</td>"
        f"<td>{_esc(h.get('netblock_owner'))}</td>"
        f"<td>{_esc(h.get('web_server'))}</td>"
        f"<td>{_esc(h.get('tls_issuer'))}</td>"
        "</tr>"
        for h in history
    )
    return (
        "<table class='grid'><thead><tr>"
        "<th>First seen</th><th>Last seen</th><th>IP address</th>"
        "<th>Netblock owner</th><th>Web server</th><th>Certificate issuer</th>"
        "</tr></thead>"
        f"<tbody>{rows}</tbody></table>"
        "<p class='dash-note'>History reflects only scans run by this tool.</p>"
    )


def render_dashboard(dash: dict) -> str:
    """Render the site-report dashboard: at-a-glance tiles, grouped panels,
    technology chips, passive observations, and observed hosting history."""
    if not dash:
        return ""
    if dash.get("error"):
        return f"<p class='error'>Reconnaissance failed: {_esc(dash['error'])}</p>"

    panels = [
        _dash_panel(section["title"], _dash_rows(section["rows"]))
        for section in dash.get("sections", [])
    ]
    panels.append(_dash_panel("Site technology", _dash_technology(dash.get("technology", []))))
    panels.append(_dash_panel("Observations", _dash_findings(dash.get("findings", []))))
    panels.append(_dash_panel("Hosting history (observed)", _dash_history(dash.get("history", []))))

    return f"""
    <section class="dash">
      <div class="dash-head">
        <h2>Site report &mdash; {_esc(dash.get('site'))}</h2>
        <span class="dash-meta">Generated {_esc(dash.get('generated_at'))}</span>
      </div>
      {_dash_cards(dash.get('cards', []))}
      <div class="dash-grid">{''.join(panels)}</div>
    </section>
    """


def render_body(result: ReconResult, dash: dict | None = None) -> str:
    """Render just the report content (no <html>/<head> wrapper), reusable
    both for the standalone report and for the inline web-UI preview.

    If `dash` is provided it is rendered above the per-module detail as a
    site-report summary."""
    if result.error:
        return f"<p class='error'>Reconnaissance failed: {_esc(result.error)}</p>"

    meta = f"""
    <table class="kv">
      <tr><th>Target</th><td>{_esc(result.target)}</td></tr>
      <tr><th>Resolved Hostname</th><td>{_esc(result.hostname)}</td></tr>
      <tr><th>Base URL</th><td>{_esc(result.base_url)}</td></tr>
      <tr><th>Generated</th><td>{_esc(result.generated_at)}</td></tr>
    </table>
    """
    sections = "".join(_module_section(key, val) for key, val in result.modules.items())
    summary = render_dashboard(dash) if dash else ""
    detail_heading = "<h2 class='detail-heading'>Full module output</h2>" if summary else ""
    return summary + detail_heading + meta + sections


def render_html(result: ReconResult, dash: dict | None = None) -> str:
    body = render_body(result, dash=dash)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Web Application Reconnaissance Report</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Roboto, Arial, sans-serif; margin:0; background:#f3f4f6; color:#111827; }}
  .container {{ max-width: 1000px; margin: 0 auto; padding: 32px; }}
  h1 {{ font-size: 22px; margin-bottom: 4px; }}
  h2 {{ font-size: 15px; margin: 0 0 10px; color:#1f2937; }}
  section.module {{ background:white; border-radius:8px; padding:16px 20px; margin-bottom:16px; box-shadow:0 1px 2px rgba(0,0,0,.06); }}
  table.kv {{ width:100%; border-collapse:collapse; margin-bottom: 8px;}}
  table.kv th {{ text-align:left; width:200px; padding:6px 8px; color:#374151; font-size:13px; vertical-align:top; border-bottom:1px solid #f0f0f0;}}
  table.kv td {{ padding:6px 8px; font-size:13px; border-bottom:1px solid #f0f0f0; word-break:break-word;}}
  table.grid {{ width:100%; border-collapse:collapse; font-size:12.5px; }}
  table.grid th, table.grid td {{ border:1px solid #e5e7eb; padding:6px 8px; text-align:left; }}
  table.grid th {{ background:#f9fafb; }}
  ul.val-list {{ margin:4px 0; padding-left:18px; font-size:13px; }}
  .error {{ color:#b91c1c; font-weight:600; }}
  .detail-heading {{ font-size:13px; text-transform:uppercase; letter-spacing:.04em; color:#6b7280; margin:24px 0 10px; }}
  footer {{ margin-top: 24px; font-size:11px; color:#9ca3af; text-align:center; }}
{DASHBOARD_CSS}
</style>
</head>
<body>
<div class="container">
  <h1>Web Application Reconnaissance Report</h1>
  {body}
  <footer>Generated by Web Application Reconnaissance Tool &mdash; for authorized security assessments only.</footer>
</div>
</body>
</html>"""


def render_pdf(result: ReconResult, output_path: str, dash: dict | None = None) -> str:
    try:
        from weasyprint import HTML
    except ImportError as exc:
        raise ImportError(
            "PDF export requires WeasyPrint and its system dependencies "
            "(Pango, Cairo, GDK-Pixbuf). Install via 'pip install weasyprint'."
        ) from exc

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    HTML(string=render_html(result, dash=dash)).write_pdf(output_path)
    return output_path
