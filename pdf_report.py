"""
pdf_report.py
-------------
Built-in PDF export for recon reports. Pure Python (ReportLab) -- no system
libraries such as Pango/Cairo are needed, so `pip install -r requirements.txt`
is all it takes and it behaves the same on Windows, macOS, Linux and Docker.

Layout: title block, at-a-glance tiles, the dashboard sections, technology,
passive observations, hosting history, optional screenshot, then the full
per-module output. Everything taken from the target is XML-escaped before
it reaches ReportLab's mini-markup, so hostile data cannot inject markup.
"""

from __future__ import annotations

import os
import re
from typing import Any, List
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    Image, KeepTogether, PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
)

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

TONES = {
    "good": colors.HexColor("#16a34a"),
    "warn": colors.HexColor("#d97706"),
    "bad": colors.HexColor("#dc2626"),
    "neutral": colors.HexColor("#7c3aed"),
}
GREY = colors.HexColor("#6b7280")
LINE = colors.HexColor("#e5e7eb")
HEAD_BG = colors.HexColor("#f3f4f6")

PAGE_W, PAGE_H = A4
MARGIN = 16 * mm
CONTENT_W = PAGE_W - 2 * MARGIN

MAX_VALUE_CHARS = 1500   # keep one giant header/blob from eating pages
MAX_LIST_ITEMS = 60
MAX_GRID_ROWS = 60

_CTRL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def _txt(value: Any, limit: int = MAX_VALUE_CHARS) -> str:
    """Make arbitrary data safe for a ReportLab Paragraph.

    Standard PDF fonts only cover Latin-1/WinAnsi, so anything else becomes
    '?' instead of a black box. Text is XML-escaped for the mini-markup.
    """
    if value is None:
        return ""
    text = _CTRL.sub("", str(value))
    text = text.encode("cp1252", "replace").decode("cp1252")
    if len(text) > limit:
        text = text[:limit] + " ... (truncated)"
    return escape(text)


def _styles():
    base = getSampleStyleSheet()
    s = {}
    s["title"] = ParagraphStyle("t", parent=base["Title"], fontSize=20, leading=24,
                                alignment=TA_LEFT, spaceAfter=2)
    s["sub"] = ParagraphStyle("sub", parent=base["Normal"], fontSize=9, textColor=GREY)
    s["h2"] = ParagraphStyle("h2", parent=base["Heading2"], fontSize=13, leading=16,
                             spaceBefore=12, spaceAfter=6)
    s["h3"] = ParagraphStyle("h3", parent=base["Heading3"], fontSize=10, leading=13,
                             textColor=colors.HexColor("#374151"), spaceBefore=8, spaceAfter=4,
                             keepWithNext=1)
    # wordWrap="CJK" lets long unbroken strings (URLs, hashes) wrap inside cells.
    s["cell"] = ParagraphStyle("cell", parent=base["Normal"], fontSize=8.5, leading=11,
                               wordWrap="CJK")
    s["cellb"] = ParagraphStyle("cellb", parent=s["cell"], fontName="Helvetica-Bold",
                                textColor=colors.HexColor("#374151"))
    s["small"] = ParagraphStyle("small", parent=base["Normal"], fontSize=7.5, leading=10,
                                textColor=GREY, wordWrap="CJK")
    s["label"] = ParagraphStyle("label", parent=s["small"], fontSize=7, textColor=GREY)
    s["value"] = ParagraphStyle("value", parent=base["Normal"], fontName="Helvetica-Bold",
                                fontSize=11, leading=13, wordWrap="CJK")
    s["err"] = ParagraphStyle("err", parent=s["cell"], textColor=colors.HexColor("#b91c1c"))
    return s


# ----------------------------------------------------------- building blocks

def _kv_table(rows: List[tuple], st, label_w=48 * mm) -> Table:
    data = [[Paragraph(_txt(k), st["cellb"]), Paragraph(_txt(v), st["cell"])] for k, v in rows]
    t = Table(data, colWidths=[label_w, CONTENT_W - label_w], repeatRows=0)
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, LINE),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    return t


def _grid_table(header: List[str], rows: List[List[Any]], st) -> Table:
    n = max(len(header), 1)
    col_w = CONTENT_W / n
    data = [[Paragraph(_txt(h), st["cellb"]) for h in header]]
    data += [[Paragraph(_txt(c), st["cell"]) for c in r] for r in rows]
    t = Table(data, colWidths=[col_w] * n, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), HEAD_BG),
        ("GRID", (0, 0), (-1, -1), 0.4, LINE),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
    ]))
    return t


def _cards(cards: list, st) -> Table | None:
    if not cards:
        return None
    per_row = 3
    gap = 3 * mm
    w = (CONTENT_W - gap * (per_row - 1)) / per_row
    cells = []
    for c in cards:
        tone = TONES.get(c.get("tone", "neutral"), TONES["neutral"])
        inner = Table(
            [[Paragraph(_txt(c.get("label")).upper(), st["label"])],
             [Paragraph(_txt(c.get("value"), 120), st["value"])],
             [Paragraph(_txt(c.get("note"), 120), st["small"])]],
            colWidths=[w],
        )
        inner.setStyle(TableStyle([
            ("BOX", (0, 0), (-1, -1), 0.5, LINE),
            ("LINEBEFORE", (0, 0), (0, -1), 3, tone),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]))
        cells.append(inner)
    while len(cells) % per_row:
        cells.append("")
    rows = [cells[i:i + per_row] for i in range(0, len(cells), per_row)]
    outer = Table(rows, colWidths=[w + gap] * per_row)
    outer.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), gap),
        ("BOTTOMPADDING", (0, 0), (-1, -1), gap),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
    ]))
    return outer


def _findings(findings: list, st) -> List[Any]:
    out = []
    for f in findings:
        tone = TONES.get(f.get("severity", "warn"), TONES["warn"])
        t = Table(
            [[Paragraph(f"<b>{_txt(f.get('title'))}</b>", st["cell"])],
             [Paragraph(_txt(f.get("detail")), st["small"])]],
            colWidths=[CONTENT_W],
        )
        t.setStyle(TableStyle([
            ("LINEBEFORE", (0, 0), (0, -1), 3, tone),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("TOPPADDING", (0, 0), (-1, -1), 1),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 1),
        ]))
        out += [KeepTogether(t), Spacer(1, 3)]
    out.append(Paragraph(
        "Passive observations from collected data only - nothing here has been "
        "verified against the target.", st["small"]))
    return out


# ------------------------------------------------- generic module rendering

def _flat(value: Any, depth: int = 0) -> str:
    """Collapse nested module data into readable multi-line text."""
    if value is None or value == "" or value == []:
        return "none"
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if isinstance(value, dict):
        lines = [f"{k}: {_flat(v, depth + 1)}" for k, v in value.items()
                 if not str(k).startswith("_")]
        return "\n".join(lines) if depth == 0 else "; ".join(lines)
    if isinstance(value, (list, tuple)):
        items = list(value)[:MAX_LIST_ITEMS]
        text = "\n".join(_flat(v, depth + 1) for v in items)
        if len(value) > MAX_LIST_ITEMS:
            text += f"\n... and {len(value) - MAX_LIST_ITEMS} more"
        return text
    return str(value)


def _module_flowables(key: str, data: Any, st) -> List[Any]:
    title = MODULE_TITLES.get(key, key.replace("_", " ").title())
    head = Paragraph(_txt(title), st["h3"])
    if isinstance(data, dict) and data.get("error"):
        return [head, Paragraph(_txt(data["error"]), st["err"])]
    if isinstance(data, dict):
        cells = []
        for k, v in data.items():
            if str(k).startswith("_"):
                continue
            body = "<br/>".join(_txt(line) for line in _flat(v).split("\n"))
            cells.append([Paragraph(_txt(k), st["cellb"]), Paragraph(body, st["cell"])])
        if not cells:
            return [head, Paragraph("No data.", st["small"])]
        lw = 48 * mm
        t = Table(cells, colWidths=[lw, CONTENT_W - lw])
        t.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LINEBELOW", (0, 0), (-1, -1), 0.4, LINE),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        return [head, t]
    return [head, Paragraph(_txt(_flat(data)), st["cell"])]


# ------------------------------------------------------------------- page

def _decorate(canvas, doc):
    canvas.saveState()
    canvas.setFont("Helvetica", 7.5)
    canvas.setFillColor(GREY)
    canvas.drawString(MARGIN, 10 * mm,
                      "Web Application Reconnaissance Tool - for authorized security assessments only.")
    canvas.drawRightString(PAGE_W - MARGIN, 10 * mm, f"Page {doc.page}")
    canvas.restoreState()


def build_pdf(result, dash: dict | None, output_path: str) -> str:
    """Render `result` (+ optional dashboard dict) to a PDF at `output_path`."""
    if dash is None:
        import dashboard  # local import keeps this module dependency-light
        dash = dashboard.build_dashboard(result)

    st = _styles()
    story: List[Any] = []

    story.append(Paragraph("Web Application Reconnaissance Report", st["title"]))
    story.append(Paragraph(
        f"{_txt(getattr(result, 'base_url', '') or getattr(result, 'target', ''))} "
        f"&nbsp;|&nbsp; Generated {_txt(getattr(result, 'generated_at', ''))}", st["sub"]))
    story.append(Spacer(1, 8))

    if result.error:
        story.append(Paragraph(f"Reconnaissance failed: {_txt(result.error)}", st["err"]))
    else:
        story.append(Paragraph("Summary", st["h2"]))
        cards = _cards(dash.get("cards", []), st)
        if cards is not None:
            story.append(cards)

        for section in dash.get("sections", []):
            story.append(Paragraph(_txt(section["title"]), st["h3"]))
            if section["rows"]:
                story.append(_kv_table(section["rows"], st))
            else:
                story.append(Paragraph("No data collected.", st["small"]))

        story.append(Paragraph("Site technology", st["h3"]))
        tech = dash.get("technology", [])
        if tech:
            story.append(_kv_table(
                [(g.get("category"), ", ".join(g.get("items", []))) for g in tech], st))
        else:
            story.append(Paragraph("No technologies fingerprinted.", st["small"]))

        story.append(Paragraph("Observations", st["h3"]))
        story += _findings(dash.get("findings", []), st)

        story.append(Paragraph("Hosting history (observed)", st["h3"]))
        history = dash.get("history", [])
        if history:
            story.append(_grid_table(
                ["First seen", "Last seen", "IP address", "Netblock owner",
                 "Web server", "Cert issuer"],
                [[h.get("first_seen"), h.get("last_seen"), h.get("ip"),
                  h.get("netblock_owner"), h.get("web_server"), h.get("tls_issuer")]
                 for h in history[:MAX_GRID_ROWS]], st))
            story.append(Paragraph("History reflects only scans run by this tool.", st["small"]))
        else:
            story.append(Paragraph("No previous scans recorded for this host yet.", st["small"]))

        shot = (result.modules or {}).get("screenshot")
        if isinstance(shot, dict) and shot.get("captured") and os.path.exists(shot.get("path", "")):
            try:
                from reportlab.lib.utils import ImageReader
                iw, ih = ImageReader(shot["path"]).getSize()
                w = CONTENT_W
                h = min(w * ih / iw, 120 * mm)
                w = h * iw / ih
                story.append(Paragraph("Screenshot", st["h3"]))
                story.append(Image(shot["path"], width=w, height=h))
            except Exception:  # noqa: BLE001 - a bad image must not sink the report
                pass

        story.append(PageBreak())
        story.append(Paragraph("Full module output", st["h2"]))
        story.append(_kv_table([
            ("Target", result.target), ("Resolved hostname", result.hostname),
            ("Base URL", result.base_url), ("Generated", result.generated_at)], st))
        for key, val in (result.modules or {}).items():
            if key == "screenshot":
                continue
            story += _module_flowables(key, val, st)

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    doc = SimpleDocTemplate(
        output_path, pagesize=A4, leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=MARGIN, bottomMargin=18 * mm,
        title="Web Application Reconnaissance Report", author="Recon Tool",
    )
    doc.build(story, onFirstPage=_decorate, onLaterPages=_decorate)
    return output_path
