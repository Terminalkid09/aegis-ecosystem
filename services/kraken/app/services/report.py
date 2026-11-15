from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table,
    TableStyle, HRFlowable,
)
from datetime import datetime, timezone
from typing import List
import io

_ACCENT = colors.HexColor("#6366f1")
_DARK   = colors.HexColor("#0f172a")
_LGRAY  = colors.HexColor("#f1f5f9")
_GRID   = colors.HexColor("#e2e8f0")


def _table_style(header_color=_ACCENT) -> TableStyle:
    return TableStyle([
        ("BACKGROUND",   (0, 0), (-1,  0), header_color),
        ("TEXTCOLOR",    (0, 0), (-1,  0), colors.white),
        ("FONTNAME",     (0, 0), (-1,  0), "Helvetica-Bold"),
        ("FONTSIZE",     (0, 0), (-1, -1), 9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, _LGRAY]),
        ("GRID",         (0, 0), (-1, -1), 0.5, _GRID),
        ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",   (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 5),
    ])


def generate_report_pdf(stats: dict, events: List[dict]) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=2*cm, bottomMargin=2*cm,
                            leftMargin=2*cm, rightMargin=2*cm)
    styles = getSampleStyleSheet()
    title_s  = ParagraphStyle("T", parent=styles["Title"],  textColor=_ACCENT, fontSize=26, spaceAfter=4)
    sub_s    = ParagraphStyle("S", parent=styles["Normal"], textColor=_DARK,   fontSize=10, spaceAfter=4)
    h2_s     = ParagraphStyle("H2",parent=styles["Heading2"],textColor=_DARK,  fontSize=13,
                               spaceBefore=18, spaceAfter=8)

    story = []

    # ── Header ────────────────────────────────────────────────────────────────
    story.append(Paragraph("🦑  KRAKEN", title_s))
    story.append(Paragraph("Honeypot Intelligence Report", sub_s))
    story.append(Paragraph(f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC", sub_s))
    story.append(HRFlowable(width="100%", thickness=1, color=_ACCENT, spaceAfter=14))

    # ── Executive summary ─────────────────────────────────────────────────────
    story.append(Paragraph("Executive Summary", h2_s))
    top_country = (stats.get("top_countries") or [{}])[0].get("country", "N/A")
    top_sensor  = (stats.get("top_sensors")   or [{}])[0].get("sensor",  "N/A")
    summary = [
        ["Metric", "Value"],
        ["Total Attacks",          str(stats.get("total_attacks", 0))],
        ["Attacks Today",          str(stats.get("attacks_today", 0))],
        ["Unique Attacker IPs",    str(stats.get("unique_ips", 0))],
        ["Top Country",            top_country],
        ["Most Targeted Sensor",   top_sensor.upper()],
    ]
    story.append(Table(summary, colWidths=[8*cm, 8*cm], style=_table_style()))
    story.append(Spacer(1, 12))

    # ── Top countries ─────────────────────────────────────────────────────────
    if stats.get("top_countries"):
        story.append(Paragraph("Top Attacking Countries", h2_s))
        rows = [["Country", "Attacks"]] + [
            [c["country"], str(c["count"])] for c in stats["top_countries"][:10]
        ]
        story.append(Table(rows, colWidths=[10*cm, 6*cm], style=_table_style()))
        story.append(Spacer(1, 12))

    # ── Sensor breakdown ─────────────────────────────────────────────────────
    if stats.get("top_sensors"):
        story.append(Paragraph("Sensor Breakdown", h2_s))
        rows = [["Sensor", "Attacks"]] + [
            [s["sensor"].upper(), str(s["count"])] for s in stats["top_sensors"]
        ]
        story.append(Table(rows, colWidths=[10*cm, 6*cm], style=_table_style()))
        story.append(Spacer(1, 12))

    # ── Recent events ─────────────────────────────────────────────────────────
    story.append(Paragraph("Recent Attack Events (last 20)", h2_s))
    if events:
        rows = [["Timestamp", "IP", "Sensor", "Country", "City"]]
        for e in events[:20]:
            ts = str(e.get("timestamp_start", ""))[:19]
            rows.append([
                ts,
                e.get("attacker_ip", ""),
                (e.get("sensor_type") or "").upper(),
                e.get("country") or "—",
                e.get("city")    or "—",
            ])
        story.append(Table(
            rows,
            colWidths=[3.8*cm, 3.5*cm, 2.5*cm, 3.5*cm, 3.5*cm],
            style=_table_style(),
        ))
    else:
        story.append(Paragraph("No attack events recorded yet.", sub_s))

    story.append(Spacer(1, 20))
    story.append(HRFlowable(width="100%", thickness=1, color=_ACCENT))
    story.append(Paragraph("Kraken Honeypot System — Confidential Intelligence Report", sub_s))

    doc.build(story)
    return buf.getvalue()
