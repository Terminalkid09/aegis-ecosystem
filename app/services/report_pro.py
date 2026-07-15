from __future__ import annotations
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from string import Template
from typing import Any, Dict, List, Optional
from uuid import uuid4
from loguru import logger
from app.core.config import settings

REPORTS_DIR = Path(settings.DATA_DIR) / "reports"
REPORT_INDEX_FILE = REPORTS_DIR / "index.json"


class ReportTemplate:
    def __init__(self, name: str, label: str, description: str, branding: Optional[dict] = None):
        self.name = name
        self.label = label
        self.description = description
        self.branding = branding or {
            "primary_color": "#6366f1",
            "secondary_color": "#0f172a",
            "accent_color": "#22d3ee",
            "logo_url": "",
            "company_name": "Kraken Security",
            "footer_text": "Kraken Honeypot System — Confidential Intelligence Report",
        }


class ReportProService:
    def __init__(self):
        self.templates: Dict[str, ReportTemplate] = {}
        self._register_templates()

    def _register_templates(self) -> None:
        self.templates["professional"] = ReportTemplate(
            "professional", "Professional Report",
            "Full professional report with executive summary, findings matrix, recommendations, and detailed event listing.",
            {"primary_color": "#6366f1", "secondary_color": "#0f172a", "accent_color": "#22d3ee",
             "logo_url": "", "company_name": "Kraken Security",
             "footer_text": "Kraken Honeypot System — Confidential Intelligence Report"},
        )
        self.templates["executive"] = ReportTemplate(
            "executive", "Executive Summary",
            "High-level executive summary with key metrics, top threats, and strategic recommendations. Suitable for management.",
            {"primary_color": "#059669", "secondary_color": "#064e3b", "accent_color": "#34d399",
             "logo_url": "", "company_name": "Kraken Security",
             "footer_text": "Kraken Honeypot System — Executive Summary"},
        )
        self.templates["technical"] = ReportTemplate(
            "technical", "Technical Report",
            "Detailed technical report with full event data, command logs, credential attempts, and malware samples.",
            {"primary_color": "#dc2626", "secondary_color": "#1e293b", "accent_color": "#f87171",
             "logo_url": "", "company_name": "Kraken Security",
             "footer_text": "Kraken Honeypot System — Technical Report"},
        )

    def list_templates(self) -> List[dict]:
        return [
            {"name": t.name, "label": t.label, "description": t.description, "branding": t.branding}
            for t in self.templates.values()
        ]

    def list_reports(self) -> List[dict]:
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        if not REPORT_INDEX_FILE.exists():
            return []
        try:
            data = json.loads(REPORT_INDEX_FILE.read_text(encoding="utf-8"))
            return sorted(data, key=lambda r: r.get("created_at", ""), reverse=True)
        except (json.JSONDecodeError, FileNotFoundError):
            return []

    def get_report(self, report_id: str) -> Optional[dict]:
        for report in self.list_reports():
            if report["id"] == report_id:
                report_path = REPORTS_DIR / f"{report_id}.json"
                if report_path.exists():
                    try:
                        full = json.loads(report_path.read_text(encoding="utf-8"))
                        return full
                    except json.JSONDecodeError:
                        return report
                return report
        return None

    def generate_report(
        self,
        title: str,
        template_name: str,
        stats: dict,
        events: List[dict],
        include_executive_summary: bool = True,
        include_findings_matrix: bool = True,
        include_recommendations: bool = True,
        days_back: Optional[int] = None,
        branding_overrides: Optional[dict] = None,
    ) -> dict:
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)

        template = self.templates.get(template_name, self.templates["professional"])
        branding = {**template.branding, **(branding_overrides or {})}

        report_id = str(uuid4())
        now = datetime.now(timezone.utc)

        executive_summary = self._build_executive_summary(stats, events, branding) if include_executive_summary else None
        findings_matrix = self._build_findings_matrix(events, branding) if include_findings_matrix else None
        recommendations = self._build_recommendations(findings_matrix) if include_recommendations and findings_matrix else None
        attack_timeline = self._build_timeline(events)
        geo_summary = self._build_geo_summary(events)
        sensor_breakdown = self._build_sensor_breakdown(events)

        report = {
            "id": report_id,
            "title": title,
            "template": template_name,
            "created_at": now.isoformat(),
            "period_start": (now.replace(hour=0, minute=0, second=0, microsecond=0) -
                           __import__("datetime").timedelta(days=days_back or 30)).isoformat() if days_back else None,
            "period_end": now.isoformat(),
            "branding": branding,
            "stats": {
                "total_attacks": stats.get("total_attacks", 0),
                "attacks_today": stats.get("attacks_today", 0),
                "unique_ips": stats.get("unique_ips", 0),
                "attacks_over_time": stats.get("attacks_over_time", []),
            },
            "executive_summary": executive_summary,
            "findings_matrix": findings_matrix,
            "recommendations": recommendations,
            "attack_timeline": attack_timeline,
            "geo_summary": geo_summary,
            "sensor_breakdown": sensor_breakdown,
            "top_countries": stats.get("top_countries", []),
            "top_sensors": stats.get("top_sensors", []),
            "events": events,
            "event_count": len(events),
        }

        report_file = REPORTS_DIR / f"{report_id}.json"
        report_file.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")

        index = self.list_reports()
        index.append({
            "id": report_id,
            "title": title,
            "template": template_name,
            "created_at": now.isoformat(),
            "event_count": len(events),
            "total_attacks": stats.get("total_attacks", 0),
            "unique_ips": stats.get("unique_ips", 0),
        })
        REPORT_INDEX_FILE.write_text(json.dumps(index, indent=2, default=str), encoding="utf-8")

        logger.info(f"Report generated: {report_id} ({title}) — {len(events)} events")
        return report

    def _build_executive_summary(self, stats: dict, events: List[dict], branding: dict) -> dict:
        top_country = (stats.get("top_countries") or [{}])[0].get("country", "N/A") if stats.get("top_countries") else "N/A"
        top_sensor = (stats.get("top_sensors") or [{}])[0].get("sensor", "N/A") if stats.get("top_sensors") else "N/A"
        threat_ips = [e["attacker_ip"] for e in events if e.get("is_known_threat")]
        total_commands = sum(len(e.get("commands") or []) for e in events)
        total_creds = sum(len(e.get("credentials") or []) for e in events)

        return {
            "organization": branding["company_name"],
            "report_period": f"Last {min(len(events), 30)} days",
            "key_findings": [
                f"Total of {stats.get('total_attacks', 0)} attack events detected",
                f"{stats.get('unique_ips', 0)} unique attacker IPs identified",
                f"Top attacking country: {top_country}",
                f"Most targeted sensor: {top_sensor.upper()}",
                f"{total_commands} commands executed by attackers",
                f"{total_creds} credential attempts captured",
                f"{len(threat_ips)} known threat IPs detected",
            ],
            "risk_level": "Critical" if stats.get("attacks_today", 0) > 100 else (
                "High" if stats.get("attacks_today", 0) > 50 else (
                    "Medium" if stats.get("attacks_today", 0) > 10 else "Low"
                )
            ),
            "threat_ips": threat_ips[:10],
        }

    def _build_findings_matrix(self, events: List[dict], branding: dict) -> List[dict]:
        sensor_types = set(e.get("sensor_type", "").lower() for e in events)
        countries = set(e.get("country", "Unknown") for e in events)
        total_commands = sum(len(e.get("commands") or []) for e in events)
        total_creds = sum(len(e.get("credentials") or []) for e in events)
        malware_count = sum(len(e.get("malware_samples") or []) for e in events)

        return [
            {"finding": "Attack Volume", "severity": "High" if len(events) > 50 else "Medium",
             "count": len(events), "details": f"{len(events)} events detected across {len(sensor_types)} sensor types"},
            {"finding": "Geographic Distribution", "severity": "Medium",
             "count": len(countries), "details": f"Attackers from {len(countries)} countries"},
            {"finding": "Credential Attacks", "severity": "Critical" if total_creds > 20 else "High",
             "count": total_creds, "details": f"{total_creds} credential attempts captured"},
            {"finding": "Command Execution", "severity": "Critical" if total_commands > 50 else "High",
             "count": total_commands, "details": f"{total_commands} commands executed by attackers"},
            {"finding": "Malware Distribution", "severity": "Critical" if malware_count > 0 else "Low",
             "count": malware_count, "details": f"{malware_count} malware samples captured" if malware_count > 0 else "No malware detected"},
            {"finding": "Repeat Offenders", "severity": "High",
             "count": len(set(e.get("attacker_ip") for e in events if e.get("is_known_threat"))),
             "details": "Known threat IPs detected in attack traffic"},
        ]

    def _build_recommendations(self, findings: List[dict]) -> List[str]:
        recs = []
        for f in findings:
            if f["finding"] == "Attack Volume" and f["severity"] in ("High", "Critical"):
                recs.append("Implement rate limiting and geo-blocking for high-volume attack sources.")
            if f["finding"] == "Credential Attacks" and f["severity"] in ("High", "Critical"):
                recs.append("Enforce multi-factor authentication and monitor for credential stuffing patterns.")
            if f["finding"] == "Command Execution" and f["severity"] in ("High", "Critical"):
                recs.append("Review and restrict shell access. Implement command whitelisting and audit logging.")
            if f["finding"] == "Malware Distribution" and f["severity"] == "Critical":
                recs.append("Isolate affected systems immediately. Conduct forensic analysis of malware samples.")
            if f["finding"] == "Geographic Distribution" and f["count"] > 5:
                recs.append("Review firewall rules and consider geo-fencing for high-risk regions.")
        recs.append("Schedule regular security audits and update incident response procedures.")
        recs.append("Ensure all systems are patched and running latest security updates.")
        return recs

    def _build_timeline(self, events: List[dict]) -> List[dict]:
        from collections import Counter
        day_counts: Counter = Counter()
        for e in events:
            day = str(e.get("timestamp_start", ""))[:10]
            if day:
                day_counts[day] += 1
        return [{"date": day, "count": count} for day, count in sorted(day_counts.items())]

    def _build_geo_summary(self, events: List[dict]) -> List[dict]:
        from collections import Counter
        country_counts: Counter = Counter()
        for e in events:
            c = e.get("country", "Unknown")
            country_counts[c] += 1
        return [{"country": c, "count": count, "percentage": round(count / len(events) * 100, 1) if events else 0}
                for c, count in country_counts.most_common(10)]

    def _build_sensor_breakdown(self, events: List[dict]) -> List[dict]:
        from collections import Counter
        sensor_counts: Counter = Counter()
        for e in events:
            s = (e.get("sensor_type") or "unknown").upper()
            sensor_counts[s] += 1
        return [{"sensor": s, "count": count, "percentage": round(count / len(events) * 100, 1) if events else 0}
                for s, count in sensor_counts.most_common()]

    def render_report_html(self, report: dict) -> str:
        branding = report.get("branding", {})
        es = report.get("executive_summary") or {}
        findings = report.get("findings_matrix") or []
        recs = report.get("recommendations") or []
        timeline = report.get("attack_timeline") or []
        geo = report.get("geo_summary") or []
        sensors = report.get("sensor_breakdown") or []
        events = report.get("events") or []
        stats = report.get("stats", {})
        pc = branding.get("primary_color", "#6366f1")
        sc = branding.get("secondary_color", "#0f172a")

        sev_class = lambda s: {
            "Critical": "bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-300",
            "High": "bg-orange-100 text-orange-800 dark:bg-orange-900/40 dark:text-orange-300",
            "Medium": "bg-yellow-100 text-yellow-800 dark:bg-yellow-900/40 dark:text-yellow-300",
            "Low": "bg-green-100 text-green-800 dark:bg-green-900/40 dark:text-green-300",
        }.get(s, "bg-gray-100")

        def sev_tag(sev):
            cls = sev_class(sev)
            return "<span class='text-xs font-medium px-2 py-0.5 rounded " + cls + "'>" + sev + "</span>"

        timeline_bars = ""
        for t in timeline[-14:]:
            d = t.get("date", "")[5:]
            c = t.get("count", 0)
            w = min(c / 20 * 100, 100)
            timeline_bars += (
                "<div class='flex items-center gap-2 text-xs'>"
                "<span class='w-24 text-right text-gray-500 shrink-0'>" + d + "</span>"
                "<div class='flex-1 bg-gray-200 dark:bg-gray-700 rounded-full h-4 overflow-hidden'>"
                "<div class='h-full rounded-full transition-all' style='width:" + str(w) + "%;background:" + pc + "'></div></div>"
                "<span class='w-10 text-left text-gray-400'>" + str(c) + "</span></div>"
            )

        findings_rows = ""
        for f_item in findings:
            findings_rows += (
                "<tr><td class='px-4 py-2 text-sm'>" + f_item["finding"] + "</td>"
                "<td class='px-4 py-2'>" + sev_tag(f_item["severity"]) + "</td>"
                "<td class='px-4 py-2 text-sm text-right font-mono'>" + str(f_item["count"]) + "</td>"
                "<td class='px-4 py-2 text-sm text-gray-500 dark:text-gray-400'>" + f_item["details"] + "</td></tr>"
            )

        recs_html = ""
        for r in recs:
            recs_html += "<li class='flex items-start gap-2 text-sm'><span class='mt-1 w-1.5 h-1.5 rounded-full shrink-0' style='background:" + pc + "'></span><span>" + r + "</span></li>"

        geo_html = ""
        for g in geo:
            geo_html += (
                "<tr><td class='px-4 py-1.5 text-sm'>" + g["country"] + "</td>"
                "<td class='px-4 py-1.5 text-sm text-right font-mono'>" + str(g["count"]) + "</td>"
                "<td class='px-4 py-1.5 text-sm text-right text-gray-500'>" + str(g["percentage"]) + "%</td></tr>"
            )

        sensor_html = ""
        for s in sensors:
            sensor_html += (
                "<tr><td class='px-4 py-1.5 text-sm'>" + s["sensor"] + "</td>"
                "<td class='px-4 py-1.5 text-sm text-right font-mono'>" + str(s["count"]) + "</td>"
                "<td class='px-4 py-1.5 text-sm text-right text-gray-500'>" + str(s["percentage"]) + "%</td></tr>"
            )

        event_rows = ""
        for e in events[:50]:
            sensor_type = (e.get("sensor_type") or "").upper()
            ts = (e.get("timestamp_start") or "")[:19]
            event_rows += (
                "<tr class='hover:bg-gray-50 dark:hover:bg-gray-700/50'>"
                "<td class='px-3 py-1.5 text-xs font-mono text-gray-500'>" + ts + "</td>"
                "<td class='px-3 py-1.5 text-xs font-mono'>" + (e.get("attacker_ip") or "") + "</td>"
                "<td class='px-3 py-1.5 text-xs'><span class='font-medium px-1.5 py-0.5 rounded text-xs'"
                " style='background:" + pc + "20;color:" + pc + "'>" + sensor_type + "</span></td>"
                "<td class='px-3 py-1.5 text-xs text-gray-500'>" + (e.get("country") or "") + "</td>"
                "<td class='px-3 py-1.5 text-xs text-gray-500'>" + (e.get("city") or "") + "</td>"
                "<td class='px-3 py-1.5 text-xs text-right'>" + ("&#128308;" if e.get("is_known_threat") else "&#128994;") + "</td></tr>"
            )

        findings_section = ""
        if findings:
            findings_section = (
                "<div class='card mb-6'>"
                "<h2 class='text-lg font-bold mb-4' style='color:" + sc + "'>Findings Matrix</h2>"
                "<div class='overflow-x-auto'><table class='w-full text-left'>"
                "<thead><tr class='border-b text-xs uppercase text-gray-500'>"
                "<th class='px-4 py-2 font-medium'>Finding</th>"
                "<th class='px-4 py-2 font-medium'>Severity</th>"
                "<th class='px-4 py-2 font-medium text-right'>Count</th>"
                "<th class='px-4 py-2 font-medium'>Details</th>"
                "</tr></thead><tbody>" + findings_rows + "</tbody></table></div></div>"
            )

        recs_section = ""
        if recs:
            recs_section = (
                "<div class='card mb-6'>"
                "<h2 class='text-lg font-bold mb-3' style='color:" + sc + "'>Recommendations</h2>"
                "<ul class='space-y-2'>" + recs_html + "</ul></div>"
            )

        es_findings_html = ""
        if es:
            for f_text in es.get("key_findings", []):
                es_findings_html += "<li class='flex items-start gap-2 text-sm'><span class='text-indigo-500 mt-1'>&#9670;</span>" + f_text + "</li>"

        risk_color = {"Critical": "text-red-600", "High": "text-orange-600", "Medium": "text-yellow-600", "Low": "text-green-600"}

        es_section = ""
        if es:
            rl = es.get("risk_level", "Low")
            rl_class = risk_color.get(rl, "text-green-600")
            es_section = (
                "<div class='card mb-6'><h2 class='text-lg font-bold mb-4' style='color:" + sc + "'>Executive Summary</h2>"
                "<div class='grid grid-cols-2 gap-4 mb-4'>"
                "<div><span class='text-xs uppercase text-gray-500'>Organization</span><p class='font-medium'>" + es.get("organization", "N/A") + "</p></div>"
                "<div><span class='text-xs uppercase text-gray-500'>Risk Level</span><p class='font-bold text-lg " + rl_class + "'>" + rl + "</p></div>"
                "<div><span class='text-xs uppercase text-gray-500'>Report Period</span><p class='font-medium'>" + es.get("report_period", "N/A") + "</p></div>"
                "<div><span class='text-xs uppercase text-gray-500'>Known Threats</span><p class='font-medium'>" + str(len(es.get("threat_ips", []))) + "</p></div>"
                "</div><h3 class='text-sm font-semibold text-gray-700 mb-2'>Key Findings</h3>"
                "<ul class='space-y-1.5'>" + es_findings_html + "</ul></div>"
            )

        timeline_section = ""
        if timeline:
            timeline_section = (
                "<div class='card mb-6'><h2 class='text-lg font-bold mb-4' style='color:" + sc + "'>Attack Timeline (Last 14 Days)</h2>"
                "<div class='space-y-1.5'>" + timeline_bars + "</div></div>"
            )

        geo_section = ""
        if geo:
            geo_section = (
                "<div class='card'><h3 class='text-sm font-bold mb-3' style='color:" + sc + "'>Geographic Distribution</h3>"
                "<table class='w-full text-left'><thead><tr class='border-b text-xs uppercase text-gray-500'>"
                "<th class='pb-1 font-medium'>Country</th><th class='pb-1 font-medium text-right'>Attacks</th><th class='pb-1 font-medium text-right'>%</th>"
                "</tr></thead><tbody>" + geo_html + "</tbody></table></div>"
            )

        sensor_section = ""
        if sensors:
            sensor_section = (
                "<div class='card'><h3 class='text-sm font-bold mb-3' style='color:" + sc + "'>Sensor Breakdown</h3>"
                "<table class='w-full text-left'><thead><tr class='border-b text-xs uppercase text-gray-500'>"
                "<th class='pb-1 font-medium'>Sensor</th><th class='pb-1 font-medium text-right'>Attacks</th><th class='pb-1 font-medium text-right'>%</th>"
                "</tr></thead><tbody>" + sensor_html + "</tbody></table></div>"
            )

        show_more = ""
        if len(events) > 50:
            show_more = "<p class='text-xs text-gray-400 mt-3'>Showing first 50 of " + str(len(events)) + " events</p>"

        footer_text = branding.get("footer_text", "Kraken Honeypot System — Confidential Intelligence Report")
        event_count = report.get("event_count", 0)
        created_at = (report.get("created_at") or "")[:19]
        title = report["title"]
        total_attacks = stats.get("total_attacks", 0)
        attacks_today = stats.get("attacks_today", 0)
        unique_ips = stats.get("unique_ips", 0)

        html = (
            "<!DOCTYPE html>\n<html lang='en'>\n<head>\n<meta charset='UTF-8'>\n"
            "<meta name='viewport' content='width=device-width, initial-scale=1.0'>\n"
            "<title>" + title + "</title>\n"
            "<script src='https://cdn.tailwindcss.com'></script>\n"
            "<script>tailwind.config={darkMode:'class',theme:{extend:{colors:{brand:'" + pc + "'}}}}</script>\n"
            "<style>body{font-family:system-ui,-apple-system,sans-serif}.card{background:white;border-radius:12px;border:1px solid #e2e8f0;padding:1.25rem}@media print{.no-print{display:none!important}}</style>\n"
            "</head>\n<body class='bg-gray-50 text-gray-900'>\n"
            "<div class='max-w-5xl mx-auto p-6'>\n"

            "<div class='flex items-center justify-between mb-8 no-print'>\n"
            "<div><h1 class='text-3xl font-bold' style='color:" + pc + "'>" + title + "</h1>"
            "<p class='text-sm text-gray-500 mt-1'>Generated: " + created_at + " UTC</p></div>\n"
            "<button onclick=\"window.print()\" class='px-4 py-2 rounded-lg text-sm font-medium text-white' style='background:" + pc + "'>Print / PDF</button>\n"
            "</div>\n"

            "<div class='grid grid-cols-4 gap-4 mb-6'>\n"
            "<div class='card text-center'><p class='text-xs uppercase text-gray-500 tracking-wide'>Total Attacks</p>"
            "<p class='text-3xl font-bold mt-1' style='color:" + pc + "'>" + "{:,}".format(total_attacks) + "</p></div>\n"
            "<div class='card text-center'><p class='text-xs uppercase text-gray-500 tracking-wide'>Attacks Today</p>"
            "<p class='text-3xl font-bold mt-1 text-emerald-600'>" + "{:,}".format(attacks_today) + "</p></div>\n"
            "<div class='card text-center'><p class='text-xs uppercase text-gray-500 tracking-wide'>Unique IPs</p>"
            "<p class='text-3xl font-bold mt-1 text-amber-600'>" + "{:,}".format(unique_ips) + "</p></div>\n"
            "<div class='card text-center'><p class='text-xs uppercase text-gray-500 tracking-wide'>Events in Report</p>"
            "<p class='text-3xl font-bold mt-1 text-rose-600'>" + "{:,}".format(event_count) + "</p></div>\n"
            "</div>\n"

            + es_section
            + timeline_section
            + findings_section
            + recs_section

            + "<div class='grid grid-cols-2 gap-4 mb-6'>\n"
            + geo_section
            + sensor_section
            + "</div>\n"

            + "<div class='card'>\n"
            "<h2 class='text-lg font-bold mb-4' style='color:" + sc + "'>Attack Events (" + str(len(events)) + " total)</h2>\n"
            "<div class='overflow-x-auto'><table class='w-full text-left'>\n"
            "<thead><tr class='border-b text-xs uppercase text-gray-500'>"
            "<th class='px-3 py-2 font-medium'>Timestamp</th><th class='px-3 py-2 font-medium'>IP</th>"
            "<th class='px-3 py-2 font-medium'>Sensor</th><th class='px-3 py-2 font-medium'>Country</th>"
            "<th class='px-3 py-2 font-medium'>City</th><th class='px-3 py-2 font-medium text-right'>Threat</th>"
            "</tr></thead>\n<tbody>" + event_rows + "</tbody>\n</table></div>\n"
            + show_more
            + "</div>\n"

            + "<div class='text-center text-xs text-gray-400 mt-8 pt-4 border-t'>\n"
            + footer_text + "\n</div>\n"
            "</div>\n</body>\n</html>"
        )
        return html

    def render_report_pdf(self, report: dict) -> bytes:
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm, mm
        from reportlab.lib import colors
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table,
            TableStyle, HRFlowable, PageBreak, KeepTogether,
        )
        import io

        branding = report.get("branding", {})
        primary = colors.HexColor(branding.get("primary_color", "#6366f1"))
        secondary = colors.HexColor(branding.get("secondary_color", "#0f172a"))
        accent = colors.HexColor(branding.get("accent_color", "#22d3ee"))
        lgray = colors.HexColor("#f1f5f9")
        grid_c = colors.HexColor("#e2e8f0")

        buf = io.BytesIO()

        def header_footer(canvas, doc):
            canvas.saveState()
            canvas.setFont("Helvetica", 7)
            canvas.setFillColor(colors.HexColor("#94a3b8"))
            canvas.drawString(2*cm, 1.5*cm, branding.get("footer_text", "Kraken — Confidential"))
            canvas.drawRightString(A4[0] - 2*cm, 1.5*cm, f"Page {doc.page}")
            canvas.restoreState()

        doc = SimpleDocTemplate(buf, pagesize=A4, topMargin=2.5*cm, bottomMargin=2.5*cm,
                                leftMargin=2*cm, rightMargin=2*cm)
        styles = getSampleStyleSheet()

        title_s = ParagraphStyle("T", parent=styles["Title"], textColor=primary, fontSize=24, spaceAfter=2)
        sub_s = ParagraphStyle("S", parent=styles["Normal"], textColor=colors.HexColor("#64748b"), fontSize=9, spaceAfter=2)
        h2_s = ParagraphStyle("H2", parent=styles["Heading2"], textColor=secondary, fontSize=14, spaceBefore=14, spaceAfter=8)
        h3_s = ParagraphStyle("H3", parent=styles["Heading3"], textColor=secondary, fontSize=11, spaceBefore=10, spaceAfter=6)
        normal_s = ParagraphStyle("N", parent=styles["Normal"], fontSize=9, leading=13)
        small_s = ParagraphStyle("SM", parent=styles["Normal"], fontSize=8, leading=11, textColor=colors.HexColor("#64748b"))
        bullet_s = ParagraphStyle("B", parent=styles["Normal"], fontSize=9, leading=13, leftIndent=12, bulletIndent=0)

        def _ts(header_color=None):
            return TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), header_color or primary),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, lgray]),
                ("GRID", (0, 0), (-1, -1), 0.5, grid_c),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ])

        story = []

        story.append(Paragraph(report["title"], title_s))
        story.append(Paragraph(f"Generated: {report.get('created_at', '')[:19]} UTC", sub_s))
        story.append(HRFlowable(width="100%", thickness=1, color=primary, spaceAfter=12))

        stats = report.get("stats", {})
        stats_data = [
            ["Total Attacks", str(stats.get("total_attacks", 0)),
             "Attacks Today", str(stats.get("attacks_today", 0))],
            ["Unique IPs", str(stats.get("unique_ips", 0)),
             "Events in Report", str(report.get("event_count", 0))],
        ]
        story.append(Table(stats_data, colWidths=[4*cm, 3*cm, 4*cm, 3*cm], style=_ts(secondary)))
        story.append(Spacer(1, 10))

        es = report.get("executive_summary")
        if es:
            story.append(Paragraph("Executive Summary", h2_s))
            risk_level = es.get("risk_level", "Low")
            risk_color_pdf = colors.red if risk_level == "Critical" else colors.orange if risk_level == "High" else colors.green
            summary_data = [
                ["Organization", es.get("organization", "N/A"),
                 "Risk Level", risk_level],
                ["Report Period", es.get("report_period", "N/A"),
                 "Known Threats", str(len(es.get("threat_ips", [])))],
            ]
            t = Table(summary_data, colWidths=[4*cm, 4*cm, 3*cm, 4*cm], style=_ts(secondary))
            story.append(t)
            story.append(Spacer(1, 6))
            story.append(Paragraph("Key Findings", h3_s))
            for f_text in es.get("key_findings", []):
                story.append(Paragraph(f"◆  {f_text}", bullet_s))
            story.append(Spacer(1, 8))

        findings = report.get("findings_matrix", [])
        if findings:
            story.append(Paragraph("Findings Matrix", h2_s))
            f_data = [["Finding", "Severity", "Count", "Details"]]
            for f_item in findings:
                f_data.append([
                    f_item["finding"],
                    f_item["severity"],
                    str(f_item["count"]),
                    f_item["details"],
                ])
            story.append(Table(f_data, colWidths=[4*cm, 2.5*cm, 1.5*cm, 8*cm], style=_ts()))
            story.append(Spacer(1, 8))

        recs = report.get("recommendations", [])
        if recs:
            story.append(Paragraph("Recommendations", h2_s))
            for r in recs:
                story.append(Paragraph(f"→  {r}", bullet_s))
            story.append(Spacer(1, 8))

        geo = report.get("geo_summary", [])
        sensors_pdf = report.get("sensor_breakdown", [])
        if geo or sensors_pdf:
            story.append(Paragraph("Breakdown", h2_s))
            if geo:
                story.append(Paragraph("Geographic Distribution", h3_s))
                g_data = [["Country", "Attacks", "%"]] + [
                    [g["country"], str(g["count"]), f"{g['percentage']}%"] for g in geo[:8]
                ]
                story.append(Table(g_data, colWidths=[6*cm, 4*cm, 4*cm], style=_ts(accent)))
                story.append(Spacer(1, 4))
            if sensors_pdf:
                story.append(Paragraph("Sensor Breakdown", h3_s))
                s_data = [["Sensor", "Attacks", "%"]] + [
                    [s["sensor"], str(s["count"]), f"{s['percentage']}%"] for s in sensors_pdf
                ]
                story.append(Table(s_data, colWidths=[6*cm, 4*cm, 4*cm], style=_ts(accent)))
            story.append(Spacer(1, 8))

        events_data = report.get("events", [])
        if events_data:
            story.append(Paragraph(f"Attack Events ({len(events_data)} total)", h2_s))
            e_data = [["Timestamp", "IP", "Sensor", "Country", "Threat"]]
            for e in events_data[:30]:
                ts = str(e.get("timestamp_start", ""))[:19]
                threat = "●" if e.get("is_known_threat") else "○"
                e_data.append([
                    ts,
                    e.get("attacker_ip", ""),
                    (e.get("sensor_type") or "").upper(),
                    e.get("country") or "—",
                    threat,
                ])
            story.append(Table(e_data, colWidths=[3.5*cm, 3.5*cm, 2.5*cm, 3.5*cm, 1.5*cm], style=_ts()))
            if len(events_data) > 30:
                story.append(Paragraph(f"Showing first 30 of {len(events_data)} events", small_s))

        story.append(Spacer(1, 16))
        story.append(HRFlowable(width="100%", thickness=0.5, color=grid_c))
        story.append(Paragraph(branding.get("footer_text", "Kraken Honeypot System — Confidential"), small_s))

        doc.build(story, onFirstPage=header_footer, onLaterPages=header_footer)
        return buf.getvalue()

    def delete_report(self, report_id: str) -> bool:
        index = self.list_reports()
        new_index = [r for r in index if r["id"] != report_id]
        if len(new_index) == len(index):
            return False
        REPORT_INDEX_FILE.write_text(json.dumps(new_index, indent=2, default=str), encoding="utf-8")
        report_file = REPORTS_DIR / f"{report_id}.json"
        if report_file.exists():
            report_file.unlink()
        return True


report_pro_service = ReportProService()
