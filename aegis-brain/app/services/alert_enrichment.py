import asyncio
import json
import re
from datetime import datetime, timezone
from typing import Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.connection import AsyncSessionLocal
from app.database.models import Alert, Agent, OSINTReport, ThreatReport, IPReputation
from app.services.osint_service import fetch_ip_info
from app.services.ai_service import generate_threat_report


IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_PATTERN = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")


def _extract_ips(text: str) -> List[str]:
    return list(set(IP_PATTERN.findall(text)))


def _extract_domains(text: str) -> List[str]:
    return list(set(DOMAIN_PATTERN.findall(text)))


async def enrich_alert(alert_id: int):
    async with AsyncSessionLocal() as db:
        alert = await db.get(Alert, alert_id)
        if not alert:
            return

        context_text = f"{alert.process_name} {alert.description} {alert.process_path or ''}"
        ips = _extract_ips(context_text)
        domains = _extract_domains(context_text)

        osint_data = {}
        for ip in ips:
            if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.16."):
                continue
            try:
                report_data = await fetch_ip_info(ip)
                if report_data:
                    osint_data[ip] = report_data
                    await _update_ip_reputation(db, ip, report_data)
            except Exception:
                pass

        for domain in domains:
            try:
                existing = await db.execute(
                    select(OSINTReport).where(OSINTReport.query == domain)
                )
                report = existing.scalars().first()
                if report:
                    osint_data[domain] = report.data
            except Exception:
                pass

        try:
            analysis = await generate_threat_report(alert, osint_data)
        except Exception:
            analysis = None

        if osint_data or analysis:
            report = ThreatReport(
                alert_id=alert.id,
                summary=analysis.get("summary", "No analysis generated") if analysis else "No analysis generated",
                confidence=analysis.get("confidence", "medium") if analysis else "medium",
                recommended_actions=analysis.get("recommended_actions", []) if analysis else [],
                osint_data=osint_data if osint_data else None,
                ai_analysis=analysis.get("detailed_analysis", None) if analysis else None,
                is_auto_generated=True,
            )
            db.add(report)
            await db.commit()


async def _update_ip_reputation(db: AsyncSession, ip: str, report_data: dict):
    vt = report_data.get("sources", {}).get("virustotal", {})
    if vt and isinstance(vt, dict):
        malicious = vt.get("malicious", 0)
        total = vt.get("total", 1) or 1
        ratio = malicious / total
        label = "malicious" if ratio > 0.3 else "suspicious" if ratio > 0.1 else "known"
        confidence = int(ratio * 100)

        result = await db.execute(select(IPReputation).where(IPReputation.ip_address == ip))
        rec = result.scalars().first()
        if rec:
            rec.label = label
            rec.confidence = max(rec.confidence, confidence)
            rec.source = "auto_osint"
            rec.details = report_data
            rec.updated_at = datetime.now(timezone.utc)
        else:
            rec = IPReputation(
                ip_address=ip,
                label=label,
                confidence=confidence,
                source="auto_osint",
                details=report_data,
            )
            db.add(rec)


async def auto_enrich_new_alerts():
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(Alert).where(
                ~Alert.id.in_(select(ThreatReport.alert_id).where(ThreatReport.is_auto_generated == True))
            ).order_by(Alert.timestamp.desc()).limit(10)
        )
        alerts = result.scalars().all()
        for alert in alerts:
            try:
                await enrich_alert(alert.id)
                await asyncio.sleep(0.5)
            except Exception:
                pass
