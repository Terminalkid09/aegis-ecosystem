import asyncio
import httpx
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.config import settings
from app.core.logging import get_logger
from app.database.models import OSINTReport

logger = get_logger(__name__)

async def get_cached_result(db: AsyncSession, scan_type: str, target: str) -> Optional[Dict[str, Any]]:
    stmt = (
        select(OSINTReport)
        .where(
            OSINTReport.query == target,
            OSINTReport.source == scan_type,
            OSINTReport.cached_until >= datetime.now(timezone.utc)
        )
        .order_by(OSINTReport.created_at.desc())
    )
    result = await db.execute(stmt)
    rec = result.scalars().first()
    return rec.data if rec else None

async def save_osint_result(db: AsyncSession, scan_type: str, target: str, data: Dict[str, Any], ttl_seconds: Optional[int] = None):
    ttl = ttl_seconds or settings.OSINT_CACHE_TTL
    cached_until = datetime.now(timezone.utc) + timedelta(seconds=ttl)
    rec = OSINTReport(query=target, source=scan_type, data=data, cached_until=cached_until)
    db.add(rec)
    await db.commit()
    return rec

async def _shodan_lookup(client: httpx.AsyncClient, ip: str) -> Dict[str, Any]:
    if not settings.SHODAN_API_KEY or settings.SHODAN_API_KEY == "your_shodan_key_here": 
        return {"error": "api_key_not_configured"}
    url = f"https://api.shodan.io/shodan/host/{ip}?key={settings.SHODAN_API_KEY}"
    try:
        r = await client.get(url, timeout=10.0)
        if r.status_code == 200:
            data = r.json()
            return {
                "isp": data.get("isp") or "Unknown",
                "org": data.get("org") or "Unknown",
                "country": data.get("country_name") or "Unknown",
                "city": data.get("city") or "Unknown"
            }
        return {"error": "provider_error", "status": r.status_code}
    except Exception as e:
        return {"error": "exception", "message": str(e)}

async def _abuseipdb_lookup(client: httpx.AsyncClient, ip: str) -> Dict[str, Any]:
    if not settings.ABUSEIPDB_API_KEY or settings.ABUSEIPDB_API_KEY == "your_abuseipdb_key_here":
        return {"error": "api_key_not_configured"}
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": settings.ABUSEIPDB_API_KEY, "Accept": "application/json"}
    try:
        r = await client.get(url, headers=headers, params={"ipAddress": ip}, timeout=10.0)
        if r.status_code == 200:
            data = r.json().get("data", {})
            return {
                "abuseConfidenceScore": data.get("abuseConfidenceScore", 0),
                "totalReports": data.get("totalReports", 0),
                "lastReportedAt": data.get("lastReportedAt", "N/A")
            }
        return {"error": "provider_error", "status": r.status_code}
    except Exception as e:
        return {"error": "exception", "message": str(e)}

async def fetch_ip_info(ip: str) -> Dict[str, Any]:
    async with httpx.AsyncClient() as client:
        shodan, abuse = await asyncio.gather(_shodan_lookup(client, ip), _abuseipdb_lookup(client, ip))
        return {
            "target": ip,
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "sources": {"shodan": shodan, "abuseipdb": abuse}
        }

async def fetch_domain_info(domain: str) -> Dict[str, Any]:
    import socket
    try:
        ip = await asyncio.to_thread(socket.gethostbyname, domain)
        return {
            "target": domain,
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "sources": {
                "dns": {
                    "resolved_ip": ip,
                    "reputation": "Clean (Simulated)"
                },
                "domain": {
                    "note": "Reputation check simulated for " + domain,
                    "domain": domain
                }
            }
        }
    except Exception as e:
        return {
            "target": domain,
            "error": str(e),
            "sources": {"error": "Failed to resolve domain"}
        }
