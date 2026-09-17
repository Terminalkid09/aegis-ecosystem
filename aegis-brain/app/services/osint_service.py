import asyncio
import httpx
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.config import settings
from app.core.logging import get_logger
from app.database.connection import AsyncSessionLocal
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

async def _provider_key(db: Optional[AsyncSession], name: str) -> str:
    """Chiave effettiva: env vince, poi override DB (integration_settings)."""
    if db is None:
        from app.services.integration_settings import get_key
        async with AsyncSessionLocal() as session:
            return await get_key(session, name)
    from app.services.integration_settings import get_key
    return await get_key(db, name)


async def _shodan_lookup(client: httpx.AsyncClient, ip: str,
                         db: Optional[AsyncSession] = None) -> Dict[str, Any]:
    key = await _provider_key(db, "shodan")
    if not key:
        return {"error": "api_key_not_configured"}
    url = f"https://api.shodan.io/shodan/host/{ip}?key={key}"
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

async def _abuseipdb_lookup(client: httpx.AsyncClient, ip: str,
                            db: Optional[AsyncSession] = None) -> Dict[str, Any]:
    key = await _provider_key(db, "abuseipdb")
    if not key:
        return {"error": "api_key_not_configured"}
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": key, "Accept": "application/json"}
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

async def _virustotal_lookup(client: httpx.AsyncClient, ip: str,
                             db: Optional[AsyncSession] = None) -> Dict[str, Any]:
    key = await _provider_key(db, "virustotal")
    if not key:
        return {"error": "api_key_not_configured"}
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": key, "Accept": "application/json"}
    try:
        r = await client.get(url, headers=headers, timeout=10.0)
        if r.status_code == 200:
            data = r.json().get("data", {}).get("attributes", {})
            last_stats = data.get("last_analysis_stats", {})
            return {
                "malicious": last_stats.get("malicious", 0),
                "suspicious": last_stats.get("suspicious", 0),
                "harmless": last_stats.get("harmless", 0),
                "undetected": last_stats.get("undetected", 0),
                "reputation": data.get("reputation", 0),
                "country": data.get("country", ""),
                "as_owner": data.get("as_owner", ""),
            }
        return {"error": "provider_error", "status": r.status_code}
    except Exception as e:
        return {"error": "exception", "message": str(e)}

async def fetch_ip_info(ip: str, db: Optional[AsyncSession] = None) -> Dict[str, Any]:
    async with httpx.AsyncClient() as client:
        shodan, abuse, vt = await asyncio.gather(
            _shodan_lookup(client, ip, db), _abuseipdb_lookup(client, ip, db),
            _virustotal_lookup(client, ip, db),
        )
        return {
            "target": ip,
            "fetched_at": datetime.now(timezone.utc).isoformat(),
            "sources": {"shodan": shodan, "abuseipdb": abuse, "virustotal": vt}
        }

async def _virustotal_domain_lookup(client: httpx.AsyncClient, domain: str,
                                    db: Optional[AsyncSession] = None) -> Dict[str, Any]:
    key = await _provider_key(db, "virustotal")
    if not key:
        return {"error": "api_key_not_configured"}
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": key, "Accept": "application/json"}
    try:
        r = await client.get(url, headers=headers, timeout=10.0)
        if r.status_code == 200:
            data = r.json().get("data", {}).get("attributes", {})
            last_stats = data.get("last_analysis_stats", {})
            return {
                "malicious": last_stats.get("malicious", 0),
                "suspicious": last_stats.get("suspicious", 0),
                "harmless": last_stats.get("harmless", 0),
                "undetected": last_stats.get("undetected", 0),
                "reputation": data.get("reputation", 0),
                "registrar": data.get("registrar", ""),
                "creation_date": str(data.get("creation_date", "")),
            }
        return {"error": "provider_error", "status": r.status_code}
    except Exception as e:
        return {"error": "exception", "message": str(e)}


async def fetch_domain_info(domain: str, db: Optional[AsyncSession] = None) -> Dict[str, Any]:
    import socket
    try:
        ip = await asyncio.to_thread(socket.gethostbyname, domain)
    except Exception as e:
        return {
            "target": domain,
            "error": str(e),
            "sources": {"error": "Failed to resolve domain"}
        }
    async with httpx.AsyncClient() as client:
        vt = await _virustotal_domain_lookup(client, domain, db)
    return {
        "target": domain,
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "sources": {
            "dns": {"resolved_ip": ip},
            "virustotal": vt,
        },
    }
