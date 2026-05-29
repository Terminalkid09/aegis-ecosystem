from fastapi import APIRouter, Depends, HTTPException, Query, status
from app.core.deps import get_optional_user
from app.services import osint_service
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.database.connection import get_db
from app.database.models import OSINTReport
import ipaddress
import re

router = APIRouter(tags=["OSINT"])

@router.get("/ip/{ip_address}")
async def ip_lookup(ip_address: str, force: bool = False, db: AsyncSession = Depends(get_db), user=Depends(get_optional_user)):
    try:
        ipaddress.ip_address(ip_address)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid IP address format")

    if force and not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required for live OSINT scans")

    if not force:
        cached = await osint_service.get_cached_result(db, "ip", ip_address)
        if cached: return {"cached": True, "data": cached}
    
    data = await osint_service.fetch_ip_info(ip_address)
    await osint_service.save_osint_result(db, "ip", ip_address, data)
    return {"cached": False, "data": data}

@router.get("/domain/{domain}")
async def domain_lookup(domain: str, force: bool = False, db: AsyncSession = Depends(get_db), user=Depends(get_optional_user)):
    domain_regex = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$")
    if not domain_regex.match(domain):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid domain format")

    if force and not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required for live OSINT scans")

    if not force:
        cached = await osint_service.get_cached_result(db, "domain", domain)
        if cached: return {"cached": True, "data": cached}

    data = await osint_service.fetch_domain_info(domain)
    await osint_service.save_osint_result(db, "domain", domain, data)
    return {"cached": False, "data": data}

@router.get("/history")
async def osint_history(limit: int = Query(10, ge=1, le=100), db: AsyncSession = Depends(get_db), user=Depends(get_optional_user)):
    stmt = select(OSINTReport).order_by(OSINTReport.created_at.desc()).limit(limit)
    result = await db.execute(stmt)
    items = [
        {
            "query": item.query,
            "source": item.source,
            "created_at": item.created_at,
            "cached_until": item.cached_until
        }
        for item in result.scalars().all()
    ]
    return {"items": items}
