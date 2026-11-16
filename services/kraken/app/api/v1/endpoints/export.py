from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.session import get_db
from app.services.attack_service import get_events, get_dashboard_stats
from app.services.report import generate_report_pdf
from app.api.v1.endpoints.deps import get_current_user
from app.core.limiter import limiter
import csv
import json
import io

router = APIRouter(prefix="/export", tags=["export"])


@router.get("/csv")
@limiter.limit("30/minute")
async def export_csv(request: Request, db: AsyncSession = Depends(get_db), _=Depends(get_current_user)):
    events = await get_events(db, limit=10000)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["session_id", "attacker_ip", "attacker_port", "sensor_type",
                     "timestamp_start", "country", "city", "asn", "is_known_threat"])
    for e in events:
        writer.writerow([
            e.session_id, e.attacker_ip, e.attacker_port, e.sensor_type,
            e.timestamp_start, e.country, e.city, e.asn, e.is_known_threat,
        ])
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=kraken_events.csv"},
    )


@router.get("/json")
@limiter.limit("30/minute")
async def export_json(request: Request, db: AsyncSession = Depends(get_db), _=Depends(get_current_user)):
    events = await get_events(db, limit=10000)
    data = [
        {
            "session_id": e.session_id,
            "attacker_ip": e.attacker_ip,
            "attacker_port": e.attacker_port,
            "sensor_type": e.sensor_type,
            "timestamp_start": str(e.timestamp_start),
            "country": e.country,
            "city": e.city,
            "asn": e.asn,
            "is_known_threat": e.is_known_threat,
        }
        for e in events
    ]
    return Response(
        content=json.dumps(data, indent=2, default=str),
        media_type="application/json",
        headers={"Content-Disposition": "attachment; filename=kraken_events.json"},
    )


@router.get("/pdf")
@limiter.limit("30/minute")
async def export_pdf(request: Request, db: AsyncSession = Depends(get_db), _=Depends(get_current_user)):
    stats = await get_dashboard_stats(db)
    events = await get_events(db, limit=20)
    events_dicts = [
        {
            "timestamp_start": str(e.timestamp_start),
            "attacker_ip": e.attacker_ip,
            "sensor_type": e.sensor_type,
            "country": e.country,
            "city": e.city,
        }
        for e in events
    ]
    pdf_bytes = generate_report_pdf(stats, events_dicts)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": "attachment; filename=kraken_report.pdf"},
    )
