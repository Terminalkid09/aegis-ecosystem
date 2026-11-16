from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, Response
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.session import get_db
from app.services.attack_service import get_events, get_dashboard_stats, get_event_by_session
from app.services.report_pro import report_pro_service
from app.api.v1.endpoints.deps import get_current_user, get_current_admin
from app.core.event_bus import event_bus
from typing import Optional

router = APIRouter(prefix="/reports", tags=["reports"])


@router.get("/")
async def list_reports(_=Depends(get_current_user)):
    return report_pro_service.list_reports()


@router.post("/generate")
async def generate_report(
    request: Request,
    title: str = Query("Kraken Intelligence Report", max_length=200),
    template: str = Query("professional", max_length=50),
    include_executive_summary: bool = Query(True),
    include_findings_matrix: bool = Query(True),
    include_recommendations: bool = Query(True),
    limit: int = Query(100, ge=1, le=10000),
    days_back: Optional[int] = Query(None, ge=1, le=365),
    db: AsyncSession = Depends(get_db),
    _=Depends(get_current_admin),
):
    stats = await get_dashboard_stats(db)
    events = await get_events(db, limit=limit)
    events_dicts = [
        {
            "id": e.id,
            "session_id": e.session_id,
            "attacker_ip": e.attacker_ip,
            "attacker_port": e.attacker_port,
            "sensor_type": e.sensor_type,
            "sensor_port": e.sensor_port,
            "timestamp_start": str(e.timestamp_start),
            "timestamp_end": str(e.timestamp_end) if e.timestamp_end else "",
            "country": e.country or "Unknown",
            "city": e.city or "Unknown",
            "asn": e.asn or "",
            "isp": e.isp or "",
            "is_known_threat": e.is_known_threat,
            "threat_tags": e.threat_tags or "",
            "commands": [c.command for c in (e.commands or [])],
            "credentials": [{"username": c.username, "success": c.success} for c in (e.credentials or [])],
            "malware_samples": [{"filename": m.filename, "sha256": m.sha256} for m in (e.malware_samples or [])],
        }
        for e in events
    ]

    report = report_pro_service.generate_report(
        title=title,
        template_name=template,
        stats=stats,
        events=events_dicts,
        include_executive_summary=include_executive_summary,
        include_findings_matrix=include_findings_matrix,
        include_recommendations=include_recommendations,
        days_back=days_back,
    )

    await event_bus.emit("report.generated", report_id=report["id"], title=title, event_count=len(events_dicts))
    return report


@router.get("/{report_id}/html")
async def view_report_html(report_id: str, _=Depends(get_current_user)):
    report = report_pro_service.get_report(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    html = report_pro_service.render_report_html(report)
    return HTMLResponse(content=html)


@router.get("/{report_id}/pdf")
async def download_report_pdf(report_id: str, _=Depends(get_current_user)):
    report = report_pro_service.get_report(report_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    pdf_bytes = report_pro_service.render_report_pdf(report)
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=kraken_report_{report_id[:8]}.pdf",
        },
    )


@router.delete("/{report_id}")
async def delete_report(report_id: str, _=Depends(get_current_admin)):
    success = report_pro_service.delete_report(report_id)
    if not success:
        raise HTTPException(status_code=404, detail="Report not found")
    return {"status": "deleted", "report_id": report_id}


@router.get("/templates")
async def list_templates(_=Depends(get_current_user)):
    return report_pro_service.list_templates()
