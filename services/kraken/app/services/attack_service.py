from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, distinct, desc
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import selectinload
from datetime import datetime, timezone
from typing import List, Optional

from app.models.models import AttackEvent, AttackCommand, CredentialAttempt, MalwareSample
from app.schemas.schemas import SensorEventIn
from app.services.geoip import geoip_service
from app.services.telegram import telegram_service
from app.core.security import hash_credential
from loguru import logger


async def ingest_sensor_event(db: AsyncSession, payload: SensorEventIn) -> AttackEvent:
    # Sensor retries must be idempotent: session_id is the natural key.
    existing = await get_event_by_session(db, payload.session_id)
    if existing is not None:
        logger.info(f"Duplicate sensor event ignored: {payload.session_id}")
        return existing

    geo = geoip_service.lookup(payload.attacker_ip)

    event = AttackEvent(
        session_id=payload.session_id,
        attacker_ip=payload.attacker_ip,
        attacker_port=payload.attacker_port,
        sensor_type=payload.sensor_type,
        sensor_port=payload.sensor_port,
        country=geo.get("country"),
        city=geo.get("city"),
        latitude=geo.get("latitude"),
        longitude=geo.get("longitude"),
        asn=geo.get("asn"),
        isp=geo.get("isp"),
    )
    db.add(event)
    await db.flush()

    if payload.username or payload.password:
        db.add(CredentialAttempt(
            event_id=event.id,
            username=payload.username,
            password=hash_credential(payload.password) if payload.password else None,
        ))

    for cmd in payload.commands or []:
        db.add(AttackCommand(event_id=event.id, command=cmd))

    try:
        await db.commit()
    except IntegrityError:
        # Two retries can race between the SELECT and the INSERT.
        await db.rollback()
        duplicate = await get_event_by_session(db, payload.session_id)
        if duplicate is None:
            raise
        return duplicate
    await db.refresh(event, ["credentials", "commands", "malware_samples"])

    from app.core.event_bus import event_bus
    event_dict = {
        "id": event.id,
        "session_id": event.session_id,
        "attacker_ip": event.attacker_ip,
        "attacker_port": event.attacker_port,
        "sensor_type": event.sensor_type,
        "sensor_port": event.sensor_port,
        "timestamp_start": str(event.timestamp_start),
        "country": event.country,
        "city": event.city,
        "asn": event.asn,
        "isp": event.isp,
        "is_known_threat": event.is_known_threat,
        "threat_tags": event.threat_tags,
        "username": payload.username,
        "commands": payload.commands or [],
    }
    await event_bus.emit_async("attack.ingested", attack_event=event_dict)

    # Gate D: the signed event is what makes the attack visible in Aegis.
    # Fail-soft: Aegis being down must not lose the local honeypot record.
    try:
        from app.services.aegis_ingest import publish_attack_event
        await publish_attack_event(event, payload)
    except Exception as e:
        logger.warning(f"Aegis event emission failed: {e}")

    try:
        # La password in chiaro non deve mai uscire dal percorso di ingest.
        # Telegram riceve solo i campi che servono all'alert: il dump completo
        # includeva anche `password`, anche se il formatter non la stampava.
        await telegram_service.send_alert({
            **payload.model_dump(exclude={"password"}),
            "country": geo.get("country"),
            "city": geo.get("city"),
        })
    except Exception as e:
        logger.error(f"Telegram alert failed: {e}")

    from app.services.siem import siem_logger
    siem_logger.log_attack({
        "session_id": payload.session_id,
        "attacker_ip": payload.attacker_ip,
        "sensor_type": payload.sensor_type,
        "commands": payload.commands,
        "country": geo.get("country"),
        "city": geo.get("city")
    })

    return event


async def record_malware_sample(db: AsyncSession, event_id: int, filename: str, sha256: str, path: str, size: int):
    """Store a malware sample reference in the database."""
    sample = MalwareSample(
        event_id=event_id,
        filename=filename,
        sha256=sha256,
        path=path,
        size=size,
    )
    db.add(sample)
    await db.commit()


async def get_events(
    db: AsyncSession,
    skip: int = 0,
    limit: int = 50,
    sensor_type: Optional[str] = None,
    attacker_ip: Optional[str] = None,
) -> List[AttackEvent]:
    q = (
        select(AttackEvent)
        .options(
            selectinload(AttackEvent.credentials),
            selectinload(AttackEvent.commands),
            selectinload(AttackEvent.malware_samples),
        )
        .order_by(desc(AttackEvent.timestamp_start))
    )
    if sensor_type:
        q = q.where(AttackEvent.sensor_type == sensor_type)
    if attacker_ip:
        q = q.where(AttackEvent.attacker_ip == attacker_ip)
    q = q.offset(skip).limit(limit)
    result = await db.execute(q)
    return list(result.scalars().all())


async def get_event_by_session(db: AsyncSession, session_id: str) -> Optional[AttackEvent]:
    q = (
        select(AttackEvent)
        .options(
            selectinload(AttackEvent.credentials),
            selectinload(AttackEvent.commands),
            selectinload(AttackEvent.malware_samples),
        )
        .where(AttackEvent.session_id == session_id)
    )
    result = await db.execute(q)
    event = result.scalar_one_or_none()
    return event


async def get_dashboard_stats(db: AsyncSession) -> dict:
    today = datetime.now(timezone.utc).date()

    total = (await db.scalar(select(func.count(AttackEvent.id)))) or 0
    today_count = (await db.scalar(
        select(func.count(AttackEvent.id))
        .where(func.date(AttackEvent.timestamp_start) == today)
    )) or 0
    unique_ips = (await db.scalar(
        select(func.count(distinct(AttackEvent.attacker_ip)))
    )) or 0

    top_countries = [
        {"country": r[0], "count": r[1]}
        for r in (await db.execute(
            select(AttackEvent.country, func.count(AttackEvent.id).label("c"))
            .where(AttackEvent.country.isnot(None))
            .group_by(AttackEvent.country)
            .order_by(desc("c"))
            .limit(10)
        )).all()
    ]

    top_sensors = [
        {"sensor": r[0], "count": r[1]}
        for r in (await db.execute(
            select(AttackEvent.sensor_type, func.count(AttackEvent.id).label("c"))
            .group_by(AttackEvent.sensor_type)
            .order_by(desc("c"))
        )).all()
    ]

    attacks_over_time = [
        {"day": str(r[0]), "count": r[1]}
        for r in (await db.execute(
            select(
                func.date(AttackEvent.timestamp_start).label("day"),
                func.count(AttackEvent.id).label("c"),
            )
            .group_by("day")
            .order_by("day")
            .limit(30)
        )).all()
    ]

    geo_points = [
        {"lat": r[0], "lng": r[1], "country": r[2], "ip": r[3]}
        for r in (await db.execute(
            select(
                AttackEvent.latitude,
                AttackEvent.longitude,
                AttackEvent.country,
                AttackEvent.attacker_ip,
            )
            .where(AttackEvent.latitude.isnot(None))
            .limit(500)
        )).all()
    ]

    return {
        "total_attacks": total,
        "attacks_today": today_count,
        "unique_ips": unique_ips,
        "top_countries": top_countries,
        "top_sensors": top_sensors,
        "attacks_over_time": attacks_over_time,
        "geo_points": geo_points,
    }
