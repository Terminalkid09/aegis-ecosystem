"""Endpoint di ingestione multi-sorgente.

Due modi di autenticarsi, entrambi espliciti:
- **X-Api-Key** (la stessa chiave usata da Aegis-Link) per shipper e
  integrazioni server-to-server;
- **Bearer JWT** per la dashboard e per l'operatore che fa una prova.

L'ingestione è idempotente per `event_id`: un relay che reinvia la stessa riga
non produce alert duplicati (vedi `siem_store.claim_event`).
"""
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Body, Depends, Header, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import log_audit
from app.core.config import settings
from app.core.deps import get_current_user, require_perm
from app.database.connection import get_db
from app.ingest import default_registry
from app.ingest.registry import parser_catalog
from app.rules.sigma import get_engine as get_sigma_engine
from app.services import siem_store
from app.services.correlation import get_correlation_engine
from app.services.siem_pipeline import ingest_payload


router = APIRouter(tags=["SIEM Ingest"])


async def ingest_auth(
    x_api_key: Optional[str] = Header(None, alias="X-Api-Key"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
    db: AsyncSession = Depends(get_db),
) -> Dict[str, Any]:
    """Accetta API key globale oppure JWT valido. Nessuna ingestione anonima.

    Un JWT presente ma non valido è un 401, non un accesso anonimo: lasciar
    passare un token invalido renderebbe l'endpoint di fatto aperto.
    """
    if x_api_key:
        # `verify_api_key` è sincrona e non va attesa: attenderla solleva
        # TypeError e rende l'ingestione via API key un 500 sistematico
        # (bug trovato rieseguendo la demo contro un brain reale).
        from app.core.deps import verify_api_key
        verify_api_key(x_api_key)
        return {"kind": "api_key", "username": "api-key"}
    if authorization:
        try:
            user = await _resolve_user(authorization, db)
        except HTTPException:
            raise HTTPException(status_code=401, detail="Invalid token")
        return {"kind": "bearer", "username": user.username, "role": user.role}
    raise HTTPException(
        status_code=401,
        detail="Ingestion requires X-Api-Key or a Bearer token",
    )


async def _resolve_user(authorization: str, db: AsyncSession):
    from app.core.deps import _validate_token
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid Authorization header")
    return await _validate_token(authorization[7:], db)


class SourceCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=128, pattern=r"^[A-Za-z0-9._:-]+$")
    source_type: Optional[str] = Field(None, max_length=64)
    parser: str = Field("auto", max_length=64)
    description: Optional[str] = Field(None, max_length=255)


class ParseTestBody(BaseModel):
    parser: str = "auto"
    payload: Any


@router.get("/catalog")
async def parser_catalog_endpoint(user=Depends(get_current_user)):
    """Sorgenti supportate: nome parser + tipo. Usato dalla UI Log Sources."""
    return {
        "parsers": [{"name": name, "source_type": source_type}
                    for name, source_type in parser_catalog()],
        "aliases": {
            "winevent": "windows_event", "evtx": "windows_event",
            "eve": "suricata", "ids": "suricata", "bro": "zeek",
            "opnsense": "pfsense", "filterlog": "pfsense",
            "windows_firewall": "pfirewall", "ufw": "iptables",
            "apache": "nginx", "httpd": "nginx", "access_log": "nginx",
            "rfc5424": "syslog", "rfc3164": "syslog", "ndjson": "json",
        },
        "note": "With source='auto' the parser is chosen from the payload "
                "shape; an unrecognized payload is counted as unparsed and "
                "produces no events.",
    }


@router.get("/sources")
async def list_sources(db: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    return {"items": await siem_store.list_sources(db)}


@router.post("/sources")
async def upsert_source(
    payload: SourceCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(require_perm("deploy")),
):
    """Registra (o aggiorna) una sorgente senza inviare eventi.

    Utile per preparare il canale e monitorarne la salute prima che i log
    arrivino.
    """
    parser_name = payload.parser or "auto"
    if parser_name != "auto" and default_registry.get(parser_name) is None:
        raise HTTPException(status_code=422,
                            detail=f"unknown parser {parser_name!r}; see /ingest/catalog")
    resolved = default_registry.get(parser_name) if parser_name != "auto" else None
    source = await siem_store.upsert_source(
        db, payload.name,
        source_type=payload.source_type or (resolved.source_type if resolved else "unknown"),
        parser=parser_name,
        description=payload.description,
    )
    await log_audit(db, action="ingest_source_upsert", resource="log_source",
                    resource_id=payload.name, details={"parser": parser_name},
                    user_id=user.id, username=user.username,
                    ip_address=request.client.host if request.client else None)
    await db.commit()
    return {"status": "ok", "id": source.id, "name": source.name, "parser": source.parser}


@router.post("/test")
async def test_parse(payload: ParseTestBody, user=Depends(get_current_user)):
    """Prova un parser senza salvare nulla: serve a chi integra una sorgente."""
    result = default_registry.parse(payload.parser, payload.payload,
                                    {"source": "preview", "received_at": None})
    return {
        "parser": result.parser,
        "detected_by": result.detected_by,
        "unparsed": result.unparsed,
        "errors": result.errors,
        "events": [event.to_record() for event in result.events[:50]],
    }


@router.get("/stats")
async def ingest_stats(hours: int = Query(24, ge=1, le=720),
                       db: AsyncSession = Depends(get_db),
                       user=Depends(get_current_user)):
    stats = await siem_store.event_stats(db, hours=hours)
    signs = get_sigma_engine()
    correlation = get_correlation_engine()
    stats["detection"] = {
        "sigma_rules": signs.coverage()["rules_executable"],
        "sigma_rules_total": signs.coverage()["rules_total"],
        "correlation_rules": correlation.coverage()["rules_executable"],
        "correlation_rules_total": correlation.coverage()["rules_total"],
    }
    return stats


@router.get("/detection-coverage")
async def detection_coverage(user=Depends(get_current_user)):
    """Copertura reale: quante regole Sigma e di correlazione girano, e perché
    le altre sono escluse. Un numero onesto invece di un conteggio gonfiato."""
    return {
        "sigma": get_sigma_engine().coverage(),
        "correlation": get_correlation_engine().coverage(),
    }


@router.post("/{source}")
async def ingest_event(
    source: str,
    request: Request,
    payload: Any = Body(...),
    db: AsyncSession = Depends(get_db),
    auth=Depends(ingest_auth),
    parser: Optional[str] = Query(None, description="Forza il parser (default: nome sorgente o auto)"),
):
    """Ingerisce uno o più eventi per la sorgente indicata.

    `source` è il nome della sorgente (libero) oppure il nome di un parser.
    Con `parser` si forza esplicitamente il formato; senza, si usa il nome
    sorgente se è un parser noto, altrimenti auto-detection.
    """
    if not settings.SIEM_ENABLED:
        raise HTTPException(status_code=503, detail="SIEM ingestion is disabled")
    if source == "auto" and parser is None:
        parser = "auto"
    result = await ingest_payload(db, source, payload, parser=parser)
    if not result.get("accepted"):
        # Payload arrivato ma nessun evento riconosciuto: 422 con la diagnosi,
        # così l'integratore capisce subito e non pensa a un problema di rete.
        # Un 200 silenzioso qui è il modo in cui una sorgente resta rotta per
        # settimane senza che nessuno se ne accorga.
        raise HTTPException(status_code=422, detail={
            "message": "payload received but no event could be parsed",
            "source": source,
            "parser": result.get("parser"),
            "unparsed": result.get("unparsed"),
            "errors": result.get("errors"),
        })
    if not result.get("stored") and not result.get("duplicates"):
        # Eventi riconosciuti ma non salvati: è un guasto dello store, non un
        # problema del payload. Dichiararlo evita di far credere all'integratore
        # che il formato sia sbagliato.
        raise HTTPException(status_code=503, detail={
            "message": "events parsed but store failed",
            "source": source,
            "accepted": result.get("accepted"),
        })
    return result

