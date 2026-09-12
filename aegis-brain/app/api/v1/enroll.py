from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.responses import PlainTextResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import hashlib
import hmac
import os
import redis.asyncio as redis
import secrets
import uuid
from datetime import datetime, timezone
from pydantic import BaseModel, Field

from app.database.connection import get_db
from app.database.models import Agent, EnrollToken, RevokedCert
from app.core.agent_deps import get_bootstrap_agent
from app.core.audit import log_audit
from app.core.config import settings
from app.core.deps import get_current_user
from app.core.security import hash_password
from app.core.logging import get_logger
from app.core.redis_utils import get_redis_url

logger = get_logger(__name__)
router = APIRouter(tags=["Agent Enrollment"])

class EnrollRequest(BaseModel):
    hostname: str
    os: str
    enroll_key: str

class EnrollResponse(BaseModel):
    agent_id: str
    agent_secret: str
    status: str

@router.post("/enroll", response_model=EnrollResponse)
async def enroll_agent(payload: EnrollRequest, db: AsyncSession = Depends(get_db)):
    # Static key (headless/IoT) OR single-use EnrollToken (one-liner install).
    # Use constant-time comparison to prevent timing attacks on the static key
    valid_static = (
        bool(settings.AGENT_ENROLL_KEY)
        and hmac.compare_digest(payload.enroll_key.strip(), settings.AGENT_ENROLL_KEY)
    )
    used_token: EnrollToken | None = None
    if not valid_static:
        digest = hashlib.sha256(payload.enroll_key.strip().encode()).hexdigest()
        r = await db.execute(select(EnrollToken).where(EnrollToken.token_hash == digest))
        tok = r.scalars().first()
        now = datetime.now(timezone.utc)
        not_expired = (tok is not None and tok.expires_at is not None
                       and tok.expires_at.replace(tzinfo=timezone.utc) > now)
        if tok and not tok.revoked and not tok.used_at and not_expired:
            used_token = tok
        else:
            logger.warning(f"Invalid enrollment attempt from {payload.hostname}")
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid enrollment key")
    if used_token:
        used_token.used_at = datetime.now(timezone.utc)
        used_token.used_by_hostname = payload.hostname[:255]

    agent_id = uuid.uuid4()
    agent_secret = secrets.token_urlsafe(32)

    # Check if agent with same hostname+os already exists (race-safe via unique constraint)
    result = await db.execute(
        select(Agent).where(
            Agent.hostname == payload.hostname,
            Agent.os_type == payload.os
        )
    )
    existing = result.scalars().first()
    if existing:
        # Revoca permanente: un agent revocato non si ri-iscrive da solo
        # (sarebbe un bypass con un token rubato). Riammissione solo manuale
        # (rimozione entry + audit, OPERATIONS.md). Fail-closed su I/O.
        # DB è primario, file è fallback: basta uno dei due per negare.
        try:
            _rl = _revocations()
            _rl.require_healthy()
            file_revoked = _rl.agent_revoked(str(existing.agent_id))
            db_revoked = (await db.execute(select(RevokedCert).where(RevokedCert.agent_id == str(existing.agent_id)).limit(1))).scalars().first() is not None
            if file_revoked or db_revoked:
                logger.warning(f"Re-enroll negato (revocato): {existing.agent_id}")
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                    detail="Agent revoked: contact SOC for re-admission")
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                                detail=f"PKI unavailable: {e}")
        # Re-enroll: issue a fresh secret so agent can authenticate again
        new_secret = secrets.token_urlsafe(32)
        existing.device_token_hash = hash_password(new_secret)
        await db.commit()

        # Update Redis cache (best-effort — auth falls back to DB verify)
        # Hash the secret before using it as a Redis key to avoid plaintext exposure
        try:
            redis_client = redis.from_url(get_redis_url(), decode_responses=True)
            secret_hash = hashlib.sha256(new_secret.encode()).hexdigest()
            await redis_client.set(f"auth:agent:{secret_hash}", str(existing.agent_id))
        except Exception:
            pass

        logger.info(f"Agent re-enrolled: {existing.agent_id} ({payload.hostname})")
        return EnrollResponse(
            agent_id=str(existing.agent_id),
            agent_secret=new_secret,
            status="re-enrolled"
        )
    
    new_agent = Agent(
        agent_id=agent_id,
        hostname=payload.hostname,
        os_type=payload.os,
        agent_type="aegis-guard",
        device_token_hash=hash_password(agent_secret)
    )
    db.add(new_agent)
    await db.commit()
    await db.refresh(new_agent)

    # Cache in Redis for fast validation (best-effort)
    # Hash the secret before using it as a Redis key to avoid plaintext exposure
    try:
        redis_client = redis.from_url(get_redis_url(), decode_responses=True)
        secret_hash = hashlib.sha256(agent_secret.encode()).hexdigest()
        cache_key = f"auth:agent:{secret_hash}"
        await redis_client.set(cache_key, str(agent_id))
    except Exception:
        pass
    
    logger.info(f"New agent enrolled: {agent_id} ({payload.hostname})")

    return EnrollResponse(
        agent_id=str(agent_id),
        agent_secret=agent_secret,
        status="enrolled"
    )


def _pki_paths():
    from app.services import pki as _pki
    _pki.ensure_ca(settings.PKI_DIR, ttl_days=settings.PKI_CA_TTL_DAYS)
    return _pki


def _revocations():
    from app.services import pki as _pki
    import os
    return _pki.RevokeList(os.path.join(settings.PKI_DIR, _pki.REVOKED))


@router.get("/ca.crt", response_class=PlainTextResponse)
async def device_ca_cert():
    """Certificato pubblico della Device CA (materiale pubblico, no auth).

    Niente bootstrap implicito: CA assente → 503 con rimando al runbook
    (bootstrap operatore esplicito, OPERATIONS.md §2).
    """
    from app.services import pki as _pki
    try:
        return _pki.ca_cert_pem(settings.PKI_DIR).decode("ascii")
    except OSError as e:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                            detail=f"Device CA not initialized (run PKI bootstrap): {e}")


class CsrRequest(BaseModel):
    csr_pem: str = Field(..., max_length=8000)


@router.post("/csr")
async def sign_device_csr(payload: CsrRequest, request: Request,
                          db: AsyncSession = Depends(get_db),
                          agent: Agent = Depends(get_bootstrap_agent)):
    """Firma la CSR dell'agente (chiave generata LOCALMENTE dall'agent).

    CN deve coincidere con l'agent_id autenticato via device secret.
    Agente revocato → 403. Audit trail completo.
    """
    try:
        _pki = _pki_paths()
        _pki.RevokeList(os.path.join(settings.PKI_DIR, _pki.REVOKED)).require_healthy()
        _pki.load_ca(settings.PKI_DIR)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                            detail=f"PKI unavailable: {e}")
    if _revocations().agent_revoked(str(agent.agent_id)):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                            detail="Agent revoked")
    try:
        ca_key, ca_cert = _pki.load_ca(settings.PKI_DIR)
        cert_pem, serial, exp = _pki.sign_csr(
            ca_key, ca_cert, payload.csr_pem.encode("ascii"),
            str(agent.agent_id), ttl_days=settings.PKI_DEVICE_TTL_DAYS)
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    # Lega il fingerprint all'agent (meta JSON, migration-free): serve alla
    # verifica via hash del proxy mTLS. Preserva le altre chiavi (es. site).
    fingerprint = _pki.fingerprint_sha256(cert_pem)
    meta = dict(agent.meta) if isinstance(agent.meta, dict) else {}
    meta["device_cert_sha256"] = fingerprint
    agent.meta = meta
    await log_audit(db, action="device_cert_issue", resource="agent",
                    resource_id=str(agent.agent_id),
                    details={"serial": serial, "fingerprint": fingerprint,
                             "expires_at": exp.isoformat() if exp else None},
                    username=agent.hostname,
                    ip_address=request.client.host if request.client else None)
    await db.commit()
    return {"certificate_pem": cert_pem.decode("ascii"),
            "serial": serial, "fingerprint_sha256": fingerprint,
            "expires_at": exp.isoformat() if exp else None}


class RevokeRequest(BaseModel):
    reason: str = Field(default="", max_length=500)


@router.post("/agents/{agent_id}/revoke")
async def revoke_agent(agent_id: str, payload: RevokeRequest, request: Request,
                       db: AsyncSession = Depends(get_db),
                       user=Depends(get_current_user)):
    """Revoca un agente compromesso/sospetto (analyst/admin).

    Invalida il device secret (rotazione a valore inutilizzabile: la cache
    Redis ricade sul DB e fallisce) e revoca tutti i certificati emessi
    (seriali ignoti → revoca per agent_id, verificata in verify). Il re-enroll
    con token fresco ripristina l'agente (flusso reimaged/duplicato).
    """
    if (user.role or "user").lower() not in {"admin", "analyst"}:
        raise HTTPException(status_code=403, detail="Revocation requires analyst or admin role")
    try:
        agent_uuid = uuid.UUID(agent_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid agent_id format")
    result = await db.execute(select(Agent).where(Agent.agent_id == agent_uuid))
    agent = result.scalars().first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    agent.device_token_hash = hash_password(secrets.token_urlsafe(48))
    # DB è primario (audit + transazione), file è fallback per boot senza DB.
    db.add(RevokedCert(agent_id=str(agent_uuid), reason=payload.reason, revoked_by=user.id))
    try:
        _revocations().revoke(f"agent:{agent_uuid}")
    except Exception as e:
        # Fail-closed: revoca non persistita = 503, rollback DB per coerenza.
        await db.rollback()
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                            detail=f"Revocation not persisted: {e}")
    await log_audit(db, action="agent_revoke", resource="agent",
                    resource_id=str(agent_uuid),
                    details={"hostname": agent.hostname, "reason": payload.reason},
                    user_id=user.id, username=user.username,
                    ip_address=request.client.host if request.client else None)
    await db.commit()
    logger.warning("Agent revoked: %s (%s) by %s", agent_uuid, agent.hostname, user.username)
    return {"status": "revoked", "agent_id": str(agent_uuid)}


@router.get("/agents/{agent_id}/certificate-status")
async def certificate_status(agent_id: str, db: AsyncSession = Depends(get_db),
                             user=Depends(get_current_user)):
    """Stato revoca di un agente (per dashboard e triage)."""
    try:
        agent_uuid = uuid.UUID(agent_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid agent_id format")
    file_revoked = _revocations().agent_revoked(str(agent_uuid))
    db_revoked = (await db.execute(select(RevokedCert).where(RevokedCert.agent_id == str(agent_uuid)).limit(1))).scalars().first() is not None
    revoked = file_revoked or db_revoked
    return {"agent_id": str(agent_uuid), "revoked": revoked,
            "mtls": "issuance-active"}
