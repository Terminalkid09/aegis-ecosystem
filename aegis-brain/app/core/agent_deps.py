from fastapi import Header, HTTPException, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession
import uuid
from app.database.connection import get_db
from app.database.models import Agent
from app.core.security import verify_password
from sqlalchemy import select

async def _verify_agent_secret(
    x_agent_id: str, authorization: str, db: AsyncSession,
):
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid token format")

    token = authorization[7:]

    try:
        agent_id_uuid = uuid.UUID(x_agent_id)
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid Agent ID format")

    result = await db.execute(select(Agent).where(Agent.agent_id == agent_id_uuid))
    agent = result.scalars().first()

    if not agent or not agent.device_token_hash:
        raise HTTPException(status_code=401, detail="Agent not found or not registered")

    if not verify_password(token, agent.device_token_hash):
        raise HTTPException(status_code=401, detail="Invalid agent credentials")

    # Revoca persistita in DB (primaria, auditata) — nega subito,.fail-closed.
    # Se la tabella non esiste ancora (migr. non applicata) ignora gracefully.
    try:
        from app.database.models import RevokedCert
        r = await db.execute(select(RevokedCert).where(RevokedCert.agent_id == str(agent_id_uuid)).limit(1))
        if r.scalars().first() is not None:
            raise HTTPException(status_code=403, detail="Agent revoked: contact SOC for re-admission")
    except HTTPException:
        raise
    except Exception:
        pass  # tabella assente o errore transitorio: lascia passare al check file/mTLS (fail-open qui, fail-closed lì)

    return agent


def _cert_headers(request: Request, x_client_cert: str | None) -> dict:
    headers = dict(request.headers) if request is not None else {}
    if x_client_cert:
        headers["x-client-cert"] = x_client_cert
    return headers


def apply_agent_mtls(agent, request: Request, x_client_cert: str | None,
                bootstrap: bool) -> None:
    """Due prove alternative (una basta): certificato completo inline,
    oppure hash legato all'agent (proxy mTLS). Assenza: ok solo in
    bootstrap/off, 401 in required. Tutto il resto nega (401) o va in
    fail-closed (503 su I/O)."""
    from app.services.mtls import (
        enforce, enforce_fingerprint, extract_cert_hash,
        extract_client_cert, mtls_mode, _header_present,
    )
    if mtls_mode() == "off":
        return
    headers = _cert_headers(request, x_client_cert)
    pem = extract_client_cert(headers)
    if pem is not None or _header_present(headers):
        enforce(headers, str(agent.agent_id), bootstrap=bootstrap)
        return
    if extract_cert_hash(headers) is not None:
        enforce_fingerprint(agent, headers)
        return
    enforce(headers, str(agent.agent_id), bootstrap=bootstrap)


async def get_current_agent(
    x_agent_id: str = Header(..., alias="X-Agent-Id"),
    authorization: str = Header(..., alias="Authorization"),
    x_client_cert: str | None = Header(None, alias="X-Client-Cert"),
    request: Request = None,
    db: AsyncSession = Depends(get_db)
):
    agent = await _verify_agent_secret(x_agent_id, authorization, db)
    # Post-audit: mutual auth — certificato device oltre al secret.
    # Fail-closed: PKI illeggibile → 503, MAI allow.
    apply_agent_mtls(agent, request, x_client_cert, bootstrap=False)
    return agent


async def get_bootstrap_agent(
    x_agent_id: str = Header(..., alias="X-Agent-Id"),
    authorization: str = Header(..., alias="Authorization"),
    x_client_cert: str | None = Header(None, alias="X-Client-Cert"),
    request: Request = None,
    db: AsyncSession = Depends(get_db)
):
    """Come get_current_agent ma con bootstrap mTLS (solo /enroll/csr).

    In modo required permette la chiamata SENZA alcuna prova per il primo
    rilascio (secret valido obbligatorio); se una prova è presente deve
    comunque verificare. Tutto il resto identico.
    """
    agent = await _verify_agent_secret(x_agent_id, authorization, db)
    apply_agent_mtls(agent, request, x_client_cert, bootstrap=True)
    return agent
