from fastapi import Header, HTTPException, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession
import asyncio
import hashlib
import threading
import time
import uuid
from app.database.connection import get_db
from app.database.models import Agent
from app.core.security import (
    device_token_proof,
    verify_device_token_proof,
    verify_password,
)
from app.core.logging import get_logger
from sqlalchemy import select

logger = get_logger(__name__)


class _AgentSecretCache:
    """Short-lived proof that an agent secret was already verified.

    Argon2 is deliberately expensive, but running it on every telemetry POST
    made a single agent cap out around 8 reports/s. The cache is keyed by the
    secret digest *and* the stored hash: a re-enrollment that changes the hash
    gets a cache miss immediately, while revocation is still checked against
    the database on every request. TTL is intentionally short.
    """

    def __init__(self, ttl: float = 60.0, max_entries: int = 4096):
        self.ttl = ttl
        self.max_entries = max_entries
        self._entries: dict[tuple[str, str, str], float] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _key(agent_id: str, token: str, stored_hash: str) -> tuple[str, str, str]:
        return (
            agent_id,
            hashlib.sha256(token.encode("utf-8")).hexdigest(),
            hashlib.sha256((stored_hash or "").encode("utf-8")).hexdigest(),
        )

    def valid(self, agent_id: str, token: str, stored_hash: str) -> bool:
        key = self._key(agent_id, token, stored_hash)
        now = time.monotonic()
        with self._lock:
            timestamp = self._entries.get(key)
            if timestamp is None:
                return False
            if now - timestamp > self.ttl:
                self._entries.pop(key, None)
                return False
            return True

    def remember(self, agent_id: str, token: str, stored_hash: str) -> None:
        key = self._key(agent_id, token, stored_hash)
        now = time.monotonic()
        with self._lock:
            if len(self._entries) >= self.max_entries:
                cutoff = now - self.ttl
                stale = [k for k, ts in self._entries.items() if ts <= cutoff]
                for k in stale[: self.max_entries // 4 or 1]:
                    self._entries.pop(k, None)
                while len(self._entries) >= self.max_entries:
                    self._entries.pop(next(iter(self._entries)), None)
            self._entries[key] = now

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()


_AGENT_SECRET_CACHE = _AgentSecretCache()


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

    meta = agent.meta if isinstance(getattr(agent, "meta", None), dict) else {}
    proof = meta.get("device_token_proof")
    if verify_device_token_proof(token, agent.device_token_hash, proof):
        # Prova veloce valida: niente Argon2. Il controllo di revoca sotto
        # resta obbligatorio e viene eseguito a ogni richiesta.
        _AGENT_SECRET_CACHE.remember(str(agent.agent_id), token, agent.device_token_hash)
    elif not _AGENT_SECRET_CACHE.valid(str(agent.agent_id), token, agent.device_token_hash):
        valid = await asyncio.to_thread(
            verify_password, token, agent.device_token_hash
        )
        if not valid:
            raise HTTPException(status_code=401, detail="Invalid agent credentials")
        _AGENT_SECRET_CACHE.remember(str(agent.agent_id), token, agent.device_token_hash)
        # Backfill per i token emessi prima di questa versione: la prossima
        # richiesta (anche su un altro worker) evita Argon2. Il commit avviene
        # nella transazione dell'endpoint, insieme alla telemetria.
        new_meta = dict(meta)
        new_meta["device_token_proof"] = device_token_proof(token, agent.device_token_hash)
        agent.meta = new_meta

    # Revoca persistita in DB (primaria, auditata) — nega subito,.fail-closed.
    # Se la tabella non esiste ancora (migr. non applicata) ignora gracefully.
    try:
        from app.database.models import RevokedCert
        r = await db.execute(select(RevokedCert).where(RevokedCert.agent_id == str(agent_id_uuid)).limit(1))
        if r.scalars().first() is not None:
            raise HTTPException(status_code=403, detail="Agent revoked: contact SOC for re-admission")
    except HTTPException:
        raise
    except Exception as exc:
        # Fail-closed: con MTLS_MODE=off questo e' l'unico controllo di revoca.
        # Un errore DB non puo' trasformare un agente revocato in autorizzato.
        logger.exception("Revocation check failed for agent %s", agent_id_uuid)
        raise HTTPException(
            status_code=503,
            detail="Revocation store unavailable: agent authentication refused",
        ) from exc

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
