"""Rate limiting per client (audit S1).

`get_remote_address` dietro reverse proxy restituisce l'IP del **proxy**, non del
client: con Caddy davanti, tutti i limiti per-IP collassano in un unico bucket
condiviso (10 login/minuto per l'intera piattaforma = DoS del login e limiti
decorativi). Qui la chiave è l'IP reale del client quando l'ingress è il nostro
proxy fidato, altrimenti il peer diretto.

Storage:
  - default `memory://` — contatori per processo (lab/single worker);
  - `RATE_LIMIT_STORAGE_URI=redis://...` — contatori condivisi (pilot/HA,
    più worker uvicorn).

Tutti i wrapper di `limits`/`slowapi` sono tolleranti: se lo storage non è
raggiungibile la richiesta non deve diventare un 500, ma il fatto va loggato.
"""

import ipaddress

from slowapi import Limiter
from slowapi.util import get_remote_address

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)


def _first_valid_ip(header_value: str | None) -> str | None:
    """Primo IP valido in una lista CSV (`X-Forwarded-For`), None se nessuno."""
    if not header_value:
        return None
    for raw in header_value.split(","):
        candidate = raw.strip()
        if not candidate:
            continue
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        return candidate
    return None


def client_key(request) -> str:
    """Chiave di rate limiting: IP reale del client, con fallback sul peer.

    `X-Forwarded-For` è attendibile SOLO se l'unico ingress è il nostro proxy
    (`RATE_LIMIT_TRUST_FORWARDED_FOR=true`): con un ingress esposto a internet
    senza proxy fidato l'header è spoofabile e va ignorato.
    """
    if settings.RATE_LIMIT_TRUST_FORWARDED_FOR:
        forwarded = _first_valid_ip(request.headers.get("x-forwarded-for"))
        if forwarded:
            return forwarded
        real_ip = _first_valid_ip(request.headers.get("x-real-ip"))
        if real_ip:
            return real_ip
    return get_remote_address(request) or "unknown"


_storage_uri = (settings.RATE_LIMIT_STORAGE_URI or "").strip()
if not _storage_uri:
    logger.info(
        "Rate limiting su storage in-memory (per processo). "
        "Imposta RATE_LIMIT_STORAGE_URI=redis://… per pilot/HA multi-worker."
    )

limiter = Limiter(key_func=client_key, storage_uri=_storage_uri or "memory://")
