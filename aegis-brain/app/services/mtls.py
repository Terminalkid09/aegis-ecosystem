"""Mutual auth agent (post-audit hardening).

Il certificato device (firmato dalla CA via /enroll/csr, chiave MAI uscita
dall'endpoint) viaggia nell'header X-Client-Cert e viene verificato a ogni
chiamata agent: catena CA, finestre, CN==agent_id, revoca. Insieme al device
secret esistente (prova di possesso) realizza l'autenticazione mutua a
livello applicativo; la terminazione TLS con client_auth resta il passo
pilot (Caddyfile.mtls).

MTLS_MODE: off (compat, default) | optional (verifica se presente, log) |
required (certificato valido obbligatorio, 401 altrimenti).

Fail-closed (punto 5): qualunque errore I/O su CA/revoche → 503, MAI allow.
"""
from typing import Optional, Tuple

from fastapi import HTTPException, status

from app.core.config import settings
from app.services.pki import PkiUnavailable

HEADER = "x-client-cert"
DER_HEADER = "x-client-cert-der"
HASH_HEADER = "x-client-cert-hash"
MAX_PEM_BYTES = 8192


def _raw_header(headers, name: str):
    """Valore header grezzo (case-insensitive) o None."""
    try:
        if hasattr(headers, "get"):
            v = headers.get(name)
            if v is None:
                v = headers.get(name.upper())
            if v is not None:
                return v
        if hasattr(headers, "items"):
            lowered = {str(k).lower(): v for k, v in headers.items()}
            return lowered.get(name)
    except Exception:
        return None
    return None


def extract_client_cert(headers) -> Optional[bytes]:
    """Estrae il certificato device come PEM.

    Sorgenti (prima valida vince):
    - X-Client-Cert: base64(DER) single-line (agent diretti) o PEM (test);
    - X-Client-Cert-Der: base64(DER) iniettato dal reverse proxy mTLS.
    Gli header HTTP non ammettono newline: il PEM multilinea non viaggia.
    Ritorna None se assente o malformato.
    """
    import base64 as _b64
    import re as _re
    import ssl as _ssl
    for name in (HEADER, DER_HEADER):
        raw = _raw_header(headers, name)
        if not raw:
            continue
        text = raw.decode("ascii", errors="ignore") if isinstance(raw, bytes) else str(raw)
        text = text.strip().strip('"').strip("'")
        if not text or len(text) > MAX_PEM_BYTES:
            continue
        if "BEGIN CERTIFICATE" in text:
            return text.encode("ascii")
        compact = _re.sub(r"\s+", "", text)
        if 500 <= len(compact) <= 20000 and _re.fullmatch(r"[A-Za-z0-9+/=]+", compact):
            try:
                der = _b64.b64decode(compact)
                return _ssl.DER_cert_to_PEM_cert(der).encode("ascii")
            except Exception:
                continue
    return None


def extract_cert_hash(headers) -> Optional[str]:
    """SHA256 hex del cert (iniettato dal reverse proxy mTLS)."""
    raw = _raw_header(headers, HASH_HEADER)
    if not raw:
        return None
    text = raw.decode("ascii", errors="ignore") if isinstance(raw, bytes) else str(raw)
    text = text.strip().lower()
    if len(text) == 64 and all(c in "0123456789abcdef" for c in text):
        return text
    return None


def verify_agent_cert(agent_id: str, cert_pem: bytes) -> Tuple[bool, str]:
    """Catena + validità + CN + revoca. I/O error → PkiUnavailable."""
    from app.services import pki as _pki
    import os as _os
    ca_crt = _os.path.join(settings.PKI_DIR, _pki.CA_CRT)
    try:
        with open(ca_crt, "rb") as f:
            ca_pem = f.read()
        from cryptography import x509 as _x509
        ca_cert = _x509.load_pem_x509_certificate(ca_pem)
    except OSError as e:
        raise PkiUnavailable(f"CA illeggibile: {e}")
    try:
        revoked = _pki.RevokeList(_os.path.join(settings.PKI_DIR, _pki.REVOKED))
        revoked.require_healthy()
        if revoked.agent_revoked(str(agent_id)):
            return False, "agent revocato"
        serials = {e for e in revoked.entries() if not e.startswith("agent:")}
    except OSError as e:
        raise PkiUnavailable(f"revoche illeggibili: {e}")
    ok, reason = _pki.verify_device_cert(ca_cert, cert_pem, str(agent_id),
                                         revoked_serials=serials)
    return ok, reason


def _header_present(headers) -> bool:
    """True se un header di prova esiste (anche malformato)."""
    return (_raw_header(headers, HEADER) is not None
            or _raw_header(headers, DER_HEADER) is not None)


def enforce_fingerprint(agent, headers) -> str:
    """Binding via hash (proxy mTLS): confronta con il fingerprint legato
    all'agent all'emissione. Revoca sempre applicata. 401/503 altrimenti."""
    import hmac as _hmac
    from app.services import pki as _pki
    import os as _os
    given = extract_cert_hash(headers)
    if given is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Malformed client certificate hash")
    meta = agent.get("meta") if isinstance(agent, dict) else getattr(agent, "meta", None)
    expected = (meta or {}).get("device_cert_sha256") if isinstance(meta, dict) else None
    if not expected or not _hmac.compare_digest(str(given), str(expected).lower()):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Client certificate not bound to agent")
    agent_id = agent.get("agent_id") if isinstance(agent, dict) else getattr(agent, "agent_id", "")
    try:
        revoked = _pki.RevokeList(_os.path.join(settings.PKI_DIR, _pki.REVOKED))
        revoked.require_healthy()
        if revoked.agent_revoked(str(agent_id)):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail="Agent revoked")
    except PkiUnavailable as e:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                            detail=f"PKI unavailable: {e}")
    return "fingerprint-ok"


def mtls_mode() -> str:
    mode = (getattr(settings, "MTLS_MODE", "off") or "off").strip().lower()
    return mode if mode in ("off", "optional", "required") else "off"


def enforce(headers, agent_id: str, bootstrap: bool = False) -> Optional[str]:
    """Applica MTLS_MODE. Ritorna motivo di log, o solleva 401/503.

    - off: nessun controllo (compatibilità rollout).
    - optional: se il cert è presente deve essere valido, altrimenti 401.
    - required: cert valido obbligatorio, altrimenti 401; I/O error → 503.
    - bootstrap=True (solo /enroll/csr): senza cert si passa in required
      (primo rilascio), ma se presente deve verificare comunque.
    """
    mode = mtls_mode()
    if mode == "off":
        return None
    pem = extract_client_cert(headers)
    if pem is None:
        if _header_present(headers):
            # Header presente ma illeggibile: tentativo, non assenza → 401.
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail="Malformed client certificate")
        if mode == "required" and not bootstrap:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail="Client certificate required")
        return "no-cert-optional" if mode == "optional" else "bootstrap-no-cert"
    try:
        ok, reason = verify_agent_cert(str(agent_id), pem)
    except PkiUnavailable as e:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                            detail=f"PKI unavailable: {e}")
    if not ok:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail=f"Invalid client certificate: {reason}")
    return "cert-ok"
