"""Identita device mTLS per NodeTrace (gap-closing, come il Guard Java).

La chiave EC P-256 nasce LOCALMENTE (mai trasmessa); solo la CSR (CN =
agent_id) va al SOC. Chiave+cert in PEM con 600 best-effort. Rinnovo quando
scade entro 30 giorni. Tutto fail-closed: errori = niente identita, l'agent
resta in poll senza cert (compat) o nega in modo required (server).
"""
import base64
import datetime as _dt
import os
import ssl

KEY_FILE = "device.key"
CRT_FILE = "device.crt"
RENEW_DAYS = 30


def _need_crypto():
    try:
        from cryptography import x509 as _x509
        from cryptography.hazmat.primitives import hashes as _h, serialization as _s
        from cryptography.hazmat.primitives.asymmetric import ec as _ec
        from cryptography.x509.oid import NameOID as _N
        return _x509, _h, _s, _ec, _N
    except ImportError as e:
        raise RuntimeError(
            "mTLS richiede il pacchetto 'cryptography' (requirements.txt)") from e


def identity_paths(base_dir):
    return (os.path.join(base_dir, KEY_FILE), os.path.join(base_dir, CRT_FILE))


def _chmod600(path):
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass  # Windows: ACL di default


def generate_key():
    _x509, _h, _s, _ec, _N = _need_crypto()
    return _ec.generate_private_key(_ec.SECP256R1())


def build_csr(agent_id):
    """Ritorna (key_pem, csr_pem) nuovi con CN=agent_id."""
    _x509, _h, _s, _ec, _N = _need_crypto()
    key = _ec.generate_private_key(_ec.SECP256R1())
    csr = (_x509.CertificateSigningRequestBuilder().subject_name(
        _x509.Name([_x509.NameAttribute(_N.COMMON_NAME, str(agent_id))])
    ).sign(key, _h.SHA256()))
    key_pem = key.private_bytes(_s.Encoding.PEM, _s.PrivateFormat.PKCS8,
                                _s.NoEncryption()).decode("ascii")
    csr_pem = csr.public_bytes(_s.Encoding.PEM).decode("ascii")
    return key_pem, csr_pem


def save_identity(base_dir, key_pem, cert_pem):
    key_path, crt_path = identity_paths(base_dir)
    os.makedirs(base_dir, exist_ok=True)
    with open(key_path, "w", encoding="utf-8") as f:
        f.write(key_pem)
    _chmod600(key_path)
    with open(crt_path, "w", encoding="utf-8") as f:
        f.write(cert_pem)
    _chmod600(crt_path)
    return key_path, crt_path


def load_identity(base_dir):
    """Ritorna (key_pem, cert_pem) o (None, None). Corrotto -> quarantena .bad."""
    key_path, crt_path = identity_paths(base_dir)
    try:
        with open(key_path, encoding="utf-8") as f:
            key_pem = f.read()
        with open(crt_path, encoding="utf-8") as f:
            cert_pem = f.read()
        if "PRIVATE KEY" not in key_pem or "CERTIFICATE" not in cert_pem:
            raise ValueError("formato invalido")
        return key_pem, cert_pem
    except FileNotFoundError:
        return None, None
    except (OSError, ValueError, UnicodeDecodeError):
        for p in (key_path, crt_path):
            try:
                os.replace(p, p + ".bad")
            except OSError:
                pass
        return None, None


def cert_expiry(cert_pem):
    """datetime UTC di scadenza o None se illeggibile."""
    try:
        _x509, _h, _s, _ec, _N = _need_crypto()
        cert = _x509.load_pem_x509_certificate(cert_pem.encode("ascii"))
        exp = cert.not_valid_after_utc
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=_dt.timezone.utc)
        return exp
    except Exception:
        return None


def needs_renewal(cert_pem, days=RENEW_DAYS):
    """True se assente/illeggibile/in scadenza (puro e testabile)."""
    exp = cert_expiry(cert_pem)
    if exp is None:
        return True
    now = _dt.datetime.now(_dt.timezone.utc)
    return exp <= now + _dt.timedelta(days=days)


def cert_b64der(cert_pem):
    """DER-base64 single-line per l'header X-Client-Cert."""
    _x509, _h, _s, _ec, _N = _need_crypto()
    cert = _x509.load_pem_x509_certificate(cert_pem.encode("ascii"))
    return base64.b64encode(
        cert.public_bytes(_s.Encoding.DER)).decode("ascii")


def fingerprint_sha256(cert_pem):
    import hashlib
    _x509, _h, _s, _ec, _N = _need_crypto()
    cert = _x509.load_pem_x509_certificate(cert_pem.encode("ascii"))
    return hashlib.sha256(cert.public_bytes(_s.Encoding.DER)).hexdigest()


def build_ssl_context(server_ca, key_pem, cert_pem):
    """Contesto TLS client con cert device + CA pinnata (mai trust-all).

    server_ca: path al PEM della CA server provisionata. Assente = ValueError
    (fail-closed, il chiamante degrada esplicitamente).
    """
    if not server_ca or not os.path.isfile(server_ca):
        raise ValueError("CA server non provisionata: niente TLS mutuo")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cafile=server_ca)
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.check_hostname = True
    import tempfile
    kf = cf = None
    try:
        kf = tempfile.NamedTemporaryFile("w", suffix=".key", delete=False)
        kf.write(key_pem)
        kf.close()
        cf = tempfile.NamedTemporaryFile("w", suffix=".crt", delete=False)
        cf.write(cert_pem)
        cf.close()
        ctx.load_cert_chain(cf.name, kf.name)
    finally:
        for p in (kf.name if kf else None, cf.name if cf else None):
            try:
                if p:
                    os.remove(p)
            except OSError:
                pass
    return ctx
