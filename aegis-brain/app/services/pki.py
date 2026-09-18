"""Device PKI + manifest firmati (M6 Fase 7). Dipende da `cryptography`.

CA locale on-premise (mai in repo, solo PKI_DIR esterno):
  - bootstrap: EC P-256 self-signed 10 anni, file 600;
  - agent: genera la chiave LOCALMENTE, invia CSR -> server firma EE
    (ECDSA, EKU clientAuth, CN = agent_id, default 825 giorni);
  - revoche: seriali + agent_id in revoked.txt (file+memoria, sopravvive reboot);
  - manifest artefatti: Ed25519 separata dalla CA (firma veloce, verifica
    nativa su JVM 15+ e Python), HMAC resta per compatibilità.

Niente rete, niente DB: tutto file + memoria, testabile ovunque.
"""
import base64
import json
import os
import threading
from datetime import datetime, timedelta, timezone
from typing import Dict, Tuple

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

CA_KEY = "ca.key"
CA_CRT = "ca.crt"
REVOKED = "revoked.txt"
MANIFEST_KEY = "manifest-ed25519.key"
MANIFEST_PUB = "manifest-ed25519.pub"


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _write_private(path: str, key) -> None:
    with open(path, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()))
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _write_cert(path: str, cert) -> None:
    with open(path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def ensure_ca(ca_dir: str, org: str = "Aegis", ttl_days: int = 3650) -> Tuple[str, str]:
    """Crea la CA se assente (idempotente), ritorna (key_path, cert_path)."""
    os.makedirs(ca_dir, exist_ok=True)
    key_path = os.path.join(ca_dir, CA_KEY)
    crt_path = os.path.join(ca_dir, CA_CRT)
    if os.path.exists(key_path) and os.path.exists(crt_path):
        return key_path, crt_path
    key = ec.generate_private_key(ec.SECP256R1())
    now = _utcnow()
    import secrets
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME,
                           "ca-" + secrets.token_hex(4)),
        x509.NameAttribute(NameOID.COMMON_NAME, "Aegis Device CA"),
    ])
    cert = (x509.CertificateBuilder()
            .subject_name(subject).issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now).not_valid_after(now + timedelta(days=ttl_days))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True,
                                         crl_sign=True, content_commitment=False,
                                         data_encipherment=False, key_encipherment=False,
                                         key_agreement=False, encipher_only=False,
                                         decipher_only=False), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                           critical=False)
            .sign(key, hashes.SHA256()))
    _write_private(key_path, key)
    _write_cert(crt_path, cert)
    return key_path, crt_path


def load_ca(ca_dir: str):
    """Ritorna (private_key, certificate). Lancia FileNotFoundError se assente."""
    with open(os.path.join(ca_dir, CA_KEY), "rb") as f:
        key = serialization.load_pem_private_key(f.read(), password=None)
    with open(os.path.join(ca_dir, CA_CRT), "rb") as f:
        cert = x509.load_pem_x509_certificate(f.read())
    return key, cert


def ca_cert_pem(ca_dir: str) -> bytes:
    with open(os.path.join(ca_dir, CA_CRT), "rb") as f:
        return f.read()


def sign_csr(ca_key, ca_cert, csr_pem: bytes, agent_id: str,
             ttl_days: int = 825):
    """Firma una CSR agent: CN deve essere l'agent_id autenticato.

    Lancia ValueError su CSR invalida/firma CSR errata/CN diverso.
    Ritorna (cert_pem, serial_hex, expires_at).
    """
    try:
        csr = x509.load_pem_x509_csr(csr_pem)
    except Exception as e:
        raise ValueError(f"unreadable CSR: {e}")
    if not csr.is_signature_valid:
        raise ValueError("invalid CSR signature")
    cn = None
    try:
        cn = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except (IndexError, ValueError):
        cn = None
    if not cn or cn.strip() != str(agent_id).strip():
        raise ValueError("CSR CN diverso dall'agent_id autenticato")
    now = _utcnow()
    cert = (x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(ca_cert.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=ttl_days))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=False,
                                         crl_sign=False, content_commitment=False,
                                         data_encipherment=False, key_encipherment=True,
                                         key_agreement=False, encipher_only=False,
                                         decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
                           critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
                           critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(
                ca_key.public_key()), critical=False)
            .sign(ca_key, hashes.SHA256()))
    pem = cert.public_bytes(serialization.Encoding.PEM)
    return pem, format(cert.serial_number, "x"), cert.not_valid_after_utc


def verify_device_cert(ca_cert, cert_pem: bytes, expected_agent_id: str,
                       revoked_serials=()) -> Tuple[bool, str]:
    """Verifica catena (firma CA), finestre, CN e revoca. (ok, motivo)."""
    try:
        cert = x509.load_pem_x509_certificate(cert_pem)
    except Exception as e:
        return False, f"certificato illeggibile: {e}"
    if cert.issuer != ca_cert.subject:
        return False, "issuer diverso dalla CA"
    try:
        ca_cert.public_key().verify(
            cert.signature, cert.tbs_certificate_bytes,
            ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False, "firma CA non valida"
    except Exception as e:
        return False, f"verifica firma impossibile: {e}"
    now = _utcnow()
    if not (cert.not_valid_before_utc <= now <= cert.not_valid_after_utc):
        return False, "fuori finestra di validità"
    try:
        cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except (IndexError, ValueError):
        return False, "CN assente"
    if cn.strip() != str(expected_agent_id).strip():
        return False, "CN diverso dall'agent_id"
    if format(cert.serial_number, "x") in set(revoked_serials or ()):
        return False, "certificato revocato"
    return True, ""


class PkiUnavailable(Exception):
    """CA o revoche non leggibili/scrivibili: negare, MAI permettere."""


class RevokeList:
    """Seriali + agent_id revocati: file append + set in memoria (thread-safe).

    Fail-closed: errori I/O in lettura all'avvio o in scrittura in revoke()
    NON sono silenziati — require_healthy()/revoke() sollevano
    PkiUnavailable così i verificatori negano invece di fidarsi.
    """

    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        self._entries = set()
        self._load_error: str | None = None
        try:
            d = os.path.dirname(os.path.abspath(path))
            if d:
                os.makedirs(d, exist_ok=True)
            if os.path.exists(path):
                with open(path, encoding="utf-8") as f:
                    for line in f:
                        line = line.strip().lower()
                        if line:
                            self._entries.add(line)
        except OSError as e:
            # Directory/file illeggibili: registrato, fail-closed via require_healthy().
            self._load_error = str(e)

    def require_healthy(self) -> None:
        """Solleva PkiUnavailable se il backend non è affidabile."""
        if self._load_error:
            raise PkiUnavailable(f"revoke list non affidabile: {self._load_error}")

    def revoke(self, entry: str) -> None:
        entry = (entry or "").strip().lower()
        if not entry:
            raise ValueError("empty entry")
        with self._lock:
            self._entries.add(entry)
            try:
                # Scrittura atomica: append + fsync + directory fsync (POSIX).
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(entry + "\n")
                    f.flush()
                    try:
                        os.fsync(f.fileno())
                    except OSError:
                        pass
                # Fsync directory per garantire la durabilità del nome file.
                try:
                    d = os.path.dirname(os.path.abspath(self.path))
                    if d and os.name != "nt":
                        fd = os.open(d, os.O_DIRECTORY)
                        try:
                            os.fsync(fd)
                        finally:
                            os.close(fd)
                except OSError:
                    pass
            except OSError as e:
                # Persistenza fallita: l'entry resta in memoria ma il reboot la
                # perderebbe → fail-closed, il chiamante nega (503).
                raise PkiUnavailable(f"revoca non persistita: {e}")

    def is_revoked(self, entry: str) -> bool:
        return (entry or "").strip().lower() in self._entries

    def agent_revoked(self, agent_id: str) -> bool:
        return self.is_revoked(f"agent:{agent_id}")

    def entries(self):
        """Copia degli entry (seriali + agent:) per i verificatori."""
        with self._lock:
            return set(self._entries)

    def __len__(self) -> int:
        return len(self._entries)

    def rebuild_from_db(self, db_entries):
        """Ricostruisce il file cache da DB (fonte autorevole). Atomico + fsync."""
        with self._lock:
            new_set = set(e.strip().lower() for e in db_entries if e)
            tmp = self.path + ".tmp"
            try:
                with open(tmp, "w", encoding="utf-8") as f:
                    for e in sorted(new_set):
                        f.write(e + "\n")
                    f.flush()
                    try:
                        os.fsync(f.fileno())
                    except OSError:
                        pass
                os.replace(tmp, self.path)
                try:
                    d = os.path.dirname(os.path.abspath(self.path))
                    if d and os.name != "nt":
                        fd = os.open(d, os.O_DIRECTORY)
                        try:
                            os.fsync(fd)
                        finally:
                            os.close(fd)
                except OSError:
                    pass
                self._entries = new_set
                self._load_error = None
            except OSError as e:
                raise PkiUnavailable(f"rebuild cache fallito: {e}")
            finally:
                try:
                    if os.path.exists(tmp):
                        os.remove(tmp)
                except OSError:
                    pass


# ─── Manifest firmati (Ed25519, chiave separata dalla CA) ────────────


def ensure_manifest_key(keys_dir: str) -> Tuple[str, str]:
    """Crea/carica la chiave manifest. Ritorna (priv_path, pub_path)."""
    os.makedirs(keys_dir, exist_ok=True)
    priv = os.path.join(keys_dir, MANIFEST_KEY)
    pub = os.path.join(keys_dir, MANIFEST_PUB)
    if not (os.path.exists(priv) and os.path.exists(pub)):
        key = ed25519.Ed25519PrivateKey.generate()
        _write_private(priv, key)
        with open(pub, "wb") as f:
            f.write(key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw))
    return priv, pub


def load_manifest_private(priv_path: str):
    with open(priv_path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def manifest_pubkey_b64(pub_path: str) -> str:
    with open(pub_path, "rb") as f:
        return base64.b64encode(f.read()).decode("ascii")


def canonical_manifest_bytes(manifest: Dict) -> bytes:
    return json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_manifest(private_key, manifest: Dict) -> str:
    """Firma hex Ed25519 sul manifest canonico (senza campo 'ed25519')."""
    body = dict(manifest)
    body.pop("ed25519", None)
    return private_key.sign(canonical_manifest_bytes(body)).hex()


def verify_manifest_signature(pubkey_raw: bytes, manifest: Dict, signature_hex: str) -> bool:
    try:
        pub = ed25519.Ed25519PublicKey.from_public_bytes(pubkey_raw)
        body = dict(manifest)
        body.pop("ed25519", None)
        pub.verify(bytes.fromhex(signature_hex), canonical_manifest_bytes(body))
        return True
    except (InvalidSignature, ValueError):
        return False


def build_agent_csr(agent_id: str):
    """Lato agent (o test): genera chiave EC + CSR con CN=agent_id."""
    key = ec.generate_private_key(ec.SECP256R1())
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name([
               x509.NameAttribute(NameOID.COMMON_NAME, str(agent_id)),
               x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "aegis-device"),
           ]))
           .sign(key, hashes.SHA256()))
    return key, csr.public_bytes(serialization.Encoding.PEM)


def fingerprint_sha256(cert_pem: bytes) -> str:
    cert = x509.load_pem_x509_certificate(cert_pem)
    import hashlib
    return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


def issue_server_cert(ca_key, ca_cert, common_name: str, san_dns=(),
                      ttl_days: int = 825):
    """Certificato serverAuth per test e2e / pilot (SAN obbligatori)."""
    from cryptography.x509.oid import ExtendedKeyUsageOID as _EKU
    now = _utcnow()
    sans = [x509.DNSName(str(d)) for d in (san_dns or (common_name,))]
    key = ec.generate_private_key(ec.SECP256R1())
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, str(common_name))]))
            .issuer_name(ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=ttl_days))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                           critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=False,
                                         crl_sign=False, content_commitment=False,
                                         data_encipherment=False, key_encipherment=True,
                                         key_agreement=False, encipher_only=False,
                                         decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([_EKU.SERVER_AUTH]), critical=True)
            .add_extension(x509.SubjectAlternativeName(sans), critical=False)
            .sign(ca_key, hashes.SHA256()))
    key_pem = key.private_bytes(serialization.Encoding.PEM,
                                serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())
    return key_pem, cert.public_bytes(serialization.Encoding.PEM)


if __name__ == "__main__":  # bootstrap operatore: python -m app.services.pki
    import argparse
    ap = argparse.ArgumentParser(description="Aegis PKI bootstrap (CA + manifest key)")
    ap.add_argument("--dir", default=os.getenv("PKI_DIR", "/app/pki"))
    ap.add_argument("--org", default="Aegis")
    args = ap.parse_args()
    kp, cp = ensure_ca(args.dir, org=args.org)
    mp, mb = ensure_manifest_key(args.dir)
    print(f"CA: {cp}\nmanifest pub: {mb}")
    print("pubkey_b64 (AEGIS_MANIFEST_PUBKEY):", manifest_pubkey_b64(mb))
