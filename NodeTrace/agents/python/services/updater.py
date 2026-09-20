"""Staged OTA update per NodeTrace — stesse regole del Guard (fail-closed).

Protocollo (condiviso col brain, app/api/v1/deploy.py):
  UPDATE_AGENT {url, sha256, signature} con signature = HMAC_SHA256(enroll_key, sha256).
  1. verifica HMAC con la propria enroll key → stop se invalida
  2. download in temp → verifica SHA-256 → stage in update.pending/ + update.state
  3. ack ok/failed a /telemetry/commands/ack — l'apply è al restart
     (l'exe PyInstaller in esecuzione è lockato su Windows).

Funzioni pure qui (testate in tests/test_update.py), I/O negli Agent methods.
"""
import hashlib
import hmac
import os

PENDING_DIR = "update.pending"
STATE_FILE = "update.state"


def hmac_sign(sha256: str, enroll_key: str) -> str:
    return hmac.new(enroll_key.encode("utf-8"), sha256.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_signature(sha256: str, signature, enroll_key) -> bool:
    if not sha256 or not signature or not enroll_key or not str(enroll_key).strip():
        return False
    try:
        expected = hmac_sign(sha256.strip(), enroll_key)
        return hmac.compare_digest(expected, str(signature).strip().lower())
    except Exception:
        return False


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _parse_version(v) -> tuple:
    if not v:
        return ()
    parts = []
    for p in str(v).strip().lstrip("vV").split("."):
        num = ""
        for ch in p:
            if ch.isdigit():
                num += ch
            else:
                break
        parts.append(int(num) if num else 0)
    return tuple(parts)


def is_newer(current, target) -> bool:
    if not target or str(target).strip().lower() == "latest":
        return True
    if not current:
        return True
    return _parse_version(target) > _parse_version(current)


def stage_package(downloaded_path: str, expected_sha256: str, base_dir: str,
                  current_version=None, target_version=None) -> str:
    """Riverifica SHA, rifiuta downgrade, sposta in base_dir/update.pending/,
    scrive update.state (non sigillato: usare seal_staged_state dopo)."""
    if target_version is not None and not is_newer(current_version, target_version):
        try:
            os.remove(downloaded_path)
        except OSError:
            pass
        raise ValueError(f"Rollback rifiutato: current={current_version} target={target_version}")
    actual = sha256_file(downloaded_path)
    if not hmac.compare_digest(actual, expected_sha256.strip().lower()):
        try:
            os.remove(downloaded_path)
        except OSError:
            pass
        raise ValueError(f"SHA-256 mismatch: expected={expected_sha256} actual={actual}")
    pending = os.path.join(base_dir, PENDING_DIR)
    os.makedirs(pending, exist_ok=True)
    staged = os.path.join(pending, os.path.basename(downloaded_path))
    os.replace(downloaded_path, staged)
    with open(os.path.join(base_dir, STATE_FILE), "w", encoding="utf-8") as f:
        f.write(f"staged={staged}\nsha256={actual}\nstatus=pending-restart\n")
    return staged


def seal_staged_state(base_dir: str, secret: str) -> None:
    """Aggiunge MAC HMAC-SHA256(device secret) a update.state (audit P6:
    l'apply al restart riverifica prima di toccare l'agent live)."""
    import hashlib as _hashlib
    if not (secret or "").strip():
        raise ValueError("seal_staged_state: secret mancante — refusing")
    path = os.path.join(base_dir, STATE_FILE)
    with open(path, encoding="utf-8") as f:
        body = f.read()
    if "mac=" in body:
        raise ValueError("update.state gia' sigillato")
    tag = hmac.new(str(secret).encode(), body.encode(), _hashlib.sha256).hexdigest()
    with open(path, "w", encoding="utf-8") as f:
        f.write(body + f"mac={tag}\n")


def verify_staged_state(base_dir: str, secret: str):
    """Ritorna (staged, sha256) se il MAC e' valido, altrimenti ValueError."""
    import hashlib as _hashlib
    if not (secret or "").strip():
        raise ValueError("verify_staged_state: secret mancante — refusing")
    with open(os.path.join(base_dir, STATE_FILE), encoding="utf-8") as f:
        lines = f.read().splitlines()
    vals = {}
    for ln in lines:
        if "=" in ln:
            k, v = ln.split("=", 1)
            vals[k.strip()] = v.strip()
    if not vals.get("staged") or not vals.get("sha256") or not vals.get("mac"):
        raise ValueError("update.state incompleto o manomesso")
    body = f"staged={vals['staged']}\nsha256={vals['sha256']}\nstatus=pending-restart\n"
    expected = hmac.new(str(secret).encode(), body.encode(), _hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, vals["mac"].lower()):
        raise ValueError("update.state MAC invalido: possibile tampering")
    return vals["staged"], vals["sha256"]


def verify_manifest_ed25519(manifest_json: str, signature_hex: str, pubkey_b64: str):
    """Verifica Ed25519 del manifest (M6 Fase 7).

    Ritorna True/False, oppure None se `cryptography` non è installato
    (agent lean): il chiamante decide fail-closed con messaggio esplicito.
    """
    if not manifest_json or not signature_hex or not (pubkey_b64 or "").strip():
        return False
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PublicKey,
        )
    except ImportError:
        return None
    try:
        import base64
        pub = Ed25519PublicKey.from_public_bytes(
            base64.b64decode(pubkey_b64.strip()))
        pub.verify(bytes.fromhex(signature_hex.strip()),
                   manifest_json.encode("utf-8"))
        return True
    except Exception:
        return False


def manifest_covers(manifest_json: str, name: str, sha256: str) -> bool:
    """L'artefatto atteso è nel manifest firmato (nome+sha esatti)."""
    if not manifest_json or not name or not sha256:
        return False
    try:
        import json as _json
        doc = _json.loads(manifest_json)
        for a in doc.get("artifacts") or []:
            if not isinstance(a, dict):
                continue
            if a.get("name") == name and str(a.get("sha256", "")).lower() == sha256.strip().lower():
                return True
        return False
    except Exception:
        return False
