"""M1: modern agent deploy — Falcon-style one-liner + job queue.

Replaces the legacy flow (VaultX password parsing + copy-paste sshpass strings
in discovery.py) with:
  - short-lived single-use enroll tokens (15 min default)
  - one-liner install scripts (ps1/sh) served by the brain
  - server-side DeployJob with per-target status (no password persistence)
"""
import base64
import hashlib
import hmac
import ipaddress
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Header, Query
from fastapi.responses import PlainTextResponse, Response
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.agent_deps import get_current_agent
from app.core.audit import log_audit
from app.core.config import settings
from app.database.connection import get_db
from app.database.models import Agent, DeployJob, DiscoveredHost, EnrollToken
from app.core.deps import get_current_user, get_optional_user
from app.core.rate_limit import limiter

router = APIRouter(tags=["Agent Deploy"])

VALID_AGENT_TYPES = {"unified"}
VALID_METHODS = {"ssh", "winrm", "oneline", "interactive"}


def _require_deploy_operator(user):
    if (user.role or "user").lower() not in {"admin", "analyst"}:
        raise HTTPException(status_code=403, detail="Deployment operations require analyst or admin role")


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


# Audit S4: PIN/token di approvazione legati a una chiave server e al contesto.
# Un PIN di 6 cifre hashato con sha256 nudo si brute-forza offline in
# millisecondi leggendo il DB; con HMAC keyed serve la chiave server, e il
# binding su (tipo, job, IP) impedisce il riuso su un altro target.
def _approval_hmac_key() -> bytes:
    """Approval MACs must never fall back to a known development key."""
    secret = (settings.JWT_SECRET or "").strip()
    if not secret:
        raise HTTPException(status_code=503, detail="Approval signing key unavailable")
    return hashlib.sha256(secret.encode()).digest()


def _approval_mac(kind: str, job_id: int, ip_address: str, value: str) -> str:
    message = f"{kind}:{job_id}:{ip_address}:{value}".encode()
    return hmac.new(_approval_hmac_key(), message, hashlib.sha256).hexdigest()


def _validate_targets(targets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    clean: List[Dict[str, Any]] = []
    for t in targets[:100]:  # mass-deploy cap like CrowdStrike static groups
        ip = str(t.get("ip_address", "")).strip()
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            raise HTTPException(status_code=400, detail=f"Invalid IP in targets: {ip}")
        method = str(t.get("method", "ssh")).lower()
        if method not in VALID_METHODS and method != "interactive":
            raise HTTPException(status_code=400, detail=f"Invalid method {method}")
        clean.append({"ip_address": ip, "method": method})
    if not clean:
        raise HTTPException(status_code=400, detail="Empty targets")
    return clean


# ─── enroll tokens ────────────────────────────────────────────────

class EnrollTokenRequest(BaseModel):
    label: Optional[str] = None
    agent_type: str = Field(default="unified", pattern="^unified$")
    ttl_minutes: int = Field(default=15, ge=5, le=1440)
    dashboard_remote: bool = True
    dashboard_local: bool = False
    # Re-enroll: il token è valido solo per questo host. Un token senza
    # target_hostname resta utilizzabile per il primo enrollment, mai per
    # sostituire un agente già registrato.
    target_hostname: Optional[str] = Field(default=None, max_length=255)


@router.post("/token")
async def create_enroll_token(
    payload: EnrollTokenRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
):
    _require_deploy_operator(user)
    if payload.dashboard_local:
        raise HTTPException(status_code=422, detail="Local dashboard packaging is not available yet")
    target_hostname = (payload.target_hostname or "").strip() or None
    raw = secrets.token_urlsafe(32)
    install_config = {"dashboard_remote": payload.dashboard_remote}
    if target_hostname:
        install_config["target_hostname"] = target_hostname
    rec = EnrollToken(
        token_hash=_hash_token(raw),
        label=payload.label,
        agent_type=payload.agent_type,
        created_by=user.id,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=payload.ttl_minutes),
        install_config=install_config,
    )
    db.add(rec)
    await log_audit(
        db, action="deploy_token_create", resource="enroll_token",
        details={"label": payload.label, "agent_type": payload.agent_type,
                 "target_hostname": target_hostname},
        user_id=user.id, username=user.username,
        ip_address=request.client.host if request else None,
    )
    await db.commit()
    base = settings.PUBLIC_BASE_URL.rstrip("/")
    query = f"?agent={payload.agent_type}"
    ps1 = f"irm {base}/api/v1/deploy/install.ps1{query} -Headers @{{'X-Enroll-Token'='{raw}'}} | iex"
    sh = f"curl -fsSL -H 'X-Enroll-Token: {raw}' '{base}/api/v1/deploy/install.sh{query}' | sudo bash"
    return {
        "token": raw,
        "expires_at": rec.expires_at.isoformat(),
        "agent_type": payload.agent_type,
        "target_hostname": target_hostname,
        "dashboard_remote": payload.dashboard_remote,
        "dashboard_local": payload.dashboard_local,
        "oneline_windows": ps1,
        "oneline_linux": sh,
        "note": "Single-use, short-lived. Never commit it. Regenerate per rollout batch.",
    }


@router.get("/token")
async def list_enroll_tokens(db: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    result = await db.execute(select(EnrollToken).order_by(EnrollToken.created_at.desc()).limit(50))
    out = []
    for t in result.scalars().all():
        cfg = t.install_config if isinstance(t.install_config, dict) else {}
        out.append({
            "id": t.id, "label": t.label, "agent_type": t.agent_type,
            "target_hostname": cfg.get("target_hostname"),
            "expires_at": t.expires_at.isoformat() if t.expires_at else None,
            "used_at": t.used_at.isoformat() if t.used_at else None,
            "revoked": t.revoked,
        })
    return {"items": out}


@router.post("/token/{token_id}/revoke")
async def revoke_enroll_token(token_id: int, request: Request, db: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    _require_deploy_operator(user)
    rec = await db.get(EnrollToken, token_id)
    if not rec:
        raise HTTPException(status_code=404, detail="Token not found")
    rec.revoked = True
    await log_audit(db, action="deploy_token_revoke", resource="enroll_token", resource_id=str(token_id),
                    user_id=user.id, username=user.username,
                    ip_address=request.client.host if request else None)
    await db.commit()
    return {"status": "revoked"}


# ─── one-liner install scripts (served, token validated at enroll time) ──

INSTALL_PS1 = r"""# Aegis one-liner installer (Windows, admin PowerShell)
$ErrorActionPreference = "Stop"
$Base = "{BASE}/api/v1"
$EnrollToken = "{ENROLL_TOKEN}"
$ManifestPubkey = "{MANIFEST_PUBKEY}"
$RemoteDashboard = {REMOTE_DASHBOARD}
$Dir = "C:\Aegis\Agent"
$Service = "AegisAgent"

New-Item -ItemType Directory -Force -Path $Dir | Out-Null
Write-Host "[aegis] downloading the unified AegisAgent into $Dir ..."
$pkg = Join-Path $Dir "agent.pkg"
Invoke-WebRequest -Uri "$Base/deploy/bootstrap-artifacts/unified-latest.zip" `
    -Headers @{"X-Enroll-Token" = $EnrollToken} -OutFile $pkg -UseBasicParsing
Expand-Archive -Path $pkg -DestinationPath $Dir -Force
Remove-Item -Force $pkg

$binary = Join-Path $Dir "aegis-agent.exe"
if (-not (Test-Path $binary)) {
    throw "No unified runtime found after extraction: $binary"
}

if ($RemoteDashboard) {
    [Environment]::SetEnvironmentVariable("AEGIS_BRAIN_URL", $Base, "Machine")
    [Environment]::SetEnvironmentVariable("AEGIS_MANIFEST_PUBKEY", $ManifestPubkey, "Machine")
    [Environment]::SetEnvironmentVariable("AEGIS_AGENT_PROFILE", "unified", "Machine")

    # Token one-shot su file 0600, mai nell'env persistente.
    $TokenDir = Join-Path $env:ProgramData "Aegis"
    New-Item -ItemType Directory -Force -Path $TokenDir | Out-Null
    $TokenFile = Join-Path $TokenDir "enroll.token"
    Set-Content -Path $TokenFile -Value $EnrollToken -NoNewline -Encoding ascii
    & icacls $TokenFile /inheritance:r /grant:r "*S-1-5-18:F" "*S-1-5-32-544:F" | Out-Null
    [Environment]::SetEnvironmentVariable("AEGIS_ENROLL_TOKEN_FILE", $TokenFile, "Machine")

    $etw = Join-Path $Dir "aegis-etw.exe"
    if (Test-Path $etw) {
        [Environment]::SetEnvironmentVariable("AEGIS_ETW_ENABLED", "true", "Machine")
        [Environment]::SetEnvironmentVariable("AEGIS_ETW_PATH", $etw, "Machine")
        [Environment]::SetEnvironmentVariable("AEGIS_ETW_ALLOW_UNSIGNED", "true", "Machine")
        # Unsigned is accepted only with a pinned digest; the agent refuses
        # both an empty pin and a binary whose hash changed after install.
        $etwHash = (Get-FileHash -Algorithm SHA256 $etw).Hash.ToLower()
        [Environment]::SetEnvironmentVariable("AEGIS_ETW_SHA256", $etwHash, "Machine")
    } else {
        Write-Host "[aegis] no ETW collector in the artifact: unified will declare quality=degraded:etw-..."
    }

    if (Get-Service $Service -ErrorAction SilentlyContinue) {
        Stop-Service $Service -Force -ErrorAction SilentlyContinue
        sc.exe delete $Service | Out-Null
        Start-Sleep -Milliseconds 500
    }
    New-Service -Name $Service -BinaryPathName "`"$binary`"" `
        -DisplayName $Service -Description "Aegis unified agent" `
        -StartupType Automatic | Out-Null
    sc.exe failure $Service reset= 86400 actions= restart/5000/restart/5000/restart/5000 | Out-Null
    Start-Service $Service
    Write-Host "[aegis] $Service service installed and started."
} else {
    Write-Host "[aegis] remote dashboard NOT selected: files extracted, no service registered."
    Write-Host "        Start the agent from $Dir, or re-issue a token with remote dashboard enabled."
}

Write-Host "[aegis] The agent will consume the single-use token during its first enrollment."
Write-Host "[aegis] Verify: Get-Service $Service; logs under $Dir\logs."
Write-Host "[aegis] Docs: https://aegis.local/docs/agent-install"
"""

INSTALL_SH = """#!/usr/bin/env bash
# Aegis one-liner installer (Linux, root)
# usage: curl -fsSL -H 'X-Enroll-Token: <token>' https://aegis.local/api/v1/deploy/install.sh | sudo bash
set -euo pipefail
BASE="{BASE}/api/v1"
ENROLL_TOKEN="{ENROLL_TOKEN}"
MANIFEST_PUBKEY="{MANIFEST_PUBKEY}"
REMOTE_DASHBOARD="{REMOTE_DASHBOARD}"
DIR="/opt/aegis/unified"

mkdir -p "$DIR"
echo "[aegis] downloading the unified AegisAgent into $DIR ..."
curl -fsSL -H "X-Enroll-Token: $ENROLL_TOKEN" \
    "$BASE/deploy/bootstrap-artifacts/unified-latest.tar.gz" -o /tmp/aegis-agent.pkg
tar -xzf /tmp/aegis-agent.pkg -C "$DIR"
rm -f /tmp/aegis-agent.pkg
chmod 755 "$DIR/aegis-agent"
if [ -f "$DIR/aegis-collector" ]; then
    chmod 755 "$DIR/aegis-collector"
fi

if [ "$REMOTE_DASHBOARD" = "1" ]; then
    printf '%s' "$ENROLL_TOKEN" > "$DIR/enroll.token"
    chmod 600 "$DIR/enroll.token"
    cat > "$DIR/aegis.env" <<EOF
AEGIS_BRAIN_URL=$BASE
AEGIS_MANIFEST_PUBKEY=$MANIFEST_PUBKEY
AEGIS_ENROLL_TOKEN_FILE=$DIR/enroll.token
AEGIS_AGENT_PROFILE=unified
EOF
    if [ -x "$DIR/aegis-collector" ] && [ -f "$DIR/aegis_exec.bpf.o" ]; then
        cat >> "$DIR/aegis.env" <<EOF
NODETRACE_EBPF=1
NODETRACE_EBPF_COLLECTOR=$DIR/aegis-collector
NODETRACE_EBPF_OBJ=$DIR/aegis_exec.bpf.o
EOF
    fi
    chmod 600 "$DIR/aegis.env"

    cat > /etc/systemd/system/aegis-unified.service <<EOF
[Unit]
Description=Aegis unified agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$DIR/aegis-agent
EnvironmentFile=$DIR/aegis.env
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF
    systemctl enable --now aegis-unified.service
    systemctl is-active --quiet aegis-unified.service
    echo "[aegis] aegis-unified service installed and started."
else
    echo "[aegis] remote dashboard NOT selected: files extracted, no service registered."
fi
"""


def _manifest_pubkey_b64() -> str:
    """Chiave pubblica Ed25519 del manifest, obbligatoria per l'OTA."""
    from app.services import pki as _pki
    pub_path = Path(settings.PKI_DIR) / _pki.MANIFEST_PUB
    try:
        raw = pub_path.read_bytes()
    except OSError as exc:
        raise HTTPException(
            status_code=503,
            detail=f"Manifest Ed25519 public key unavailable: {exc}",
        )
    if len(raw) != 32:
        raise HTTPException(status_code=503, detail="Manifest Ed25519 public key is invalid")
    return base64.b64encode(raw).decode("ascii")


async def _validate_install_token(x_enroll_token: str, db: AsyncSession):
    if not x_enroll_token:
        raise HTTPException(status_code=401, detail="Missing X-Enroll-Token header")
    digest = hashlib.sha256(x_enroll_token.strip().encode()).hexdigest()
    result = await db.execute(select(EnrollToken).where(EnrollToken.token_hash == digest, EnrollToken.revoked == False))
    token = result.scalars().first()
    if not token or (token.expires_at and token.expires_at < datetime.now(timezone.utc)):
        raise HTTPException(status_code=401, detail="Invalid or expired enroll token")
    return token

@router.get("/install.ps1", response_class=PlainTextResponse)
async def install_ps1(
    agent: str = Query("unified", pattern="^unified$"),
    x_enroll_token: str = Header(None, alias="X-Enroll-Token"),
    db: AsyncSession = Depends(get_db),
):
    token = await _validate_install_token(x_enroll_token, db)
    if token.agent_type != "unified":
        raise HTTPException(status_code=403, detail="Legacy enrollment tokens are no longer accepted")
    config = token.install_config or {}
    pubkey = _manifest_pubkey_b64()
    return INSTALL_PS1.replace("{BASE}", settings.PUBLIC_BASE_URL.rstrip("/")).replace(
        "{ENROLL_TOKEN}", x_enroll_token.strip()).replace("{MANIFEST_PUBKEY}", pubkey).replace(
        "{REMOTE_DASHBOARD}", "$true" if config.get("dashboard_remote", True) else "$false")


@router.get("/install.sh", response_class=PlainTextResponse)
async def install_sh(
    agent: str = Query("unified", pattern="^unified$"),
    x_enroll_token: str = Header(None, alias="X-Enroll-Token"),
    db: AsyncSession = Depends(get_db),
):
    token = await _validate_install_token(x_enroll_token, db)
    if token.agent_type != "unified":
        raise HTTPException(status_code=403, detail="Legacy enrollment tokens are no longer accepted")
    config = token.install_config or {}
    pubkey = _manifest_pubkey_b64()
    return INSTALL_SH.replace("{BASE}", settings.PUBLIC_BASE_URL.rstrip("/")).replace(
        "{ENROLL_TOKEN}", x_enroll_token.strip()).replace("{MANIFEST_PUBKEY}", pubkey).replace(
        "{REMOTE_DASHBOARD}", "1" if config.get("dashboard_remote", True) else "0")


@router.get("/artifacts")
async def list_artifacts(user=Depends(get_current_user)):
    """List published agent artifacts (CI publishes here, installers download)."""
    root = Path(settings.ARTIFACT_DIR)
    items = []
    if root.exists():
        for p in sorted(root.glob("*")):
            if p.is_file():
                items.append({"name": p.name, "size": p.stat().st_size})
    return {
        "items": items,
        "expected": ["unified-latest.zip", "unified-latest.tar.gz"],
        "note": "Publish from CI (build.bat/mvn) into ARTIFACT_DIR. Installers pull from here — never compile on target.",
    }


# ─── OTA firmata (staged update) ──────────────────────────────────
# Ed25519 obbligatorio: la chiave manifest è separata dalla enroll key e dal
# device secret. L'HMAC OTA è stato rimosso in 4.1.0 (AEGIS-SEC-002): un
# comando senza manifest firmato viene rifiutato dall'agente, in ogni profilo.


class ManifestUnavailable(RuntimeError):
    """La chiave privata Ed25519 del manifest non è disponibile."""


def artifact_name_for(agent_type: str, version: str) -> str:
    if agent_type != "unified":
        raise ValueError(f"unsupported agent type: {agent_type}")
    v = (version or "latest").strip() or "latest"
    return f"unified-{v}.zip"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def is_newer_version(current: Optional[str], target: str) -> bool:
    """Confronto versioni semplice: 'latest' è sempre newer; altrimenti tuple numeriche."""
    if not target or target.strip().lower() == "latest":
        return True
    if not current:
        return True
    def parts(v: str):
        out = []
        for p in v.strip().lstrip("v").split("."):
            try:
                out.append(int(p))
            except ValueError:
                out.append(0)
        return out
    return parts(target) > parts(current)


def build_update_command(agent_type: str, version: str, base_url: str, sha256: str,
                         manifest: str, manifest_sig: str) -> Dict[str, Any]:
    return {
        "command": "UPDATE_AGENT",
        "agent_type": agent_type,
        "version": version,
        "url": f"{base_url.rstrip('/')}/api/v1/deploy/artifacts/{artifact_name_for(agent_type, version)}",
        "sha256": sha256,
        "manifest": manifest,
        "manifest_sig": manifest_sig,
    }


def build_manifest(artifacts: List[Dict[str, str]]) -> Dict[str, Any]:
    """Manifest repository versionato; la firma Ed25519 è esterna al manifest."""
    return {"key_id": "aegis-manifest-v1",
            "artifacts": [{"name": a["name"], "sha256": a["sha256"]}
                          for a in artifacts]}


def sign_manifest_bundle(manifest: Dict[str, Any]) -> Dict[str, Any]:
    """Firma il manifest con la chiave Ed25519 dedicata in PKI_DIR.

    La enroll key non partecipa mai alla firma. Se la PKI non è inizializzata
    l'operazione fallisce: non esiste un fallback HMAC silenzioso.
    """
    from app.services import pki as _pki
    import os as _os
    priv_path = _os.path.join(settings.PKI_DIR, _pki.MANIFEST_KEY)
    if not _os.path.exists(priv_path):
        raise ManifestUnavailable(
            "Manifest Ed25519 private key missing: run PKI bootstrap "
            "(python -m app.services.pki --dir ...)"
        )
    try:
        key = _pki.load_manifest_private(priv_path)
        signature = _pki.sign_manifest(key, manifest)
    except Exception as exc:
        raise ManifestUnavailable(f"Manifest Ed25519 signing failed: {exc}") from exc
    return {"manifest": manifest, "ed25519": signature, "signed": True}


@router.get("/manifest")
async def get_manifest():
    """Manifest firmato degli artefatti pubblicati (materiale pubblico).

    Ed25519 è obbligatorio: senza chiave privata l'endpoint risponde 503,
    invece di esporre un manifest non firmato o un fallback HMAC.
    """
    from app.services import pki as _pki
    root = Path(settings.ARTIFACT_DIR)
    items = []
    if root.exists():
        for p in sorted(root.glob("*")):
            if p.is_file() and not p.name.startswith("."):
                items.append({"name": p.name, "sha256": sha256_file(p)})
    manifest = build_manifest(items)
    try:
        bundle = sign_manifest_bundle(manifest)
    except ManifestUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    try:
        pub_path = Path(settings.PKI_DIR) / _pki.MANIFEST_PUB
        bundle["pubkey_b64"] = base64.b64encode(pub_path.read_bytes()).decode("ascii")
    except OSError as exc:
        raise HTTPException(status_code=503,
                            detail=f"Manifest Ed25519 public key unavailable: {exc}")
    return bundle


def _artifact_response(path: Path, name: str) -> Response:
    """Return an artifact without Starlette's streaming FileResponse.

    Starlette 1.10.0 wrapped by BaseHTTPMiddleware drops the body of a
    FileResponse: the client receives Content-Length and zero bytes. That
    breaks the one-liner install path, which downloads exactly these files.
    The agent archives are single-digit MB, so a bounded in-memory response
    is safer than a streaming path that silently truncates.
    """
    return Response(
        content=path.read_bytes(),
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{name}"'},
    )


@router.get("/artifacts/{name}")
async def download_artifact(name: str, agent=Depends(get_current_agent)):
    """Serve artifact all'agente autenticato (l'update lo scarica da qui)."""
    safe = Path(name).name  # anti-traversal: solo basename
    if not safe or safe.startswith("."):
        raise HTTPException(status_code=400, detail="Invalid artifact name")
    path = Path(settings.ARTIFACT_DIR) / safe
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Artifact not found")
    return _artifact_response(path, safe)


@router.get("/bootstrap-artifacts/{name}")
async def download_bootstrap_artifact(
    name: str,
    x_enroll_token: str = Header(None, alias="X-Enroll-Token"),
    db: AsyncSession = Depends(get_db),
):
    """Serve one published artifact before the agent has credentials.

    The token is only checked here and is consumed later by /enroll, so a
    failed download does not burn the operator's single-use enrollment.
    """
    token = await _validate_install_token(x_enroll_token, db)
    safe = Path(name).name
    if not safe or safe.startswith("."):
        raise HTTPException(status_code=400, detail="Invalid artifact name")
    if token.agent_type != "unified":
        raise HTTPException(status_code=403, detail="Legacy enrollment tokens are no longer accepted")
    if not safe.startswith("unified-"):
        raise HTTPException(status_code=403, detail="Token agent type does not match artifact")
    path = Path(settings.ARTIFACT_DIR) / safe
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Artifact not found")
    return _artifact_response(path, safe)


class UpdateCommandRequest(BaseModel):
    agent_id: str = Field(..., max_length=64)
    version: str = Field(default="latest", max_length=50)


@router.post("/update-command")
async def push_update_command(
    payload: UpdateCommandRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
):
    _require_deploy_operator(user)
    """Accoda UPDATE_AGENT firmato Ed25519 a un agente (o lo restituisce se la coda è giù).

    Il comando contiene url, sha256, manifest canonico e firma Ed25519: l'agente
    verifica la firma e la copertura prima di mettere in stage. Se Redis è giù,
    ritorna comunque il payload firmato (202) invece di 500.
    """
    import uuid as _uuid
    try:
        agent_uuid = _uuid.UUID(payload.agent_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid agent_id format")
    result = await db.execute(select(Agent).where(Agent.agent_id == agent_uuid))
    agent = result.scalars().first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent not found")
    normalized_type = (agent.agent_type or "").lower()
    if normalized_type != "unified":
        raise HTTPException(status_code=400, detail="OTA supported for unified agents only")
    fname = artifact_name_for("unified", payload.version)
    path = Path(settings.ARTIFACT_DIR) / fname
    if not path.is_file():
        raise HTTPException(status_code=404, detail=f"Artifact {fname} not published in ARTIFACT_DIR")
    digest = sha256_file(path)
    try:
        bundle = sign_manifest_bundle(build_manifest([{"name": fname, "sha256": digest}]))
    except ManifestUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    from app.services import pki as _pki2
    cmd = build_update_command(
        "unified", payload.version, settings.PUBLIC_BASE_URL, digest,
        _pki2.canonical_manifest_bytes(bundle["manifest"]).decode("utf-8"),
        bundle["ed25519"],
    )

    try:
        from app.services.telemetry_service import send_command_to_agent
        await send_command_to_agent(agent.agent_id, {**cmd, "alert_id": None})
        queued = True
    except Exception:
        queued = False
    await log_audit(
        db, action="deploy_update_push", resource="agent", resource_id=str(agent.agent_id),
        details={"version": payload.version, "artifact": fname, "sha256": digest,
                 "queued": queued, "manifest_signed": True},
        user_id=user.id, username=user.username,
        ip_address=request.client.host if request else None,
    )
    await db.commit()
    return {"queued": queued, "status": 200 if queued else 202, "command": cmd,
            "agent_id": str(agent.agent_id),
            "note": "Agent verifies the Ed25519 manifest before staging. Restart applies (service wrapper)."} if queued else \
           {"queued": False, "status": 202, "command": cmd, "agent_id": str(agent.agent_id),
            "note": "Queue unavailable — deliver command manually. The Ed25519 signature remains valid."}


# ─── deploy jobs (mass rollout, server-side, no password storage) ──

class DeployJobRequest(BaseModel):
    agent_type: str = Field(default="unified", pattern="^unified$")
    agent_version: str = Field(default="latest", max_length=50)
    targets: List[Dict[str, Any]]
    username: Optional[str] = Field(default=None, max_length=255)
    password: Optional[str] = Field(default=None, max_length=512)
    method_default: str = Field(default="ssh", pattern="^(ssh|winrm|oneline|interactive)$")


def _redacted_results(targets: List[Dict[str, Any]], method: str) -> Dict[str, Any]:
    # Initial per-target state. Worker updates via PUT /deploy/jobs/{id}/status
    # (agent callback) or server-side executor. Password is NEVER stored.
    return {t["ip_address"]: {"status": "queued", "method": t.get("method", method), "log": ""} for t in targets}


@router.post("/jobs")
async def create_deploy_job(
    payload: DeployJobRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
):
    _require_deploy_operator(user)
    if payload.agent_type not in VALID_AGENT_TYPES:
        raise HTTPException(status_code=400, detail="Invalid agent_type")
    if payload.method_default != "oneline":
        raise HTTPException(
            status_code=501,
            detail="SSH/WinRM execution is not enabled yet; use the signed one-line enrollment flow",
        )
    if payload.username or payload.password:
        raise HTTPException(status_code=400, detail="Credentials are not accepted for manual one-line deployment")
    targets = _validate_targets([
        {**t, "method": t.get("method", payload.method_default)} for t in payload.targets
    ])
    job = DeployJob(
        agent_type=payload.agent_type,
        agent_version=payload.agent_version,
        targets=targets,
        status="queued",
        results=_redacted_results(targets, payload.method_default),
        created_by=user.id,
    )
    db.add(job)
    await db.flush()  # get job.id for credential ref

    # Touch discovered hosts so the Discovery UI shows rollout state
    for t in targets:
        r = await db.execute(select(DiscoveredHost).where(DiscoveredHost.ip_address == t["ip_address"]))
        host = r.scalars().first()
        if host:
            host.notes = ((host.notes or "") + f"\n[aegis-deploy] job #{job.id} queued ({payload.agent_type})").strip()[-2000:]

    await log_audit(
        db, action="deploy_job_create", resource="deploy_job", resource_id=str(job.id),
        details={"agent_type": payload.agent_type, "targets": [t["ip_address"] for t in targets],
                 "has_transient_creds": bool(payload.username)},
        user_id=user.id, username=user.username,
        ip_address=request.client.host if request else None,
    )
    await db.commit()

    # One-line deployment is intentionally manual: the signed, single-use
    # token is copied to the target by the operator. Password-based remote
    # execution is rejected until a dedicated ephemeral worker exists.
    for entry in job.results.values():
        entry["status"] = "manual_required"
        entry["log"] = "Use a short-lived signed enrollment token on the target host."
    job.status = "manual_required"
    await db.commit()
    return {
        "job_id": job.id, "status": job.status,
        "targets": targets,
        "poll": f"/api/v1/deploy/jobs/{job.id}",
        "warning": "Manual one-line enrollment required; no credentials were accepted or stored.",
    }


@router.get("/jobs")
async def list_deploy_jobs(db: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    result = await db.execute(select(DeployJob).order_by(DeployJob.created_at.desc()).limit(50))
    return {"items": [
        {"id": j.id, "agent_type": j.agent_type, "agent_version": j.agent_version,
         "status": j.status, "targets": j.targets, "results": j.results,
         "created_at": j.created_at.isoformat() if j.created_at else None}
        for j in result.scalars().all()
    ]}


@router.get("/jobs/{job_id}")
async def get_deploy_job(job_id: int, db: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    job = await db.get(DeployJob, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return {"id": job.id, "agent_type": job.agent_type, "agent_version": job.agent_version,
            "status": job.status, "targets": job.targets, "results": job.results,
            "created_at": job.created_at.isoformat() if job.created_at else None,
            "updated_at": job.updated_at.isoformat() if job.updated_at else None}


class JobStatusUpdate(BaseModel):
    ip_address: str
    status: str = Field(pattern="^(queued|running|ok|failed)$")
    log: Optional[str] = Field(default="", max_length=8000)


@router.put("/jobs/{job_id}/status")
async def update_job_status(
    job_id: int, payload: JobStatusUpdate, request: Request,
    db: AsyncSession = Depends(get_db), user=Depends(get_current_user),
):
    _require_deploy_operator(user)
    """Worker/agent callback to stream per-target rollout status."""
    job = await db.get(DeployJob, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    results = dict(job.results or {})
    entry = results.get(payload.ip_address, {"method": "ssh", "log": ""})
    entry.update({"status": payload.status, "log": (payload.log or "")[-4000:]})
    results[payload.ip_address] = entry
    job.results = results
    states = {v.get("status") for v in results.values()}
    if states and states <= {"ok", "failed"}:
        job.status = "done" if "failed" not in states else "partial"
    elif "running" in states or "queued" in states:
        job.status = "running"
    await log_audit(db, action="deploy_job_status", resource="deploy_job", resource_id=str(job_id),
                    details={"ip": payload.ip_address, "status": payload.status},
                    user_id=user.id, username=user.username,
                    ip_address=request.client.host if request else None)
    await db.commit()
    return {"job_id": job.id, "status": job.status, "results": job.results}


# ─── Google-style Remote Approvals ──────────────────────────────────────────

class ApprovalRequestPayload(BaseModel):
    ip_address: str
    pin: str = Field(..., min_length=6, max_length=10, pattern=r"^[0-9]+$")

@router.post("/jobs/{job_id}/request-approval")
@limiter.limit("10/minute")
async def request_interactive_approval(
    job_id: int, payload: ApprovalRequestPayload, request: Request,
    db: AsyncSession = Depends(get_db), user=Depends(get_current_user),
):
    _require_deploy_operator(user)
    """Mark a deployment job as waiting for remote interactive approval."""
    job = await db.get(DeployJob, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    results = dict(job.results or {})
    entry = results.get(payload.ip_address)
    if not entry:
        raise HTTPException(status_code=400, detail="Target is not part of this job")
    approval_token = secrets.token_urlsafe(32)
    entry.update({
        "status": "waiting_approval",
        "approval_pin_hash": _approval_mac("pin", job.id, payload.ip_address, payload.pin),
        "approval_token_hash": _approval_mac("token", job.id, payload.ip_address, approval_token),
        "approval_attempts": 0,
        "log": "Waiting for the remote user to enter the approval PIN on the target device."
    })
    results[payload.ip_address] = entry
    job.results = results
    job.status = "waiting_approval"
    await db.commit()
    return {"status": "waiting_approval", "job_id": job.id, "approval_token": approval_token}


class ApproveJobPayload(BaseModel):
    ip_address: str
    pin: str = Field(..., min_length=6, max_length=10, pattern=r"^[0-9]+$")

@router.post("/jobs/{job_id}/approve")
@limiter.limit("5/minute")
async def approve_job_remotely(
    job_id: int, payload: ApproveJobPayload, request: Request,
    x_approval_token: str | None = Header(None, alias="X-Approval-Token"),
    db: AsyncSession = Depends(get_db), user=Depends(get_optional_user),
):
    """Callback used by the remote GUI script to approve the installation."""
    job = await db.get(DeployJob, job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    results = dict(job.results or {})
    entry = results.get(payload.ip_address)
    if not entry or entry.get("status") != "waiting_approval":
        raise HTTPException(status_code=400, detail="Job not waiting for approval")
    
    token_ok = bool(x_approval_token) and hmac.compare_digest(
        _approval_mac("token", job.id, payload.ip_address, x_approval_token),
        entry.get("approval_token_hash", ""),
    )
    user_ok = bool(user and (user.role or "user").lower() in {"admin", "analyst"})
    if not token_ok and not user_ok:
        raise HTTPException(status_code=401, detail="Approval authentication required")

    pin_ok = hmac.compare_digest(
        _approval_mac("pin", job.id, payload.ip_address, payload.pin),
        entry.get("approval_pin_hash", ""),
    )
    if not pin_ok:
        attempts = int(entry.get("approval_attempts", 0)) + 1
        entry["approval_attempts"] = attempts
        if attempts >= 5:
            entry.update({"status": "failed", "log": "Approval expired after too many invalid attempts."})
            job.status = "failed"
        else:
            entry["log"] = "Invalid approval PIN."
        job.results = results
        await db.commit()
        raise HTTPException(status_code=403, detail="Invalid PIN")

    entry.pop("approval_pin_hash", None)
    entry.pop("approval_token_hash", None)
    entry.pop("approval_attempts", None)
    entry.update({"status": "queued", "log": "Approval granted. Proceeding with installation..."})
    results[payload.ip_address] = entry
    job.results = results
    job.status = "running"
    await db.commit()
    return {"status": "approved", "message": "Installation will proceed"}
