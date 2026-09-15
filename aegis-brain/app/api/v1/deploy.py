"""M1: modern agent deploy — Falcon-style one-liner + job queue.

Replaces the legacy flow (VaultX password parsing + copy-paste sshpass strings
in discovery.py) with:
  - short-lived single-use enroll tokens (15 min default)
  - one-liner install scripts (ps1/sh) served by the brain
  - server-side DeployJob with per-target status (no password persistence)
"""
import hashlib
import hmac
import ipaddress
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Header
from fastapi.responses import FileResponse, PlainTextResponse
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

VALID_AGENT_TYPES = {"nodetrace", "aegis-guard", "unified"}
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
_APPROVAL_HMAC_KEY = hashlib.sha256(
    (settings.JWT_SECRET or "aegis-approval-dev-only").encode()
).digest()


def _approval_mac(kind: str, job_id: int, ip_address: str, value: str) -> str:
    message = f"{kind}:{job_id}:{ip_address}:{value}".encode()
    return hmac.new(_APPROVAL_HMAC_KEY, message, hashlib.sha256).hexdigest()


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
    agent_type: str = Field(default="aegis-guard", pattern="^(nodetrace|aegis-guard|unified)$")
    ttl_minutes: int = Field(default=15, ge=5, le=1440)


@router.post("/token")
async def create_enroll_token(
    payload: EnrollTokenRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
):
    _require_deploy_operator(user)
    raw = secrets.token_urlsafe(32)
    rec = EnrollToken(
        token_hash=_hash_token(raw),
        label=payload.label,
        agent_type=payload.agent_type,
        created_by=user.id,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=payload.ttl_minutes),
    )
    db.add(rec)
    await log_audit(
        db, action="deploy_token_create", resource="enroll_token",
        details={"label": payload.label, "agent_type": payload.agent_type},
        user_id=user.id, username=user.username,
        ip_address=request.client.host if request else None,
    )
    await db.commit()
    base = settings.PUBLIC_BASE_URL.rstrip("/")
    if payload.agent_type == "unified":
        ps1 = f"irm {base}/api/v1/deploy/install.ps1?agent=unified -Headers @{{'X-Enroll-Token'='{raw}'}} | iex"
        sh = f"curl -fsSL -H 'X-Enroll-Token: {raw}' '{base}/api/v1/deploy/install.sh?agent=unified' | sudo bash"
    elif payload.agent_type == "aegis-guard":
        ps1 = f"irm {base}/api/v1/deploy/install.ps1 -Headers @{{'X-Enroll-Token'='{raw}'}} | iex"
        sh = f"curl -fsSL -H 'X-Enroll-Token: {raw}' {base}/api/v1/deploy/install.sh | sudo bash"
    else:
        ps1 = f"irm {base}/api/v1/deploy/install.ps1?agent=nodetrace -Headers @{{'X-Enroll-Token'='{raw}'}} | iex"
        sh = f"curl -fsSL -H 'X-Enroll-Token: {raw}' '{base}/api/v1/deploy/install.sh?agent=nodetrace' | sudo bash"
    return {
        "token": raw,
        "expires_at": rec.expires_at.isoformat(),
        "agent_type": payload.agent_type,
        "oneline_windows": ps1,
        "oneline_linux": sh,
        "note": "Single-use, short-lived. Never commit it. Regenerate per rollout batch.",
    }


@router.get("/token")
async def list_enroll_tokens(db: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    result = await db.execute(select(EnrollToken).order_by(EnrollToken.created_at.desc()).limit(50))
    out = []
    for t in result.scalars().all():
        out.append({
            "id": t.id, "label": t.label, "agent_type": t.agent_type,
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
param([string]$Agent = "aegis-guard")
$ErrorActionPreference = "Stop"
$Token = $env:AEGIS_ENROLL_TOKEN
if (-not $Token -and $Request.Headers) { $Token = $Request.Headers["X-Enroll-Token"] }
# Token is passed via -Headers @{'X-Enroll-Token'='...'} | iex
$Base = "{BASE}/api/v1"

function Install-AegisAgent($TargetAgent) {
    $Dir = if ($TargetAgent -eq "nodetrace") { "C:\Aegis\NodeTrace" } else { "C:\Aegis\Guard" }
    New-Item -ItemType Directory -Force -Path $Dir | Out-Null
    Write-Host "[aegis] downloading $TargetAgent into $Dir ..."
    try {
        $pkg = "$Dir\agent.pkg"
        Invoke-WebRequest -Uri "$Base/artifacts/$TargetAgent-latest.zip" -OutFile $pkg -UseBasicParsing
        Expand-Archive -Path $pkg -DestinationPath $Dir -Force
        Remove-Item -Force $pkg
    } catch {
        Write-Host "[aegis] failed to download $TargetAgent, ensure artifact is published."
        throw
    }
}

if ($Agent -eq "unified") {
    Install-AegisAgent "nodetrace"
    Install-AegisAgent "aegis-guard"
    Write-Host "[aegis] both agents installed."
} else {
    Install-AegisAgent $Agent
    Write-Host "[aegis] installed."
}
Write-Host "[aegis] Enroll with your one-time token, then start the service."
Write-Host "[aegis] Docs: https://aegis.local/docs/agent-install"
"""

INSTALL_SH = """#!/usr/bin/env bash
# Aegis one-liner installer (Linux, root)
# usage: curl -fsSL -H 'X-Enroll-Token: <token>' https://aegis.local/api/v1/deploy/install.sh | sudo bash
set -euo pipefail
AGENT="${AGENT:-aegis-guard}"
BASE="{BASE}/api/v1"

install_agent() {
    local target_agent=$1
    local dir="/opt/aegis/${target_agent}"
    mkdir -p "$dir"
    echo "[aegis] downloading ${target_agent} into ${dir} ..."
    curl -fsSL "$BASE/artifacts/${target_agent}-latest.tar.gz" -o /tmp/aegis-agent.pkg
    tar -xzf /tmp/aegis-agent.pkg -C "$dir"
    rm -f /tmp/aegis-agent.pkg
}

if [ "$AGENT" = "unified" ]; then
    install_agent "nodetrace"
    install_agent "aegis-guard"
    echo "[aegis] both agents installed."
else
    install_agent "$AGENT"
    echo "[aegis] installed."
fi
echo "[aegis] Enroll with your one-time token, then: systemctl enable --now aegis-agent"
"""


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
async def install_ps1(x_enroll_token: str = Header(None, alias="X-Enroll-Token"), db: AsyncSession = Depends(get_db)):
    await _validate_install_token(x_enroll_token, db)
    return INSTALL_PS1.replace("{BASE}", settings.PUBLIC_BASE_URL.rstrip("/"))


@router.get("/install.sh", response_class=PlainTextResponse)
async def install_sh(x_enroll_token: str = Header(None, alias="X-Enroll-Token"), db: AsyncSession = Depends(get_db)):
    await _validate_install_token(x_enroll_token, db)
    return INSTALL_SH.replace("{BASE}", settings.PUBLIC_BASE_URL.rstrip("/"))


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
        "expected": ["aegis-guard-latest.zip", "nodetrace-latest.zip",
                     "aegis-guard-latest.tar.gz", "nodetrace-latest.tar.gz"],
        "note": "Publish from CI (build.bat/mvn) into ARTIFACT_DIR. Installers pull from here — never compile on target.",
    }


# ─── OTA firmata (staged update, alla CrowdStrike) ────────────────────
# L'agente conosce AGENT_ENROLL_KEY (env) e verifica HMAC(sha256) prima di
# mettere in stage. Niente firma valida → niente download applicato.

def artifact_name_for(agent_type: str, version: str) -> str:
    v = (version or "latest").strip() or "latest"
    if agent_type == "aegis-guard":
        return f"aegis-guard-{v}.zip"
    return f"nodetrace-{v}.zip"


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def sign_artifact(sha256: str, key: Optional[str] = None) -> str:
    k = (key if key is not None else (settings.AGENT_ENROLL_KEY or "")).encode()
    return hmac.new(k, sha256.encode(), hashlib.sha256).hexdigest()


def verify_artifact_signature(sha256: str, signature: str, key: Optional[str] = None) -> bool:
    expected = sign_artifact(sha256, key)
    return hmac.compare_digest(expected, (signature or "").strip())


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


def build_update_command(agent_type: str, version: str, base_url: str, sha256: str, signature: str) -> Dict[str, Any]:
    return {
        "command": "UPDATE_AGENT",
        "agent_type": agent_type,
        "version": version,
        "url": f"{base_url.rstrip('/')}/api/v1/deploy/artifacts/{artifact_name_for(agent_type, version)}",
        "sha256": sha256,
        "signature": signature,
    }


def build_manifest(artifacts: List[Dict[str, str]]) -> Dict[str, Any]:
    """Manifest repository versionato: ogni entry ha hmac di compatibilità."""
    return {"key_id": "aegis-manifest-v1",
            "artifacts": [
                {"name": a["name"], "sha256": a["sha256"],
                 "hmac": sign_artifact(a["sha256"])}
                for a in artifacts
            ]}


def sign_manifest_bundle(manifest: Dict[str, Any]) -> Dict[str, Any]:
    """Allega firma Ed25519 al manifest (chiave dedicata in PKI_DIR).

    Senza chiave manifest (setup incompleto): bundle non firmato, gli agenti
    restano sull'HMAC e il report lo dichiara (mai downgrade silenzioso).
    """
    from app.services import pki as _pki
    import os as _os
    bundle = {"manifest": manifest, "ed25519": None, "signed": False}
    try:
        priv_path = _os.path.join(settings.PKI_DIR, _pki.MANIFEST_KEY)
        if not _os.path.exists(priv_path):
            return bundle
        key = _pki.load_manifest_private(priv_path)
        bundle["ed25519"] = _pki.sign_manifest(key, manifest)
        bundle["signed"] = True
    except Exception:
        pass
    return bundle


@router.get("/manifest")
async def get_manifest():
    """Manifest firmato degli artefatti pubblicati (materiale pubblico).

    Gli agenti con AEGIS_MANIFEST_PUBKEY verificano Ed25519 + copertura;
    gli altri restano sull'HMAC per-entry (dichiarato in `signed`).
    """
    from app.services import pki as _pki
    root = Path(settings.ARTIFACT_DIR)
    items = []
    if root.exists():
        for p in sorted(root.glob("*")):
            if p.is_file() and not p.name.startswith("."):
                items.append({"name": p.name, "sha256": sha256_file(p)})
    manifest = build_manifest(items)
    bundle = sign_manifest_bundle(manifest)
    try:
        import base64 as _b64
        pub_path = Path(settings.PKI_DIR) / _pki.MANIFEST_PUB
        bundle["pubkey_b64"] = _b64.b64encode(pub_path.read_bytes()).decode("ascii") \
            if pub_path.exists() else None
    except OSError:
        bundle["pubkey_b64"] = None
    return bundle


@router.get("/artifacts/{name}")
async def download_artifact(name: str, agent=Depends(get_current_agent)):
    """Serve artifact all'agente autenticato (l'update lo scarica da qui)."""
    safe = Path(name).name  # anti-traversal: solo basename
    if not safe or safe.startswith("."):
        raise HTTPException(status_code=400, detail="Invalid artifact name")
    path = Path(settings.ARTIFACT_DIR) / safe
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Artifact not found")
    return FileResponse(path, filename=safe)


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
    """Accoda UPDATE_AGENT firmato a un agente (o lo restituisce se la coda è giù).

    Il comando contiene url+sha256+HMAC così l'agente verifica prima di
    mettere in stage. Se Redis è giù, ritorna comunque il payload firmato
    (202) invece di 500 — l'operatore lo recapita via one-liner.
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
    if (agent.agent_type or "").lower() not in ("aegis-guard", "nodetrace", "guard"):
        raise HTTPException(status_code=400, detail="OTA supported for aegis-guard/nodetrace agents")

    atype = "aegis-guard" if "guard" in (agent.agent_type or "").lower() else "nodetrace"
    fname = artifact_name_for(atype, payload.version)
    path = Path(settings.ARTIFACT_DIR) / fname
    if not path.is_file():
        raise HTTPException(status_code=404, detail=f"Artifact {fname} not published in ARTIFACT_DIR")
    digest = sha256_file(path)
    sig = sign_artifact(digest)
    cmd = build_update_command(atype, payload.version, settings.PUBLIC_BASE_URL, digest, sig)
    # Manifest firmato (M6 Fase 7): l'agente con pubkey verifica Ed25519 +
    # copertura; gli altri restano sull'HMAC (dichiarato, mai silenzioso).
    # Fase 5: in pilot/enterprise Ed25519 è obbligatorio, HMAC solo per lab
    # con warning esplicito, mai downgrade silenzioso.
    bundle = sign_manifest_bundle(build_manifest([{"name": fname, "sha256": digest}]))
    if settings.ENTERPRISE_STRICT and not bundle["signed"]:
        raise HTTPException(status_code=500, detail="Manifest Ed25519 required in enterprise mode: run PKI bootstrap (pki --dir)")
    if bundle["signed"]:
        from app.services import pki as _pki2
        cmd["manifest"] = _pki2.canonical_manifest_bytes(bundle["manifest"]).decode("utf-8")
        cmd["manifest_sig"] = bundle["ed25519"]
    elif settings.ENTERPRISE_STRICT:
        # Già fallito sopra, ma per completezza logga il fallback
        import logging as _logging
        _logging.getLogger(__name__).warning("HMAC fallback in enterprise mode for %s — should not happen", fname)

    try:
        from app.services.telemetry_service import send_command_to_agent
        await send_command_to_agent(agent.agent_id, {**cmd, "alert_id": None})
        queued = True
    except Exception:
        queued = False
    await log_audit(
        db, action="deploy_update_push", resource="agent", resource_id=str(agent.agent_id),
        details={"version": payload.version, "artifact": fname, "sha256": digest,
                 "queued": queued, "manifest_signed": bundle["signed"]},
        user_id=user.id, username=user.username,
        ip_address=request.client.host if request else None,
    )
    await db.commit()
    return {"queued": queued, "status": 200 if queued else 202, "command": cmd,
            "agent_id": str(agent.agent_id),
            "note": "Agent verifies HMAC before staging. Restart applies (service wrapper)."} if queued else \
           {"queued": False, "status": 202, "command": cmd, "agent_id": str(agent.agent_id),
            "note": "Queue unavailable — deliver command manually. Signature still valid."}


# ─── deploy jobs (mass rollout, server-side, no password storage) ──

class DeployJobRequest(BaseModel):
    agent_type: str = Field(default="nodetrace", pattern="^(nodetrace|aegis-guard|unified)$")
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
