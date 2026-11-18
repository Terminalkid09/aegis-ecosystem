"""Operational views and fleet control for the Kraken UI.

This module deliberately does not proxy the Brain and does not execute lab
scenarios. It stores metadata, issues per-node credentials and signs the
desired sensor configuration. A revoked node loses access on its next request;
no key is ever returned after creation.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
import secrets
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, File, Header, HTTPException, Query, UploadFile, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.session import get_db
from app.models.models import (
    AnalysisJob, AttackEvent, Campaign, LabRun, MalwareSample, SensorNode, Topology,
)
from app.services.file_analysis import delete_stored_sample, run_analysis_job, store_upload
from app.api.v1.endpoints.deps import get_current_admin, get_current_user

router = APIRouter(prefix="/ops", tags=["Operations"])


class CampaignCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=128)
    description: str = Field("", max_length=4000)
    status: str = Field("active", pattern=r"^(active|archived)$")
    fingerprint: Optional[str] = Field(None, max_length=128)


class SensorCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=128)
    site: str = Field("default", pattern=r"^[a-z0-9][a-z0-9-]{0,63}$")
    config: Dict[str, Any] = Field(default_factory=dict)


class HeartbeatIn(BaseModel):
    applied_version: int = Field(0, ge=0)
    health: Dict[str, Any] = Field(default_factory=dict)


class TopologyCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=128)
    description: str = Field("", max_length=4000)
    spec: Dict[str, Any] = Field(default_factory=dict)


class LabRunCreate(BaseModel):
    scenario_id: str = Field(..., min_length=2, max_length=64)
    topology_id: Optional[int] = None
    mode: str = Field("shadow", pattern=r"^shadow$")


class LabRunFinish(BaseModel):
    status: str = Field("completed", pattern=r"^(completed|failed|aborted)$")
    evidence: Dict[str, Any] = Field(default_factory=dict)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _hash_key(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def _signing_key() -> bytes:
    raw = (settings.SENSOR_CONFIG_SIGNING_KEY or settings.SECRET_KEY or "").encode()
    if len(raw) < 32:
        raise HTTPException(status_code=503, detail="Sensor signing key is not configured")
    return raw


def signed_config(node: SensorNode) -> Dict[str, Any]:
    payload = {
        "node_id": node.node_id,
        "version": int(node.config_version or 1),
        "config": node.config or {},
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    signature = hmac.new(_signing_key(), encoded, hashlib.sha256).hexdigest()
    return {**payload, "signature": signature}


def _node_out(node: SensorNode) -> Dict[str, Any]:
    return {
        "node_id": node.node_id,
        "name": node.name,
        "site": node.site,
        "status": node.status,
        "config_version": node.config_version,
        "applied_version": node.applied_version,
        "last_seen": node.last_seen.isoformat() if node.last_seen else None,
        "revoked": node.revoked_at is not None,
        "config": node.config or {},
    }


async def _node_or_404(db: AsyncSession, node_id: str) -> SensorNode:
    node = (await db.execute(select(SensorNode).where(SensorNode.node_id == node_id))).scalars().first()
    if node is None:
        raise HTTPException(status_code=404, detail="Sensor node not found")
    return node


async def _authenticate_node(node: SensorNode, raw_key: str) -> None:
    if node.revoked_at is not None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Sensor node revoked")
    if not raw_key or not hmac.compare_digest(_hash_key(raw_key), node.key_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid sensor key")


@router.get("/summary")
async def summary(db: AsyncSession = Depends(get_db), _user=Depends(get_current_user)):
    async def count(model):
        return int((await db.execute(select(func.count()).select_from(model))).scalar() or 0)

    nodes = (await db.execute(select(SensorNode))).scalars().all()
    return {
        "campaigns": await count(Campaign),
        "sensor_nodes": len(nodes),
        "sensor_nodes_online": len([n for n in nodes if n.status == "online"]),
        "sensor_nodes_revoked": len([n for n in nodes if n.revoked_at is not None]),
        "topologies": await count(Topology),
        "lab_runs": await count(LabRun),
        "samples": await count(MalwareSample),
        "analysis_jobs": await count(AnalysisJob),
    }


def _job_out(job: AnalysisJob) -> Dict[str, Any]:
    return {
        "job_id": job.job_id, "sha256": job.sha256, "filename": job.filename,
        "size": job.size, "status": job.status, "report": job.report or {},
        "error": job.error,
        "created_at": job.created_at.isoformat() if job.created_at else None,
        "finished_at": job.finished_at.isoformat() if job.finished_at else None,
    }


@router.post("/analysis-jobs", status_code=202)
async def create_analysis_job(
    file: UploadFile = File(...), db: AsyncSession = Depends(get_db),
    _admin=Depends(get_current_admin),
):
    if not settings.FILE_ANALYSIS_ENABLED:
        raise HTTPException(status_code=503, detail="File analysis is disabled")
    try:
        path, sha, size = await store_upload(file)
    except ValueError as exc:
        raise HTTPException(status_code=413, detail=str(exc))
    job = AnalysisJob(
        job_id=f"analysis-{uuid.uuid4().hex[:12]}", sha256=sha,
        filename=(file.filename or "upload.bin")[:255], size=size,
        storage_path=path, status="queued", report={},
    )
    db.add(job)
    await db.commit()
    await db.refresh(job)
    # Analysis runs after the response, in a task with its own DB session. It
    # has a timeout and never executes the sample.
    asyncio.create_task(run_analysis_job(job.job_id))
    return _job_out(job)


@router.get("/analysis-jobs")
async def list_analysis_jobs(db: AsyncSession = Depends(get_db), _user=Depends(get_current_user)):
    rows = (await db.execute(
        select(AnalysisJob).order_by(AnalysisJob.created_at.desc()).limit(200)
    )).scalars().all()
    return [_job_out(job) for job in rows]


@router.get("/analysis-jobs/{job_id}")
async def get_analysis_job(job_id: str, db: AsyncSession = Depends(get_db),
                           _user=Depends(get_current_user)):
    job = (await db.execute(
        select(AnalysisJob).where(AnalysisJob.job_id == job_id)
    )).scalars().first()
    if job is None:
        raise HTTPException(status_code=404, detail="Analysis job not found")
    return _job_out(job)


@router.delete("/analysis-jobs/{job_id}")
async def delete_analysis_job(job_id: str, db: AsyncSession = Depends(get_db),
                              _admin=Depends(get_current_admin)):
    job = (await db.execute(
        select(AnalysisJob).where(AnalysisJob.job_id == job_id)
    )).scalars().first()
    if job is None:
        raise HTTPException(status_code=404, detail="Analysis job not found")
    removed = delete_stored_sample(job.storage_path)
    if not removed:
        raise HTTPException(status_code=500, detail="Sample deletion could not be verified")
    job.storage_path = None
    job.status = "deleted"
    job.report = {"deleted": True}
    job.finished_at = _utcnow()
    await db.commit()
    return {"status": "deleted", "job_id": job.job_id, "verified": True}


@router.get("/campaigns")
async def list_campaigns(db: AsyncSession = Depends(get_db), _user=Depends(get_current_user)):
    rows = (await db.execute(select(Campaign).order_by(Campaign.created_at.desc()).limit(200))).scalars().all()
    return [{
        "id": row.id, "name": row.name, "description": row.description,
        "status": row.status, "fingerprint": row.fingerprint,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    } for row in rows]


@router.post("/campaigns", status_code=201)
async def create_campaign(payload: CampaignCreate, db: AsyncSession = Depends(get_db),
                          _admin=Depends(get_current_admin)):
    campaign = Campaign(**payload.model_dump())
    db.add(campaign)
    try:
        await db.commit()
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=409, detail="Campaign name already exists")
    await db.refresh(campaign)
    return {"id": campaign.id, "name": campaign.name, "status": campaign.status}


@router.get("/sensors")
async def list_sensors(db: AsyncSession = Depends(get_db), _user=Depends(get_current_user)):
    rows = (await db.execute(select(SensorNode).order_by(SensorNode.created_at.desc()).limit(500))).scalars().all()
    return [_node_out(node) for node in rows]


@router.post("/sensors", status_code=201)
async def create_sensor(payload: SensorCreate, db: AsyncSession = Depends(get_db),
                        _admin=Depends(get_current_admin)):
    raw_key = f"ks_{secrets.token_urlsafe(32)}"
    node = SensorNode(
        node_id=f"node-{uuid.uuid4().hex[:12]}",
        name=payload.name,
        site=payload.site,
        status="pending",
        key_hash=_hash_key(raw_key),
        config=payload.config,
        config_version=1,
    )
    db.add(node)
    await db.commit()
    await db.refresh(node)
    # Returned exactly once. The database only contains the hash.
    return {**_node_out(node), "sensor_key": raw_key}


@router.get("/sensors/{node_id}/config")
async def sensor_config(node_id: str, x_sensor_key: str = Header("", alias="X-Sensor-Key"),
                        db: AsyncSession = Depends(get_db)):
    node = await _node_or_404(db, node_id)
    await _authenticate_node(node, x_sensor_key)
    return signed_config(node)


@router.post("/sensors/{node_id}/heartbeat")
async def sensor_heartbeat(node_id: str, payload: HeartbeatIn,
                           x_sensor_key: str = Header("", alias="X-Sensor-Key"),
                           db: AsyncSession = Depends(get_db)):
    node = await _node_or_404(db, node_id)
    await _authenticate_node(node, x_sensor_key)
    node.last_seen = _utcnow()
    node.applied_version = payload.applied_version
    node.status = "online" if payload.applied_version >= node.config_version else "degraded"
    # Health is intentionally not persisted in a free-form column: the node
    # already has an explicit applied version and last_seen, which are the two
    # facts the UI needs to distinguish desired from applied.
    await db.commit()
    return {"status": node.status, "desired": signed_config(node),
            "applied_version": node.applied_version, "health": payload.health}


@router.post("/sensors/{node_id}/revoke")
async def revoke_sensor(node_id: str, db: AsyncSession = Depends(get_db),
                        _admin=Depends(get_current_admin)):
    node = await _node_or_404(db, node_id)
    node.revoked_at = _utcnow()
    node.status = "revoked"
    await db.commit()
    return {"status": "revoked", "node_id": node.node_id}


@router.get("/topologies")
async def list_topologies(db: AsyncSession = Depends(get_db), _user=Depends(get_current_user)):
    rows = (await db.execute(select(Topology).order_by(Topology.created_at.desc()).limit(200))).scalars().all()
    return [{
        "id": row.id, "name": row.name, "description": row.description,
        "spec": row.spec or {}, "active": row.active,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    } for row in rows]


@router.post("/topologies", status_code=201)
async def create_topology(payload: TopologyCreate, db: AsyncSession = Depends(get_db),
                          _admin=Depends(get_current_admin)):
    topology = Topology(**payload.model_dump(), active=True)
    db.add(topology)
    try:
        await db.commit()
    except Exception:
        await db.rollback()
        raise HTTPException(status_code=409, detail="Topology name already exists")
    await db.refresh(topology)
    return {"id": topology.id, "name": topology.name}


@router.get("/lab-runs")
async def list_lab_runs(db: AsyncSession = Depends(get_db), _user=Depends(get_current_user)):
    rows = (await db.execute(select(LabRun).order_by(LabRun.started_at.desc()).limit(200))).scalars().all()
    return [{
        "run_id": row.run_id, "scenario_id": row.scenario_id, "mode": row.mode,
        "status": row.status, "topology_id": row.topology_id, "evidence": row.evidence or {},
        "started_at": row.started_at.isoformat() if row.started_at else None,
        "finished_at": row.finished_at.isoformat() if row.finished_at else None,
    } for row in rows]


@router.post("/lab-runs", status_code=201)
async def create_lab_run(payload: LabRunCreate, db: AsyncSession = Depends(get_db),
                         _admin=Depends(get_current_admin)):
    if payload.topology_id is not None:
        topology = (await db.execute(select(Topology).where(Topology.id == payload.topology_id))).scalars().first()
        if topology is None:
            raise HTTPException(status_code=404, detail="Topology not found")
    run = LabRun(
        run_id=f"lab-{uuid.uuid4().hex[:12]}",
        topology_id=payload.topology_id,
        scenario_id=payload.scenario_id,
        mode="shadow",  # 4.2 ships shadow runs only; active mode is out of scope.
        status="running",
        evidence={},
    )
    db.add(run)
    await db.commit()
    await db.refresh(run)
    return {"run_id": run.run_id, "mode": run.mode, "status": run.status}


@router.post("/lab-runs/{run_id}/finish")
async def finish_lab_run(run_id: str, payload: LabRunFinish, db: AsyncSession = Depends(get_db),
                         _user=Depends(get_current_user)):
    run = (await db.execute(select(LabRun).where(LabRun.run_id == run_id))).scalars().first()
    if run is None:
        raise HTTPException(status_code=404, detail="Lab run not found")
    if run.mode != "shadow":
        raise HTTPException(status_code=409, detail="Only shadow runs can be finished here")
    run.status = payload.status
    run.evidence = payload.evidence
    run.finished_at = _utcnow()
    await db.commit()
    return {"run_id": run.run_id, "status": run.status}


@router.get("/samples")
async def list_samples(
    sha256: Optional[str] = Query(None, max_length=64),
    sensor_type: Optional[str] = Query(None, max_length=32),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: AsyncSession = Depends(get_db), _user=Depends(get_current_user),
):
    query = select(MalwareSample, AttackEvent.sensor_type).join(
        AttackEvent, AttackEvent.id == MalwareSample.event_id)
    if sha256:
        query = query.where(MalwareSample.sha256 == sha256)
    if sensor_type:
        query = query.where(AttackEvent.sensor_type == sensor_type)
    rows = (await db.execute(
        query.order_by(MalwareSample.timestamp.desc()).offset(offset).limit(limit)
    )).all()
    # `path` is deliberately absent: the Aegis UI and Kraken overview must not
    # expose a filesystem location of captured malware.
    return [{
        "id": sample.id, "event_id": sample.event_id, "filename": sample.filename,
        "sha256": sample.sha256, "size": sample.size, "sensor_type": sensor,
        "timestamp": sample.timestamp.isoformat() if sample.timestamp else None,
    } for sample, sensor in rows]
