"""Asynchronous file intelligence for uploaded files and ZIP archives.

Static analysis is always bounded and local. Samples are stored through the
object-store abstraction (local volume or S3/MinIO), and each job has its own
key. A background worker claims queued/running jobs with a Redis lease, so a
process restart does not leave a job stranded. An optional external detonator
can add process tree and DNS history; without it the report says static-only.
"""
from __future__ import annotations

import asyncio
import hashlib
import os
import re
import uuid
import zipfile
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from fastapi import UploadFile
from loguru import logger
from sqlalchemy import select

from app.core.config import settings
from app.db.session import AsyncSessionLocal
from app.models.models import AnalysisJob
from app.services import object_store
from app.services.detonation import DetonationError, detonate_sample

_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.I)
_URL = re.compile(r"https?://[^\s\"'<>]{4,512}", re.I)
_SHA256 = re.compile(r"\b[a-f0-9]{64}\b", re.I)
_EMAIL = re.compile(r"\b[\w.+-]+@[\w.-]+\.[a-z]{2,24}\b", re.I)

_STATIC_LIMITATION = (
    "static-only: no process tree or DNS history; configure DETONATION_URL "
    "to import behaviour from an isolated detonator"
)


def storage_dir() -> str:
    return object_store.local_root()


async def store_upload(upload: UploadFile, job_id: Optional[str] = None) -> tuple[str, str, int]:
    return await object_store.store_upload(upload, job_id or uuid.uuid4().hex)


async def delete_stored_sample(path: Optional[str]) -> bool:
    return await object_store.delete_stored_sample(path)


def _indicators(raw: bytes) -> Dict[str, list[str]]:
    text = "\n".join(
        part.decode("utf-8", "replace")
        for part in re.findall(rb"[ -~]{4,}", raw[:8 * 1024 * 1024])[:20000]
    )
    values: Dict[str, set[str]] = {"ips": set(), "domains": set(), "urls": set(),
                                   "sha256": set(), "emails": set()}
    for match in _IP.findall(text):
        values["ips"].add(match)
    for match in _DOMAIN.findall(text):
        if match.lower().endswith((".exe", ".dll", ".bin", ".txt", ".csv", ".zip")):
            continue
        values["domains"].add(match)
    for match in _URL.findall(text):
        values["urls"].add(match)
    for match in _SHA256.findall(text):
        values["sha256"].add(match.lower())
    for match in _EMAIL.findall(text):
        values["emails"].add(match)
    return {key: sorted(items)[:200] for key, items in values.items()}


def _zip_manifest(path: str) -> list[dict[str, Any]]:
    if not zipfile.is_zipfile(path):
        return []
    entries: list[dict[str, Any]] = []
    total = 0
    try:
        with zipfile.ZipFile(path) as archive:
            for info in archive.infolist()[:500]:
                name = os.path.normpath(info.filename)
                if name.startswith("..") or os.path.isabs(name):
                    continue
                total += max(0, int(info.file_size or 0))
                if total > settings.MALWARE_MAX_SESSION_BYTES:
                    break
                entries.append({"name": name[:512], "size": int(info.file_size or 0),
                                "compressed_size": int(info.compress_size or 0)})
    except (OSError, zipfile.BadZipFile):
        return []
    return entries


def _candidate_sigma(sha: str, filename: str, indicators: Dict[str, list[str]]) -> str:
    safe_name = re.sub(r"[^A-Za-z0-9._-]", "_", filename or "sample")[:80]
    domains = indicators.get("domains", [])[:5]
    lines = [
        "title: Kraken candidate file indicator",
        f"id: kraken-candidate-{sha[:12]}",
        "status: experimental",
        "description: Generated from bounded static analysis; requires analyst review.",
        "logsource:",
        "  product: kraken",
        "detection:",
        "  selection:",
        f"    file_name|endswith: \"{safe_name}\"",
    ]
    if domains:
        lines += ["  network:", "    dst_domain|contains:"]
        lines += [f"      - \"{domain}\"" for domain in domains]
        lines += ["  condition: selection or network"]
    else:
        lines += ["  condition: selection"]
    lines += [
        "falsepositives:",
        "  - Legitimate file with the same name",
        "level: low",
        "tags:",
        "  - attack.t1204",
    ]
    return "\n".join(lines) + "\n"


def analyze_sample(path: str, filename: str) -> Dict[str, Any]:
    """Pure, bounded static analysis. Never executes the sample."""
    st = os.stat(path)
    with open(path, "rb") as handle:
        raw = handle.read(settings.FILE_ANALYSIS_MAX_BYTES + 1)
    indicators = _indicators(raw)
    sha = hashlib.sha256(raw).hexdigest()
    return {
        "filename": filename[:255],
        "sha256": sha,
        "size": st.st_size,
        "zip_entries": _zip_manifest(path),
        "iocs": indicators,
        "process_tree": [],
        "dns_history": [],
        "candidate_sigma": _candidate_sigma(sha, filename, indicators),
        "confidence": "low",
        "provenance": "static-only; no execution, network or sandbox detonation",
        "limitations": [_STATIC_LIMITATION],
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
    }


def _merge_iocs(base: Dict[str, list[str]], extra: Dict[str, Any]) -> Dict[str, list[str]]:
    merged = {key: set(base.get(key) or []) for key in ("ips", "domains", "urls", "sha256", "emails")}
    for key in merged:
        values = extra.get(key) if isinstance(extra, dict) else None
        if isinstance(values, list):
            merged[key].update(str(value)[:512] for value in values if str(value).strip())
    return {key: sorted(values)[:200] for key, values in merged.items()}


def _merge_detonation(report: Dict[str, Any], detonation: Dict[str, Any]) -> Dict[str, Any]:
    report["process_tree"] = detonation.get("process_tree") or []
    report["dns_history"] = detonation.get("dns_history") or []
    report["iocs"] = _merge_iocs(report.get("iocs") or {}, detonation.get("iocs") or {})
    report["mitre"] = detonation.get("mitre") or []
    report["behavior"] = detonation.get("behavior") or []
    report["detonation"] = {
        "status": detonation.get("status"),
        "verdict": detonation.get("verdict"),
        "score": detonation.get("score"),
        "provenance": detonation.get("provenance"),
    }
    report["provenance"] = "static+detonation:http"
    report["confidence"] = "medium" if detonation.get("verdict") in ("malicious", "suspicious") else "low"
    report["limitations"] = []
    return report


async def _get_lock_client():
    try:
        from app.db.redis import get_redis
        return await get_redis()
    except Exception:
        return None


async def run_analysis_job(
    job_id: str,
    session_factory=AsyncSessionLocal,
    lock_client=None,
) -> bool:
    """Run one job under a Redis lease. False means another worker owns it."""
    lock = lock_client if lock_client is not None else await _get_lock_client()
    lock_key = f"kraken:analysis:lock:{job_id}"
    acquired = False
    if lock is not None:
        try:
            # The lease must outlive static analysis *and* the optional
            # detonator, otherwise a second worker can claim the same job
            # while the first is still waiting for a 120 s detonation.
            lease = int(settings.FILE_ANALYSIS_TIMEOUT_S) + 30
            if settings.DETONATION_ENABLED:
                lease += int(settings.DETONATION_TIMEOUT_S)
            acquired = bool(await lock.set(lock_key, "1", nx=True, ex=max(60, lease)))
        except Exception:
            acquired = False
        if not acquired:
            return False
    try:
        async with session_factory() as db:
            job = (await db.execute(
                select(AnalysisJob).where(AnalysisJob.job_id == job_id)
            )).scalars().first()
            if job is None or job.status == "deleted" or job.status == "completed":
                return True
            if not settings.FILE_ANALYSIS_ENABLED:
                job.status = "failed"
                job.error = "file analysis is disabled by FILE_ANALYSIS_ENABLED"
                job.finished_at = datetime.now(timezone.utc)
                await db.commit()
                return True
            job.status = "running"
            await db.commit()
            if not job.storage_path:
                job.status = "failed"
                job.error = "stored sample is missing"
                job.finished_at = datetime.now(timezone.utc)
                await db.commit()
                return True
            try:
                async with object_store.materialize(job.storage_path) as local_path:
                    report = await asyncio.wait_for(
                        asyncio.to_thread(analyze_sample, local_path, job.filename),
                        timeout=settings.FILE_ANALYSIS_TIMEOUT_S,
                    )
                    if settings.DETONATION_ENABLED:
                        try:
                            detonation = await detonate_sample(
                                local_path, job.filename, report["sha256"]
                            )
                            if detonation.get("status") == "completed":
                                _merge_detonation(report, detonation)
                            else:
                                report["detonation"] = detonation
                                report["limitations"] = [
                                    f"static-only: detonation {detonation.get('status')}"
                                ]
                        except DetonationError as exc:
                            logger.warning("Detonation failed for %s: %s", job_id, exc)
                            report["detonation"] = {"status": "failed", "reason": str(exc)[:500]}
                            report["limitations"] = [f"static-only: detonation failed: {exc}"]
                    else:
                        report["detonation"] = {"status": "disabled"}
                job.report = report
                job.status = "completed"
                job.error = None
            except asyncio.TimeoutError:
                job.status = "failed"
                job.error = "analysis timeout"
            except Exception as exc:
                logger.exception("File analysis failed for %s", job_id)
                job.status = "failed"
                job.error = str(exc)[:500]
            job.finished_at = datetime.now(timezone.utc)
            await db.commit()
        return True
    finally:
        if acquired and lock is not None:
            try:
                await lock.delete(lock_key)
            except Exception:
                pass


async def recover_pending_analysis_jobs(
    session_factory=AsyncSessionLocal,
    lock_client=None,
    limit: int = 20,
    skip_ids: Optional[set[str]] = None,
) -> list[tuple[str, asyncio.Task]]:
    """Schedule queued and previously-running jobs; the Redis lease deduplicates."""
    async with session_factory() as db:
        rows = (await db.execute(
            select(AnalysisJob.job_id)
            .where(AnalysisJob.status.in_(("queued", "running")))
            .order_by(AnalysisJob.created_at)
            .limit(max(1, int(limit)))
        )).scalars().all()
    skip = skip_ids or set()
    tasks: list[tuple[str, asyncio.Task]] = []
    for job_id in rows:
        if job_id in skip:
            continue
        task = asyncio.create_task(
            run_analysis_job(job_id, session_factory, lock_client),
            name=f"analysis:{job_id}",
        )
        tasks.append((job_id, task))
    return tasks


async def analysis_worker_loop(
    stop_event: asyncio.Event,
    session_factory=AsyncSessionLocal,
    interval: Optional[float] = None,
) -> None:
    """Poll the database and keep one in-process task per job.

    The DB row is the durable queue; Redis is only the cross-process lease.
    A crash loses the task, not the job: the next process finds it in `queued`
    or `running` and retries it.
    """
    in_flight: set[str] = set()
    pause = max(0.1, float(interval if interval is not None else settings.FILE_ANALYSIS_POLL_INTERVAL_S))
    while not stop_event.is_set():
        try:
            scheduled = await recover_pending_analysis_jobs(
                session_factory=session_factory, skip_ids=set(in_flight)
            )
            for job_id, task in scheduled:
                in_flight.add(job_id)
                task.add_done_callback(lambda _t, jid=job_id: in_flight.discard(jid))
        except Exception:
            logger.exception("Analysis recovery loop failed")
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=pause)
        except asyncio.TimeoutError:
            pass
