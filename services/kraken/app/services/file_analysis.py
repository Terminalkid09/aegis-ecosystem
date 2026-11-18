"""Asynchronous static analysis for uploaded files and ZIP archives.

The sample is stored under Kraken's own data volume and never sent to Aegis.
There is no detonation, no network and no subprocess: the job reads bounded
bytes, lists ZIP members without extracting them, extracts indicators and
produces a low-confidence Sigma candidate with provenance. This keeps the 4.2
file-intelligence path useful without turning the Brain into a malware host.
"""
from __future__ import annotations

import asyncio
import hashlib
import os
import re
import tempfile
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

_IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.I)
_URL = re.compile(r"https?://[^\s\"'<>]{4,512}", re.I)
_SHA256 = re.compile(r"\b[a-f0-9]{64}\b", re.I)
_EMAIL = re.compile(r"\b[\w.+-]+@[\w.-]+\.[a-z]{2,24}\b", re.I)


def storage_dir() -> str:
    directory = settings.FILE_ANALYSIS_STORAGE_DIR or os.path.join(settings.DATA_DIR, "samples")
    os.makedirs(directory, exist_ok=True)
    return directory


async def store_upload(upload: UploadFile) -> tuple[str, str, int]:
    """Stream an upload to disk with a hard cap; return path, sha256 and size."""
    directory = storage_dir()
    handle = tempfile.NamedTemporaryFile(delete=False, dir=directory, prefix="upload-")
    digest = hashlib.sha256()
    size = 0
    try:
        while True:
            chunk = await upload.read(1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            if size > settings.FILE_ANALYSIS_MAX_BYTES:
                raise ValueError("file exceeds FILE_ANALYSIS_MAX_BYTES")
            digest.update(chunk)
            handle.write(chunk)
        handle.close()
        sha = digest.hexdigest()
        final_path = os.path.join(directory, sha)
        # Content-addressed storage: two uploads of the same bytes share one
        # object. The temporary file is removed by os.replace.
        os.replace(handle.name, final_path)
        return final_path, sha, size
    except Exception:
        handle.close()
        try:
            os.unlink(handle.name)
        except OSError:
            pass
        raise


def delete_stored_sample(path: Optional[str]) -> bool:
    """Delete an object only inside the analysis storage root; verify absence."""
    if not path:
        return True
    root = os.path.realpath(storage_dir())
    target = os.path.realpath(path)
    if os.path.commonpath([root, target]) != root:
        return False
    try:
        os.unlink(target)
    except FileNotFoundError:
        return True
    except OSError as exc:
        logger.warning("Sample delete failed: %s", exc)
        return False
    return not os.path.exists(target)


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
        # Avoid classifying every dotted token as a domain.
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
    """Pure, bounded analysis function (called in a worker thread)."""
    st = os.stat(path)
    with open(path, "rb") as handle:
        raw = handle.read(settings.FILE_ANALYSIS_MAX_BYTES + 1)
    indicators = _indicators(raw)
    return {
        "filename": filename[:255],
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size": st.st_size,
        "zip_entries": _zip_manifest(path),
        "iocs": indicators,
        "process_tree": [],
        "dns_history": [],
        "candidate_sigma": _candidate_sigma(hashlib.sha256(raw).hexdigest(),
                                            filename, indicators),
        "confidence": "low",
        "provenance": "static-only; no execution, network or sandbox detonation",
        "analyzed_at": datetime.now(timezone.utc).isoformat(),
    }


async def run_analysis_job(job_id: str, session_factory=AsyncSessionLocal) -> None:
    async with session_factory() as db:
        job = (await db.execute(
            select(AnalysisJob).where(AnalysisJob.job_id == job_id)
        )).scalars().first()
        if job is None:
            return
        if not settings.FILE_ANALYSIS_ENABLED:
            job.status = "failed"
            job.error = "file analysis is disabled by FILE_ANALYSIS_ENABLED"
            job.finished_at = datetime.now(timezone.utc)
            await db.commit()
            return
        job.status = "running"
        await db.commit()
        if not job.storage_path or not os.path.exists(job.storage_path):
            job.status = "failed"
            job.error = "stored sample is missing"
            job.finished_at = datetime.now(timezone.utc)
            await db.commit()
            return
        try:
            report = await asyncio.wait_for(
                asyncio.to_thread(analyze_sample, job.storage_path, job.filename),
                timeout=settings.FILE_ANALYSIS_TIMEOUT_S,
            )
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
