"""Optional sandbox detonation adapter.

Kraken never executes an uploaded sample inside the web process. When an
operator configures an isolated detonation worker, this module sends the sample
over HTTP and imports only a bounded, validated behaviour report. Without a
worker the analysis remains static and the report explicitly says so.
"""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, Dict

import httpx
from loguru import logger

from app.core.config import settings

_MAX_ITEMS = 200
_MAX_ITEM_BYTES = 4096


class DetonationError(RuntimeError):
    pass


def _bounded_items(value: Any, max_items: int = _MAX_ITEMS) -> list[Any]:
    if not isinstance(value, list):
        return []
    out: list[Any] = []
    for item in value[:max_items]:
        try:
            if len(json.dumps(item, default=str).encode("utf-8")) <= _MAX_ITEM_BYTES:
                out.append(item)
        except Exception:
            continue
    return out


def normalize_report(payload: Dict[str, Any], expected_sha: str) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        raise DetonationError("detonation response is not a JSON object")
    reported_sha = str(payload.get("sha256") or "").lower()
    if reported_sha and reported_sha != expected_sha.lower():
        raise DetonationError("detonation response SHA-256 does not match the sample")
    iocs = payload.get("iocs") if isinstance(payload.get("iocs"), dict) else {}
    clean_iocs: Dict[str, list[str]] = {}
    for key in ("ips", "domains", "urls", "sha256", "emails"):
        values = iocs.get(key) if isinstance(iocs.get(key), list) else []
        clean_iocs[key] = sorted({str(v)[:512] for v in values if str(v).strip()})[:200]
    return {
        "status": "completed",
        "sha256": expected_sha,
        "process_tree": _bounded_items(payload.get("process_tree")),
        "dns_history": _bounded_items(payload.get("dns_history")),
        "iocs": clean_iocs,
        "mitre": _bounded_items(payload.get("mitre"), max_items=50),
        "behavior": _bounded_items(payload.get("behavior"), max_items=100),
        "verdict": str(payload.get("verdict") or "unknown")[:64],
        "score": int(payload.get("score") or 0),
        "provenance": "detonation:http",
    }


async def detonate_sample(path: str, filename: str, sha256: str) -> Dict[str, Any]:
    if not settings.DETONATION_ENABLED:
        return {
            "status": "disabled",
            "reason": "DETONATION_ENABLED is false",
        }
    if not settings.DETONATION_URL:
        return {
            "status": "not_configured",
            "reason": "DETONATION_URL is empty",
        }
    raw = await asyncio.to_thread(Path(path).read_bytes)
    if len(raw) > settings.FILE_ANALYSIS_MAX_BYTES:
        raise DetonationError("sample exceeds the detonation size limit")
    headers = {}
    if settings.DETONATION_TOKEN:
        headers["Authorization"] = f"Bearer {settings.DETONATION_TOKEN}"
    try:
        async with httpx.AsyncClient(
            timeout=settings.DETONATION_TIMEOUT_S, follow_redirects=False
        ) as client:
            response = await client.post(
                settings.DETONATION_URL,
                headers=headers,
                data={"sha256": sha256},
                files={"file": (filename[:255] or "sample.bin", raw,
                                "application/octet-stream")},
            )
    except (httpx.HTTPError, OSError) as exc:
        raise DetonationError(f"detonation request failed: {exc}") from exc
    if response.status_code < 200 or response.status_code >= 300:
        raise DetonationError(f"detonation returned HTTP {response.status_code}")
    try:
        payload = response.json()
    except Exception as exc:
        raise DetonationError("detonation response is not JSON") from exc
    return normalize_report(payload, sha256)
