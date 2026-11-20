"""Signed YARA feed ingestion.

This is deliberately a *feed*, not a downloader that executes arbitrary
content. A bundle is accepted only when:

1. the URL is HTTPS (or explicit localhost HTTP for lab tests);
2. the exact response body has a valid Ed25519 signature from the configured
   public key;
3. the JSON has the documented `aegis-yara-feed/v1` shape;
4. every rule compiles with the local YARA engine;
5. no rule name collides with a manual rule or another feed.

A failed check changes nothing in the database. The last error is recorded in
`yara_feed_state`, so the UI can show "feed unreachable / bad signature" while
the previously imported rules keep protecting the fleet.

The feed server is operator-owned. Aegis does not ship a vendor rule feed or
silently pull rules from GitHub: the key and URL are deployment decisions.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import log_audit
from app.core.config import settings
from app.core.logging import get_logger
from app.database.connection import AsyncSessionLocal, engine
from app.database.models import YaraFeedState, YaraRule
from app.services import yara_engine

logger = get_logger(__name__)

FEED_FORMAT = "aegis-yara-feed/v1"
SIGNATURE_HEADER = "X-Aegis-Signature"
KEY_ID_HEADER = "X-Aegis-Key-Id"
MAX_RULES_PER_BUNDLE = 5000
MAX_RULE_CONTENT = 64 * 1024
MAX_DESCRIPTION = 1000
SEVERITIES = ("low", "medium", "high", "critical")
_FEED_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_RULE_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_MITRE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_YARA_LOCK_KEY = 0x59415241  # "YARA"
_task: Optional[asyncio.Task] = None


class FeedError(Exception):
    """A feed was rejected; the message is safe to show to an operator."""


@dataclass(frozen=True)
class FeedRule:
    name: str
    content: str
    severity: str
    description: Optional[str]
    tags: Tuple[str, ...]
    mitre: Optional[str]


@dataclass(frozen=True)
class FeedBundle:
    feed_id: str
    version: str
    rules: Tuple[FeedRule, ...]


@dataclass(frozen=True)
class FetchedFeed:
    body: bytes
    signature: str
    etag: Optional[str]
    last_modified: Optional[str]
    key_id: Optional[str]


def configured_feeds() -> List[str]:
    """Configured URLs, in order, without duplicates."""
    seen = set()
    out: List[str] = []
    for raw in (settings.YARA_FEED_URLS or "").split(","):
        url = raw.strip()
        if url and url not in seen:
            seen.add(url)
            out.append(url)
    return out


def redact_url(url: str) -> str:
    """Status/UI form: never expose userinfo, query tokens or fragments."""
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        if parts.port:
            host = f"{host}:{parts.port}"
        return f"{parts.scheme}://{host}{parts.path}"
    except Exception:
        return "(invalid-url)"


def validate_feed_url(url: str) -> None:
    if not url or len(url) > 2048:
        raise FeedError("feed URL missing or too long")
    try:
        parts = urlsplit(url)
    except Exception as exc:
        raise FeedError("feed URL is not valid") from exc
    if parts.username or parts.password:
        raise FeedError("feed URL must not contain credentials")
    if parts.fragment:
        raise FeedError("feed URL must not contain a fragment")
    if not parts.hostname:
        raise FeedError("feed URL has no host")
    if parts.scheme == "https":
        return
    loopback = parts.hostname.lower() in {"localhost", "127.0.0.1", "::1"}
    if parts.scheme == "http" and settings.YARA_FEED_ALLOW_HTTP and loopback:
        return
    raise FeedError("feed URL must use HTTPS (HTTP is allowed only for explicit localhost tests)")


def _public_key() -> Ed25519PublicKey:
    raw = (settings.YARA_FEED_PUBLIC_KEY_B64 or "").strip()
    if not raw:
        raise FeedError("YARA feed public key is not configured")
    try:
        key = base64.b64decode(raw, validate=True)
    except Exception as exc:
        raise FeedError("YARA feed public key is not valid base64") from exc
    if len(key) != 32:
        raise FeedError("YARA feed public key must be 32 bytes")
    return Ed25519PublicKey.from_public_bytes(key)


def key_fingerprint() -> Optional[str]:
    """Stable short fingerprint for operator correlation; never the key."""
    raw = (settings.YARA_FEED_PUBLIC_KEY_B64 or "").strip()
    if not raw:
        return None
    try:
        key = base64.b64decode(raw, validate=True)
    except Exception:
        return None
    return hashlib.sha256(key).hexdigest()[:16]


def verify_bundle(body: bytes, signature_b64: str) -> None:
    if not signature_b64:
        raise FeedError("feed signature missing")
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except Exception as exc:
        raise FeedError("feed signature is not valid base64") from exc
    if len(signature) != 64:
        raise FeedError("feed signature must be 64 bytes")
    try:
        _public_key().verify(signature, body)
    except InvalidSignature as exc:
        raise FeedError("feed signature verification failed") from exc
    except FeedError:
        raise
    except Exception as exc:
        raise FeedError(f"feed signature verification failed: {exc}") from exc


def _clean_text(value: Any, field: str, limit: int) -> Optional[str]:
    if value is None:
        return None
    if not isinstance(value, str):
        raise FeedError(f"rule {field} must be a string")
    value = value.strip()
    if len(value) > limit:
        raise FeedError(f"rule {field} exceeds {limit} characters")
    return value or None


def _parse_rule(raw: Any, index: int) -> FeedRule:
    if not isinstance(raw, dict):
        raise FeedError(f"rule #{index + 1} is not an object")
    name = _clean_text(raw.get("name"), "name", 128)
    if not name or not _RULE_NAME_RE.fullmatch(name):
        raise FeedError(f"rule #{index + 1} has an invalid name")
    content = raw.get("content")
    if not isinstance(content, str) or not content.strip():
        raise FeedError(f"rule {name}: content missing")
    if len(content.encode("utf-8")) > MAX_RULE_CONTENT:
        raise FeedError(f"rule {name}: content exceeds {MAX_RULE_CONTENT} bytes")
    if not any(token in content for token in ("rule ", "private rule ", "global rule ")):
        raise FeedError(f"rule {name}: content does not look like a YARA rule")
    severity = str(raw.get("severity") or "high").strip().lower()
    if severity not in SEVERITIES:
        raise FeedError(f"rule {name}: severity must be one of {', '.join(SEVERITIES)}")
    description = _clean_text(raw.get("description"), "description", MAX_DESCRIPTION)
    tags_raw = raw.get("tags") or []
    if not isinstance(tags_raw, list) or len(tags_raw) > 20:
        raise FeedError(f"rule {name}: tags must be a list of at most 20 strings")
    tags: List[str] = []
    for tag in tags_raw:
        if not isinstance(tag, str) or len(tag.strip()) > 64:
            raise FeedError(f"rule {name}: invalid tag")
        cleaned = tag.strip()
        if cleaned and cleaned not in tags:
            tags.append(cleaned)
    mitre = _clean_text(raw.get("mitre"), "mitre", 20)
    if mitre and not _MITRE_RE.fullmatch(mitre):
        raise FeedError(f"rule {name}: mitre must look like T1234 or T1234.001")
    return FeedRule(
        name=name,
        content=content,
        severity=severity,
        description=description,
        tags=tuple(tags),
        mitre=mitre,
    )


def parse_bundle(body: bytes) -> FeedBundle:
    try:
        payload = json.loads(body.decode("utf-8"))
    except Exception as exc:
        raise FeedError("feed body is not valid UTF-8 JSON") from exc
    if not isinstance(payload, dict):
        raise FeedError("feed body must be a JSON object")
    if payload.get("format") != FEED_FORMAT:
        raise FeedError(f"feed format must be {FEED_FORMAT}")
    feed_id = str(payload.get("feed_id") or "").strip()
    if not _FEED_ID_RE.fullmatch(feed_id):
        raise FeedError("feed_id is missing or invalid")
    version = _clean_text(payload.get("version"), "version", 100)
    if not version:
        raise FeedError("feed version is missing")
    raw_rules = payload.get("rules")
    if not isinstance(raw_rules, list) or not raw_rules:
        raise FeedError("feed must contain at least one rule")
    if len(raw_rules) > MAX_RULES_PER_BUNDLE:
        raise FeedError(f"feed contains more than {MAX_RULES_PER_BUNDLE} rules")

    rules: List[FeedRule] = []
    names = set()
    for index, raw_rule in enumerate(raw_rules):
        rule = _parse_rule(raw_rule, index)
        if rule.name in names:
            raise FeedError(f"duplicate rule name in feed: {rule.name}")
        names.add(rule.name)
        rules.append(rule)

    if not yara_engine.YARA_AVAILABLE:
        raise FeedError(
            "yara-python is not available in this Brain; refusing to import an unvalidated feed"
        )
    compiled, errors = yara_engine.compile_rules([(r.name, r.content) for r in rules])
    if errors:
        detail = "; ".join(f"{e['rule']}: {e['error'][:120]}" for e in errors[:5])
        raise FeedError(f"feed contains invalid YARA rules: {detail}")
    if len(compiled) != len(rules):
        raise FeedError("not all feed rules compiled; refusing a partial import")
    return FeedBundle(feed_id=feed_id, version=version, rules=tuple(rules))


async def fetch_bundle(url: str) -> FetchedFeed:
    validate_feed_url(url)
    timeout = httpx.Timeout(settings.YARA_FEED_TIMEOUT_S)
    headers = {
        "Accept": "application/json",
        "User-Agent": "Aegis-Brain/YARA-Feed",
    }
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=False) as client:
            response = await client.get(url, headers=headers)
    except Exception as exc:
        raise FeedError(f"feed fetch failed: {exc}") from exc
    if response.status_code != 200:
        raise FeedError(f"feed returned HTTP {response.status_code}")
    declared = response.headers.get("content-length")
    if declared:
        try:
            if int(declared) > settings.YARA_FEED_MAX_BYTES:
                raise FeedError("feed body exceeds YARA_FEED_MAX_BYTES")
        except ValueError:
            pass
    body = response.content
    if len(body) > settings.YARA_FEED_MAX_BYTES:
        raise FeedError("feed body exceeds YARA_FEED_MAX_BYTES")
    signature = response.headers.get(SIGNATURE_HEADER, "")
    key_id = response.headers.get(KEY_ID_HEADER) or None
    if settings.YARA_FEED_KEY_ID and key_id and key_id != settings.YARA_FEED_KEY_ID:
        raise FeedError("feed key_id does not match YARA_FEED_KEY_ID")
    verify_bundle(body, signature)
    return FetchedFeed(
        body=body,
        signature=signature,
        etag=response.headers.get("etag"),
        last_modified=response.headers.get("last-modified"),
        key_id=key_id,
    )


async def _state_for(db: AsyncSession, url: str) -> YaraFeedState:
    state = (await db.execute(select(YaraFeedState).where(YaraFeedState.url == url))).scalars().first()
    if state is None:
        state = YaraFeedState(url=url, rules_count=0)
        db.add(state)
        await db.flush()
    return state


async def _record_failure(db: AsyncSession, url: str, error: str, now: datetime) -> None:
    state = await _state_for(db, url)
    state.last_checked_at = now
    state.last_error = error[:2000]
    await db.commit()


async def sync_one(
    db: AsyncSession,
    url: str,
    body: bytes,
    signature: str,
    *,
    key_id: Optional[str] = None,
    etag: Optional[str] = None,
    last_modified: Optional[str] = None,
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Verify and atomically upsert one signed bundle.

    This function is intentionally usable from tests without a network call:
    the body/signature are supplied by the caller.
    """
    validate_feed_url(url)
    verify_bundle(body, signature)
    if settings.YARA_FEED_KEY_ID and key_id and key_id != settings.YARA_FEED_KEY_ID:
        raise FeedError("feed key_id does not match YARA_FEED_KEY_ID")
    bundle = parse_bundle(body)
    stamp = now or datetime.now(timezone.utc)
    source = f"feed:{bundle.feed_id}"
    names = [r.name for r in bundle.rules]

    # Read all matching names before changing anything. A feed must never
    # overwrite a SOC rule that happens to have the same identifier.
    existing_by_name = {
        r.name: r
        for r in (await db.execute(select(YaraRule).where(YaraRule.name.in_(names)))).scalars().all()
    }
    for rule in bundle.rules:
        existing = existing_by_name.get(rule.name)
        if existing is not None and existing.source != source:
            raise FeedError(
                f"rule name collision: '{rule.name}' belongs to {existing.source!r}, not {source!r}"
            )

    existing_source = {
        r.name: r
        for r in (await db.execute(select(YaraRule).where(YaraRule.source == source))).scalars().all()
    }
    for rule in bundle.rules:
        row = existing_by_name.get(rule.name)
        checksum = hashlib.sha256(rule.content.encode("utf-8")).hexdigest()
        if row is None:
            row = YaraRule(
                name=rule.name,
                content=rule.content,
                is_active=True,
                severity=rule.severity,
                description=rule.description,
                tags=list(rule.tags),
                mitre_technique_id=rule.mitre,
                source=source,
                source_version=bundle.version,
                checksum=checksum,
                managed=True,
                last_synced_at=stamp,
            )
            db.add(row)
        else:
            row.content = rule.content
            row.severity = rule.severity
            row.description = rule.description
            row.tags = list(rule.tags)
            row.mitre_technique_id = rule.mitre
            row.source_version = bundle.version
            row.checksum = checksum
            row.managed = True
            row.is_active = True
            row.last_synced_at = stamp

    # A rule removed from the feed is deactivated, not deleted: the previous
    # finding/audit evidence must remain attributable to a real rule row.
    removed = 0
    for name, row in existing_source.items():
        if name not in names and row.is_active:
            row.is_active = False
            row.last_synced_at = stamp
            removed += 1

    state = await _state_for(db, url)
    state.feed_id = bundle.feed_id
    state.key_id = key_id or settings.YARA_FEED_KEY_ID or state.key_id
    state.etag = etag or state.etag
    state.last_modified = last_modified or state.last_modified
    state.last_checked_at = stamp
    state.last_success_at = stamp
    state.last_error = None
    state.bundle_version = bundle.version
    state.rules_count = len(bundle.rules)

    await log_audit(
        db,
        action="yara_feed_sync",
        resource="yara_feed",
        resource_id=redact_url(url),
        details={
            "feed_id": bundle.feed_id,
            "version": bundle.version,
            "rules": len(bundle.rules),
            "removed": removed,
        },
        username="system",
    )
    await db.commit()
    logger.info(
        "YARA feed synchronized: %s version=%s rules=%d removed=%d",
        bundle.feed_id, bundle.version, len(bundle.rules), removed,
    )
    return {
        "ok": True,
        "url": redact_url(url),
        "feed_id": bundle.feed_id,
        "version": bundle.version,
        "rules": len(bundle.rules),
        "removed": removed,
    }


async def sync_all_feeds() -> Dict[str, Any]:
    if not settings.YARA_FEED_ENABLED:
        return {"enabled": False, "ok": False, "results": [], "note": "YARA feeds are disabled"}
    urls = configured_feeds()
    if not urls:
        return {"enabled": True, "ok": False, "results": [], "note": "no feed URL configured"}

    # Multiple uvicorn workers share the database. The advisory lock makes the
    # periodic sync single-flight; a skipped worker simply leaves the work to
    # the one holding the lock. SQLite (tests) has no advisory locks.
    lock_conn = None
    locked = True
    if engine.dialect.name == "postgresql":
        lock_conn = await engine.connect()
        try:
            got = (
                await lock_conn.execute(
                    text("SELECT pg_try_advisory_lock(:key)"), {"key": _YARA_LOCK_KEY}
                )
            ).scalar()
            await lock_conn.commit()
            locked = bool(got)
        except Exception:
            await lock_conn.close()
            raise
        if not locked:
            return {
                "enabled": True,
                "ok": False,
                "skipped": "another sync is running",
                "results": [],
            }

    results: List[Dict[str, Any]] = []
    try:
        for url in urls:
            try:
                fetched = await fetch_bundle(url)
                async with AsyncSessionLocal() as db:
                    result = await sync_one(
                        db,
                        url,
                        fetched.body,
                        fetched.signature,
                        key_id=fetched.key_id,
                        etag=fetched.etag,
                        last_modified=fetched.last_modified,
                    )
                results.append(result)
            except Exception as exc:
                message = str(exc)[:500]
                logger.warning("YARA feed sync failed for %s: %s", redact_url(url), message)
                try:
                    async with AsyncSessionLocal() as db:
                        await _record_failure(db, url, message, datetime.now(timezone.utc))
                except Exception as state_exc:
                    logger.warning("YARA feed failure state not recorded: %s", state_exc)
                results.append({"ok": False, "url": redact_url(url), "error": message})
    finally:
        if lock_conn is not None:
            try:
                await lock_conn.execute(
                    text("SELECT pg_advisory_unlock(:key)"), {"key": _YARA_LOCK_KEY}
                )
                await lock_conn.commit()
            finally:
                await lock_conn.close()

    ok = bool(results) and all(item.get("ok") for item in results)
    return {"enabled": True, "ok": ok, "results": results}


async def _scheduler_loop() -> None:
    # Do not race the first request/migration during startup.
    await asyncio.sleep(10)
    while True:
        try:
            await sync_all_feeds()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.warning("YARA feed scheduler error: %s", exc)
        await asyncio.sleep(max(int(settings.YARA_FEED_INTERVAL_S), 60))


async def start_yara_feed_task() -> None:
    global _task
    if not settings.YARA_FEED_ENABLED:
        return
    if _task is not None and not _task.done():
        return
    _task = asyncio.create_task(_scheduler_loop())
    logger.info("YARA feed scheduler started (interval=%ss)", settings.YARA_FEED_INTERVAL_S)


async def stop_yara_feed_task() -> None:
    global _task
    if _task is None:
        return
    _task.cancel()
    try:
        await _task
    except asyncio.CancelledError:
        pass
    finally:
        _task = None
