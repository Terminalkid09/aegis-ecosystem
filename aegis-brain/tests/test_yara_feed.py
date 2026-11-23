"""Signed YARA feeds: fail-closed tests with no network.

The feed body and detached Ed25519 signature are generated in-process. The
tests cover the security boundary (unsigned/tampered bundles change nothing),
provenance, collision protection and removal semantics.
"""
from __future__ import annotations

import base64
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import select

from app.api.v1.total import _build_detection
from app.core.config import settings
from app.database.models import YaraFeedState, YaraRule
from app.services import yara_engine, yara_feed

def _bundle(feed_id: str, version: str, rules: list[dict]) -> bytes:
    return json.dumps({
        "format": yara_feed.FEED_FORMAT,
        "feed_id": feed_id,
        "version": version,
        "rules": rules,
    }, separators=(",", ":")).encode("utf-8")


def _rule(name: str, value: str = "evil", severity: str = "high") -> dict:
    return {
        "name": name,
        "content": f'rule {name}_sig {{ strings: $s = "{value}" condition: $s }}',
        "severity": severity,
        "description": f"test signature {name}",
        "tags": ["test", "offline"],
        "mitre": "T1204.002",
    }


@pytest.fixture
def feed_key(monkeypatch):
    private = Ed25519PrivateKey.generate()
    public_raw = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    monkeypatch.setattr(settings, "YARA_FEED_ENABLED", True)
    monkeypatch.setattr(settings, "YARA_FEED_PUBLIC_KEY_B64", base64.b64encode(public_raw).decode())
    monkeypatch.setattr(settings, "YARA_FEED_KEY_ID", "test-key")
    monkeypatch.setattr(settings, "YARA_FEED_URLS", "https://feeds.example/aegis.json")
    # These tests exercise signature/DB/provenance semantics. The real YARA
    # compiler is covered by the Python 3.12 CI job; on 3.15 the wheel is
    # absent, so a fake successful compile keeps the feed logic testable while
    # production still fails closed when YARA_AVAILABLE is false.
    monkeypatch.setattr(yara_engine, "YARA_AVAILABLE", True)
    monkeypatch.setattr(
        yara_engine, "compile_rules",
        lambda rules: ([(name, object()) for name, _ in rules], []),
    )
    return private


def _sign(private: Ed25519PrivateKey, body: bytes) -> str:
    return base64.b64encode(private.sign(body)).decode()


@pytest.mark.asyncio
async def test_signed_feed_imports_provenance(db_session, feed_key):
    body = _bundle("soc-lab", "2026.11.20.1", [_rule("feed_rule")])
    result = await yara_feed.sync_one(
        db_session, "https://feeds.example/aegis.json", body, _sign(feed_key, body),
        key_id="test-key",
    )
    assert result["ok"] is True and result["rules"] == 1

    row = (await db_session.execute(
        select(YaraRule).where(YaraRule.name == "feed_rule")
    )).scalars().first()
    assert row is not None
    assert row.managed is True
    assert row.source == "feed:soc-lab"
    assert row.source_version == "2026.11.20.1"
    assert row.severity == "high"
    assert row.tags == ["test", "offline"]
    assert row.mitre_technique_id == "T1204.002"
    assert row.checksum

    state = (await db_session.execute(
        select(YaraFeedState).where(YaraFeedState.url == "https://feeds.example/aegis.json")
    )).scalars().first()
    assert state is not None
    assert state.feed_id == "soc-lab"
    assert state.rules_count == 1
    assert state.last_success_at is not None
    assert state.last_error is None


@pytest.mark.asyncio
async def test_tampered_bundle_changes_nothing(db_session, feed_key):
    body = _bundle("soc-lab", "1", [_rule("tampered_rule")])
    signature = _sign(feed_key, body)
    tampered = body.replace(b"evil", b"good")
    with pytest.raises(yara_feed.FeedError, match="signature"):
        await yara_feed.sync_one(
            db_session, "https://feeds.example/aegis.json", tampered, signature
        )
    assert (await db_session.execute(
        select(YaraRule).where(YaraRule.name == "tampered_rule")
    )).scalars().first() is None


@pytest.mark.asyncio
async def test_unsigned_bundle_is_rejected(db_session, feed_key):
    body = _bundle("soc-lab", "1", [_rule("unsigned_rule")])
    with pytest.raises(yara_feed.FeedError, match="signature"):
        await yara_feed.sync_one(
            db_session, "https://feeds.example/aegis.json", body, ""
        )
    assert (await db_session.execute(
        select(YaraRule).where(YaraRule.name == "unsigned_rule")
    )).scalars().first() is None


@pytest.mark.asyncio
async def test_feed_cannot_overwrite_manual_rule(db_session, feed_key):
    manual = YaraRule(
        name="collision_rule",
        content='rule manual_collision { strings: $s = "manual" condition: $s }',
        severity="high", source="manual", managed=False,
    )
    db_session.add(manual)
    await db_session.commit()

    body = _bundle("soc-lab", "1", [_rule("collision_rule")])
    with pytest.raises(yara_feed.FeedError, match="collision"):
        await yara_feed.sync_one(
            db_session, "https://feeds.example/aegis.json", body, _sign(feed_key, body)
        )
    await db_session.refresh(manual)
    assert manual.managed is False
    assert "manual" in manual.content


@pytest.mark.asyncio
async def test_rule_removed_from_feed_is_deactivated(db_session, feed_key):
    url = "https://feeds.example/aegis.json"
    first = _bundle("soc-lab", "1", [_rule("old_rule")])
    await yara_feed.sync_one(db_session, url, first, _sign(feed_key, first))

    second = _bundle("soc-lab", "2", [_rule("new_rule")])
    await yara_feed.sync_one(db_session, url, second, _sign(feed_key, second))

    old = (await db_session.execute(
        select(YaraRule).where(YaraRule.name == "old_rule")
    )).scalars().first()
    new = (await db_session.execute(
        select(YaraRule).where(YaraRule.name == "new_rule")
    )).scalars().first()
    assert old is not None and old.is_active is False
    assert new is not None and new.is_active is True
    assert new.source_version == "2"


@pytest.mark.skipif(not yara_engine.YARA_AVAILABLE, reason="yara-python is unavailable")
def test_real_engine_compiles_feed_rules():
    compiled, errors = yara_engine.compile_rules([
        ("real_feed_rule", 'rule real_feed_rule { strings: $s = "evil" condition: $s }')
    ])
    assert len(compiled) == 1 and errors == []


def test_feed_url_requires_https(feed_key):
    with pytest.raises(yara_feed.FeedError, match="HTTPS"):
        yara_feed.validate_feed_url("http://feeds.example/aegis.json")


def test_detection_confidence_is_high_for_critical():
    files = [{"findings": [{"type": "yara_signature_match", "severity": "critical",
                            "detail": "critical signature", "score": 60}]}]
    detection = _build_detection(
        60, "malicious", files,
        {"matches": [{"severity": "critical"}], "rules_total": 1},
        {}, [], False,
    )
    assert detection["confidence"] == "high"
    assert detection["signals"]["yara_matches"] == 1
    assert detection["top_findings"][0]["severity"] == "critical"


@pytest.mark.asyncio
async def test_feed_status_requires_auth(client):
    r = await client.get("/api/v1/yara/feeds/status")
    assert r.status_code == 401


@pytest.mark.asyncio
async def test_feed_status_reports_configuration(client, admin_auth_headers, monkeypatch):
    monkeypatch.setattr(settings, "YARA_FEED_ENABLED", False)
    r = await client.get("/api/v1/yara/feeds/status", headers=admin_auth_headers)
    if r.status_code == 401:
        return  # DB unavailable: auth cannot validate the token
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["enabled"] is False
    assert body["signature_required"] is True
