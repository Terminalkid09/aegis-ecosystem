from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from app.database.models import Suppression
from app.services.suppressions import find_matching_suppression, normalize_expiry
from app.api.v1.detections import coverage


def test_expiry_requires_ttl_and_caps_at_ninety_days():
    now = datetime.now(timezone.utc)
    assert normalize_expiry(now + timedelta(hours=1), now=now)
    with pytest.raises(ValueError):
        normalize_expiry(now + timedelta(seconds=30), now=now)
    with pytest.raises(ValueError):
        normalize_expiry(now + timedelta(days=91), now=now)


@pytest.mark.asyncio
async def test_scoped_suppression_matches_only_its_host(db_session):
    now = datetime.now(timezone.utc)
    db_session.add(Suppression(
        rule_id="sigma-test", scope={"hostname": "host-a"},
        reason="known admin activity", expires_at=now + timedelta(hours=1),
        active=True, suppressed_count=0,
    ))
    await db_session.commit()

    assert await find_matching_suppression(
        db_session, "sigma-test", SimpleNamespace(hostname="host-a"), now=now
    ) is not None
    assert await find_matching_suppression(
        db_session, "sigma-test", SimpleNamespace(hostname="host-b"), now=now
    ) is None


def test_coverage_uses_the_executable_sigma_rules():
    result = coverage()
    assert result["engines"]["sigma"]["rules_total"] >= 1
    assert result["techniques_covered"] >= 1
    assert any(rule["engine"] == "sigma"
               for item in result["items"] for rule in item["rules"])
