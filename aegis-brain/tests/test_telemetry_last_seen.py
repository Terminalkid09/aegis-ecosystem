"""last_seen is refreshed periodically, not on every event."""
from datetime import datetime, timedelta, timezone

from app.services.telemetry_service import _last_seen_needs_refresh


def test_last_seen_refreshes_when_missing_or_stale():
    now = datetime.now(timezone.utc)
    assert _last_seen_needs_refresh(None, now)
    assert _last_seen_needs_refresh(now - timedelta(seconds=31), now)
    assert _last_seen_needs_refresh(now - timedelta(seconds=30), now)


def test_last_seen_is_not_rewritten_for_fresh_agent():
    now = datetime.now(timezone.utc)
    assert not _last_seen_needs_refresh(now - timedelta(seconds=29), now)
    # SQLite can hand back naive datetimes; they must not crash the hot path.
    assert not _last_seen_needs_refresh(
        (now - timedelta(seconds=5)).replace(tzinfo=None), now
    )
