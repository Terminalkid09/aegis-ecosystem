import os
import time

from app.services.retention import prune_malware


def _write(path, content, mtime):
    path.write_bytes(content)
    os.utime(path, (mtime, mtime))


def test_prunes_samples_older_than_retention(tmp_path):
    now = time.time()
    old = tmp_path / "old"
    fresh = tmp_path / "fresh"
    _write(old, b"old!", now - 31 * 86400)
    _write(fresh, b"new!", now)

    deleted = prune_malware(str(tmp_path), retention_days=30, max_total_bytes=1024, now=now)

    assert not old.exists()
    assert fresh.exists()
    assert [item["reason"] for item in deleted] == ["retention"]


def test_prunes_oldest_when_quota_is_exceeded(tmp_path):
    now = time.time()
    oldest = tmp_path / "oldest"
    newest = tmp_path / "newest"
    _write(oldest, b"123456", now - 10)
    _write(newest, b"abcdef", now)

    deleted = prune_malware(str(tmp_path), retention_days=30, max_total_bytes=6, now=now)

    assert not oldest.exists()
    assert newest.exists()
    assert deleted and deleted[0]["reason"] == "quota"
    # Secure deletion overwrites contents before unlinking.
    assert not oldest.exists()


def test_missing_directory_is_safe(tmp_path):
    assert prune_malware(str(tmp_path / "missing"), 30, 1024) == []
