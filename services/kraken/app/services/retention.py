import os
import time
from pathlib import Path
from typing import Optional

from loguru import logger


def _secure_unlink(path: Path) -> None:
    """Best-effort overwrite before unlink; SSD/CoW storage may retain copies."""
    try:
        size = path.stat().st_size
        with path.open("r+b") as fh:
            remaining = size
            while remaining > 0:
                chunk = min(remaining, 1024 * 1024)
                fh.write(b"\0" * chunk)
                remaining -= chunk
            fh.flush()
            os.fsync(fh.fileno())
    except OSError as e:
        logger.warning(f"Could not overwrite sample before deletion: {path.name}: {e}")
    try:
        path.unlink()
    except FileNotFoundError:
        pass


def prune_malware(
    directory: str,
    retention_days: int,
    max_total_bytes: int,
    now: Optional[float] = None,
) -> list[dict]:
    """Apply age and quota retention to captured samples, returning an audit trail."""
    root = Path(directory)
    if not root.is_dir():
        return []
    current = time.time() if now is None else now
    cutoff = current - retention_days * 86400
    deleted: list[dict] = []
    files: list[tuple[float, int, Path]] = []
    for entry in os.scandir(root):
        if not entry.is_file(follow_symlinks=False):
            continue
        stat = entry.stat(follow_symlinks=False)
        files.append((stat.st_mtime, stat.st_size, Path(entry.path)))

    for mtime, size, path in sorted(files):
        if mtime >= cutoff:
            continue
        _secure_unlink(path)
        deleted.append({"path": str(path), "size": size, "reason": "retention"})
        logger.info(f"Malware retention deleted {path.name} ({size} bytes, age policy)")

    remaining = [item for item in sorted(files) if item[2].exists()]
    total = sum(size for _, size, _ in remaining)
    for _, size, path in remaining:
        if total <= max_total_bytes:
            break
        _secure_unlink(path)
        total -= size
        deleted.append({"path": str(path), "size": size, "reason": "quota"})
        logger.info(f"Malware quota deleted {path.name} ({size} bytes)")
    return deleted
