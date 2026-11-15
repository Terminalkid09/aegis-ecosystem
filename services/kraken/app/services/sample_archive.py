import hashlib
import os
import tarfile
from typing import Optional

from loguru import logger

from app.core.config import settings


def safe_extract(
    tar: tarfile.TarFile,
    dest: str,
    max_file_bytes: Optional[int] = None,
    max_total_bytes: Optional[int] = None,
) -> list[dict]:
    """Safely extract tar members with path-traversal and size caps."""
    file_limit = max_file_bytes if max_file_bytes is not None else settings.MALWARE_MAX_FILE_BYTES
    total_limit = max_total_bytes if max_total_bytes is not None else settings.MALWARE_MAX_SESSION_BYTES
    results = []
    total = 0
    for member in tar.getmembers():
        name = os.path.normpath(member.name)
        if name.startswith("/") or ".." in name.split(os.sep):
            continue
        if not member.isfile():
            continue
        if member.size < 0 or member.size > file_limit:
            logger.warning(f"Skipping oversized archive member: {member.name} ({member.size} bytes)")
            continue
        if total + member.size > total_limit:
            logger.warning("Archive session size cap reached; skipping remaining members.")
            break
        f = tar.extractfile(member)
        if f is None:
            continue
        content = f.read(file_limit + 1)
        f.close()
        if len(content) > file_limit:
            logger.warning(f"Skipping oversized archive member: {member.name}")
            continue
        total += len(content)
        sha256_hash = hashlib.sha256(content).hexdigest()
        safe_path = os.path.join(dest, sha256_hash)
        with open(safe_path, "wb") as out:
            out.write(content)
        results.append({
            "sha256": sha256_hash,
            "size": len(content),
            "path": safe_path,
            "filename": os.path.basename(member.name),
        })
    return results
