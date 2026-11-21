"""Object storage for Kraken file intelligence.

The default backend is the local volume used by the existing 4.2 tests. The
S3 backend is S3-compatible (AWS, MinIO, Ceph) and keeps the sample out of the
application database. Every job gets its own key, so deleting one job can never
remove a blob still referenced by another identical upload.
"""
from __future__ import annotations

import asyncio
import os
import tempfile
from contextlib import asynccontextmanager
from typing import AsyncIterator, Optional
from urllib.parse import urlparse

from loguru import logger

from app.core.config import settings


class ObjectStoreError(RuntimeError):
    """The object could not be stored, read, or deleted."""


def local_root() -> str:
    directory = settings.FILE_ANALYSIS_STORAGE_DIR or os.path.join(settings.DATA_DIR, "samples")
    os.makedirs(directory, exist_ok=True)
    return directory


def _safe_local_path(key: str) -> str:
    root = os.path.realpath(local_root())
    target = os.path.realpath(os.path.join(root, *key.split("/")))
    if os.path.commonpath([root, target]) != root:
        raise ObjectStoreError("object key escapes the storage root")
    return target


class LocalObjectStore:
    backend = "local"

    async def put_file(self, source: str, key: str) -> str:
        target = _safe_local_path(key)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        try:
            await asyncio.to_thread(os.replace, source, target)
        except OSError as exc:
            raise ObjectStoreError(f"local object write failed: {exc}") from exc
        return target

    @asynccontextmanager
    async def materialize(self, ref: str) -> AsyncIterator[str]:
        # Existing 4.2 jobs stored absolute paths before the object-store
        # abstraction. A path is still a valid local ref and remains readable.
        if not os.path.isfile(ref):
            raise ObjectStoreError("local object is missing")
        yield ref

    async def delete(self, ref: str) -> bool:
        root = os.path.realpath(local_root())
        target = os.path.realpath(ref)
        if os.path.commonpath([root, target]) != root:
            raise ObjectStoreError("refusing to delete outside the local object root")
        try:
            await asyncio.to_thread(os.unlink, target)
        except FileNotFoundError:
            return True
        except OSError as exc:
            logger.warning("Local object delete failed: {}", exc)
            return False
        return not os.path.exists(target)

    async def exists(self, ref: str) -> bool:
        return os.path.isfile(ref)


class S3ObjectStore:
    backend = "s3"

    def __init__(self) -> None:
        if not settings.OBJECT_STORE_S3_BUCKET:
            raise ObjectStoreError("OBJECT_STORE_S3_BUCKET is required for the S3 backend")
        try:
            import boto3
        except ImportError as exc:  # pragma: no cover - exercised by deployment check
            raise ObjectStoreError("boto3 is required for the S3 backend") from exc
        self.bucket = settings.OBJECT_STORE_S3_BUCKET
        self.prefix = (settings.OBJECT_STORE_S3_PREFIX or "kraken-samples").strip("/")
        kwargs = {
            "region_name": settings.OBJECT_STORE_S3_REGION or None,
            "use_ssl": bool(settings.OBJECT_STORE_S3_USE_SSL),
        }
        if settings.OBJECT_STORE_S3_ENDPOINT:
            kwargs["endpoint_url"] = settings.OBJECT_STORE_S3_ENDPOINT
            # MinIO/S3-compatible endpoints commonly require path-style
            # addressing; AWS itself continues to accept it.
            from botocore.config import Config
            kwargs["config"] = Config(s3={"addressing_style": "path"})
        if settings.OBJECT_STORE_S3_ACCESS_KEY:
            kwargs["aws_access_key_id"] = settings.OBJECT_STORE_S3_ACCESS_KEY
        if settings.OBJECT_STORE_S3_SECRET_KEY:
            kwargs["aws_secret_access_key"] = settings.OBJECT_STORE_S3_SECRET_KEY
        self.client = boto3.client("s3", **kwargs)

    def _key(self, ref: str) -> str:
        parsed = urlparse(ref)
        if parsed.scheme != "s3" or parsed.netloc != self.bucket:
            raise ObjectStoreError("S3 ref does not belong to the configured bucket")
        key = parsed.path.lstrip("/")
        if not key or ".." in key.split("/"):
            raise ObjectStoreError("invalid S3 object key")
        return key

    async def put_file(self, source: str, key: str) -> str:
        full_key = f"{self.prefix}/{key}" if self.prefix else key
        try:
            await asyncio.to_thread(
                self.client.upload_file, source, self.bucket, full_key
            )
        except Exception as exc:
            raise ObjectStoreError(f"S3 upload failed: {exc}") from exc
        return f"s3://{self.bucket}/{full_key}"

    @asynccontextmanager
    async def materialize(self, ref: str) -> AsyncIterator[str]:
        key = self._key(ref)
        handle = tempfile.NamedTemporaryFile(delete=False, prefix="kraken-s3-")
        path = handle.name
        handle.close()
        try:
            await asyncio.to_thread(self.client.download_file, self.bucket, key, path)
            yield path
        except Exception as exc:
            raise ObjectStoreError(f"S3 download failed: {exc}") from exc
        finally:
            try:
                os.unlink(path)
            except FileNotFoundError:
                pass

    async def delete(self, ref: str) -> bool:
        key = self._key(ref)
        try:
            await asyncio.to_thread(self.client.delete_object, Bucket=self.bucket, Key=key)
            await asyncio.to_thread(self.client.head_object, Bucket=self.bucket, Key=key)
        except Exception as exc:
            # NoSuchKey/404 after delete is success; other errors are failures.
            code = str(getattr(exc, "response", {}).get("Error", {}).get("Code", ""))
            if code in ("404", "NoSuchKey", "NotFound"):
                return True
            logger.warning("S3 delete verification failed: {}", exc)
            return False
        return False

    async def exists(self, ref: str) -> bool:
        try:
            await asyncio.to_thread(
                self.client.head_object, Bucket=self.bucket, Key=self._key(ref)
            )
            return True
        except Exception:
            return False


def get_object_store():
    backend = (settings.OBJECT_STORE_BACKEND or "local").strip().lower()
    if backend == "local":
        return LocalObjectStore()
    if backend == "s3":
        return S3ObjectStore()
    raise ObjectStoreError(f"unsupported OBJECT_STORE_BACKEND: {backend}")


async def store_upload(upload, job_id: str) -> tuple[str, str, int]:
    """Stream an upload once, then hand it to the configured object store.

    The key contains the job id and the SHA-256. Two uploads of the same bytes
    are deliberately stored separately: deletion is then a simple, verified
    operation with no cross-job reference count that can race.
    """
    import hashlib

    store = get_object_store()
    directory = local_root()
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
        key = f"{job_id}/{sha}"
        ref = await store.put_file(handle.name, key)
        return ref, sha, size
    except Exception:
        handle.close()
        try:
            os.unlink(handle.name)
        except OSError:
            pass
        raise


async def delete_stored_sample(ref: Optional[str]) -> bool:
    if not ref:
        return True
    store = get_object_store()
    if not await store.delete(ref):
        return False
    return not await store.exists(ref)


def materialize(ref: str):
    """Return an async context manager yielding a local path for analysis."""
    return get_object_store().materialize(ref)
