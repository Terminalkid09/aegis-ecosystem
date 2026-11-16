"""AEGIS-SEC-004: archivi compressi non devono essere decompressi in blocco."""
import gzip
import io
import tarfile
import zipfile

import pytest
from fastapi import HTTPException

from app.api.v1 import total as total_mod


def _tar_gz(payload: bytes) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        info = tarfile.TarInfo("sample.txt")
        info.size = len(payload)
        tf.addfile(info, io.BytesIO(payload))
    return buf.getvalue()


def test_tar_gz_is_not_materialized_with_gzip_decompress(monkeypatch):
    """Il vecchio `gzip.decompress(raw)` decomprompeva tutto prima del cap."""
    raw = _tar_gz(b"hello" * 100)

    def forbidden(_data):
        raise AssertionError("gzip.decompress non deve essere usato su un tar.gz")

    monkeypatch.setattr(total_mod.gzip, "decompress", forbidden)
    detail = total_mod._analyze_tar_like(raw, "gzip", "sample.tar.gz")
    assert detail is not None
    assert detail["analyzed_members"] == 1


def test_single_gzip_stream_over_cap_is_flagged(monkeypatch):
    monkeypatch.setattr(total_mod, "PER_ENTRY_MAX_BYTES", 1024)
    raw = gzip.compress(b"A" * 100_000)
    detail = total_mod._analyze_tar_like(raw, "gzip", "bomb.gz")
    assert detail is not None
    assert detail["bomb_suspected"] is True
    assert len(detail.get("preview", "")) <= 1024


def test_zip_declared_expansion_over_budget_is_rejected(monkeypatch):
    monkeypatch.setattr(total_mod, "TOTAL_UNCOMPRESSED_MAX", 1024)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("large.txt", b"x" * 4096)
    with pytest.raises(HTTPException) as exc:
        total_mod._reject_zip_bomb(buf.getvalue())
    assert exc.value.status_code == 422
