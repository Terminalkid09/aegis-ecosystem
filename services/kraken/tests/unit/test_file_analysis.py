import os
import zipfile

import pytest

from app.core.config import settings
from app.models.models import AnalysisJob
from app.services.file_analysis import (
    analyze_sample, delete_stored_sample, run_analysis_job,
)


def test_static_analysis_extracts_iocs_and_zip_manifest(tmp_path):
    archive = tmp_path / "sample.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("readme.txt", "contact c2.example.com or 203.0.113.9 https://bad.example/x")
    report = analyze_sample(str(archive), "sample.zip")
    assert report["sha256"]
    assert report["zip_entries"][0]["name"] == "readme.txt"
    assert "203.0.113.9" in report["iocs"]["ips"]
    assert "c2.example.com" in report["iocs"]["domains"]
    assert "kraken-candidate-" in report["candidate_sigma"]
    assert "static-only" in report["provenance"]


@pytest.mark.asyncio
async def test_job_runs_and_delete_is_verified(tmp_path, monkeypatch, test_session_factory):
    monkeypatch.setattr(settings, "FILE_ANALYSIS_STORAGE_DIR", str(tmp_path))
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"hello https://evil.example/path 198.51.100.4")
    job = AnalysisJob(
        job_id="analysis-test", sha256="0" * 64, filename="sample.bin",
        size=sample.stat().st_size, storage_path=str(sample), status="queued", report={},
    )
    async with test_session_factory() as db:
        db.add(job)
        await db.commit()
    await run_analysis_job("analysis-test", test_session_factory)
    async with test_session_factory() as db:
        from sqlalchemy import select
        row = (await db.execute(select(AnalysisJob).where(AnalysisJob.job_id == "analysis-test"))).scalars().first()
        assert row.status == "completed"
        assert "198.51.100.4" in row.report["iocs"]["ips"]
    assert delete_stored_sample(str(sample)) is True
    assert not os.path.exists(sample)
