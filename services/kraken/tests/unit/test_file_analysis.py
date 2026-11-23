import asyncio
import hashlib
import io
import json
import os
import threading
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from starlette.datastructures import UploadFile

from app.core.config import settings
from app.models.models import AnalysisJob
from app.services import file_analysis
from app.services.file_analysis import (
    analyze_sample,
    delete_stored_sample,
    recover_pending_analysis_jobs,
    run_analysis_job,
    store_upload,
)


class LiveDetonationHandler(BaseHTTPRequestHandler):
    report = {}

    def do_POST(self):
        length = int(self.headers.get("content-length", "0"))
        self.rfile.read(length)
        body = json.dumps(self.report).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class FakeLease:
    def __init__(self):
        self.keys: set[str] = set()

    async def set(self, key, value, ex=None, nx=False):
        if nx and key in self.keys:
            return None
        self.keys.add(key)
        return True

    async def delete(self, key):
        self.keys.discard(key)
        return 1


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
    assert report["process_tree"] == []
    assert report["limitations"]


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
        assert row.report["detonation"]["status"] == "disabled"
    assert await delete_stored_sample(str(sample)) is True
    assert not os.path.exists(sample)


@pytest.mark.asyncio
async def test_identical_uploads_have_independent_objects(tmp_path, monkeypatch):
    monkeypatch.setattr(settings, "FILE_ANALYSIS_STORAGE_DIR", str(tmp_path))
    first = UploadFile(filename="one.bin", file=io.BytesIO(b"same bytes"))
    second = UploadFile(filename="two.bin", file=io.BytesIO(b"same bytes"))
    ref1, sha1, _ = await store_upload(first, "job-one")
    ref2, sha2, _ = await store_upload(second, "job-two")

    assert sha1 == sha2
    assert ref1 != ref2
    assert os.path.exists(ref1) and os.path.exists(ref2)
    assert await delete_stored_sample(ref1) is True
    assert not os.path.exists(ref1)
    assert os.path.exists(ref2), "deleting one job must not remove another job's object"
    assert await delete_stored_sample(ref2) is True


@pytest.mark.asyncio
async def test_recovery_claims_a_restarted_job(tmp_path, monkeypatch, test_session_factory):
    monkeypatch.setattr(settings, "FILE_ANALYSIS_STORAGE_DIR", str(tmp_path))
    sample = tmp_path / "recover.bin"
    sample.write_bytes(b"recover me")
    async with test_session_factory() as db:
        db.add(AnalysisJob(
            job_id="analysis-recover", sha256="1" * 64, filename="recover.bin",
            size=sample.stat().st_size, storage_path=str(sample),
            status="running", report={},
        ))
        await db.commit()

    lease = FakeLease()
    scheduled = await recover_pending_analysis_jobs(
        session_factory=test_session_factory, lock_client=lease, limit=100
    )
    target = [task for job_id, task in scheduled if job_id == "analysis-recover"]
    assert target
    await asyncio.gather(*target)
    async with test_session_factory() as db:
        from sqlalchemy import select
        row = (await db.execute(
            select(AnalysisJob).where(AnalysisJob.job_id == "analysis-recover")
        )).scalars().first()
        assert row.status == "completed"
        assert row.report["sha256"] != "1" * 64


@pytest.mark.asyncio
async def test_detonation_adds_process_tree_and_dns_history(
    tmp_path, monkeypatch, test_session_factory
):
    monkeypatch.setattr(settings, "FILE_ANALYSIS_STORAGE_DIR", str(tmp_path))
    monkeypatch.setattr(settings, "DETONATION_ENABLED", True)
    sample = tmp_path / "behaviour.bin"
    sample.write_bytes(b"c2.example.com")
    async with test_session_factory() as db:
        db.add(AnalysisJob(
            job_id="analysis-behaviour", sha256="2" * 64, filename="behaviour.bin",
            size=sample.stat().st_size, storage_path=str(sample),
            status="queued", report={},
        ))
        await db.commit()

    async def fake_detonate(path, filename, sha256):
        return {
            "status": "completed",
            "sha256": sha256,
            "process_tree": [{"pid": 42, "ppid": 1, "name": "behaviour.bin"}],
            "dns_history": [{"query": "c2.example.com", "answer": "203.0.113.9"}],
            "iocs": {"domains": ["c2.example.com"], "ips": ["203.0.113.9"]},
            "mitre": [{"technique": "T1071"}],
            "behavior": [{"action": "dns_query"}],
            "verdict": "suspicious",
            "score": 70,
            "provenance": "detonation:http",
        }

    monkeypatch.setattr(file_analysis, "detonate_sample", fake_detonate)
    await run_analysis_job("analysis-behaviour", test_session_factory, FakeLease())
    async with test_session_factory() as db:
        from sqlalchemy import select
        row = (await db.execute(
            select(AnalysisJob).where(AnalysisJob.job_id == "analysis-behaviour")
        )).scalars().first()
        assert row.status == "completed"
        assert row.report["process_tree"][0]["pid"] == 42
        assert row.report["dns_history"][0]["query"] == "c2.example.com"
        assert row.report["detonation"]["status"] == "completed"
        assert row.report["provenance"] == "static+detonation:http"
        assert row.report["limitations"] == []


@pytest.mark.asyncio
async def test_worker_merges_a_live_http_detonation(
    tmp_path, monkeypatch, test_session_factory
):
    monkeypatch.setattr(settings, "FILE_ANALYSIS_STORAGE_DIR", str(tmp_path))
    monkeypatch.setattr(settings, "DETONATION_ENABLED", True)
    payload = b"live integrated detonation"
    sha = hashlib.sha256(payload).hexdigest()
    sample = tmp_path / "integrated.bin"
    sample.write_bytes(payload)
    async with test_session_factory() as db:
        db.add(AnalysisJob(
            job_id="analysis-integrated", sha256="3" * 64, filename="integrated.bin",
            size=len(payload), storage_path=str(sample), status="queued", report={},
        ))
        await db.commit()

    LiveDetonationHandler.report = {
        "sha256": sha,
        "process_tree": [{"pid": 99, "ppid": 1, "name": "integrated.bin"}],
        "dns_history": [{"query": "live.example", "answer": "198.51.100.7"}],
        "iocs": {"domains": ["live.example"]},
        "verdict": "suspicious",
        "score": 55,
        "provenance": "detonation:http",
    }
    server = ThreadingHTTPServer(("127.0.0.1", 0), LiveDetonationHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        monkeypatch.setattr(
            settings, "DETONATION_URL",
            f"http://127.0.0.1:{server.server_port}/detonate",
        )
        await run_analysis_job("analysis-integrated", test_session_factory, FakeLease())
    finally:
        server.shutdown()
        server.server_close()

    async with test_session_factory() as db:
        from sqlalchemy import select
        row = (await db.execute(
            select(AnalysisJob).where(AnalysisJob.job_id == "analysis-integrated")
        )).scalars().first()
        assert row.status == "completed"
        assert row.report["process_tree"][0]["pid"] == 99
        assert row.report["dns_history"][0]["query"] == "live.example"
        assert row.report["detonation"]["verdict"] == "suspicious"
