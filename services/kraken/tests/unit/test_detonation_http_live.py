"""Live HTTP detonation check for the Kraken analysis worker.

Run from the repository root:
    .venv315/Scripts/python.exe services/kraken/tests/unit/test_detonation_http_live.py

The test starts a real localhost HTTP server, so it exercises httpx, multipart
upload, SHA-256 validation and the report merge. It does not execute malware.
"""
import asyncio
import io
import json
import os
import sys
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from starlette.datastructures import UploadFile

from app.core.config import settings
from app.services import object_store


class Handler(BaseHTTPRequestHandler):
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


async def main():
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory() as directory:
            settings.FILE_ANALYSIS_STORAGE_DIR = directory
            settings.OBJECT_STORE_BACKEND = "local"
            settings.DETONATION_ENABLED = True
            settings.DETONATION_URL = f"http://127.0.0.1:{server.server_port}/detonate"
            sample = os.path.join(directory, "sample.bin")
            with open(sample, "wb") as handle:
                handle.write(b"live detonation simulation")
            upload = UploadFile(filename="sample.bin", file=io.BytesIO(b"live detonation simulation"))
            ref, sha, size = await object_store.store_upload(upload, "live-job")
            Handler.report = {
                "sha256": sha,
                "process_tree": [{"pid": 7, "ppid": 1, "name": "sample.bin"}],
                "dns_history": [{"query": "c2.example", "answer": "203.0.113.7"}],
                "iocs": {"domains": ["c2.example"], "ips": ["203.0.113.7"]},
                "verdict": "suspicious",
                "score": 61,
                "provenance": "detonation:http",
            }
            from app.services.detonation import detonate_sample
            result = await detonate_sample(sample, "sample.bin", sha)
            print(json.dumps({
                "object_ref": ref,
                "sha256": sha,
                "size": size,
                "process_tree": result["process_tree"],
                "dns_history": result["dns_history"],
                "verdict": result["verdict"],
            }, indent=2))
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    asyncio.run(main())
