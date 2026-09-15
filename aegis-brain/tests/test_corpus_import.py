"""Import corpus esterno — feature di validazione con dati reali.

Il replay interno gira su un corpus sintetico; senza poter caricare un dataset
esterno (Atomic Red Team, log convertiti) un P/R/F1 "1.0" resta un numero che
nessun cliente può riprodurre. Questi test coprono il parsing JSONL e il fatto
che il motore reale venga usato su input esterni.
"""
import json

import pytest

from app.api.v1.rules import _IMPORT_MAX_BYTES, _read_jsonl_upload
from app.services.replay import score_corpus


class FakeUpload:
    def __init__(self, data: bytes):
        self._data = data

    async def read(self):
        return self._data


def _jsonl(*rows):
    return ("\n".join(json.dumps(r) for r in rows)).encode()


@pytest.mark.asyncio
async def test_read_jsonl_parses_rows():
    rows = await _read_jsonl_upload(FakeUpload(_jsonl({"event_type": "PROCESS_CREATED"}, {"a": 1})), "benign")
    assert rows == [{"event_type": "PROCESS_CREATED"}, {"a": 1}]


@pytest.mark.asyncio
async def test_read_jsonl_rejects_bad_json_outside_malformed():
    with pytest.raises(Exception) as exc:
        await _read_jsonl_upload(FakeUpload(b'{"ok": 1}\nnot json\n'), "suspicious")
    assert "valid JSON" in str(exc.value) or "422" in str(exc.value)


@pytest.mark.asyncio
async def test_read_jsonl_malformed_tolerates_broken_lines():
    rows = await _read_jsonl_upload(FakeUpload(b'{"ok": 1}\ngarbage\n{"b": 2}'), "malformed")
    assert {"ok": 1} in rows and {"b": 2} in rows and "garbage" in rows


@pytest.mark.asyncio
async def test_read_jsonl_enforces_size_cap():
    big = FakeUpload(b"x" * (_IMPORT_MAX_BYTES + 1))
    with pytest.raises(Exception):
        await _read_jsonl_upload(big, "benign")


def test_score_corpus_accepts_external_lists():
    """Il motore determina TP/FN sul dataset esterno, non sul corpus interno."""
    benign = [{"event_type": "PROCESS_CREATED", "process_name": "notepad.exe",
               "process_path": "C:\\Windows\\notepad.exe", "pid": 10}]
    suspicious = [
        {"event_type": "PROCESS_CREATED", "process_name": "mimikatz.exe",
         "process_path": "C:\\temp\\mimikatz.exe", "pid": 20, "expect": []},
    ]
    report = score_corpus(benign=benign, suspicious=suspicious, malformed=[])
    assert report["benign_lines"] == 1
    assert report["suspicious_lines"] == 1
    assert report["tp"] + report["fn"] == 1
    assert report["engine"] == "static-replay-v1"


def test_external_corpus_with_expectation_measures_recall():
    # Una riga con `expect` di una regola che NON esiste → FN (recall misurato,
    # non nascosto). `expect` di una regola nota su input non corrispondente → FN.
    rows = [{"event_type": "PROCESS_CREATED", "process_name": "x", "pid": 1,
             "expect": ["AEGIS-S999"]}]
    report = score_corpus(benign=[], suspicious=rows, malformed=[])
    assert report["fn"] == 1 and report["tp"] == 0
    assert report["recall"] == 0.0
