"""M4 audit F2: gate sugli split detection indipendenti.

training/validation/regression devono restare:
- presenti con manifest.json integro (sha256 su contenuto normalizzato LF),
- disgiunti (nessun evento condiviso: niente overfitting mascherato),
- verdi: FP=0, FN=0, F1=1.0 su ogni split.

Tutto senza DB/rete: il replay statico e' deterministico.
"""
import hashlib
import json
import os

import pytest

from app.services.replay import (
    score_corpus, DATASET_VERSION, DATASET_SPLITS, CORPUS_HOST_DAYS,
)

CORPUS_DIR = os.path.join(os.path.dirname(__file__), "corpus")


def _raw_lf(*parts: str) -> bytes:
    with open(os.path.join(CORPUS_DIR, *parts), "rb") as f:
        return f.read().replace(b"\r\n", b"\n")


def _manifest(split: str) -> dict:
    path = os.path.join(CORPUS_DIR, split, "manifest.json") if split != "training" \
        else os.path.join(CORPUS_DIR, "manifest.json")
    with open(path, encoding="utf-8") as f:
        return json.load(f)


@pytest.mark.parametrize("split", list(DATASET_SPLITS))
def test_manifest_exists_and_hashes_match(split):
    man = _manifest(split)
    assert man["split"] == split
    assert man["dataset_version"] == DATASET_VERSION
    assert man["host_days"] == CORPUS_HOST_DAYS
    assert set(man["files"]) == {"benign.jsonl", "suspicious.jsonl", "malformed.jsonl"}
    for fname, meta in man["files"].items():
        raw = _raw_lf(split, fname) if split != "training" else _raw_lf(fname)
        assert hashlib.sha256(raw).hexdigest() == meta["sha256"], fname
        assert len(raw) == meta["bytes"], fname
        assert len(raw.splitlines()) == meta["lines"], fname


def test_splits_are_disjoint():
    """Nessun evento identico tra split: validation/regression misurano
    generalizzazione, non memoria del training."""
    seen: dict[str, str] = {}
    for split in DATASET_SPLITS:
        for fname in ("benign.jsonl", "suspicious.jsonl"):
            rel = os.path.join(split, fname) if split != "training" else fname
            for line in _raw_lf(rel).splitlines():
                row = json.loads(line)
                canon = json.dumps(row.get("event", row), sort_keys=True)
                assert canon not in seen, f"evento duplicato tra {seen.get(canon)} e {split}/{fname}"
                seen[canon] = f"{split}/{fname}"


@pytest.mark.parametrize("split", list(DATASET_SPLITS))
def test_split_scores_clean(split):
    rep = score_corpus(split=split)
    assert rep["split"] == split, rep
    assert rep["fn"] == 0, rep["fn_line_indexes"]
    assert rep["fp"] == 0
    assert rep["precision"] == 1.0 and rep["recall"] == 1.0 and rep["f1"] == 1.0
    assert rep["false_positives_per_host_day"] == 0.0
    assert rep["mttd_seconds"] is None  # solo live, mai inventato


def test_split_sizes_documented():
    assert score_corpus(split="training")["benign_lines"] == 12
    assert score_corpus(split="validation")["suspicious_lines"] == 16
    assert score_corpus(split="validation")["malformed_lines"] == 4
    assert score_corpus(split="regression")["suspicious_lines"] == 7
    assert score_corpus(split="regression")["malformed_lines"] == 2
