"""M4 Fase 5: replay deterministico, metriche e canary (tutto senza DB)."""
from app.services.replay import run_static_replay, score_corpus, CORPUS_HOST_DAYS
from app.rules.rule_definitions import (
    STATIC_RULES, ALL_RULES, RULE_BY_FN, stamp_result,
    is_canary_rule, canary_rule_ids,
)
from app.api.schemas.common import EventSchema


def _ev(**kw):
    base = {"agent_id": "t", "timestamp": "2026-09-01T00:00:00+00:00",
            "event_type": "PROCESS_CREATED", "process_name": "x"}
    base.update(kw)
    return base


def test_registry_ids_unique_and_versioned():
    ids = [s.rule_id for s in STATIC_RULES]
    # Invariante: unicità + copertura, non un numero fisso (aggiungere una regola
    # al registry non è una regressione). Il minimo resta perché scendere sotto
    # il baseline validato dal corpus toglierebbe copertura senza segnalarlo.
    assert len(ids) == len(set(ids))
    assert len(ids) >= 15
    assert all(i.startswith("AEGIS-S") for i in ids)
    assert all(s.version == "1.0" for s in STATIC_RULES)
    assert {s.confidence for s in STATIC_RULES} <= {"high", "medium", "low"}
    assert len(RULE_BY_FN) == len(ALL_RULES)


def test_stamp_result_attaches_identity():
    from app.rules.rule_definitions import rule_known_attack_tool
    e = EventSchema(**_ev(process_name="mimikatz.exe"))
    r = rule_known_attack_tool(e)
    assert r.triggered
    stamp_result(rule_known_attack_tool, r)
    assert r.rule_id == "AEGIS-S001"
    assert r.version == "1.0"
    assert r.confidence == "high"


def test_replay_deterministic():
    benign_note = _ev(process_name="notepad.exe",
                      process_path="C:\\Windows\\System32\\notepad.exe")
    evs = [{"event": _ev(process_name="mimikatz.exe")},
           {"event": benign_note}]
    assert run_static_replay(evs) == run_static_replay(evs)
    rep = run_static_replay(evs)
    assert rep["events"] == 2 and rep["invalid"] == 0
    assert {h["rule_id"] for h in rep["hits"]} == {"AEGIS-S001"}
    assert rep["hits"][0]["confidence"] == "high"


def test_replay_counts_invalid_without_raising():
    rep = run_static_replay([{"event": {"bogus": 1}}, "not-a-dict", {}])
    assert rep["invalid"] == 3 and rep["hits"] == []


def test_canary_excluded_by_default(monkeypatch):
    from app.core import config
    monkeypatch.setattr(config.settings, "RULE_CANARY_IDS", "AEGIS-S001", raising=False)
    assert is_canary_rule("aegis-s001")
    assert "AEGIS-S001" in canary_rule_ids()
    evs = [{"event": _ev(process_name="mimikatz.exe")}]
    assert run_static_replay(evs)["hits"] == []
    rep = run_static_replay(evs, include_canary=True)
    assert [h["rule_id"] for h in rep["canary_hits"]] == ["AEGIS-S001"]
    monkeypatch.setattr(config.settings, "RULE_CANARY_IDS", "", raising=False)
    assert not is_canary_rule("AEGIS-S001")


def test_corpus_scores_clean():
    rep = score_corpus()
    assert rep["tp"] == 12 and rep["fn"] == 0, rep["fn_line_indexes"]
    assert rep["fp"] == 0
    assert rep["precision"] == 1.0 and rep["recall"] == 1.0 and rep["f1"] == 1.0
    assert rep["false_positives_per_host_day"] == 0.0
    assert rep["host_days_assumption"] == CORPUS_HOST_DAYS
    assert rep["mttd_seconds"] is None  # solo live, mai inventato
    assert rep["benign_lines"] == 12 and rep["suspicious_lines"] == 12
    assert rep["malformed_lines"] == 6
    assert rep["malformed_invalid"] >= 4  # righe indubbiamente malformate
    assert rep["rules"] == len(STATIC_RULES)
    assert rep["dataset_version"] is not None


def test_prf_edge_cases():
    from app.services.replay import _prf
    assert _prf(0, 0, 0) == {"precision": None, "recall": None, "f1": None}
    assert _prf(2, 0, 0)["f1"] == 1.0
    assert _prf(0, 3, 0)["precision"] == 0.0


def test_seed_shuffle_is_reproducible():
    benign_note = _ev(process_name="notepad.exe",
                      process_path="C:\\Windows\\System32\\notepad.exe")
    evs = [{"event": _ev(process_name="mimikatz.exe")},
           {"event": benign_note},
           {"event": _ev(process_name="x.exe", process_path="C:\\temp\\y.exe")}]
    a = run_static_replay(evs, seed=7)
    b = run_static_replay(evs, seed=7)
    c = run_static_replay(evs, seed=8)
    assert a == b
    # Seed diversi possono produrre ordini diversi degli hit (indice inclusi),
    # ma lo stesso numero di hit e gli stessi rule_id.
    assert sorted(h["rule_id"] for h in a["hits"]) == sorted(h["rule_id"] for h in c["hits"])
