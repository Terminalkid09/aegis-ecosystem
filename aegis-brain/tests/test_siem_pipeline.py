"""Test della pipeline SIEM: dal payload normalizzato all'alert.

Verifica le due cose che, se sbagliate, rompono il SOC in modo silenzioso:
1. gli alert generati da una sorgente di log devono avere la stessa forma degli
   alert degli agenti (altrimenti triage, playbook e dashboard li ignorano);
2. con `SIEM_ENABLED=false` l'ingestione esterna deve essere spenta davvero.
"""
import json
import os
import uuid

from app.core.config import settings
from app.ingest import default_registry as registry
from app.rules.sigma import get_engine as get_sigma_engine
from app.services import siem_pipeline
from app.services.correlation import CorrelationMatch

LOGS = os.path.join(os.path.dirname(__file__), "corpus", "logs")
AGENT_ID = uuid.uuid4()


def _windows_events(filename: str = "windows_security.jsonl"):
    payload = open(os.path.join(LOGS, filename), encoding="utf-8").read()
    result = registry.parse("windows_event", payload, {"source": "win-dev01"})
    assert result.events
    return result.events


def _by_message_id(events, message_id: int):
    return next(e for e in events if str(e.message_id) == str(message_id))


# ── alert da Sigma ───────────────────────────────────────────────────────────
def test_sigma_match_becomes_agent_compatible_alert():
    event = _by_message_id(_windows_events(), 1102)
    matches = get_sigma_engine().evaluate(event)
    assert matches, "la regola log-cleared deve scattare sull'evento 1102"

    alert = siem_pipeline._alert_from_sigma(event, matches[0], AGENT_ID)
    assert alert.agent_id == AGENT_ID
    assert alert.severity in ("LOW", "MEDIUM", "HIGH", "CRITICAL")
    assert alert.description.startswith("[SIGMA ")
    assert alert.event_type
    assert not alert.is_resolved  # default: alert aperto
    # Il campo su cui la UI raggruppa non può essere vuoto.
    assert alert.process_name


def test_sigma_alert_carries_mitre_technique():
    event = _by_message_id(_windows_events(), 7045)
    matches = get_sigma_engine().evaluate(event)
    assert matches
    alert = siem_pipeline._alert_from_sigma(event, matches[0], AGENT_ID)
    if alert.mitre_technique_id:
        assert alert.mitre_technique_id.startswith("T")


def test_sigma_alert_description_is_bounded():
    """Una descrizione lunghissima non deve finire intera nel DB."""
    from app.rules.sigma.model import SigmaMatch

    event = _by_message_id(_windows_events(), 1102)
    event.message = "x" * 5000
    match = SigmaMatch(rule_id="test-rule", title="Test Rule", level="HIGH",
                       description="", mitre_techniques=[], tags=[], event_id=event.event_id)
    alert = siem_pipeline._alert_from_sigma(event, match, AGENT_ID)
    assert len(alert.description) < 1000


# ── alert da correlazione ────────────────────────────────────────────────────
def test_correlation_match_becomes_alert_with_detail():
    event = _by_message_id(_windows_events(), 1102)
    match = CorrelationMatch(
        rule_id="corr-ssh-bruteforce", title="SSH Brute Force From Single Source",
        severity="HIGH", description="desc", mitre=["T1110"],
        group_key="203.0.113.9", group_label="203.0.113.9",
        observed=7, window_seconds=120, event=event,
    )
    alert = siem_pipeline._alert_from_correlation(match, AGENT_ID)
    assert alert.event_type == "CORRELATION"
    assert "7 eventi in 120s" in alert.description
    assert alert.mitre_technique_id == "T1110"
    assert alert.severity == "HIGH"


def test_correlation_alert_without_event_still_builds():
    """Un match senza evento associato non deve produrre un alert rotto."""
    match = CorrelationMatch(
        rule_id="corr-port-sweep", title="Port Sweep", severity="MEDIUM",
        description="", mitre=[], group_key="global", group_label="",
        observed=15, window_seconds=60, event=None,
    )
    alert = siem_pipeline._alert_from_correlation(match, AGENT_ID)
    assert alert.process_name
    assert alert.mitre_technique_id is None


# ── interruttore di configurazione ───────────────────────────────────────────
async def test_ingestion_is_disabled_when_switched_off(monkeypatch):
    monkeypatch.setattr(settings, "SIEM_ENABLED", False)
    result = await siem_pipeline.ingest_payload(None, "syslog", "anything")
    assert result["accepted"] == 0
    assert result["error"] == "SIEM ingestion disabled"


# ── ingest_batch ─────────────────────────────────────────────────────────────
async def test_ingest_batch_sums_results(monkeypatch):
    calls = []

    async def fake_ingest(db, source, payload, meta=None, parser=None):
        calls.append(payload)
        return {"accepted": 1, "stored": 1, "alerts": 0, "duplicates": 0, "errors": []}

    monkeypatch.setattr(siem_pipeline, "ingest_payload", fake_ingest)
    totals = await siem_pipeline.ingest_batch(None, "src", ["a", "b", "c"])
    assert calls == ["a", "b", "c"]
    assert totals["accepted"] == 3
    assert totals["stored"] == 3


async def test_ingest_batch_collects_errors(monkeypatch):
    async def fake_ingest(db, source, payload, meta=None, parser=None):
        return {"accepted": 0, "stored": 0, "alerts": 0, "duplicates": 1,
                "errors": [f"bad {payload}"]}

    monkeypatch.setattr(siem_pipeline, "ingest_payload", fake_ingest)
    totals = await siem_pipeline.ingest_batch(None, "src", ["x"])
    assert totals["duplicates"] == 1
    assert totals["errors"] == ["bad x"]


# ── payload reale riconosciuto/rifiutato ─────────────────────────────────────
def test_windows_jsonl_payload_is_auto_detected():
    payload = open(os.path.join(LOGS, "windows_security.jsonl"), encoding="utf-8").read()
    result = registry.parse("auto", payload, {"source": "auto-test"})
    assert result.parser == "windows_event"
    assert result.unparsed == 0
    assert len(result.events) == 8


def test_json_payload_is_not_double_counted():
    """Un NDJSON generico deve produrre un evento per riga, non una riga sola."""
    payload = json.dumps({"message": "hello", "src_ip": "10.0.0.1"}) + "\n" + \
        json.dumps({"message": "world", "src_ip": "10.0.0.2"})
    result = registry.parse("json", payload, {"source": "json-test"})
    assert len(result.events) == 2
    assert result.unparsed == 0


def test_garbage_payload_produces_no_event():
    result = registry.parse("auto", "not a log line at all", {"source": "bad"})
    assert result.events == []
    assert result.errors
