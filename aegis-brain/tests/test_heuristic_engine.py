import pytest
from api.schemas import EventSchema
from rules.heuristic_engine import HeuristicEngine
from datetime import datetime

@pytest.fixture
def engine():
    return HeuristicEngine()

def test_rule_known_attack_tool(engine):
    event = EventSchema(
        agentId="test-agent",
        pid=123,
        processName="mimikatz.exe",
        os="Windows",
        eventType="PROCESS_CREATED",
        timestamp=datetime.now()
    )
    result = engine.analyze(event)
    assert result.is_threat is True
    assert result.severity == "CRITICAL"
    assert "Known attack tool" in result.description

def test_rule_suspicious_path(engine):
    event = EventSchema(
        agentId="test-agent",
        pid=123,
        processName="legit.exe",
        processPath="C:\\Windows\\Temp\\legit.exe",
        os="Windows",
        eventType="PROCESS_CREATED",
        timestamp=datetime.now()
    )
    result = engine.analyze(event)
    assert result.is_threat is True
    assert result.severity == "HIGH"
    assert "suspicious path" in result.description

def test_rule_double_extension(engine):
    event = EventSchema(
        agentId="test-agent",
        pid=123,
        processName="invoice.pdf.exe",
        os="Windows",
        eventType="PROCESS_CREATED",
        timestamp=datetime.now()
    )
    result = engine.analyze(event)
    assert result.is_threat is True
    assert result.severity == "HIGH"
    assert "Double extension" in result.description

def test_benign_event(engine):
    event = EventSchema(
        agentId="test-agent",
        pid=123,
        processName="explorer.exe",
        processPath="C:\\Windows\\explorer.exe",
        os="Windows",
        eventType="PROCESS_CREATED",
        timestamp=datetime.now()
    )
    result = engine.analyze(event)
    assert result.is_threat is False
