"""AEGIS-LOGIC-001: isolate/release non devono restituire lo stato vecchio."""
from types import SimpleNamespace

from app.api.v1.telemetry import _containment_state


def _agent(isolated=False):
    return SimpleNamespace(isolated=isolated)


def test_isolate_queued_reports_pending_not_old_false():
    state = _containment_state(_agent(False), queued=True)
    assert state == {"isolated": True, "pending": "ISOLATE_HOST"}


def test_release_queued_reports_pending_release():
    state = _containment_state(_agent(True), queued=True, releasing=True)
    assert state == {"isolated": False, "pending": "DEISOLATE_HOST"}


def test_queue_unavailable_keeps_actual_state():
    assert _containment_state(_agent(False), queued=False) == {
        "isolated": False, "pending": None,
    }
    assert _containment_state(_agent(True), queued=False, releasing=True) == {
        "isolated": True, "pending": None,
    }
