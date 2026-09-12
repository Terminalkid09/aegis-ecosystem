"""Fase 1 (M0): retention configurabile — default approvati, nessun DB richiesto."""

from app.core.config import Settings


def test_retention_defaults_match_approved_decisions():
    fields = Settings.model_fields
    assert fields["RETENTION_TELEMETRY_DAYS"].default == 14
    assert fields["RETENTION_ALERTS_DAYS"].default == 90
    assert fields["RETENTION_AUDIT_DAYS"].default == 365
    assert fields["RETENTION_SYSLOG_DAYS"].default == 30


def test_retention_values_are_positive():
    for name in (
        "RETENTION_TELEMETRY_DAYS",
        "RETENTION_ALERTS_DAYS",
        "RETENTION_AUDIT_DAYS",
        "RETENTION_SYSLOG_DAYS",
    ):
        assert Settings.model_fields[name].default > 0
