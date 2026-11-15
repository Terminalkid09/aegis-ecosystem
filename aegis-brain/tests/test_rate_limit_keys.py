"""AEGIS-SEC-005: dietro proxy il bucket deve essere per IP client reale."""
from types import SimpleNamespace

from app.core import rate_limit


def _request(headers, peer="10.0.0.10"):
    return SimpleNamespace(headers=headers, client=SimpleNamespace(host=peer))


def test_x_forwarded_for_uses_first_valid_client(monkeypatch):
    monkeypatch.setattr(rate_limit.settings, "RATE_LIMIT_TRUST_FORWARDED_FOR", True)
    req = _request({"x-forwarded-for": "203.0.113.7, 10.0.0.1, 198.51.100.9"})
    assert rate_limit.client_key(req) == "203.0.113.7"


def test_untrusted_proxy_ignores_spoofed_header(monkeypatch):
    monkeypatch.setattr(rate_limit.settings, "RATE_LIMIT_TRUST_FORWARDED_FOR", False)
    req = _request({"x-forwarded-for": "203.0.113.7"})
    assert rate_limit.client_key(req) == "10.0.0.10"


def test_invalid_forwarded_value_falls_back_to_real_ip(monkeypatch):
    monkeypatch.setattr(rate_limit.settings, "RATE_LIMIT_TRUST_FORWARDED_FOR", True)
    req = _request({"x-forwarded-for": "not-an-ip", "x-real-ip": "198.51.100.9"})
    assert rate_limit.client_key(req) == "198.51.100.9"
