"""Le sei regole Sigma deception devono avere un positivo e un negativo.

Il corpus è sintetico e costruito sul contratto Kraken, non su dati di
produzione. Il caso "solo banner" è deliberatamente negativo: uno scanner che
apre la connessione senza credenziali non deve generare un alert.
"""
from datetime import datetime, timezone
from uuid import uuid4

from app.ingest import default_registry as registry
from app.rules.sigma.engine import SigmaEngine

eng = SigmaEngine()


def _event(*, sensor: str = "ssh", user: str | None = None,
           command: str | None = None, sample: str | None = None,
           category: str = "intrusion_attempt"):
    payload = {
        "events": [{
            "event_id": f"kraken:test:{uuid4().hex}:{sensor}",
            "occurred_at": datetime.now(timezone.utc).isoformat(),
            "source": "kraken",
            "category": category,
            "severity": "HIGH",
            "user": {"name": user} if user else {},
            "network": {"src_ip": "203.0.113.77", "dst_port": 22,
                        "protocol": sensor},
            "process": {"command_line": command} if command else {},
            "raw": {
                "sensor": sensor,
                "session_id": f"s-{uuid4().hex[:10]}",
                "sample_sha256": sample,
                "context": "sensor",
            },
            "tags": ["deception", "kraken"],
        }]
    }
    result = registry.parse("kraken", payload, {"source": "sigma-test"})
    assert result.events, result.errors
    return result.events[0]


def _titles(event) -> set[str]:
    return {match.title for match in eng.evaluate(event)}


def test_six_kraken_rules_are_loaded_and_executable():
    rules = [r for r in eng.rules() if (r.logsource or {}).get("product") == "kraken"]
    assert len(rules) == 6
    assert all(r.executable for r in rules), [r.unsupported for r in rules if not r.executable]


def test_ssh_bruteforce_positive_and_banner_negative():
    assert "Deception SSH Brute Force" in _titles(_event(sensor="ssh", user="root"))
    assert "Deception SSH Brute Force" not in _titles(_event(sensor="ssh"))


def test_post_auth_commands_positive_and_negative():
    assert "Deception Commands After Authentication" in _titles(
        _event(sensor="ssh", user="root", command="id")
    )
    assert "Deception Commands After Authentication" not in _titles(
        _event(sensor="ssh", user="root")
    )


def test_credential_stuffing_positive_and_negative():
    assert "Deception Credential Stuffing" in _titles(
        _event(sensor="http", user="admin")
    )
    assert "Deception Credential Stuffing" not in _titles(_event(sensor="http"))


def test_malware_download_positive_and_negative():
    assert "Deception Malware Download" in _titles(
        _event(sensor="http", sample="a" * 64)
    )
    assert "Deception Malware Download" not in _titles(_event(sensor="http"))


def test_lateral_scan_positive_and_negative():
    assert "Deception Lateral Scan" in _titles(_event(category="port_scan"))
    assert "Deception Lateral Scan" not in _titles(_event(category="intrusion_attempt"))


def test_smb_netntlm_positive_and_negative():
    assert "Deception SMB NetNTLM Attempt" in _titles(
        _event(sensor="smb", user="Administrator")
    )
    assert "Deception SMB NetNTLM Attempt" not in _titles(_event(sensor="smb"))


def test_banner_only_scanner_produces_no_kraken_alert():
    banner = _event(sensor="ssh")
    assert not [t for t in _titles(banner) if t.startswith("Deception ")]
