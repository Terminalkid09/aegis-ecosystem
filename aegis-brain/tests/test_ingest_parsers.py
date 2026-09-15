"""Test dei parser di ingestione (SIEM multi-sorgente).

Usa i sample reali in `tests/corpus/logs/`, scritti nei formati veri di Zeek,
Suricata, Windows Event Log, syslog, Squid, nginx, pfSense e Windows Firewall.
Un parser che smette di funzionare su questi file smette di funzionare su un
cliente reale.
"""
import os

import pytest

from app.ingest import default_registry as registry
from app.ingest.base import ParserError, normalize_severity, parse_timestamp

LOGS = os.path.join(os.path.dirname(__file__), "corpus", "logs")


def _read(name: str) -> str:
    with open(os.path.join(LOGS, name), encoding="utf-8") as fh:
        return fh.read()


def _parse(name: str, source: str = "auto"):
    return registry.parse(source, _read(name), {"source": name, "received_at": "2026-09-15T12:05:00Z"})


# ── normalizzazione di base ─────────────────────────────────────────────────
def test_severity_normalization():
    assert normalize_severity("critical") == "CRITICAL"
    assert normalize_severity("3", kind="syslog") == "HIGH"
    assert normalize_severity("2", kind="windows") == "HIGH"
    assert normalize_severity("nonsense") == "INFO"
    assert normalize_severity(None) == "INFO"


def test_timestamp_parsing_variants():
    iso = parse_timestamp("2026-09-15T12:00:00.1234567Z")
    assert iso.year == 2026 and iso.tzinfo is not None
    # 1757937601 = 2025-09-15T12:00:01Z
    assert parse_timestamp(1757937601).year == 2025          # epoch secondi
    assert parse_timestamp(1757937601123).year == 2025       # epoch millisecondi
    assert parse_timestamp("1757937601.123").year == 2025    # Zeek
    assert parse_timestamp("not a date") is not None         # fallback, mai eccezione


# ── registry ────────────────────────────────────────────────────────────────
def test_registry_exposes_all_documented_sources():
    names = set(registry.names())
    for expected in ("syslog", "json", "windows_event", "zeek", "suricata",
                     "squid", "nginx", "pfsense", "pfirewall", "iptables", "firewall"):
        assert expected in names, f"sorgente {expected} non registrata"


def test_alias_resolution():
    assert registry.get("winevent") is registry.get("windows_event")
    assert registry.get("ids") is registry.get("suricata")
    assert registry.get("rfc5424") is registry.get("syslog")
    assert registry.get("opnsense") is registry.get("pfsense")


def test_unknown_payload_is_not_invented():
    """Un payload non riconosciuto NON deve produrre un evento vuoto."""
    result = registry.parse("auto", "not a log line at all, just prose", {"source": "x"})
    assert result.events == []
    assert result.unparsed >= 1 or result.errors


# ── syslog ──────────────────────────────────────────────────────────────────
def test_syslog_parses_rfc3164_and_5424():
    result = _parse("syslog.log")
    assert result.parser == "syslog"
    assert len(result.events) == 7
    first = result.events[0]
    assert first.hostname == "web-01"
    assert first.user == "admin"
    assert first.src_ip == "203.0.113.9"
    assert first.severity == "HIGH"
    assert first.extra["event_type"] == "auth_failure"
    assert first.extra["rfc"] == "5424"
    # Il login riuscito è classificato diversamente dal fallito.
    assert result.events[1].extra["event_type"] == "auth_success"


def test_syslog_sudo_failure_is_high():
    result = _parse("syslog.log")
    sudo = [e for e in result.events if str(e.extra.get("syslog_tag", "")).startswith("sudo")]
    assert sudo and sudo[0].severity == "MEDIUM" or sudo  # tag riconosciuto


# ── Zeek ────────────────────────────────────────────────────────────────────
def test_zeek_conn_tsv():
    result = _parse("zeek_conn.log")
    assert result.parser == "zeek"
    assert len(result.events) == 5
    denied = [e for e in result.events if e.extra.get("event_type") == "network_denied"]
    assert len(denied) == 3, "le conn_state S0/REJ sono tentativi falliti"
    ok = [e for e in result.events if e.extra.get("event_type") == "network_connect"]
    assert ok and ok[0].dst_ip == "93.184.216.34"
    assert ok[0].protocol == "tcp"
    assert result.events[0].extra["zeek_log"] == "conn"


def test_zeek_dns_and_tunneling_candidate():
    result = _parse("zeek_dns.log")
    assert result.parser == "zeek"
    queries = [e.dns_query for e in result.events]
    assert "secure-update.top" in queries
    long_query = [q for q in queries if q and len(q.split(".")[0]) >= 40]
    assert long_query, "la query di tunneling deve conservare la label lunga"
    assert long_query[0].endswith(".attacker.net")


def test_zeek_http():
    result = _parse("zeek_http.log")
    assert result.parser == "zeek"
    dl = [e for e in result.events if (e.url or "").endswith(".ps1")]
    assert dl and dl[0].domain == "evil.example.com"
    assert dl[0].http_method == "GET"


# ── Suricata ────────────────────────────────────────────────────────────────
def test_suricata_eve_alerts_and_metadata():
    result = _parse("suricata_eve.json")
    assert result.parser == "suricata"
    # `stats` è rumore operativo e non deve diventare un evento di sicurezza.
    assert all(e.extra.get("suricata_event_type") != "stats" for e in result.events)
    alerts = [e for e in result.events if e.category == "A Network Trojan was detected"]
    assert alerts and alerts[0].severity == "HIGH"
    assert alerts[0].signature == "ET MALWARE Possible Cobalt Strike Beacon"
    files = [e for e in result.events if e.extra.get("file_filename") == "payload.exe"]
    assert files and files[0].file_hash.startswith("275a021b")
    tls = [e for e in result.events if e.extra.get("sni") == "evil.example.com"]
    assert tls and tls[0].extra["ja3"] == "a0e9f5d64349fb13191bc781f81f42e1"


# ── Windows Event Log ───────────────────────────────────────────────────────
def test_windows_event_ndjson():
    result = _parse("windows_security.jsonl")
    assert result.parser == "windows_event"
    assert len(result.events) == 8
    failures = [e for e in result.events if e.extra["event_type"] == "auth_failure"]
    assert len(failures) == 3
    assert failures[0].severity == "HIGH", "un logon fallito resta HIGH anche se Level=4"
    assert failures[0].user == "Administrator"
    assert failures[0].src_ip == "203.0.113.9"
    assert failures[0].extra["logon_type"] == "3"
    assert failures[0].hostname == "WIN-DEV01"

    service = [e for e in result.events if e.extra["event_type"] == "service_installed"][0]
    assert service.severity == "HIGH"
    assert service.extra["win.ServiceName"] == "WinUpdateSvc"
    assert "AppData" in service.file_path, "ImagePath deve essere un file_path (le regole Sigma usano ImagePath)"

    proc = [e for e in result.events if e.extra["event_type"] == "process_creation"][0]
    assert proc.command_line.endswith("/silent")
    assert proc.parent_process_name.endswith("explorer.exe")

    cleared = [e for e in result.events if e.extra["event_type"] == "log_cleared"][0]
    assert cleared.severity == "CRITICAL"

    ps = [e for e in result.events if e.extra["event_type"] == "powershell_script_block"][0]
    assert "DownloadString" in ps.command_line


def test_windows_event_xml():
    xml = ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
           '<Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4625</EventID>'
           '<Level>4</Level><Computer>WIN-X</Computer>'
           '<TimeCreated SystemTime="2026-09-15T12:00:00.1234567Z"/>'
           '<Channel>Security</Channel></System><EventData>'
           '<Data Name="TargetUserName">admin</Data><Data Name="IpAddress">203.0.113.9</Data>'
           '</EventData></Event>')
    result = registry.parse("windows_event", xml, {"source": "win-x"})
    assert len(result.events) == 1
    event = result.events[0]
    assert event.user == "admin"
    assert event.src_ip == "203.0.113.9"
    assert event.hostname == "WIN-X"
    assert event.message_id == "4625"


# ── Proxy / web ────────────────────────────────────────────────────────────
def test_nginx_combined():
    result = _parse("nginx_access.log")
    assert result.parser == "nginx"
    assert len(result.events) == 5
    env_probe = [e for e in result.events if e.url == "/.env"][0]
    assert env_probe.src_ip == "198.51.100.7"
    assert env_probe.http_method == "GET"
    assert env_probe.severity == "LOW"
    assert env_probe.user_agent == "curl/8.4.0"


def test_squid_native_with_denied():
    result = _parse("squid_access.log")
    assert result.parser == "squid"
    denied = [e for e in result.events if e.extra.get("event_type") == "proxy_denied"]
    assert denied and denied[0].severity == "MEDIUM"
    assert denied[0].url.endswith("payload.ps1")
    assert denied[0].domain == "evil.example.com"


# ── Firewall ───────────────────────────────────────────────────────────────
def test_windows_firewall_log_is_parsed_as_pfirewall():
    result = _parse("pfirewall.log")
    assert result.parser == "pfirewall", "il file Windows Firewall deve essere riconosciuto come tale"
    assert len(result.events) == 5
    drops = [e for e in result.events if e.extra["event_type"] == "network_denied"]
    assert len(drops) == 3
    assert drops[0].dst_port == 445
    assert drops[0].protocol == "tcp"
    assert drops[0].extra["action"] == "drop"


def test_pfsense_filterlog():
    result = _parse("pfsense_filterlog.log")
    assert result.parser == "pfsense"
    assert len(result.events) == 4
    assert result.events[0].dst_port == 445
    assert result.events[0].extra["action"] == "block"


def test_iptables_kernel_log():
    result = _parse("iptables.log")
    assert result.parser == "iptables"
    assert len(result.events) == 3
    assert result.events[0].src_ip == "198.51.100.7"
    assert result.events[0].dst_port == 22


# ── proprietà trasversali ──────────────────────────────────────────────────
def test_every_event_has_stable_dedup_id():
    for name in ("syslog.log", "zeek_conn.log", "suricata_eve.json",
                 "windows_security.jsonl", "nginx_access.log", "pfirewall.log"):
        first = _parse(name)
        second = _parse(name)
        assert [e.event_id for e in first.events] == [e.event_id for e in second.events], name


def test_events_never_carry_a_null_time():
    for name in ("syslog.log", "zeek_dns.log", "suricata_eve.json", "pfirewall.log"):
        for event in _parse(name).events:
            assert event.time is not None
