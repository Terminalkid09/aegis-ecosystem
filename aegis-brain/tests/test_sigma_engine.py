"""Test del motore Sigma: caricamento, logsource, modificatori, condizioni.

Ogni regola del bundle viene provata **positiva e negativa**: una regola che
scatta su tutto è inutile quanto una che non scatta mai.
"""
import os

import pytest

from app.ingest import default_registry as registry
from app.rules.sigma.engine import SigmaEngine
from app.rules.sigma.matcher import compile_field_match, level_to_severity

LOGS = os.path.join(os.path.dirname(__file__), "corpus", "logs")
eng = SigmaEngine()


def _events(filename: str, source: str = "auto"):
    with open(os.path.join(LOGS, filename), encoding="utf-8") as fh:
        result = registry.parse(source, fh.read(), {"source": "test"})
    assert result.events, f"nessun evento da {filename}: {result.errors}"
    return result.events


def _fire(event) -> set:
    return {m.title for m in eng.evaluate(event)}


def _win(event_dict):
    result = registry.parse("windows_event", event_dict, {"source": "win-test"})
    assert result.events, result.errors
    return result.events[0]


# ── caricamento e copertura ─────────────────────────────────────────────────
def test_all_bundled_rules_are_executable():
    coverage = eng.coverage()
    assert coverage["rules_total"] >= 14
    assert coverage["rules_excluded"] == 0, coverage["excluded"]
    assert coverage["rules_executable"] == coverage["rules_total"]


def test_coverage_maps_mitre_techniques():
    coverage = eng.coverage()
    assert "T1070.001" in coverage["mitre_techniques"]
    assert "T1543.003" in coverage["mitre_techniques"]
    assert coverage["by_level"]["critical"] >= 1


def test_rule_summary_exposes_metadata():
    summary = eng.get_rule("3f2a1b64-0f6b-4a17-9d0e-6c1f4a2b7d10").to_summary()
    assert summary["executable"] is True
    assert summary["condition"] == "selection"
    assert "selection" in summary["selections"]
    assert summary["falsepositives"], "una regola deve dichiarare i falsi positivi attesi"


# ── Windows Event Log ───────────────────────────────────────────────────────
def test_log_cleared_rule():
    events = _events("windows_security.jsonl")
    cleared = [e for e in events if e.extra["event_type"] == "log_cleared"]
    assert "Windows Event Log Cleared" in _fire(cleared[0])
    # Un evento normale NON deve attivarla.
    logon = [e for e in events if e.extra["event_type"] == "auth_success"][0]
    assert "Windows Event Log Cleared" not in _fire(logon)


def test_service_installed_from_temp_rule():
    events = _events("windows_security.jsonl")
    service = [e for e in events if e.extra["event_type"] == "service_installed"][0]
    assert "Service Installed From User-Writable Directory" in _fire(service)


def test_service_installed_benign_path_does_not_fire():
    benign = _win({"Id": 7045, "Channel": "System", "Computer": "W",
                   "EventData": {"ServiceName": "GoodSvc",
                                 "ImagePath": r"C:\Program Files\Vendor\svc.exe"}})
    assert "Service Installed From User-Writable Directory" not in _fire(benign)


def test_powershell_encoded_command_rule():
    events = _events("windows_security.jsonl")
    ps = [e for e in events if e.extra["event_type"] == "powershell_script_block"][0]
    assert "PowerShell Script Block With Encoded Or In-Memory Payload" in _fire(ps)


def test_process_from_user_writable_dir_rule():
    events = _events("windows_security.jsonl")
    proc = [e for e in events if e.extra["event_type"] == "process_creation"][0]
    assert "Process Execution From User-Writable Directory" in _fire(proc)


def test_process_creation_filter_excludes_signed_setup():
    signing = _win({"Id": 4688, "Channel": "Security", "Computer": "W",
                    "EventData": {"NewProcessName": r"C:\Users\bob\Downloads\setup.exe",
                                  "CommandLine": "setup.exe"}})
    assert "Process Execution From User-Writable Directory" not in _fire(signing)


def test_failed_logon_builtin_rule_fires_only_on_privileged_accounts():
    events = _events("windows_security.jsonl")
    failures = [e for e in events if e.extra["event_type"] == "auth_failure"]
    fired = [e for e in failures if "Failed Logon Against Built-in Or Admin Account" in _fire(e)]
    assert len(fired) == 2, "solo i due tentativi su Administrator"
    assert all(e.user.lower() == "administrator" for e in fired)


def test_admin_group_member_added_rule():
    event = _win({"Id": 4728, "Channel": "Security", "Computer": "W",
                  "EventData": {"MemberName": r"CORP\bob", "GroupName": "Administrators"}})
    assert "User Added To Privileged Local Group" in _fire(event)
    benign = _win({"Id": 4728, "Channel": "Security", "Computer": "W",
                   "EventData": {"MemberName": r"CORP\bob", "GroupName": "Backup Operators"}})
    assert "User Added To Privileged Local Group" not in _fire(benign)


def test_scheduled_task_rule_excludes_microsoft_tasks():
    evil = _win({"Id": 4698, "Channel": "Security", "Computer": "W",
                 "EventData": {"TaskName": r"\Evil\Update", "SubjectUserName": "bob"}})
    assert "Scheduled Task Created" in _fire(evil)
    system = _win({"Id": 4698, "Channel": "Security", "Computer": "W",
                   "EventData": {"TaskName": r"\Microsoft\Windows\Update", "SubjectUserName": "SYSTEM"}})
    assert "Scheduled Task Created" not in _fire(system), "i task di sistema sono filtrati"


# ── Linux / syslog ─────────────────────────────────────────────────────────
def test_ssh_authentication_failure_rule():
    events = _events("syslog.log")
    failures = [e for e in events if e.extra.get("event_type") == "auth_failure"]
    assert failures and "SSH Authentication Failure" in _fire(failures[0])


def test_ssh_root_login_rule():
    result = registry.parse(
        "syslog",
        "<38>Sep 15 12:00:01 web sshd[9]: Accepted password for root from 10.0.0.5 port 55 ssh2",
        {"source": "linux"})
    assert "Direct Root SSH Login" in _fire(result.events[0])
    # Un login non-root non deve attivarla.
    other = registry.parse(
        "syslog",
        "<38>Sep 15 12:00:01 web sshd[9]: Accepted password for deploy from 10.0.0.5 port 55 ssh2",
        {"source": "linux"})
    assert "Direct Root SSH Login" not in _fire(other.events[0])


# ── Rete ───────────────────────────────────────────────────────────────────
def test_dns_suspicious_tld_rule_and_allowlist():
    events = _events("zeek_dns.log")
    by_query = {e.dns_query: e for e in events}
    assert "DNS Query To Frequently Abused TLD" in _fire(by_query["secure-update.top"])
    assert "DNS Query To Frequently Abused TLD" not in _fire(by_query["cdn.example.com"])


def test_dns_tunneling_regex_rule():
    events = _events("zeek_dns.log")
    long_query = [e for e in events if e.dns_query and len(e.dns_query.split(".")[0]) >= 40][0]
    assert "DNS Query With Suspiciously Long Labels" in _fire(long_query)


def test_suricata_malware_alert_rule():
    events = _events("suricata_eve.json")
    alert = [e for e in events if e.extra.get("suricata_event_type") == "alert"][0]
    assert "Suricata Alert For Malware Or C2 Category" in _fire(alert)
    # Un evento non-alert di Suricata non deve scattare.
    dns = [e for e in events if e.extra.get("suricata_event_type") == "dns"][0]
    assert "Suricata Alert For Malware Or C2 Category" not in _fire(dns)


def test_suricata_low_severity_filter():
    result = registry.parse("suricata", {
        "timestamp": "2026-09-15T12:00:00+0000", "event_type": "alert",
        "src_ip": "10.0.0.5", "dest_ip": "1.2.3.4",
        "alert": {"signature": "ET INFO Misc", "category": "A Network Trojan was detected",
                  "severity": 3}}, {"source": "ids"})
    assert result.events, result.errors
    assert "Suricata Alert For Malware Or C2 Category" not in _fire(result.events[0])


def test_firewall_denied_admin_port_rule():
    events = _events("pfirewall.log")
    denied = [e for e in events if e.extra["event_type"] == "network_denied"]
    hits = [e for e in denied if "Firewall Denied Connection To Remote Administration Port" in _fire(e)]
    assert len(hits) == 2, "445 e 3389 sì, 1434 (SQL) no"
    assert {e.dst_port for e in hits} == {445, 3389}
    allowed = [e for e in events if e.extra["event_type"] == "network_allow"][0]
    assert "Firewall Denied Connection To Remote Administration Port" not in _fire(allowed)


def test_proxy_executable_download_rule():
    events = _events("squid_access.log")
    denied = [e for e in events if e.extra.get("event_type") == "proxy_denied"][0]
    assert "Executable Or Script Download Through Web Proxy" in _fire(denied)
    # Un download HTML legittimo non deve far scattare la regola.
    html = [e for e in events if "microsoftonline" in (e.url or "")][0]
    assert "Executable Or Script Download Through Web Proxy" not in _fire(html)


# ── isolamento della logsource ──────────────────────────────────────────────
def test_windows_rules_do_not_apply_to_network_events():
    zeek_event = _events("zeek_dns.log")[0]
    windows_rules = [r for r in eng.rules() if r.logsource.get("product") == "windows"]
    assert windows_rules
    for rule in windows_rules:
        assert not eng.logsource_matches(rule, zeek_event), rule.title


def test_zeek_rules_do_not_apply_to_windows_events():
    win_event = _events("windows_security.jsonl")[0]
    for rule in eng.rules():
        if rule.logsource.get("product") == "zeek":
            assert not eng.logsource_matches(rule, win_event), rule.title


def test_sysmon_service_maps_to_channel():
    sysmon = _win({"Id": 1, "Channel": "Microsoft-Windows-Sysmon/Operational",
                   "Computer": "W", "EventData": {"Image": "C:\\x.exe", "CommandLine": "x"}})
    assert sysmon.process_name == "C:\\x.exe"
    assert sysmon.extra["event_type"] == "process_creation"


# ── modificatori (unit) ────────────────────────────────────────────────────
def _matcher(field, modifiers, patterns, values):
    def get_values(_event, _field):
        return values.get(_field, [])
    predicate, problems = compile_field_match(field, modifiers, patterns, get_values,
                                             lambda e, f: f in values)
    assert not problems, problems
    return predicate


def test_modifier_contains_and_endswith_and_startswith():
    assert _matcher("f", ["contains"], "admin", {"f": ["domain admin user"]})(None)
    assert not _matcher("f", ["contains"], "root", {"f": ["domain admin user"]})(None)
    assert _matcher("f", ["endswith"], ["admin", "root"], {"f": ["superadmin"]})(None)
    assert _matcher("f", ["startswith"], r"C:\Windows", {"f": [r"C:\Windows\System32\x.exe"]})(None)


def test_modifier_wildcards_are_supported_by_default():
    assert _matcher("f", [], "*cmd.exe*", {"f": [r"C:\Windows\System32\cmd.exe"]})(None)
    assert _matcher("f", [], "power?hell", {"f": ["powershell"]})(None)
    assert not _matcher("f", [], "power?hell", {"f": ["powershellx"]})(None)


def test_modifier_case_sensitivity():
    assert _matcher("f", [], "ADMIN", {"f": ["admin"]})(None)
    assert not _matcher("f", ["cased"], "ADMIN", {"f": ["admin"]})(None)


def test_modifier_re_and_numeric_and_cidr_and_exists():
    assert _matcher("f", ["re"], r"[a-z0-9]{5,}\.", {"f": ["abcdef1234.evil.net"]})(None)
    assert _matcher("f", ["gt"], 1000, {"f": [1800]})(None)
    assert not _matcher("f", ["gt"], 2000, {"f": [1800]})(None)
    assert _matcher("f", ["cidr"], "10.0.0.0/8", {"f": ["10.4.5.6"]})(None)
    assert not _matcher("f", ["cidr"], "10.0.0.0/8", {"f": ["11.4.5.6"]})(None)
    assert _matcher("f", ["exists"], True, {"f": ["x"]})(None)
    assert _matcher("f", ["exists"], False, {})(None)


def test_modifier_all_requires_every_pattern():
    assert _matcher("f", ["contains", "all"], ["a", "b"], {"f": ["ab"]})(None)
    assert not _matcher("f", ["contains", "all"], ["a", "z"], {"f": ["ab"]})(None)


def test_modifier_base64offset_and_windash():
    import base64
    encoded = base64.b64encode(b"Invoke-Mimikatz").decode()
    assert _matcher("f", ["base64offset"], "Invoke-Mimikatz", {"f": [encoded]})(None)
    assert _matcher("f", ["windash"], "-EncodedCommand",
                    {"f": ["/EncodedCommand"]})(None)


def test_unsupported_modifier_is_reported_not_ignored():
    predicate, problems = compile_field_match("f", ["expand"], "x", lambda e, f: [], lambda e, f: False)
    assert predicate is None
    assert problems and "unsupported" in problems[0]
    predicate, problems = compile_field_match("f", ["fieldref"], "x", lambda e, f: [], lambda e, f: False)
    assert predicate is None and problems


def test_level_to_severity_mapping():
    assert level_to_severity("critical") == "CRITICAL"
    assert level_to_severity("informational") == "INFO"
    assert level_to_severity("unknown-level") == "MEDIUM"


# ── condizioni (unit) ──────────────────────────────────────────────────────
def test_condition_quantifiers_and_boolean_logic():
    from app.rules.sigma.compiler import compile_condition
    fn = compile_condition("1 of them", ["a", "b", "c"])
    assert fn({"a": False, "b": True, "c": False}) is True
    assert fn({"a": False, "b": False, "c": False}) is False

    fn = compile_condition("all of selection*", ["selection_a", "selection_b", "other"])
    assert fn({"selection_a": True, "selection_b": True, "other": False}) is True
    assert fn({"selection_a": True, "selection_b": False, "other": True}) is False

    fn = compile_condition("2 of them", ["a", "b", "c"])
    assert fn({"a": True, "b": True, "c": False}) is True
    assert fn({"a": True, "b": False, "c": False}) is False

    fn = compile_condition("selection and not filter", ["selection", "filter"])
    assert fn({"selection": True, "filter": False}) is True
    assert fn({"selection": True, "filter": True}) is False

    fn = compile_condition("(a or b) and c", ["a", "b", "c"])
    assert fn({"a": True, "b": False, "c": True}) is True
    assert fn({"a": True, "b": True, "c": False}) is False


def test_condition_referencing_unknown_selection_is_rejected():
    from app.rules.sigma.compiler import compile_condition
    with pytest.raises(ValueError):
        compile_condition("selection and missing", ["selection"])


def test_malformed_rule_is_excluded_not_executed():
    from app.rules.sigma.loader import build_rule
    rule = build_rule({
        "title": "Broken",
        "logsource": {"product": "windows"},
        "detection": {"selection": {"CommandLine|expand": "x"}, "condition": "selection"},
    })
    assert rule is not None
    assert rule.executable is False
    assert rule.unsupported
