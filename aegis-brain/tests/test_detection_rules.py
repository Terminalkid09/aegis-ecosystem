import pytest
from app.api.schemas.common import EventSchema
from app.rules.heuristic_engine import HeuristicEngine
from app.rules.rule_definitions import (
    ALL_RULES, STATIC_RULES,
    rule_known_attack_tool, rule_suspicious_execution_path,
    rule_script_interpreter_abuse, rule_privilege_escalation,
    rule_double_extension, rule_encoded_command, rule_network_tool,
    rule_suspicious_parent_child, rule_malware_family,
    rule_persistence_path, rule_dll_hijack_path, rule_lolbin_usage,
    rule_high_thread_count, rule_network_beacon, rule_persistence_autorun,
    CREDENTIAL_TOOLS, SCANNER_TOOLS, EXPLOIT_TOOLS, POST_EXPLOIT_TOOLS,
    RAT_TOOLS, RANSOMWARE, EVASION_TOOLS, INFO_STEALERS,
    SUSPICIOUS_PATHS, SCRIPT_INTERPRETERS, SUSPICIOUS_PARENT_CHILD,
    MALWARE_FAMILIES,
)
from datetime import datetime


@pytest.fixture
def engine():
    return HeuristicEngine()


def make_event(process_name, **kw):
    """Helper to create EventSchema with defaults."""
    d = dict(
        agent_id="test-agent",
        timestamp=datetime.now(),
        event_type="PROCESS_CREATED",
        process_name=process_name,
        user="test-user",
    )
    d.update(kw)
    return EventSchema(**d)


# ═══════════════════════════════════════════════════════════════════
#  STATIC RULES — UNIT TESTS
# ═══════════════════════════════════════════════════════════════════

class TestRuleKnownAttackTool:
    def test_mimikatz_detected(self):
        r = rule_known_attack_tool(make_event("mimikatz.exe"))
        assert r.triggered and r.severity == "CRITICAL"

    def test_lockbit_detected(self):
        r = rule_known_attack_tool(make_event("lockbit.exe"))
        assert r.triggered

    def test_conti_detected(self):
        r = rule_known_attack_tool(make_event("conti.exe"))
        assert r.triggered

    def test_lazagne_detected(self):
        r = rule_known_attack_tool(make_event("lazagne.exe"))
        assert r.triggered

    def test_redline_detected(self):
        r = rule_known_attack_tool(make_event("redline.exe"))
        assert r.triggered

    def test_cobalt_strike_detected(self):
        r = rule_known_attack_tool(make_event("cobalt_strike"))
        assert r.triggered

    def test_sliver_detected(self):
        r = rule_known_attack_tool(make_event("sliver-server.exe"))
        assert r.triggered

    def test_normal_chrome_not_flagged(self):
        r = rule_known_attack_tool(make_event("chrome.exe"))
        assert not r.triggered


class TestRuleSuspiciousExecutionPath:
    def test_temp_path_flagged(self):
        r = rule_suspicious_execution_path(
            make_event("mal.exe", process_path=r"C:\Users\test\AppData\Local\Temp\mal.exe")
        )
        assert r.triggered and r.severity == "HIGH"

    def test_desktop_path_flagged(self):
        r = rule_suspicious_execution_path(
            make_event("mal.exe", process_path=r"C:\Users\test\Desktop\mal.exe")
        )
        assert r.triggered

    def test_program_files_not_flagged(self):
        r = rule_suspicious_execution_path(
            make_event("chrome.exe", process_path=r"C:\Program Files\Google\Chrome\chrome.exe")
        )
        assert not r.triggered


class TestRuleScriptInterpreter:
    def test_powershell_flagged(self):
        r = rule_script_interpreter_abuse(make_event("powershell.exe"))
        assert r.triggered and r.severity == "MEDIUM"

    def test_python3_flagged(self):
        r = rule_script_interpreter_abuse(make_event("python3"))
        assert r.triggered

    def test_bash_flagged(self):
        r = rule_script_interpreter_abuse(make_event("bash"))
        assert r.triggered

    def test_normal_not_flagged(self):
        r = rule_script_interpreter_abuse(make_event("chrome.exe"))
        assert not r.triggered


class TestRulePrivilegeEscalation:
    def test_chrome_as_system_flagged(self):
        r = rule_privilege_escalation(
            make_event("chrome.exe", user="SYSTEM")
        )
        assert r.triggered and r.severity == "HIGH"

    def test_notepad_as_root_flagged(self):
        r = rule_privilege_escalation(
            make_event("notepad.exe", user="root")
        )
        assert r.triggered

    def test_normal_user_not_flagged(self):
        r = rule_privilege_escalation(make_event("chrome.exe", user="test-user"))
        assert not r.triggered


class TestRuleDoubleExtension:
    def test_pdf_exe_flagged(self):
        r = rule_double_extension(make_event("invoice.pdf.exe"))
        assert r.triggered and r.severity == "HIGH"

    def test_doc_ps1_flagged(self):
        r = rule_double_extension(make_event("document.doc.ps1"))
        assert r.triggered

    def test_normal_exe_not_flagged(self):
        r = rule_double_extension(make_event("chrome.exe"))
        assert not r.triggered


class TestRuleEncodedCommand:
    def test_encoded_command_flagged(self):
        r = rule_encoded_command(
            make_event("powershell.exe", process_path="powershell -enc SQBFAFgAIABOAEUAVwAtAE8AQgBKAEUAQwBUAA==")
        )
        assert r.triggered and r.severity == "HIGH"

    def test_normal_command_not_flagged(self):
        r = rule_encoded_command(
            make_event("powershell.exe", process_path="powershell -NoProfile -Command Get-Process")
        )
        assert not r.triggered


class TestRuleNetworkTool:
    def test_nmap_in_temp_flagged(self):
        r = rule_network_tool(
            make_event("nmap.exe", process_path=r"C:\temp\nmap.exe")
        )
        assert r.triggered and r.severity == "MEDIUM"

    def test_nmap_in_program_files_not_flagged(self):
        r = rule_network_tool(
            make_event("nmap.exe", process_path=r"C:\Program Files\Nmap\nmap.exe")
        )
        assert not r.triggered


class TestRuleSuspiciousParentChild:
    def test_word_spawning_powershell_critical(self):
        r = rule_suspicious_parent_child(
            make_event("powershell.exe", parent_pid=100, parent_process_name="WINWORD.EXE")
        )
        assert r.triggered and r.severity == "CRITICAL"

    def test_chrome_spawning_cmd_flagged(self):
        r = rule_suspicious_parent_child(
            make_event("cmd.exe", parent_pid=200, parent_process_name="chrome.exe")
        )
        assert r.triggered

    def test_pdf_spawning_powershell_critical(self):
        r = rule_suspicious_parent_child(
            make_event("powershell.exe", parent_pid=300, parent_process_name="acrord32.exe")
        )
        assert r.triggered and r.severity == "CRITICAL"

    def test_email_spawning_script_critical(self):
        r = rule_suspicious_parent_child(
            make_event("wscript.exe", parent_pid=400, parent_process_name="outlook.exe")
        )
        assert r.triggered and r.severity == "CRITICAL"

    def test_explorer_spawning_reliable_medium(self):
        r = rule_suspicious_parent_child(
            make_event("rundll32.exe", parent_pid=500, parent_process_name="explorer.exe")
        )
        assert r.triggered and r.severity == "MEDIUM"

    def test_system_spawning_svchost_not_flagged(self):
        r = rule_suspicious_parent_child(
            make_event("svchost.exe", parent_pid=4, parent_process_name="System", user="SYSTEM")
        )
        assert not r.triggered

    def test_explorer_spawning_chrome_not_flagged(self):
        r = rule_suspicious_parent_child(
            make_event("chrome.exe", parent_pid=1000, parent_process_name="explorer.exe")
        )
        assert not r.triggered


class TestRuleMalwareFamily:
    def test_lockbit_flagged(self):
        r = rule_malware_family(make_event("lockbit.exe"))
        assert r.triggered

    def test_trojan_flagged(self):
        r = rule_malware_family(make_event("trojan.exe"))
        assert r.triggered and r.severity == "HIGH"

    def test_ransomware_flagged(self):
        r = rule_malware_family(make_event("ransomware.exe"))
        assert r.triggered and r.severity == "HIGH"

    def test_keylogger_flagged(self):
        r = rule_malware_family(make_event("keylogger.exe"))
        assert r.triggered and r.severity == "HIGH"

    def test_miner_flagged(self):
        r = rule_malware_family(make_event("miner.exe"))
        assert r.triggered and r.severity == "MEDIUM"

    def test_normal_not_flagged(self):
        r = rule_malware_family(make_event("chrome.exe"))
        assert not r.triggered


class TestRulePersistencePath:
    def test_startup_path_flagged(self):
        r = rule_persistence_path(
            make_event("mal.exe", process_path=r"C:\Users\test\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\mal.exe")
        )
        assert r.triggered and r.severity == "HIGH"

    def test_cron_path_flagged(self):
        r = rule_persistence_path(
            make_event("mal", process_path="/etc/cron.d/mal")
        )
        assert r.triggered

    def test_normal_path_not_flagged(self):
        r = rule_persistence_path(
            make_event("chrome.exe", process_path=r"C:\Program Files\chrome.exe")
        )
        assert not r.triggered


class TestRuleDllHijack:
    def test_dll_in_temp_flagged(self):
        r = rule_dll_hijack_path(
            make_event("evil.dll", process_path=r"C:\Users\test\AppData\Local\Temp\evil.dll")
        )
        assert r.triggered and r.severity == "HIGH"

    def test_exe_not_flagged(self):
        r = rule_dll_hijack_path(
            make_event("evil.exe", process_path=r"C:\temp\evil.exe")
        )
        assert not r.triggered

    def test_dll_in_system32_not_flagged(self):
        r = rule_dll_hijack_path(
            make_event("win32u.dll", process_path=r"C:\Windows\System32\win32u.dll")
        )
        assert not r.triggered


class TestRuleLolbinAbuse:
    def test_rundll32_in_temp_flagged(self):
        r = rule_lolbin_usage(
            make_event("rundll32.exe", process_path=r"C:\temp\rundll32.exe")
        )
        assert r.triggered and r.severity == "HIGH"

    def test_powershell_in_temp_flagged(self):
        r = rule_lolbin_usage(
            make_event("powershell.exe", process_path=r"C:\temp\powershell.exe")
        )
        assert r.triggered

    def test_rundll32_in_system32_not_flagged(self):
        r = rule_lolbin_usage(
            make_event("rundll32.exe", process_path=r"C:\Windows\System32\rundll32.exe")
        )
        assert not r.triggered


class TestRuleHighThreadCount:
    def test_high_threads_flagged(self):
        r = rule_high_thread_count(
            make_event("test.exe", thread_count=300)
        )
        assert r.triggered and r.severity == "MEDIUM"

    def test_normal_threads_not_flagged(self):
        r = rule_high_thread_count(
            make_event("chrome.exe", thread_count=45)
        )
        assert not r.triggered


class TestRuleNetworkBeacon:
    def test_outbound_to_public_ip_flagged(self):
        r = rule_network_beacon(
            make_event("beacon.exe", network_connections=[
                {"remote": "185.234.72.18:443", "state": "ESTABLISHED"}
            ])
        )
        assert r.triggered and r.severity == "MEDIUM"

    def test_private_ip_not_flagged(self):
        r = rule_network_beacon(
            make_event("chrome.exe", network_connections=[
                {"remote": "10.0.0.1:443", "state": "ESTABLISHED"}
            ])
        )
        assert not r.triggered

    def test_no_connections_not_flagged(self):
        r = rule_network_beacon(make_event("chrome.exe"))
        assert not r.triggered


class TestRulePersistenceAutorun:
    def test_svch0st_flagged(self):
        r = rule_persistence_autorun(make_event("svch0st.exe"))
        assert r.triggered and r.severity == "HIGH"

    def test_update_flagged(self):
        r = rule_persistence_autorun(make_event("update.exe"))
        assert r.triggered

    def test_chrome_not_flagged(self):
        r = rule_persistence_autorun(make_event("chrome.exe"))
        assert not r.triggered


# ═══════════════════════════════════════════════════════════════════
#  INTEGRATION TEST — HeuristicEngine
# ═══════════════════════════════════════════════════════════════════

@pytest.mark.asyncio
async def test_engine_detects_mimikatz(engine):
    e = make_event("mimikatz.exe")
    r = await engine.analyze(e)
    assert r.is_threat and r.severity == "CRITICAL"


@pytest.mark.asyncio
async def test_engine_detects_suspicious_parent_child(engine):
    e = make_event("powershell.exe", parent_pid=100, parent_process_name="WINWORD.EXE")
    r = await engine.analyze(e)
    assert r.is_threat and r.severity == "CRITICAL"


@pytest.mark.asyncio
async def test_engine_detects_lolbin_abuse(engine):
    e = make_event("rundll32.exe", process_path=r"C:\temp\rundll32.exe")
    r = await engine.analyze(e)
    assert r.is_threat and r.severity == "HIGH"


@pytest.mark.asyncio
async def test_engine_detects_high_thread_count(engine):
    e = make_event("test.exe", thread_count=300)
    r = await engine.analyze(e)
    assert r.is_threat and r.severity == "MEDIUM"


@pytest.mark.asyncio
async def test_engine_benign_event_not_flagged(engine):
    e = make_event("chrome.exe",
                   process_path=r"C:\Program Files\Google\Chrome\Application\chrome.exe",
                   parent_pid=1000, parent_process_name="explorer.exe",
                   thread_count=45)
    r = await engine.analyze(e)
    assert not r.is_threat


# ═══════════════════════════════════════════════════════════════════
#  THREAT DATABASE SIZE VERIFICATION
# ═══════════════════════════════════════════════════════════════════

class TestThreatDatabaseSize:
    def test_total_attack_tools_over_200(self):
        combined = CREDENTIAL_TOOLS | SCANNER_TOOLS | EXPLOIT_TOOLS | POST_EXPLOIT_TOOLS | RAT_TOOLS | RANSOMWARE | EVASION_TOOLS | INFO_STEALERS
        assert len(combined) >= 200, f"Only {len(combined)} attack tools — expected 200+"

    def test_static_rules_count(self):
        assert len(STATIC_RULES) >= 15, f"Only {len(STATIC_RULES)} rules — expected 15+"

    def test_suspicious_parent_child_rules_count(self):
        assert len(SUSPICIOUS_PARENT_CHILD) >= 7

    def test_malware_family_patterns_count(self):
        assert len(MALWARE_FAMILIES) >= 17

    def test_suspicious_paths_count(self):
        assert len(SUSPICIOUS_PATHS) >= 15

    def test_script_interpreters_count(self):
        assert len(SCRIPT_INTERPRETERS) >= 30
