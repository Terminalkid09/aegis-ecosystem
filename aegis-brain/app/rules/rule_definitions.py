import re
from dataclasses import dataclass, field
from typing import Optional
from app.api.schemas.common import EventSchema

@dataclass
class RuleResult:
    triggered: bool
    severity: str = "LOW"
    description: str = ""
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    mitre_technique_id: Optional[str] = None

@dataclass
class StaticRule:
    name: str
    severity: str
    description: str
    mitre_tactic: str
    mitre_technique: str
    mitre_technique_id: str
    fn: callable

KNOWN_ATTACK_TOOLS = {
    "mimikatz.exe", "mimikatz", "wce.exe", "fgdump.exe", "pwdump.exe",
    "gsecdump.exe", "lsadump.exe", "procdump.exe",
    "nc.exe", "ncat.exe", "netcat", "socat",
    "nmap", "nmap.exe", "msfconsole", "msf", "metasploit",
    "cobalt_strike", "beacon.exe", "psexec.exe", "psexec64.exe",
}

SUSPICIOUS_PATHS = {
    "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\",
    "\\downloads\\", "\\desktop\\", "/tmp/", "/var/tmp/", "/dev/shm/",
}

SCRIPT_INTERPRETERS = {
    "powershell.exe", "powershell", "pwsh.exe", "cmd.exe",
    "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
    "bash", "sh", "python", "python3",
}

NON_ROOT_PROCESSES = {
    "chrome.exe", "firefox.exe", "notepad.exe", "calc.exe",
}

NETWORK_TOOLS = {
    "wireshark.exe", "wireshark", "tcpdump", "tshark",
    "netstat", "arp.exe", "arp", "route.exe",
    "curl.exe", "curl", "wget", "wget.exe",
}

def rule_known_attack_tool(event: EventSchema) -> RuleResult:
    name = event.process_name.lower().strip()
    if name in KNOWN_ATTACK_TOOLS:
        return RuleResult(
            triggered=True, severity="CRITICAL",
            description=f"Known attack tool detected: '{event.process_name}'.",
            mitre_tactic="Execution", mitre_technique="User Execution",
            mitre_technique_id="T1204"
        )
    return RuleResult(triggered=False)

def rule_suspicious_execution_path(event: EventSchema) -> RuleResult:
    if not event.process_path:
        return RuleResult(triggered=False)
    path_lower = event.process_path.lower()
    for suspicious in SUSPICIOUS_PATHS:
        if suspicious in path_lower:
            return RuleResult(
                triggered=True, severity="HIGH",
                description=f"Process '{event.process_name}' executing from suspicious path: '{event.process_path}'.",
                mitre_tactic="Execution", mitre_technique="Command and Scripting Interpreter",
                mitre_technique_id="T1059"
            )
    return RuleResult(triggered=False)

def rule_script_interpreter_abuse(event: EventSchema) -> RuleResult:
    name = event.process_name.lower().strip()
    if name in SCRIPT_INTERPRETERS:
        return RuleResult(
            triggered=True, severity="MEDIUM",
            description=f"Script interpreter '{event.process_name}' detected.",
            mitre_tactic="Execution", mitre_technique="Command and Scripting Interpreter",
            mitre_technique_id="T1059"
        )
    return RuleResult(triggered=False)

def rule_privilege_escalation(event: EventSchema) -> RuleResult:
    name = event.process_name.lower().strip()
    user = (event.user or "").lower().strip()
    is_privileged = user in {"root", "system", "nt authority\\system", "administrator"}
    is_desktop_app = name in NON_ROOT_PROCESSES
    if is_privileged and is_desktop_app:
        return RuleResult(
            triggered=True, severity="HIGH",
            description=f"Privilege escalation indicator: '{event.process_name}' is running as '{event.user}'.",
            mitre_tactic="Privilege Escalation", mitre_technique="Access Token Manipulation",
            mitre_technique_id="T1134"
        )
    return RuleResult(triggered=False)

def rule_double_extension(event: EventSchema) -> RuleResult:
    name = event.process_name.lower()
    if re.search(r'\.(pdf|doc|docx|xls|xlsx|jpg|png|txt)\.(exe|bat|ps1|vbs|js|com)$', name):
        return RuleResult(
            triggered=True, severity="HIGH",
            description=f"Double extension detected in '{event.process_name}'.",
            mitre_tactic="Defense Evasion", mitre_technique="Masquerading",
            mitre_technique_id="T1036"
        )
    return RuleResult(triggered=False)

def rule_encoded_command(event: EventSchema) -> RuleResult:
    if not event.process_path:
        return RuleResult(triggered=False)
    path_lower = event.process_path.lower()
    if re.search(r'-(enc|encodedcommand|e)\s+[A-Za-z0-9+/]{20,}={0,2}', path_lower):
        return RuleResult(
            triggered=True, severity="HIGH",
            description=f"Encoded command detected in '{event.process_name}': possible payload obfuscation.",
            mitre_tactic="Defense Evasion", mitre_technique="Obfuscated Files or Information",
            mitre_technique_id="T1027"
        )
    return RuleResult(triggered=False)

def rule_network_tool(event: EventSchema) -> RuleResult:
    name = event.process_name.lower().strip()
    if name not in NETWORK_TOOLS:
        return RuleResult(triggered=False)
    if event.process_path:
        path_lower = event.process_path.lower()
        for suspicious in SUSPICIOUS_PATHS:
            if suspicious in path_lower:
                return RuleResult(
                    triggered=True, severity="MEDIUM",
                    description=f"Network tool '{event.process_name}' executed from suspicious path: '{event.process_path}'.",
                    mitre_tactic="Discovery", mitre_technique="System Network Configuration Discovery",
                    mitre_technique_id="T1016"
                )
    return RuleResult(triggered=False)

STATIC_RULES = [
    StaticRule(name="Known Attack Tool", severity="CRITICAL", description="Detects known attack tools like mimikatz, netcat, etc.",
               mitre_tactic="Execution", mitre_technique="User Execution", mitre_technique_id="T1204", fn=rule_known_attack_tool),
    StaticRule(name="Suspicious Execution Path", severity="HIGH", description="Processes executing from temp/downloads paths.",
               mitre_tactic="Execution", mitre_technique="Command and Scripting Interpreter", mitre_technique_id="T1059", fn=rule_suspicious_execution_path),
    StaticRule(name="Script Interpreter Abuse", severity="MEDIUM", description="Script interpreters like PowerShell, cmd, bash detected.",
               mitre_tactic="Execution", mitre_technique="Command and Scripting Interpreter", mitre_technique_id="T1059", fn=rule_script_interpreter_abuse),
    StaticRule(name="Privilege Escalation", severity="HIGH", description="Desktop apps running with SYSTEM/root privileges.",
               mitre_tactic="Privilege Escalation", mitre_technique="Access Token Manipulation", mitre_technique_id="T1134", fn=rule_privilege_escalation),
    StaticRule(name="Double Extension", severity="HIGH", description="Files with double extensions indicating masquerading.",
               mitre_tactic="Defense Evasion", mitre_technique="Masquerading", mitre_technique_id="T1036", fn=rule_double_extension),
    StaticRule(name="Encoded Command", severity="HIGH", description="Base64 encoded PowerShell commands.",
               mitre_tactic="Defense Evasion", mitre_technique="Obfuscated Files or Information", mitre_technique_id="T1027", fn=rule_encoded_command),
    StaticRule(name="Network Tool in Suspicious Path", severity="MEDIUM", description="Network tools executed from suspicious directories.",
               mitre_tactic="Discovery", mitre_technique="System Network Configuration Discovery", mitre_technique_id="T1016", fn=rule_network_tool),
]

ALL_RULES = [s.fn for s in STATIC_RULES]
