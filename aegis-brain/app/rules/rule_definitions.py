import re
from dataclasses import dataclass
from app.api.schemas.common import EventSchema

@dataclass
class RuleResult:
    triggered: bool
    severity: str = "LOW"
    description: str = ""

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
            triggered=True,
            severity="CRITICAL",
            description=f"Known attack tool detected: '{event.process_name}'."
        )
    return RuleResult(triggered=False)

def rule_suspicious_execution_path(event: EventSchema) -> RuleResult:
    if not event.process_path:
        return RuleResult(triggered=False)
    path_lower = event.process_path.lower()
    for suspicious in SUSPICIOUS_PATHS:
        if suspicious in path_lower:
            return RuleResult(
                triggered=True,
                severity="HIGH",
                description=f"Process '{event.process_name}' executing from suspicious path: '{event.process_path}'."
            )
    return RuleResult(triggered=False)

def rule_script_interpreter_abuse(event: EventSchema) -> RuleResult:
    name = event.process_name.lower().strip()
    if name in SCRIPT_INTERPRETERS:
        return RuleResult(
            triggered=True,
            severity="MEDIUM",
            description=f"Script interpreter '{event.process_name}' detected."
        )
    return RuleResult(triggered=False)

def rule_privilege_escalation(event: EventSchema) -> RuleResult:
    name = event.process_name.lower().strip()
    user = (event.user or "").lower().strip()
    is_privileged = user in {"root", "system", "nt authority\\system", "administrator"}
    is_desktop_app = name in NON_ROOT_PROCESSES
    if is_privileged and is_desktop_app:
        return RuleResult(
            triggered=True,
            severity="HIGH",
            description=f"Privilege escalation indicator: '{event.process_name}' is running as '{event.user}'."
        )
    return RuleResult(triggered=False)

def rule_double_extension(event: EventSchema) -> RuleResult:
    name = event.process_name.lower()
    if re.search(r'\.(pdf|doc|docx|xls|xlsx|jpg|png|txt)\.(exe|bat|ps1|vbs|js|com)$', name):
        return RuleResult(
            triggered=True,
            severity="HIGH",
            description=f"Double extension detected in '{event.process_name}'."
        )
    return RuleResult(triggered=False)

def rule_encoded_command(event: EventSchema) -> RuleResult:
    """
    Rileva comandi Base64 encoded tipici degli attacchi PowerShell.
    Esempio reale: powershell -enc SGVsbG8gV29ybGQ=
    Le flag -enc / -EncodedCommand sono usate per offuscare payload malevoli
    e bypassare soluzioni di sicurezza che analizzano la command line.
    """
    import re
    if not event.process_path:
        return RuleResult(triggered=False)
    path_lower = event.process_path.lower()
    # Cerca le flag di encoding tipiche di PowerShell
    if re.search(r'-(enc|encodedcommand|e)\s+[A-Za-z0-9+/]{20,}={0,2}', path_lower):
        return RuleResult(
            triggered=True,
            severity="HIGH",
            description=f"Encoded command detected in '{event.process_name}': possible payload obfuscation."
        )
    return RuleResult(triggered=False)

def rule_network_tool(event: EventSchema) -> RuleResult:
    """
    Rileva tool di analisi/sniffing di rete eseguiti da path sospetti.
    Tool come wireshark o tcpdump sono legittimi se usati da percorsi
    standard, ma diventano sospetti se lanciati da %TEMP%, Downloads, ecc.
    nmap e netcat sono già coperti da rule_known_attack_tool (CRITICAL).
    """
    name = event.process_name.lower().strip()
    if name not in NETWORK_TOOLS:
        return RuleResult(triggered=False)
    # Segnala solo se il path è sospetto — tool legittimi da C:\Program Files sono ok
    if event.process_path:
        path_lower = event.process_path.lower()
        for suspicious in SUSPICIOUS_PATHS:
            if suspicious in path_lower:
                return RuleResult(
                    triggered=True,
                    severity="MEDIUM",
                    description=f"Network tool '{event.process_name}' executed from suspicious path: '{event.process_path}'."
                )
    return RuleResult(triggered=False)

ALL_RULES = [
    rule_known_attack_tool,
    rule_double_extension,
    rule_suspicious_execution_path,
    rule_privilege_escalation,
    rule_script_interpreter_abuse,
    rule_encoded_command,
    rule_network_tool,
]