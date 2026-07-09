import re
from dataclasses import dataclass, field
from typing import Optional
from app.api.schemas.common import EventSchema

@dataclass
class RuleResult:
    triggered: bool
    severity: str = "LOW"
    description: str = ""
    mitre_tactic_id: Optional[str] = None
    mitre_tactic: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    mitre_technique: Optional[str] = None

@dataclass
class StaticRule:
    name: str
    severity: str
    description: str
    mitre_tactic: str
    mitre_technique: str
    mitre_technique_id: str
    fn: callable
    mitre_tactic_id: Optional[str] = None

# ═══════════════════════════════════════════════════════════════════
#  EXPANDED THREAT SIGNATURES (200+ entries across categories)
# ═══════════════════════════════════════════════════════════════════

# — Credential dumping / password recovery
CREDENTIAL_TOOLS = {
    "mimikatz.exe", "mimikatz", "wce.exe", "fgdump.exe", "pwdump.exe",
    "gsecdump.exe", "lsadump.exe", "procdump.exe", "samdump2",
    "cachedump.exe", "creddump", "creddump7", "creddump8",
    "quarkspwdump.exe", "pwddump", "pwdump7.exe", "pwdump8.exe",
    "dcdiag.exe", "ntdsutil.exe", "vssadmin.exe", "dsamain.exe",
    "secretsdump.py", "impacket-secretsdump", "lsassy",
    "spraykatz", "kerbrute", "kerberoast", "asreproast",
    "ruby_smb", "crackmapexec", "netripper", "katz.exe",
    "lazagne.exe", "lazagne", "browserpass", "webpass",
    "mailpassview", "networkpassview", "chromepass", "iepassview",
    "protectedstorage", "dpapi", "sharpdpapi", "donpapi",
}

# — Network reconnaissance / scanning
SCANNER_TOOLS = {
    "nmap", "nmap.exe", "masscan", "masscan.exe", "zmap", "zmap.exe",
    "rustscan", "naabu", "naabu.exe", "unicornscan",
    "angryip", "advanced_port_scanner", "netscan",
    "zenmap", "p0f", "amass", "subfinder", "httpx",
    "gobuster", "dirb", "wfuzz", "ffuf", "dirbuster",
}

# — Exploitation / C2 frameworks
EXPLOIT_TOOLS = {
    "msfconsole", "msf", "msfvenom", "metasploit", "msfcli",
    "cobalt_strike", "beacon.exe", "cs_beacon", "teamserver",
    "meterpreter", "shellcode", "payload.exe",
    "sliver", "sliver-server", "sliver-client",
    "havoc", "havoc_c2", "mythic", "apfell", "poseidon",
    "bruteratel", "brute_ratel", "covenant", "grunt",
    "empire", "powershellempire", "starkiller",
    "pwn", "pwntools", "exploit.exe", "shellter",
    "veil", "veil-evasion", "shellter.exe",
    "encoder.exe", "av_evasion", "pe_to_shellcode",
    "donut", "donut.exe", "scrobj", "sctobjs",
}

# — Post-exploitation / lateral movement
POST_EXPLOIT_TOOLS = {
    "psexec.exe", "psexec64.exe", "psexecsvc.exe",
    "wmiexec", "wmiexec.exe", "wmic.exe", "wmic",
    "smbexec", "smbexec.py", "smbexec.exe",
    "atexec", "atexec.py", "atexec.exe",
    "dcomexec", "dcomexec.py",
    "impacket", "impacket.exe", "impacket_smb",
    "remcom", "pth-winexe", "winexe",
    "evil-winrm", "evil_winrm", "winrm.vbs",
    "xfreerdp", "freerdp", "remmina",
    "putty.exe", "plink.exe", "ssh.exe",
    "mstsc.exe", "mstsc",
}

# — Living-off-the-land binaries (LOLBins)
LOLBINS = {
    "rundll32.exe", "regsvr32.exe", "mshta.exe",
    "certutil.exe", "bitsadmin.exe", "cscript.exe", "wscript.exe",
    "powershell.exe", "powershell", "pwsh.exe", "pwsh",
    "cmd.exe", "sh", "bash", "zsh",
    "wmic.exe", "mmc.exe", "msiexec.exe",
    "reg.exe", "schtasks.exe", "sc.exe",
    "net.exe", "net1.exe", "nslookup.exe",
    "arp.exe", "route.exe", "tracert.exe",
    "findstr.exe", "xcopy.exe", "robocopy.exe",
    "curl.exe", "curl", "wget", "wget.exe",
    "certreq.exe", "esentutl.exe", "expand.exe",
    "extract.exe", "makecab.exe", "pcalua.exe",
    "replace.exe", "syncappvpublishingserver.exe",
    "wevtutil.exe", "bcdedit.exe", "fsutil.exe",
}

# — Remote Access Trojans / Beacons
RAT_TOOLS = {
    "njrat", "njrat.exe", "bladabindi", "nanocore",
    "asyncrat", "asyncrat.exe", "darkrat", "darkcomet",
    "quasar", "quasarrat", "quasar.exe",
    "xhacker", "xhackerrat", "orcus", "orcusrat",
    "venomrat", "cybergater", "adwind", "jrat",
    "limewire", "blackshades", "poisonivy", "hvnc",
    "vnc", "tightvnc", "ultravnc", "realvnc",
    "teamviewer", "anydesk", "ammyy", "logmein",
    "screenconnect", "supremo", "remoteutilities",
    "beacon", "beacon.exe", "trojan", "backdoor",
    "agenttesla", "formbook", "lokibot", "azorult",
    "vidar", "raccoon", "raccoonstealer",
}

# — Ransomware families
RANSOMWARE = {
    "wannacry", "wanacry", "wana_decryptor",
    "badrabbit", "locky", "locker", "goldeneye",
    "notpetya", "petya", "mischa",
    "ryuk", "conti", "conti.exe", "revil", "sodinokibi",
    "darkside", "blackmatter", "hellokitty",
    "dearcry", "blackbasta", "royal", "play",
    "cryptolocker", "cryptowall", "cerber",
    "teslacrypt", "torrentlocker", "keRanger",
    "sam", "samas", "cryptXXX", "pcrypt",
    "jigsaw", "mole", "dmexe", "blc.exe",
    "encrypt.exe", "encryptor", "decrypt",
    "lockbit", "lockbit.exe",
}

# — Keyloggers / information stealers
INFO_STEALERS = {
    "keylog", "keylogger", "keylogger.exe",
    "refog", "actualkeylogger", "bestfreakeylogger",
    "pykeylog", "logkeys", "uberkey",
    "spyrix", "microkeylogger", "kidlogger",
    "revealer", "keystroke", "keystrokelogger",
    "clipboard", "clipboardlogger", "clipper",
    "screenshot", "screencapture", "screenlogger",
    "formgrabber", "formstealer", "webinject",
    "redline", "redlinestealer",
}

# — Defense evasion / AV bypass
EVASION_TOOLS = {
    "processhacker", "processhacker.exe", 
    "procexp", "procexp.exe", "procmon.exe",
    "pchunter", "pchunter.exe", "powertool",
    "gmerexe", "gmerexe.exe", "rootkitrevealer",
    "hijackthis", "autoruns", "autoruns.exe",
    "tcpview", "tcpview.exe", "dbgview.exe",
    "x64dbg", "x32dbg", "ollydbg", "windbg",
    "ida", "idapro", "ghidra", "radare2", "rizin",
    "cheatengine", "cheatengine.exe",
    "scylla", "scylla.exe", "strongod",
    "protect", "protect.exe", "vmp", "vmprotect",
    "themida", "enigma", "asprotect", "upx",
    "packer", "packed", "crypted",
}

# — Script interpreters and LOL scripting
SCRIPT_INTERPRETERS = {
    "powershell.exe", "powershell", "pwsh.exe", "pwsh",
    "cmd.exe", "cmd", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe",
    "bash", "sh", "zsh", "dash", "ksh", "tcsh",
    "python", "python.exe", "python3", "python3.exe",
    "perl", "perl.exe", "ruby", "ruby.exe",
    "php", "php.exe", "php-cgi.exe",
    "node", "node.exe", "nodejs", "nodejs.exe",
    "javaw", "javaw.exe", "java.exe", "java",
    "lua", "lua.exe", "tclsh", "autoit3.exe",
    "powershell_ise.exe", "powershell_ise",
}

# — Suspicious execution paths (expanded)
SUSPICIOUS_PATHS = {
    "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\",
    "\\downloads\\", "\\desktop\\", "\\cache\\",
    "\\recycle.bin\\", "\\$recycle.bin\\",
    "\\programdata\\", "\\appdata\\roaming\\",
    "\\users\\public\\", "\\perflogs\\",
    "\\windows\\temp\\", "\\wINDOWS\\Temp\\",
    "\\system32\\tasks\\", "\\system32\\spool\\drivers\\",
    "\\system32\\spool\\servic\\",
    "/tmp/", "/var/tmp/", "/dev/shm/",
    "/var/cache/", "/var/spool/", "/var/www/",
    "/home/*/.cache/", "/home/*/.local/share/Trash/",
    "/run/user/", "/dev/pts/",
}

# — Desktop apps that shouldn't run as root/system
NON_ROOT_PROCESSES = {
    "chrome.exe", "firefox.exe", "notepad.exe", "calc.exe",
    "wordpad.exe", "mspaint.exe", "winword.exe", "excel.exe",
    "powerpnt.exe", "outlook.exe", "acrord32.exe", "acrord64.exe",
    "iexplore.exe", "msedge.exe", "opera.exe", "brave.exe",
    "spotify.exe", "discord.exe", "slack.exe", "teams.exe",
    "zoom.exe", "skype.exe", "thunderbird.exe",
}

# — Network tools (expanded)
NETWORK_TOOLS = {
    "wireshark.exe", "wireshark", "tshark", "tcpdump",
    "dumpcap", "tshark", "ethereal",
    "netstat", "arp.exe", "arp", "route.exe",
    "curl.exe", "curl", "wget", "wget.exe",
    "nc.exe", "ncat.exe", "ncat", "netcat", "socat",
    "telnet.exe", "telnet", "ftp.exe", "ftp",
    "ssh.exe", "ssh", "sshd", "sshd.exe",
    "nslookup.exe", "nslookup", "dig", "host",
    "ping.exe", "ping", "tracert.exe", "tracert",
    "pathping.exe", "mtr", "iperf", "iperf3",
    "httpie", "http", "aria2c", "aria2",
    "nmap", "nmap.exe", "masscan", "zmap",
    "rustscan", "naabu",
}

# — Anomalous parent-child process pairs
# Format: (parent_name_substring, child_name_substring, severity, description, mitre)
SUSPICIOUS_PARENT_CHILD = [
    (("winword.exe", "word.exe", "excel.exe", "powerpnt.exe", "outlook.exe"),
     ("powershell", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe",
      "rundll32.exe", "sh", "bash", "python", "wmic.exe", "regsvr32.exe",
      "certutil.exe", "bitsadmin.exe"),
     "CRITICAL", "Office process spawning script interpreter: '{parent}' -> '{child}'.",
     "TA0002", "Execution", "User Execution", "T1204"),

    (("chrome.exe", "msedge.exe", "firefox.exe", "opera.exe", "brave.exe",
      "iexplore.exe", "safari.exe", "safari"),
     ("powershell", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe",
      "sh", "bash", "python", "rundll32.exe"),
     "HIGH", "Browser spawning script interpreter: '{parent}' -> '{child}'.",
     "TA0002", "Execution", "User Execution", "T1204"),

    (("acrord32.exe", "acrord64.exe", "pdf", "reader", "foxit"),
     ("powershell", "cmd.exe", "wscript.exe", "mshta.exe",
      "sh", "bash", "python"),
     "CRITICAL", "PDF reader spawning script interpreter: '{parent}' -> '{child}'.",
     "TA0002", "Execution", "User Execution", "T1204"),

    (("outlook.exe", "thebat.exe", "thunderbird.exe", "mail"),
     ("powershell", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe",
      "sh", "bash"),
     "CRITICAL", "Email client spawning script interpreter: '{parent}' -> '{child}'.",
     "TA0002", "Execution", "User Execution", "T1204"),

    (("svchost.exe", "services.exe", "lsass.exe", "wininit.exe", "system",
      "winlogon.exe"),
     ("powershell", "cmd.exe", "wscript.exe", "cscript.exe",
      "sh", "bash", "python"),
     "CRITICAL", "System process spawning script interpreter: '{parent}' -> '{child}'.",
     "TA0004", "Privilege Escalation", "Process Injection", "T1055"),

    (("explorer.exe", "explorer"),
     ("powershell", "cmd.exe", "wscript.exe", "mshta.exe",
      "regsvr32.exe", "rundll32.exe", "certutil.exe"),
     "MEDIUM", "Explorer spawning LOLBin: '{parent}' -> '{child}'.",
     "TA0005", "Defense Evasion", "Signed Binary Proxy Execution", "T1218"),

    (("notepad.exe", "wordpad.exe", "mspaint.exe", "calc.exe"),
     ("powershell", "cmd.exe", "sh", "bash"),
     "HIGH", "Utility process spawning script interpreter: '{parent}' -> '{child}'.",
     "TA0002", "Execution", "User Execution", "T1204"),
]

# — Known malware families (name substring match)
MALWARE_FAMILIES = [
    # Backdoors / Trojans
    ("lockbit", "HIGH", "Possible LockBit ransomware detected: process name '{name}'.",
     "TA0040", "Impact", "T1486"),
    ("trojan", "HIGH", "Possible trojan detected: process name '{name}'.",
     "TA0002", "Execution", "T1204"),
    ("backdoor", "HIGH", "Possible backdoor detected: process name '{name}'.",
     "TA0002", "Execution", "T1204"),
    ("dropper", "HIGH", "Possible dropper detected: process name '{name}'.",
     "TA0005", "Defense Evasion", "T1204"),
    ("downloader", "HIGH", "Possible downloader detected: process name '{name}'.",
     "TA0011", "Command and Control", "T1105"),
    ("loader", "MEDIUM", "Possible loader detected: process name '{name}'.",
     "TA0005", "Defense Evasion", "T1218"),
    ("worm", "MEDIUM", "Possible worm detected: process name '{name}'.",
     "TA0008", "Lateral Movement", "T1210"),
    ("rootkit", "HIGH", "Possible rootkit detected: process name '{name}'.",
     "TA0005", "Defense Evasion", "T1014"),
    ("spyware", "MEDIUM", "Possible spyware detected: process name '{name}'.",
     "TA0009", "Collection", "T1056"),
    ("adware", "LOW", "Possible adware detected: process name '{name}'.",
     "TA0009", "Collection", "T1056"),
    ("ransom", "HIGH", "Possible ransomware detected: process name '{name}'.",
     "TA0040", "Impact", "T1486"),
    ("keylogger", "HIGH", "Keylogger detected: process name '{name}'.",
     "TA0009", "Collection", "T1056"),
    ("miner", "MEDIUM", "Possible cryptocurrency miner: process name '{name}'.",
     "TA0040", "Impact", "T1496"),
    ("coin", "MEDIUM", "Possible cryptocurrency mining process: process name '{name}'.",
     "TA0040", "Impact", "T1496"),
    (" inject", "HIGH", "Possible process injection indicator: process name '{name}'.",
     "TA0005", "Defense Evasion", "T1055"),
    ("injector", "HIGH", "Process injector detected: process name '{name}'.",
     "TA0005", "Defense Evasion", "T1055"),
    ("steal", "HIGH", "Possible information stealer: process name '{name}'.",
     "TA0009", "Collection", "T1056"),
    ("password", "MEDIUM", "Password-related process: process name '{name}'.",
     "TA0006", "Credential Access", "T1003"),
]

# — Persistence locations (for process_path matching)
PERSISTENCE_PATHS = {
    "\\startup\\", "\\start menu\\programs\\startup\\",
    "\\system32\\tasks\\", "\\system32\\drivers\\etc\\",
    "\\windows\\system32\\tasks\\",
    "\\appdata\\roaming\\microsoft\\windows\\start menu\\programs\\startup\\",
    "/etc/init.d/", "/etc/systemd/system/",
    "/etc/cron.d/", "/etc/cron.hourly/", "/etc/cron.daily/",
    "/Library/LaunchAgents/", "/Library/LaunchDaemons/",
    "~/Library/LaunchAgents/",
}

# — Encoded command patterns (expanded)
ENCODED_PATTERNS = [
    r'-(enc|encodedcommand|e)\s+[A-Za-z0-9+/]{20,}={0,2}',
    r'base64.+decode',
    r'frombase64string',
    r'-e\s+[A-Za-z0-9+/]{20,}={0,2}',
    r'iex\s*\(',
    r'invoke-expression',
    r'-ec\s+',
    r'frombase64',
    r'char\(\d+\)',
    r'\\x[0-9a-f]{2}',
]

# — High thread count threshold (possible injection indicator)
HIGH_THREAD_COUNT_THRESHOLD = 200


# ═══════════════════════════════════════════════════════════════════
#  RULE FUNCTIONS
# ═══════════════════════════════════════════════════════════════════

def rule_known_attack_tool(event: EventSchema) -> RuleResult:
    if not event.process_name:
        return RuleResult(triggered=False)
    name = event.process_name.lower().strip()
    name_noexe = name.replace(".exe", "").replace(".com", "").replace(".dll", "")
    combined = CREDENTIAL_TOOLS | SCANNER_TOOLS | EXPLOIT_TOOLS | POST_EXPLOIT_TOOLS | RAT_TOOLS | RANSOMWARE | EVASION_TOOLS | INFO_STEALERS
    if name in combined or name_noexe in combined:
        return RuleResult(
            triggered=True, severity="CRITICAL",
            description=f"Known attack tool / malware detected: '{event.process_name}'.",
            mitre_tactic_id="TA0002", mitre_tactic="Execution", mitre_technique="User Execution",
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
                mitre_tactic_id="TA0002", mitre_tactic="Execution", mitre_technique="Command and Scripting Interpreter",
                mitre_technique_id="T1059"
            )
    return RuleResult(triggered=False)


def rule_script_interpreter_abuse(event: EventSchema) -> RuleResult:
    if not event.process_name:
        return RuleResult(triggered=False)
    name = event.process_name.lower().strip()
    if name in SCRIPT_INTERPRETERS:
        return RuleResult(
            triggered=True, severity="MEDIUM",
            description=f"Script interpreter '{event.process_name}' detected.",
            mitre_tactic_id="TA0002", mitre_tactic="Execution", mitre_technique="Command and Scripting Interpreter",
            mitre_technique_id="T1059"
        )
    return RuleResult(triggered=False)


def rule_privilege_escalation(event: EventSchema) -> RuleResult:
    if not event.process_name:
        return RuleResult(triggered=False)
    name = event.process_name.lower().strip()
    user = (event.user or "").lower().strip()
    is_privileged = user in {"root", "system", "nt authority\\system", "administrator", "nt authority\\local service", "nt authority\\network service"}
    is_desktop_app = name in NON_ROOT_PROCESSES
    if is_privileged and is_desktop_app:
        return RuleResult(
            triggered=True, severity="HIGH",
            description=f"Privilege escalation indicator: '{event.process_name}' running as '{event.user}'.",
            mitre_tactic_id="TA0004", mitre_tactic="Privilege Escalation", mitre_technique="Access Token Manipulation",
            mitre_technique_id="T1134"
        )
    return RuleResult(triggered=False)


def rule_double_extension(event: EventSchema) -> RuleResult:
    if not event.process_name:
        return RuleResult(triggered=False)
    name = event.process_name.lower()
    if re.search(r'\.(pdf|doc|docx|xls|xlsx|jpg|png|txt|rtf|ppt|pptx)\.(exe|bat|ps1|vbs|js|com|scr|pif|jar|wsf|hta)$', name):
        return RuleResult(
            triggered=True, severity="HIGH",
            description=f"Double extension detected in '{event.process_name}'.",
            mitre_tactic_id="TA0005", mitre_tactic="Defense Evasion", mitre_technique="Masquerading",
            mitre_technique_id="T1036"
        )
    return RuleResult(triggered=False)


def rule_encoded_command(event: EventSchema) -> RuleResult:
    if not event.process_path:
        return RuleResult(triggered=False)
    path_lower = event.process_path.lower()
    for pattern in ENCODED_PATTERNS:
        if re.search(pattern, path_lower):
            return RuleResult(
                triggered=True, severity="HIGH",
                description=f"Encoded/obfuscated command detected in '{event.process_name}': possible payload.",
                mitre_tactic_id="TA0005", mitre_tactic="Defense Evasion", mitre_technique="Obfuscated Files or Information",
                mitre_technique_id="T1027"
            )
    return RuleResult(triggered=False)


def rule_network_tool(event: EventSchema) -> RuleResult:
    if not event.process_name:
        return RuleResult(triggered=False)
    name = event.process_name.lower().strip()
    if name not in NETWORK_TOOLS:
        return RuleResult(triggered=False)
    if event.process_path:
        path_lower = event.process_path.lower()
        for suspicious in SUSPICIOUS_PATHS:
            if suspicious in path_lower:
                return RuleResult(
                    triggered=True, severity="MEDIUM",
                    description=f"Network tool '{event.process_name}' from suspicious path: '{event.process_path}'.",
                    mitre_tactic_id="TA0007", mitre_tactic="Discovery", mitre_technique="System Network Configuration Discovery",
                    mitre_technique_id="T1016"
                )
    return RuleResult(triggered=False)


def rule_suspicious_parent_child(event: EventSchema) -> RuleResult:
    if not event.parent_process_name or not event.process_name:
        return RuleResult(triggered=False)
    parent = event.parent_process_name.lower().strip()
    child = event.process_name.lower().strip()

    for parents, children, sev, desc, ta_tactic, tactic, technique, tech_id in SUSPICIOUS_PARENT_CHILD:
        if any(p in parent for p in parents):
            if any(c in child for c in children):
                return RuleResult(
                    triggered=True, severity=sev,
                    description=desc.format(parent=event.parent_process_name, child=event.process_name),
                    mitre_tactic_id=ta_tactic, mitre_tactic=tactic,
                    mitre_technique=technique, mitre_technique_id=tech_id,
                )
    return RuleResult(triggered=False)


def rule_malware_family(event: EventSchema) -> RuleResult:
    if not event.process_name:
        return RuleResult(triggered=False)
    name = event.process_name.lower().strip()
    name_stripped = name.replace(".exe", "").replace(".dll", "").replace(".bat", "").replace(".ps1", "")

    for keyword, sev, desc, ta_tactic, tech, tech_id in MALWARE_FAMILIES:
        if keyword in name or keyword in name_stripped:
            return RuleResult(
                triggered=True, severity=sev,
                description=desc.format(name=event.process_name),
                mitre_tactic_id=ta_tactic, mitre_tactic=ta_tactic.replace("TA", "Tactic "),
                mitre_technique=tech, mitre_technique_id=tech_id,
            )
    return RuleResult(triggered=False)


def rule_persistence_path(event: EventSchema) -> RuleResult:
    if not event.process_path:
        return RuleResult(triggered=False)
    path_lower = event.process_path.lower()
    for p_path in PERSISTENCE_PATHS:
        if p_path in path_lower:
            return RuleResult(
                triggered=True, severity="HIGH",
                description=f"Process '{event.process_name}' installed persistence at: '{event.process_path}'.",
                mitre_tactic_id="TA0003", mitre_tactic="Persistence", mitre_technique="Boot or Logon Autostart Execution",
                mitre_technique_id="T1547"
            )
    return RuleResult(triggered=False)


def rule_dll_hijack_path(event: EventSchema) -> RuleResult:
    if not event.process_path:
        return RuleResult(triggered=False)
    # DLL loaded from temp or user-writable path
    path_lower = event.process_path.lower()
    if not path_lower.endswith(".dll"):
        return RuleResult(triggered=False)
    for susp in SUSPICIOUS_PATHS:
        if susp in path_lower:
            return RuleResult(
                triggered=True, severity="HIGH",
                description=f"Possible DLL hijacking: '{event.process_name}' loaded from suspicious path.",
                mitre_tactic_id="TA0005", mitre_tactic="Defense Evasion", mitre_technique="DLL Side-Loading",
                mitre_technique_id="T1574"
            )
    return RuleResult(triggered=False)


def rule_lolbin_usage(event: EventSchema) -> RuleResult:
    if not event.process_name:
        return RuleResult(triggered=False)
    name = event.process_name.lower().strip()
    if name in LOLBINS and event.process_path:
        path_lower = event.process_path.lower()
        # LOLBin in non-standard path
        if "\\system32\\" not in path_lower and "\\syswow64\\" not in path_lower and "/usr/bin/" not in path_lower and "/bin/" not in path_lower:
            return RuleResult(
                triggered=True, severity="HIGH",
                description=f"LOLBin '{event.process_name}' executed from non-standard path: '{event.process_path}'.",
                mitre_tactic_id="TA0005", mitre_tactic="Defense Evasion", mitre_technique="Signed Binary Proxy Execution",
                mitre_technique_id="T1218"
            )
    return RuleResult(triggered=False)


def rule_high_thread_count(event: EventSchema) -> RuleResult:
    if event.thread_count is not None and event.thread_count > HIGH_THREAD_COUNT_THRESHOLD:
        return RuleResult(
            triggered=True, severity="MEDIUM",
            description=f"Process '{event.process_name}' has abnormally high thread count: {event.thread_count}. Possible injection.",
            mitre_tactic_id="TA0005", mitre_tactic="Defense Evasion", mitre_technique="Process Injection",
            mitre_technique_id="T1055"
        )
    return RuleResult(triggered=False)


def rule_network_beacon(event: EventSchema) -> RuleResult:
    """
    Detects processes making outbound connections to remote IPs.
    At event-level, flags any process with active outbound connections
    to public IPs (heuristic). Full beacon timing analysis in correlation_engine.
    """
    if not event.network_connections:
        return RuleResult(triggered=False)
    outbound = []
    for conn in event.network_connections:
        remote = conn.get("remote", "")
        state = conn.get("state", "")
        if ":" in remote and state == "ESTABLISHED":
            host, port = remote.rsplit(":", 1)
            # Check for public IP (not private ranges)
            if host and not _is_private_ip(host):
                outbound.append(remote)
    if outbound:
        remote_str = "; ".join(outbound[:3])
        return RuleResult(
            triggered=True, severity="MEDIUM",
            description=f"Process '{event.process_name}' has {len(outbound)} outbound connections: {remote_str}.",
            mitre_tactic_id="TA0011", mitre_tactic="Command and Control", mitre_technique="Application Layer Protocol",
            mitre_technique_id="T1071"
        )
    return RuleResult(triggered=False)


def rule_persistence_autorun(event: EventSchema) -> RuleResult:
    """Detect processes named like common persistence mechanisms."""
    if not event.process_name:
        return RuleResult(triggered=False)
    name = event.process_name.lower().strip()
    persistence_names = {
        "svch0st.exe", "scvhost.exe",
        "sysupdate.exe", "winupdate.exe", "microsofupdate.exe",
        "googledeupdate.exe", "adobeflashupdate.exe", "javupdate.exe",
        "mssecsvc.exe", "mssecsvc",
    }
    if name in persistence_names:
        return RuleResult(
            triggered=True, severity="HIGH",
            description=f"Suspicious persistence-like process name: '{event.process_name}'.",
            mitre_tactic_id="TA0003", mitre_tactic="Persistence", mitre_technique="Boot or Logon Autostart Execution",
            mitre_technique_id="T1547"
        )
    return RuleResult(triggered=False)


# ═══════════════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════════════

_PRIVATE_RANGES = re.compile(r'^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|169\.254\.|0\.)')

def _is_private_ip(ip: str) -> bool:
    return bool(_PRIVATE_RANGES.match(ip))

# ═══════════════════════════════════════════════════════════════════
#  STATIC RULES REGISTRY
# ═══════════════════════════════════════════════════════════════════

STATIC_RULES = [
    StaticRule(name="Known Attack Tool", severity="CRITICAL",
               description="Detects 200+ known attack tools, credential dumpers, scanners, RATs, ransomware, etc.",
               mitre_tactic_id="TA0002", mitre_tactic="Execution", mitre_technique="User Execution",
               mitre_technique_id="T1204", fn=rule_known_attack_tool),
    StaticRule(name="Suspicious Parent-Child", severity="CRITICAL",
               description="Anomalous process lineage: Office, browser, PDF reader spawning script interpreters.",
               mitre_tactic_id="TA0002", mitre_tactic="Execution", mitre_technique="User Execution",
               mitre_technique_id="T1204", fn=rule_suspicious_parent_child),
    StaticRule(name="Malware Family", severity="HIGH",
               description="Process names matching known malware family patterns (trojan, backdoor, miner, ransomware, etc.).",
               mitre_tactic_id="TA0002", mitre_tactic="Execution", mitre_technique="User Execution",
               mitre_technique_id="T1204", fn=rule_malware_family),
    StaticRule(name="Suspicious Execution Path", severity="HIGH",
               description="Processes executing from temp, downloads, cache, public, or other suspicious paths.",
               mitre_tactic_id="TA0002", mitre_tactic="Execution", mitre_technique="Command and Scripting Interpreter",
               mitre_technique_id="T1059", fn=rule_suspicious_execution_path),
    StaticRule(name="Privilege Escalation", severity="HIGH",
               description="Desktop/user apps running with SYSTEM/root privileges.",
               mitre_tactic_id="TA0004", mitre_tactic="Privilege Escalation", mitre_technique="Access Token Manipulation",
               mitre_technique_id="T1134", fn=rule_privilege_escalation),
    StaticRule(name="Double Extension", severity="HIGH",
               description="Files with double extensions indicating masquerading attacks.",
               mitre_tactic_id="TA0005", mitre_tactic="Defense Evasion", mitre_technique="Masquerading",
               mitre_technique_id="T1036", fn=rule_double_extension),
    StaticRule(name="Encoded Command", severity="HIGH",
               description="Base64 encoded or obfuscated commands indicating payload delivery.",
               mitre_tactic_id="TA0005", mitre_tactic="Defense Evasion", mitre_technique="Obfuscated Files or Information",
               mitre_technique_id="T1027", fn=rule_encoded_command),
    StaticRule(name="Persistence Path", severity="HIGH",
               description="Process executing from persistence locations (startup, cron, systemd, launchd).",
               mitre_tactic_id="TA0003", mitre_tactic="Persistence", mitre_technique="Boot or Logon Autostart Execution",
               mitre_technique_id="T1547", fn=rule_persistence_path),
    StaticRule(name="Script Interpreter Abuse", severity="MEDIUM",
               description="Script interpreters like PowerShell, cmd, bash, Python, Perl, etc. detected.",
               mitre_tactic_id="TA0002", mitre_tactic="Execution", mitre_technique="Command and Scripting Interpreter",
               mitre_technique_id="T1059", fn=rule_script_interpreter_abuse),
    StaticRule(name="Network Tool in Suspicious Path", severity="MEDIUM",
               description="Network reconnaissance tools executed from suspicious directories.",
               mitre_tactic_id="TA0007", mitre_tactic="Discovery", mitre_technique="System Network Configuration Discovery",
               mitre_technique_id="T1016", fn=rule_network_tool),
    StaticRule(name="DLL Hijacking", severity="HIGH",
               description="DLL loaded from suspicious/user-writable path indicating possible DLL hijacking.",
               mitre_tactic_id="TA0005", mitre_tactic="Defense Evasion", mitre_technique="DLL Side-Loading",
               mitre_technique_id="T1574", fn=rule_dll_hijack_path),
    StaticRule(name="LOLBin Abuse", severity="HIGH",
               description="Living-off-the-land binary executed from non-standard path.",
               mitre_tactic_id="TA0005", mitre_tactic="Defense Evasion", mitre_technique="Signed Binary Proxy Execution",
               mitre_technique_id="T1218", fn=rule_lolbin_usage),
    StaticRule(name="High Thread Count", severity="MEDIUM",
               description="Process with abnormally high thread count indicating possible injection.",
               mitre_tactic_id="TA0005", mitre_tactic="Defense Evasion", mitre_technique="Process Injection",
               mitre_technique_id="T1055", fn=rule_high_thread_count),
    StaticRule(name="Network Beacon", severity="MEDIUM",
               description="Process with outbound connections to public IPs — possible C2 beacon.",
               mitre_tactic_id="TA0011", mitre_tactic="Command and Control", mitre_technique="Application Layer Protocol",
               mitre_technique_id="T1071", fn=rule_network_beacon),
    StaticRule(name="Persistence Autorun", severity="HIGH",
               description="Process name mimics common persistence or masquerades as legitimate software.",
               mitre_tactic_id="TA0003", mitre_tactic="Persistence", mitre_technique="Boot or Logon Autostart Execution",
               mitre_technique_id="T1547", fn=rule_persistence_autorun),
]

ALL_RULES = [s.fn for s in STATIC_RULES]
