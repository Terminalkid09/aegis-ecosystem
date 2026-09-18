"""M2: Aegis Total — internal VirusTotal + code/binary viewer.

Engines (Phase 1 — static, no external deps/network):
  - pe_analysis:    PE header, section entropy (packer detection), import
                    triage, .NET (CLR) detection, signature presence, embedded
                    PS/shellcode strings
  - elf_analysis:   ELF magic + arch + suspicious strings
  - macho_analysis: Mach-O / fat binaries (x86_64, arm64)
  - office_analysis: OLE (doc/xls/ppt/msi) e OOXML (docx/xlsx/pptx) con
                    macro VBA, auto-exec, DDE, oggetti esterni
  - pdf_analysis:   JavaScript, /OpenAction, /Launch, embedded files, XFA
  - archive_analysis: zip/gzip/bzip2/xz/tar (+ 7z/rar detection), nesting
                    bounded, zip-bomb e per-entry cap
  - strings_scan:   printable string extraction + IOC regex
  - static_lite:    secret scan, YARA-lite heuristics on text/scripts
  - sbom_lite:      manifest parsing from archives

Phase 2 (plug-in, same schema): YARA / ClamAV / capa / Ghidra / sandbox / LLM.

Audit 2026-09: la copertura precedente era "PE/ELF oppure testo". Office, PDF,
Mach-O, .NET, Java, WASM, APK, 7z/rar/gz/tar finivano tutti come
"binary, score 10" e la UI prometteva Mach-O mai implementato. Ora ogni
famiglia ha un parser dedicato e niente viene rifiutato per estensione: ogni
file caricato riceve sempre un'analisi reale (o dichiaratamente parziale).
"""
import bz2
import gzip
import hashlib
import io
import lzma
import math
import re
import struct
import tarfile
import zipfile
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import log_audit
from app.core.config import settings
from app.core.deps import get_current_user
from app.core.logging import get_logger
from app.database.connection import get_db
from app.database.models import AEGIS_TOTAL_DISCLAIMER, TotalReport

router = APIRouter(tags=["Aegis Total"])
logger = get_logger(__name__)

# Versione del motore di analisi. Cambiare le regole o i pesi di punteggio puo'
# cambiare un verdetto, quindi entra nella chiave della cache: i report salvati
# da una versione precedente vengono rigenerati invece di essere riproposti.
ENGINE_VERSION = "3.1"

# ─── Static signatures ────────────────────────────────────────────────────────

CRACK_NAMES = re.compile(r"(crack|keygen|keymaker|patcher|serial|activator|loader).*?\.(exe|dll|zip)$", re.I)

SECRET_PATTERNS: Dict[str, re.Pattern] = {
    "aws_access_key":   re.compile(r"AKIA[0-9A-Z]{16}"),
    "aws_secret_key":   re.compile(r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]"),
    "private_key_pem":  re.compile(r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"),
    "jwt_token":        re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    "password_literal": re.compile(r"(?i)(password|passwd|pwd)\s*[:=]\s*[^\s,;\"']{4,}"),
    "generic_api_key":  re.compile(r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*['\"]?[A-Za-z0-9_\-]{16,}"),
    "github_token":     re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"),
    "slack_token":      re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    "stripe_key":       re.compile(r"(sk|pk)_(live|test)_[A-Za-z0-9]{24,}"),
    "google_api_key":   re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "connection_string":re.compile(r"(?i)(mongodb|mysql|postgresql|redis|amqp)://[^\s\"'<>]+"),
}

# Ogni alternativa che unisce due parole usa `\b` e un salto LIMITATO: senza,
# `etw.*patch` matchava 895 byte di nomi di API Windows dentro notepad.exe
# ("etWindowExtEx" contiene "etw", poi un "patch" lontano) e il file finiva
# "malicious". Un `.*` illimitato su stringhe concatenate e' un generatore di
# falsi positivi, non una detection.
SUSPICIOUS_STRINGS: List[re.Pattern] = [
    re.compile(r"(?i)\b(mimikatz|bloodhound|sharphound|rubeus|sekurlsa|kerberoast)\b"),
    re.compile(r"(?i)(\bpowershell\b.{0,60}-enc|\b-encodedcommand\b|\bfrombase64string\b|\binvoke-mimikatz\b|\binvoke-expression\b)"),
    # `\betw` (senza confine in coda) e non `\betw\b`: le stringhe reali sono
    # `EtwEventWrite` / `AmsiScanBuffer`, dove il termine e' un prefisso.
    re.compile(r"(?i)(\bdisableamsi\w*|\bamsi\w*.{0,40}\bpatch\w*|\bpatch\w*.{0,40}\bamsi\w*|\betw\w*.{0,40}\bpatch\w*|\bpatch\w*.{0,40}\betw\w*|\bunhook\w*.{0,40}\bntdll\b)"),
    re.compile(r"(?i)(\bkeylog\w*|\bclipboardlog\w*|\bcredential\w*.{0,40}\bdump\w*|\blsass\b.{0,40}\bdump\w*|\bprocdump\b)"),
    re.compile(r"(?i)(\breverse\b.{0,30}\bshell\b|\bbind\b.{0,30}\bshell\b|\bnc\.exe\b|\bncat\b|\bcobalt\b.{0,30}\bstrike\b|\bmetasploit\b|\bmeterpreter\b)"),
    re.compile(r"(?i)(\bvirtualalloc\b.{0,40}\brwx\b|\bwriteprocessmemory\b|\bcreateremotethread\b|\bntcreatethreadex\b)"),
    re.compile(r"(?i)(\bregsvr32\b.{0,60}\bscrobj\b|\bmshta\b.{0,60}\bvbscript\b|\bcertutil\b.{0,60}\bdecode\b|\bbitsadmin\b.{0,60}\btransfer\b)"),
    re.compile(r"(?i)(\bwget\b.{0,60}\|\s*(bash|sh)\b|\bcurl\b.{0,60}\|\s*(bash|sh)\b)"),
    re.compile(r"(?i)\b(xmrig|stratum\+tcp|moneropool|ethermine|nanopool)\b"),
]

# Marker di esecuzione PowerShell: senza almeno uno di questi la sola parola
# "powershell" e' un riferimento, non un dropper (la contengono binari firmati
# Microsoft e interi manuali).
POWERSHELL_EXEC_MARKERS = (
    b"-encodedcommand", b"-enc ", b"invoke-expression", b"frombase64string",
    b"-nop", b"-w hidden", b"-windowstyle hidden", b"add-type",
    b"-executionpolicy bypass", b"iex (", b"iex(", b"new-object net.webclient",
    b"downloadstring", b"downloadfile", b"invoke-webrequest", b"-noprofile",
)

# Un quad `x.y.0.0` in un binario e' quasi sempre un numero di versione, non un
# host: `version="5.1.0.0"` nel manifest di notepad.exe finiva negli IOC come
# "indirizzo IP incorporato". Un indirizzo di rete .0.0 non e' un indicatore
# utile, quindi scartarlo costa poco e toglie di mezzo la classe di rumore.
VERSIONLIKE_IPV4 = re.compile(r"^\d{1,3}\.\d{1,3}\.0\.0$")

IOC_PATTERNS: Dict[str, re.Pattern] = {
    "ipv4":         re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"),
    "domain":       re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|xyz|top|ru|cn|tk|pw|cc|biz|info|online|site|shop|live|club)\b"),
    "url":          re.compile(r"https?://[^\s\"'<>\x00-\x1f]{10,200}"),
    "registry_key": re.compile(r"HKEY_(LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS)\\[^\s\"']{5,}"),
    "onion":        re.compile(r"\b[a-z2-7]{16,56}\.onion\b"),
}

# Estensioni testuali/script analizzabili come sorgente (audit: la lista era
# troppo corta e .md/.sql/.psd1/.yaml/.env finivano come "binary").
TEXT_EXTS = {
    ".py", ".pyw", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".vue", ".svelte",
    ".ps1", ".psm1", ".psd1", ".sh", ".bash", ".zsh", ".bat", ".cmd", ".vbs", ".vbe",
    ".vba", ".hta", ".wsf", ".pl", ".pm", ".rb", ".php", ".java", ".kt", ".kts",
    ".go", ".rs", ".c", ".h", ".cc", ".cpp", ".hpp", ".cs", ".vb", ".swift",
    ".lua", ".r", ".scala", ".clj", ".groovy", ".dart", ".sql", ".asm", ".s",
    ".json", ".jsonc", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf", ".env",
    ".xml", ".xsl", ".xslt", ".html", ".htm", ".css", ".scss", ".less", ".md",
    ".txt", ".rst", ".log", ".csv", ".tsv", ".gradle", ".properties", ".cmake",
    ".dockerfile", ".makefile", ".tf", ".tfvars", ".hcl", ".reg", ".inf", ".desktop", ".service",
}

MANIFEST_NAMES = {
    "requirements.txt", "package.json", "package-lock.json", "go.mod", "go.sum",
    "cargo.toml", "cargo.lock", "pom.xml", "build.gradle", "build.gradle.kts",
    "pyproject.toml", "pipfile", "pipfile.lock", "gemfile", "composer.json",
    "venv.yml", "environment.yml", "dune-project", "mix.exs",
}

# PE imports → (capability, MITRE technique)
SUSPICIOUS_IMPORTS: Dict[str, tuple] = {
    "CreateRemoteThread":   ("Process Injection", "T1055"),
    "WriteProcessMemory":   ("Process Injection", "T1055"),
    "VirtualAllocEx":       ("Process Injection", "T1055"),
    "NtUnmapViewOfSection": ("Process Hollowing", "T1055.012"),
    "SetWindowsHookEx":     ("Keylogging", "T1056.001"),
    "GetAsyncKeyState":     ("Keylogging", "T1056.001"),
    "CryptEncrypt":         ("Ransomware/Obfuscation", "T1486"),
    "WinHttpOpen":          ("HTTP C2", "T1071.001"),
    "InternetOpenUrl":      ("HTTP C2", "T1071.001"),
    "RegSetValueEx":        ("Registry Modification", "T1112"),
    "CreateService":        ("Persistence", "T1543.003"),
    "ShellExecute":         ("Shell Execution", "T1059"),
    "WinExec":              ("Shell Execution", "T1059"),
    "CreateProcessW":       ("Process Execution", "T1106"),
    "NtQueryInformationProcess": ("Evasion/Injection", "T1055"),
    "MiniDumpWriteDump":    ("Credential Dumping", "T1003.001"),
    "AdjustTokenPrivileges":("Privilege Escalation", "T1134"),
    "SetThreadContext":     ("Process Injection", "T1055.003"),
    "QueueUserAPC":         ("Process Injection", "T1055.004"),
}

# API dual-use: le importa qualunque binario Windows normale (notepad.exe ne
# usa tre). Restano nel report perche' sono contesto utile, ma pesano poco e da
# sole non possono portare un file a "malicious".
DUAL_USE_IMPORTS = frozenset({
    "RegSetValueEx", "CreateService", "ShellExecute", "WinExec",
    "CreateProcessW", "WinHttpOpen", "InternetOpenUrl", "CryptEncrypt",
    "GetAsyncKeyState", "SetWindowsHookEx", "NtQueryInformationProcess",
})
IMPORT_WEIGHT_SPECIFIC = 15
IMPORT_WEIGHT_DUAL_USE = 5
IMPORT_SCORE_CAP = 30  # sotto la soglia "malicious" (60)

# Macro/shell markers usati dall'analisi Office (OLE + OOXML + .rtf)
VBA_AUTORUN = [
    "autoopen", "document_open", "workbook_open", "auto_close", "document_close",
    "workbook_activate", "autoexec", "autonew", "documentbeforeclose",
]
VBA_RISKY_API = [
    "createobject", "wscript.shell", "shell(", "shellexecute", "powershell",
    "cmd.exe", "urlmon", "xmlhttp", "adodb.stream", "saveToFile", "environ(",
    "getobject", "declare ptrsafe", "virtualalloc", "lib ", "kernel32",
]
OFFICE_EXEC_MARKERS = ["ddeauto", "dde ", "microsoft excel 4.0 macro", "xm|", "msexcel4macro"]

# Formati che l'engine dichiara alla UI (endpoint /formats)
SUPPORTED_FORMATS: List[Dict[str, Any]] = [
    {"id": "pe", "label": "Windows PE / .NET", "extensions": [".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx", ".msi"],
     "analysis": "header, sections+entropy, suspicious imports, CLR/.NET, signature, IOCs, PDB"},
    {"id": "elf", "label": "Linux ELF", "extensions": [".elf", ".so", ".ko", ""],
     "analysis": "architecture, entropy, suspicious strings, IOCs"},
    {"id": "macho", "label": "macOS Mach-O / fat", "extensions": [".macho", ".dylib"],
     "analysis": "magic+CPU family, entropy, suspicious strings, IOCs"},
    {"id": "office", "label": "Office OLE / OOXML", "extensions": [".doc", ".xls", ".ppt", ".docm", ".xlsm", ".pptm", ".docx", ".xlsx", ".pptx"],
     "analysis": "VBA macros, auto-exec, DDE, external objects/embeds, embedded MZ"},
    {"id": "pdf", "label": "PDF", "extensions": [".pdf"],
     "analysis": "JavaScript, /OpenAction, /Launch, attachments, XFA, automatic actions"},
    {"id": "zip", "label": "ZIP archive (incl. APK/JAR/OOXML)", "extensions": [".zip", ".jar", ".apk", ".war", ".ear", ".whl", ".xpi", ".ipa"],
     "analysis": "per-file content, nesting depth 1, VBA macros, classes.dex, anti zip-bomb bounds"},
    {"id": "tar", "label": "tar/gzip/bzip2/xz archives", "extensions": [".tar", ".gz", ".tgz", ".bz2", ".xz", ".txz"],
     "analysis": "listing + per-file analysis (bounded)"},
    {"id": "archive_other", "label": "7z / RAR / ISO / other containers", "extensions": [".7z", ".rar", ".iso", ".cab", ".deb", ".rpm"],
     "analysis": "format identification, entropy, strings/IOC (full extraction in Phase 2)"},
    {"id": "class", "label": "Java class / WASM", "extensions": [".class", ".wasm"],
     "analysis": "magic, architecture/version, strings, IOCs"},
    {"id": "script", "label": "Scripts and source code", "extensions": sorted(TEXT_EXTS),
     "analysis": "secret scan, heuristics, IOCs (always with secret redaction)"},
    {"id": "data", "label": "Database / pcap / LNK / RTF / images", "extensions": [".sqlite", ".db", ".pcap", ".pcapng", ".lnk", ".rtf", ".png", ".jpg", ".gif", ".webp", ".bmp", ".ico"],
     "analysis": "identification, entropy, strings, IOCs"},
    {"id": "binary", "label": "Any other file", "extensions": ["*"],
     "analysis": "magic identification, entropy, strings, secret scan on textual samples"},
]

# ─── Analysis helpers ─────────────────────────────────────────────────────────

ARCHIVE_KINDS = {"zip", "gzip", "bzip2", "xz", "tar", "7z", "rar", "cab", "iso"}
PER_ENTRY_MAX_BYTES = 64 * 1024 * 1024   # cap per singolo file (anti zip-bomb)
TOTAL_UNCOMPRESSED_MAX = 500 * 1024 * 1024
MAX_ANALYZED_MEMBERS = 500       # membri di un archivio analizzati per file
MAX_NESTED_DEPTH = 2             # zip-in-zip-in-zip: oltre si ferma (anti ricorsione a stack)
MAX_TEXT_SCAN_BYTES = 5 * 1024 * 1024     # sorgenti enormi: si analizza la testa
MAX_UTF16_SCAN_BYTES = 16 * 1024 * 1024


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq: Dict[int, int] = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _extract_strings(data: bytes, min_len: int = 6, limit: int = 4000) -> List[str]:
    """Stringhe ASCII + UTF-16LE (i binari Windows usano ampiamente wide)."""
    result: List[str] = []
    current: List[int] = []
    for b in data:
        if 0x20 <= b <= 0x7E:
            current.append(b)
        else:
            if len(current) >= min_len:
                result.append(bytes(current).decode("ascii"))
            current = []
    if len(current) >= min_len:
        result.append(bytes(current).decode("ascii"))
    # UTF-16LE: utile per Office/macro. Bound sui file enormi per non far
    # esplodere il costo del regex su campioni legittimi da centinaia di MB.
    wide = re.findall(rb"(?:[\x20-\x7e]\x00){6,}", data[:MAX_UTF16_SCAN_BYTES])
    for w in wide[:400]:
        result.append(w.decode("utf-16-le", errors="ignore").strip())
    return result[:limit]


def _iocs_from(text: str, limit: int = 15) -> Dict[str, List[str]]:
    iocs: Dict[str, List[str]] = {}
    safe = {"127.0.0.1", "0.0.0.0", "255.255.255.255"}  # nosec B104 - allowlist di indicatori, non un bind
    for name, pat in IOC_PATTERNS.items():
        matches = list(set(pat.findall(text)))[:limit]
        filtered = [m for m in matches if m not in safe]
        if name == "ipv4":
            # Numeri di versione (5.1.0.0) non sono indicatori di compromissione.
            filtered = [m for m in filtered if not VERSIONLIKE_IPV4.match(m)]
        if filtered:
            iocs[name] = filtered
    return iocs


def _hexdump_preview(raw: bytes, max_bytes: int = 512) -> str:
    out = []
    for off in range(0, min(len(raw), max_bytes), 16):
        chunk = raw[off:off + 16]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        asciipart = "".join(chr(b) if 0x20 <= b <= 0x7E else "." for b in chunk)
        out.append(f"{off:08x}  {hexpart:<47}  {asciipart}")
    return "\n".join(out)


def _ts_to_iso(value: int) -> Optional[str]:
    try:
        if 0 < value < 4102444800:  # < 2100
            return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()
    except Exception:
        pass
    return None


def _safe_member_name(name: str) -> str:
    """Nome da mostrare: niente traversal né path assoluti."""
    cleaned = (name or "").replace("\\", "/").lstrip("/")
    parts = [p for p in cleaned.split("/") if p and p != "."]
    if any(p == ".." for p in parts):
        return "(unsafe-path)"
    return "/".join(parts)[:400] or "(unnamed)"


# ─── PE ───────────────────────────────────────────────────────────────────────

def _pe_sections(raw: bytes, sec_off: int, num_sections: int) -> Tuple[List[Dict[str, Any]], float, int]:
    sections: List[Dict[str, Any]] = []
    overlay_start = 0
    for i in range(min(num_sections, 96)):
        base = sec_off + i * 40
        if base + 40 > len(raw):
            break
        sname = raw[base:base + 8].rstrip(b"\x00").decode("ascii", errors="replace").strip()
        virt_sz = struct.unpack_from("<I", raw, base + 8)[0]
        raw_sz = struct.unpack_from("<I", raw, base + 16)[0]
        raw_off = struct.unpack_from("<I", raw, base + 20)[0]
        characteristics = struct.unpack_from("<I", raw, base + 36)[0]
        ent = _entropy(raw[raw_off:raw_off + raw_sz]) if (raw_off and raw_sz) else 0.0
        sections.append({
            "name": sname or "(unnamed)",
            "virtual_size": virt_sz,
            "raw_size": raw_sz,
            "entropy": round(ent, 2),
            "executable": bool(characteristics & 0x20000000),
            "writable": bool(characteristics & 0x80000000),
        })
        if raw_off and raw_sz:
            overlay_start = max(overlay_start, raw_off + raw_sz)
    return sections, 0.0, overlay_start


def _analyze_pe(raw: bytes) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "format": "PE", "findings": [], "score_contribution": 0,
        "sections": [], "imports_suspicious": [], "iocs": {}, "entropy_alert": False,
    }
    try:
        if len(raw) < 64:
            return result
        e_lfanew = struct.unpack_from("<I", raw, 0x3C)[0]
        if e_lfanew + 24 > len(raw) or raw[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            return result

        coff = e_lfanew + 4
        machine = struct.unpack_from("<H", raw, coff)[0]
        num_sections = struct.unpack_from("<H", raw, coff + 2)[0]
        timestamp = struct.unpack_from("<I", raw, coff + 4)[0]
        opt_hdr_size = struct.unpack_from("<H", raw, coff + 16)[0]
        characteristics = struct.unpack_from("<H", raw, coff + 18)[0]
        result["arch"] = "x64" if machine == 0x8664 else ("x86" if machine == 0x14C else ("arm64" if machine == 0xAA64 else f"0x{machine:04X}"))
        result["compile_time"] = _ts_to_iso(timestamp)
        # IMAGE_FILE_DLL = 0x2000, IMAGE_FILE_SYSTEM = 0x1000 (driver)
        result["kind"] = ("DLL" if characteristics & 0x2000
                          else "SYS/Driver" if characteristics & 0x1000
                          else "EXE")

        opt_off = coff + 20
        pe32plus = False
        if opt_off < len(raw):
            opt_magic = struct.unpack_from("<H", raw, opt_off)[0]
            pe32plus = opt_magic == 0x20B
            result["pe_type"] = "PE32+" if pe32plus else "PE32"
            # Entry point + data directories (indice 4 = Security, 14 = CLR)
            ep_off = opt_off + (16 if pe32plus else 16)
            entry_rva = struct.unpack_from("<I", raw, ep_off)[0]
            result["entrypoint_rva"] = entry_rva
            dd_off = opt_off + (112 if pe32plus else 96)
            if dd_off + 16 * 8 <= len(raw):
                sec_dir_off = struct.unpack_from("<I", raw, dd_off + 4 * 8)[0]
                sec_dir_size = struct.unpack_from("<I", raw, dd_off + 4 * 8 + 4)[0]
                clr_rva = struct.unpack_from("<I", raw, dd_off + 14 * 8)[0]
                result["signed"] = bool(sec_dir_off and sec_dir_size)
                result["dotnet"] = bool(clr_rva)
                if not result["signed"]:
                    result["findings"].append({
                        "type": "unsigned_binary", "severity": "low",
                        "detail": "No Authenticode certificate: common in droppers/loaders.",
                    })

        sections, _, overlay_start = _pe_sections(raw, opt_off + opt_hdr_size, num_sections)
        result["sections"] = sections
        high_ent_secs = [s["name"] for s in sections if s["entropy"] > 7.0 and s.get("raw_size", 0) > 512]
        if high_ent_secs:
            result["entropy_alert"] = True
            result["findings"].append({
                "type": "packer_or_encrypted", "severity": "high",
                "detail": f"Sezioni ad alta entropia: {', '.join(high_ent_secs)} — probabile packing/cifratura (UPX, Themida…)",
                "mitre": "T1027",
            })
            result["score_contribution"] += 40

        # Overlay (dati oltre l'ultima sezione): payload appeso frequente
        if 0 < overlay_start < len(raw) - 1024:
            overlay_size = len(raw) - overlay_start
            embedded = raw.lower().count(b"mz")
            result["overlay_bytes"] = overlay_size
            sev = "high" if (overlay_size > 65536 and embedded > 1) else "low"
            result["findings"].append({
                "type": "overlay_data", "severity": sev,
                "detail": f"{overlay_size} bytes of data past the last section (appended payload / SFX installer).",
            })
            if sev == "high":
                result["score_contribution"] = min(result["score_contribution"] + 20, 100)

        strings = _extract_strings(raw)
        full_str = " ".join(strings)
        result["iocs"] = _iocs_from(full_str)

        # PDB path (debug info residua: utile per attribuzione)
        pdb = re.search(r"[A-Za-z]:\\[^\x00\r\n]{0,200}\.pdb", raw.decode("latin-1", errors="ignore"))
        if pdb:
            result["pdb_path"] = pdb.group(0)[:255]

        import_score = 0
        for fn, (cap, tid) in SUSPICIOUS_IMPORTS.items():
            if any(fn.lower() in s.lower() for s in strings):
                dual = fn in DUAL_USE_IMPORTS
                result["imports_suspicious"].append({
                    "function": fn, "capability": cap, "mitre": tid,
                    "weight": IMPORT_WEIGHT_DUAL_USE if dual else IMPORT_WEIGHT_SPECIFIC,
                })
                import_score += IMPORT_WEIGHT_DUAL_USE if dual else IMPORT_WEIGHT_SPECIFIC
        if import_score:
            # Gli import da soli non portano a "malicious" (60): pesano al
            # massimo IMPORT_SCORE_CAP. notepad.exe importa tre API comuni e
            # con il vecchio peso fisso chiudeva a 45+"malicious".
            result["score_contribution"] = min(
                result["score_contribution"] + min(import_score, IMPORT_SCORE_CAP), 100)

        for pat in SUSPICIOUS_STRINGS:
            m = pat.search(full_str)
            if m:
                result["findings"].append({"type": "suspicious_string_in_binary", "severity": "high", "match": m.group(0)[:80]})
                result["score_contribution"] = min(result["score_contribution"] + 25, 100)

        if result.get("dotnet"):
            result["findings"].append({
                "type": "dotnet_assembly", "severity": "low",
                "detail": ".NET assembly (CLR header present): possible loading via PowerShell/reflection.",
                "mitre": "T1055",
            })

        if result["iocs"].get("url") or result["iocs"].get("domain"):
            result["findings"].append({"type": "network_ioc", "severity": "medium",
                                       "detail": f"{len(result['iocs'].get('url', []))} URL(s), {len(result['iocs'].get('domain', []))} embedded domain(s)."})

        lowered = raw.lower()
        if b"powershell" in lowered or b"invoke-expression" in lowered:
            # Solo un riferimento non basta per un "high": la parola compare in
            # binari firmati Microsoft e in qualunque documentazione. Il peso
            # pieno lo prende quando c'e' un marker di esecuzione.
            exec_like = any(m in lowered for m in POWERSHELL_EXEC_MARKERS)
            result["findings"].append({
                "type": "embedded_powershell",
                "severity": "high" if exec_like else "low",
                "detail": ("PE contains PowerShell with execution flags — possible dropper."
                           if exec_like else
                           "References to PowerShell without execution flags (common in signed binaries and docs)."),
                "mitre": "T1059.001",
            })
            if exec_like:
                result["score_contribution"] = min(result["score_contribution"] + 30, 100)

    except Exception as ex:
        result["parse_error"] = str(ex)
    return result


# ─── ELF / Mach-O ─────────────────────────────────────────────────────────────

def _analyze_elf(raw: bytes) -> Dict[str, Any]:
    result: Dict[str, Any] = {"format": "ELF", "findings": [], "score_contribution": 0, "iocs": {}}
    try:
        if len(raw) < 52:
            return result
        ei_class = raw[4]
        ei_data = raw[5]
        e_type = struct.unpack_from("<H", raw, 16)[0]
        result["arch"] = ("ELF64" if ei_class == 2 else "ELF32") + (" LE" if ei_data == 1 else " BE")
        result["kind"] = {1: "relocatable", 2: "executable", 3: "shared-object", 4: "core-dump"}.get(e_type, f"type-{e_type}")
        ent = _entropy(raw)
        result["entropy"] = round(ent, 2)
        if ent > 7.2:
            result["entropy_alert"] = True
            result["findings"].append({"type": "packer_or_encrypted", "severity": "high",
                                       "detail": f"Entropia {ent:.2f} — binario probabilmente packato/cifrato.", "mitre": "T1027"})
            result["score_contribution"] += 40

        strings = _extract_strings(raw)
        full_str = " ".join(strings)
        for pat in SUSPICIOUS_STRINGS:
            m = pat.search(full_str)
            if m:
                result["findings"].append({"type": "suspicious_string_in_elf", "severity": "high", "match": m.group(0)[:80]})
                result["score_contribution"] = min(result["score_contribution"] + 25, 100)
        result["iocs"] = _iocs_from(full_str)
        if "/etc/ld.so.preload" in full_str:
            result["findings"].append({"type": "ld_preload_reference", "severity": "high",
                                       "detail": "Riferimento a ld.so.preload: tecnica classica di rootkit userland.", "mitre": "T1574.006"})
            result["score_contribution"] = min(result["score_contribution"] + 25, 100)
    except Exception as ex:
        result["parse_error"] = str(ex)
    return result


MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce": ("Mach-O 32 LE", "<"),
    b"\xfe\xed\xfa\xcf": ("Mach-O 64 LE", "<"),
    b"\xce\xfa\xed\xfe": ("Mach-O 32 BE", ">"),
    b"\xcf\xfa\xed\xfe": ("Mach-O 64 BE", ">"),
    b"\xca\xfe\xba\xbe": ("Mach-O fat/universal", ">"),
    b"\xbe\xba\xfe\xca": ("Mach-O fat/universal BE", "<"),
}
MACHO_CPUS = {7: "x86", 0x01000007: "x86_64", 12: "arm", 0x0100000C: "arm64", 18: "ppc", 0x01000012: "ppc64"}


def _analyze_macho(raw: bytes) -> Dict[str, Any]:
    result: Dict[str, Any] = {"format": "Mach-O", "findings": [], "score_contribution": 0, "iocs": {}}
    try:
        if len(raw) < 32:
            return result
        magic = raw[:4]
        if magic in (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"):
            nfat = struct.unpack_from(">I", raw, 4)[0]
            cpus = []
            for i in range(min(nfat, 8)):
                base = 8 + i * 20
                if base + 12 > len(raw):
                    break
                cpu = struct.unpack_from(">I", raw, base)[0]
                cpus.append(MACHO_CPUS.get(cpu, f"cpu-{cpu}"))
            result["arch"] = "fat:" + "+".join(cpus or ["?"])
            result["kind"] = "universal"
        else:
            label, endian = MACHO_MAGICS.get(magic, ("Mach-O", "<"))
            cputype = struct.unpack_from(endian + "I", raw, 4)[0]
            filetype = struct.unpack_from(endian + "I", raw, 12)[0]
            result["arch"] = MACHO_CPUS.get(cputype, f"cpu-{cputype}")
            result["kind"] = {1: "object", 2: "executable", 6: "dylib", 8: "bundle", 11: "dylinker"}.get(filetype, f"type-{filetype}")
            result["magic_label"] = label

        ent = _entropy(raw)
        result["entropy"] = round(ent, 2)
        strings = _extract_strings(raw)
        full_str = " ".join(strings)
        for pat in SUSPICIOUS_STRINGS:
            m = pat.search(full_str)
            if m:
                result["findings"].append({"type": "suspicious_string_in_macho", "severity": "high", "match": m.group(0)[:80]})
                result["score_contribution"] = min(result["score_contribution"] + 25, 100)
        result["iocs"] = _iocs_from(full_str)
        if "com.apple.quarantine" in full_str or "xattr" in full_str:
            result["findings"].append({"type": "quarantine_evasion", "severity": "medium",
                                       "detail": "References to Apple quarantine handling (possible Gatekeeper evasion).",
                                       "mitre": "T1553.001"})
            result["score_contribution"] = min(result["score_contribution"] + 15, 100)
    except Exception as ex:
        result["parse_error"] = str(ex)
    return result


# ─── Office (OLE CFB + OOXML) ─────────────────────────────────────────────────

def _office_findings_from_text(text: str, source: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    low = text.lower()
    autorun = [a for a in VBA_AUTORUN if a in low]
    risky = [r for r in VBA_RISKY_API if r.lower() in low]
    if autorun:
        findings.append({
            "type": "office_autorun_macro", "severity": "critical",
            "detail": f"Macro auto-eseguibile ({source}): {', '.join(sorted(set(autorun))[:6])}",
            "mitre": "T1204.002",
        })
    if risky:
        findings.append({
            "type": "office_macro_risky_api", "severity": "high",
            "detail": f"Risky API in the VBA content ({source}): {', '.join(sorted(set(risky))[:8])}",
            "mitre": "T1059.005",
        })
    for marker in OFFICE_EXEC_MARKERS:
        if marker in low:
            findings.append({
                "type": "office_dde_or_xlm", "severity": "critical",
                "detail": f"Marker di esecuzione ({source}): '{marker.strip()}' — DDE o macro Excel 4.0.",
                "mitre": "T1559.002",
            })
            break
    if "http://" in low or "https://" in low or "\\\\" in text:
        urls = IOC_PATTERNS["url"].findall(text)[:5]
        if urls:
            findings.append({
                "type": "office_external_ref", "severity": "medium",
                "detail": f"External references in the document: {', '.join(urls[:3])}",
            })
    return findings


def _analyze_ole(raw: bytes) -> Dict[str, Any]:
    """OLE/CFB (doc/xls/ppt legacy, msi): cerca stream VBA e contenuti eseguibili."""
    result: Dict[str, Any] = {"format": "OLE2/CFB", "findings": [], "score_contribution": 0, "iocs": {}, "streams": []}
    try:
        text_ascii = raw.decode("latin-1", errors="ignore")
        text_wide = raw.decode("utf-16-le", errors="ignore")
        combined = text_ascii + "\n" + text_wide

        stream_markers = [
            ("WordDocument", "Word (doc)"), ("Workbook", "Excel (xls)"), ("Book", "Excel (xls)"),
            ("PowerPoint Document", "PowerPoint (ppt)"), ("_VBA_PROJECT", "progetto VBA"),
            ("VBA", "modulo VBA"), ("Macros", "storage Macros"),
            ("ThisDocument", "modulo ThisDocument"), ("Module1", "modulo standard"),
            ("ObjectPool", "ObjectPool (embedded)"),
        ]
        result["streams"] = sorted({label for marker, label in stream_markers if marker.lower() in combined.lower()})

        has_vba = any(k in combined for k in ("_VBA_PROJECT", "VBA", "Attribute VB_"))
        if has_vba:
            result["findings"].append({
                "type": "ole_vba_project", "severity": "high",
                "detail": "VBA project present in the OLE document.", "mitre": "T1204.002",
            })
            result["score_contribution"] += 30

        result["findings"].extend(_office_findings_from_text(combined, "OLE"))

        # Oggetti incorporati eseguibili dentro il documento
        if b"MZ" in raw and raw.count(b"MZ") > 1:
            result["findings"].append({
                "type": "embedded_executable", "severity": "critical",
                "detail": "Document contains one or more embedded PE objects (MZ), possible dropper.",
                "mitre": "T1204.002",
            })
            result["score_contribution"] += 40

        result["score_contribution"] = min(result["score_contribution"] + 15 * len(
            [f for f in result["findings"] if f.get("severity") in ("high", "critical")]
        ), 100)
        result["iocs"] = _iocs_from(combined)
        result["entropy"] = round(_entropy(raw), 2)
    except Exception as ex:
        result["parse_error"] = str(ex)
    return result


def _analyze_ooxml(raw: bytes, zf: zipfile.ZipFile) -> Dict[str, Any]:
    """Office moderno (zip-based): macro VBA, relazioni esterne, embed, MZ."""
    result: Dict[str, Any] = {"format": "OOXML", "findings": [], "score_contribution": 0, "iocs": {}, "parts": []}
    names = [n for n in zf.namelist() if not n.endswith("/")]
    result["parts"] = names[:60]

    if any(n.lower().endswith("vbaproject.bin") for n in names):
        result["findings"].append({
            "type": "ooxml_vba_macro", "severity": "critical",
            "detail": "Documento OOXML con macro VBA (vbaProject.bin) — esecuzione al Document_Open.",
            "mitre": "T1204.002",
        })
        result["score_contribution"] += 45

    if any(n.lower().startswith("xl/macrosheets/") for n in names):
        result["findings"].append({
            "type": "excel4_macro_sheet", "severity": "critical",
            "detail": "Excel 4.0 macro sheet (xl/macrosheets): execution without classic VBA macros.",
            "mitre": "T1204.002",
        })
        result["score_contribution"] += 45

    embedded = [n for n in names if "/embeddings/" in n.lower() or n.lower().endswith((".bin", ".exe", ".dll"))]
    if embedded:
        result["findings"].append({
            "type": "ooxml_embedded_object", "severity": "high",
            "detail": f"Embedded objects: {', '.join(embedded[:5])}",
            "mitre": "T1204.002",
        })
        result["score_contribution"] += 20

    # Bound: si leggono solo le prime parti XML/rels e al massimo ~2 MB totali
    # (un OOXML può contenere migliaia di parti: senza cap il worker si blocca).
    text_sample = ""
    xml_parts = [n for n in names if n.lower().endswith((".rels", ".xml", ".txt"))][:60]
    for n in xml_parts:
        if len(text_sample) > 2 * 1024 * 1024:
            break
        try:
            text_sample += zf.read(n)[:200000].decode("utf-8", errors="ignore") + "\n"
        except Exception:
            continue
    result["findings"].extend(_office_findings_from_text(text_sample, "OOXML"))
    if b"DDEAUTO" in text_sample.upper().encode("latin-1", errors="ignore"):
        result["findings"].append({
            "type": "ooxml_dde", "severity": "critical",
            "detail": "DDE callback in the XML content (execution without macros).",
            "mitre": "T1559.002",
        })
        result["score_contribution"] += 40

    # PE dentro il contenitore (vedi anche embedded)
    for n in names[:200]:
        try:
            if n.lower().endswith((".bin", ".exe", ".dll", ".scr")):
                head = zf.read(n)[:4]
                if head[:2] == b"MZ":
                    result["findings"].append({
                        "type": "ooxml_embedded_pe", "severity": "critical",
                        "detail": f"Embedded PE in {n} (dropper inside the document).",
                        "mitre": "T1204.002",
                    })
                    result["score_contribution"] = min(result["score_contribution"] + 30, 100)
                    break
        except Exception:
            continue

    result["score_contribution"] = min(result["score_contribution"], 100)
    result["iocs"] = _iocs_from(text_sample)
    return result


def _analyze_rtf(raw: bytes) -> Dict[str, Any]:
    text = raw.decode("latin-1", errors="ignore")
    result: Dict[str, Any] = {"format": "RTF", "findings": [], "score_contribution": 0, "iocs": _iocs_from(text)}
    obj = len(re.findall(r"\\obj(?:data|update|emb)", text, re.I))
    if obj:
        result["findings"].append({
            "type": "rtf_embedded_object", "severity": "high",
            "detail": f"RTF with {obj} embedded object(s) (classic exploit/dropper vector).",
            "mitre": "T1204.002",
        })
        result["score_contribution"] += 45
    if re.search(r"\\objclass\s+(Equation|Package)", text, re.I):
        result["findings"].append({
            "type": "rtf_equation_exploit", "severity": "critical",
            "detail": "Equation/Package object: historical CVE vector (Eqnedt32).", "mitre": "T1203",
        })
        result["score_contribution"] = min(result["score_contribution"] + 30, 100)
    return result


# ─── PDF ──────────────────────────────────────────────────────────────────────

def _analyze_pdf(raw: bytes) -> Dict[str, Any]:
    result: Dict[str, Any] = {"format": "PDF", "findings": [], "score_contribution": 0, "iocs": {}}
    try:
        text = raw.decode("latin-1", errors="ignore")
        checks = {
            "/javascript": ("pdf_javascript", "critical", "JavaScript embedded in the PDF.", "T1059.007"),
            "/openaction": ("pdf_openaction", "high", "/OpenAction: automatic action on open.", "T1204.002"),
            "/aa": ("pdf_additional_action", "high", "/AA: automatic additional action.", "T1204.002"),
            "/launch": ("pdf_launch", "critical", "/Launch: execution of an external program.", "T1204.002"),
            "/embeddedfile": ("pdf_embedded_file", "high", "Attached file embedded in the PDF.", "T1204.002"),
            "/richmedia": ("pdf_richmedia", "medium", "RichMedia content (Flash/JS).", "T1204.002"),
            "/xfa": ("pdf_xfa_form", "medium", "XFA form (often used for obfuscation).", "T1027"),
            "/submitform": ("pdf_form_exfil", "medium", "Form submit action (possible exfiltration).", "T1041"),
            "/encrypt": ("pdf_encrypted", "low", "PDF cifrato: i contenuti non sono ispezionabili staticamente.", None),
        }
        low = text.lower()
        for token, (ftype, sev, detail, mitre) in checks.items():
            if token in low:
                finding = {"type": ftype, "severity": sev, "detail": detail}
                if mitre:
                    finding["mitre"] = mitre
                result["findings"].append(finding)
                result["score_contribution"] += {"critical": 40, "high": 25, "medium": 15, "low": 5}[sev]

        uri_count = low.count("/uri")
        if uri_count:
            result["uri_count"] = uri_count
            result["iocs"] = _iocs_from(text)
            if result["iocs"].get("url") or uri_count > 10:
                result["findings"].append({
                    "type": "pdf_external_links", "severity": "low",
                    "detail": f"{uri_count} external links in the PDF.",
                })

        # Dati dopo %%EOF: tecnica classica per appendere un archivio/payload
        eofs = [m.start() for m in re.finditer(rb"%%EOF", raw)]
        if eofs and len(raw) - eofs[-1] > 1024:
            result["findings"].append({
                "type": "pdf_data_after_eof", "severity": "medium",
                "detail": f"{len(raw) - eofs[-1]} byte dopo l'ultimo %%EOF (payload appeso).", "mitre": "T1027",
            })
            result["score_contribution"] += 20

        result["score_contribution"] = min(result["score_contribution"], 100)
        result["entropy"] = round(_entropy(raw), 2)
    except Exception as ex:
        result["parse_error"] = str(ex)
    return result


# ─── Archivi ──────────────────────────────────────────────────────────────────

def _analyze_zip(raw: bytes, *, max_files: int, max_bytes: int,
                 allow_nested: bool = True) -> Dict[str, Any]:
    """Analizza un archivio ZIP (incl. OOXML/APK/JAR). Mai eccezioni non gestite."""
    try:
        zf = zipfile.ZipFile(io.BytesIO(raw))
    except Exception:
        return {"kind": "archive", "format": "ZIP", "score": 0, "findings": [
            {"type": "invalid_zip", "severity": "medium", "detail": "Contenitore non leggibile come ZIP."}],
            "extracted": [], "truncated": False}

    infos = zf.infolist()
    declared = sum(i.file_size for i in infos)
    names_lower = [i.filename.lower() for i in infos]

    is_ooxml = any(n.endswith(".xml") and ("word/" in n or "xl/" in n or "ppt/" in n) for n in names_lower) or \
        any(n == "[content_types].xml" for n in names_lower)
    is_apk = "androidmanifest.xml" in names_lower or "classes.dex" in names_lower
    is_jar = any(n.endswith(".class") for n in names_lower) and any(n.endswith(".mf") for n in names_lower)

    if is_ooxml:
        detail = _analyze_ooxml(raw, zf)
        detail.update({"kind": "office", "analyzed_members": 0, "truncated": False})
        detail["score"] = detail.pop("score_contribution", 0)
        return detail

    findings: List[Dict[str, Any]] = []
    score = 0
    if is_apk:
        findings.append({"type": "android_package", "severity": "low",
                         "detail": "Pacchetto APK: classes.dex e AndroidManifest presenti.", "mitre": "T1400"})
        score += 10
    elif is_jar:
        findings.append({"type": "java_archive", "severity": "low",
                         "detail": "Archivio Java (class + manifest).", "mitre": "T1059.007"})

    truncated = False
    if len(infos) > max_files:
        truncated = True
        findings.append({"type": "archive_truncated", "severity": "low",
                         "detail": f"Archive with {len(infos)} files: first {max_files} analyzed.",
                         "mitre": None})
    if declared > TOTAL_UNCOMPRESSED_MAX:
        truncated = True
        findings.append({"type": "zip_bomb_suspected", "severity": "high",
                         "detail": f"Dimensione dichiarata in espansione {declared // (1024 * 1024)} MB "
                                   f"(limite {TOTAL_UNCOMPRESSED_MAX // (1024 * 1024)} MB): analisi parziale antifrode.",
                         "mitre": "T1499"})
        findings[-1].pop("mitre", None)
        score += 20

    extracted: List[Dict[str, Any]] = []
    budget = max_bytes
    for info in infos[:max_files]:
        name = info.filename
        if name.startswith("/") or ".." in name or info.is_dir():
            continue
        if info.file_size > PER_ENTRY_MAX_BYTES:
            extracted.append({"kind": "binary", "format": "OVERSIZE", "score": 0,
                              "path": _safe_member_name(name), "size": info.file_size,
                              "findings": [{"type": "entry_too_large", "severity": "medium",
                                            "detail": f"Voce da {info.file_size // (1024 * 1024)} MB non estratta (cap per-file)."}]})
            continue
        try:
            content = zf.read(name)
        except Exception:
            continue
        budget -= len(content)
        entry = _analyze_bytes(
            content, name,
            allow_nested=allow_nested and len(extracted) < MAX_ANALYZED_MEMBERS,
            nested_depth=1,
        )
        entry["path"] = _safe_member_name(name)
        entry["size"] = len(content)
        entry["sha256"] = hashlib.sha256(content).hexdigest()
        extracted.append(entry)
        if budget <= 0 and len(extracted) < len(infos):
            truncated = True
            findings.append({"type": "budget_exhausted", "severity": "low",
                             "detail": "Analysis budget exhausted: remaining files not analyzed."})
            break

    return {
        "kind": "archive", "format": "ZIP" + (" (APK)" if is_apk else " (JAR)" if is_jar else ""),
        "score": min(score, 100), "findings": findings,
        "analyzed_members": len(extracted), "total_members": len(infos), "truncated": truncated,
        "extracted": extracted,
    }


def _analyze_tar_like(raw: bytes, fmt: str, name: str = "archive") -> Optional[Dict[str, Any]]:
    """tar/gzip/bzip2/xz: listing + analisi per-file (bounded)."""
    try:
        if fmt == "tar":
            stream: Any = io.BytesIO(raw)
        elif fmt == "gzip":
            stream = io.BytesIO(gzip.decompress(raw))
        elif fmt == "bzip2":
            stream = io.BytesIO(bz2.decompress(raw))
        elif fmt == "xz":
            stream = io.BytesIO(lzma.decompress(raw))
        else:
            return None
        if not tarfile.is_tarfile(stream):  # type: ignore[arg-type]
            # Stream compresso di un singolo file (.gz di un campione): si
            # analizza il contenuto decompresso, non solo l'involucro.
            stream.seek(0)  # type: ignore[union-attr]
            expanded = stream.read(PER_ENTRY_MAX_BYTES + 1)  # type: ignore[union-attr]
            if len(expanded) > PER_ENTRY_MAX_BYTES:
                expanded = expanded[:PER_ENTRY_MAX_BYTES]
            base_name = re.sub(r"\.(gz|bz2|xz|tgz|txz)$", "", name, flags=re.I) or "decompressed.bin"
            detail = _analyze_bytes(expanded, base_name, allow_nested=False, nested_depth=1)
            detail.setdefault("findings", []).insert(0, {
                "type": "compressed_stream", "severity": "low",
                "detail": f"{fmt.upper()} content decompressed and analyzed ({len(expanded)} bytes).",
            })
            detail["format"] = f"{fmt.upper()}>" + str(detail.get("format", "BINARY"))
            detail["kind"] = "binary"
            return detail
        stream.seek(0)  # type: ignore[union-attr]
        extracted: List[Dict[str, Any]] = []
        findings: List[Dict[str, Any]] = []
        with tarfile.open(fileobj=stream) as tf:  # type: ignore[arg-type]
            members = tf.getmembers()
            for m in members[:200]:
                if not m.isfile():
                    continue
                try:
                    fh = tf.extractfile(m)
                    if fh is None:
                        continue
                    content = fh.read(PER_ENTRY_MAX_BYTES + 1)
                except Exception:
                    continue
                if len(content) > PER_ENTRY_MAX_BYTES:
                    findings.append({"type": "entry_too_large", "severity": "medium",
                                     "detail": f"{_safe_member_name(m.name)} oltre il cap per-file."})
                    continue
                entry = _analyze_bytes(content, m.name, allow_nested=False, nested_depth=1)
                entry["path"] = _safe_member_name(m.name)
                entry["size"] = len(content)
                entry["sha256"] = hashlib.sha256(content).hexdigest()
                extracted.append(entry)
        return {"kind": "archive", "format": fmt.upper(), "score": 0, "findings": findings,
                "analyzed_members": len(extracted), "total_members": len(members),
                "truncated": len(members) > 200, "extracted": extracted}
    except Exception as ex:
        return {"kind": "archive", "format": fmt.upper(), "score": 5,
                "findings": [{"type": "decompression_error", "severity": "medium", "detail": str(ex)[:200]}],
                "extracted": [], "truncated": False}


def _analyze_archive_other(raw: bytes, fmt: str) -> Dict[str, Any]:
    """7z/rar/iso/cab/deb/rpm: identificazione + stringhe (estrazione in Phase 2)."""
    strings = _extract_strings(raw)
    full = " ".join(strings)
    findings = [{
        "type": "container_format", "severity": "low",
        "detail": f"Contenitore {fmt.upper()} identificato: estrazione completa (7z/rar/ISO) in Phase 2. "
                  f"Analisi statica su header, stringhe e IOC eseguita.",
    }]
    score = 5
    for pat in SUSPICIOUS_STRINGS:
        m = pat.search(full)
        if m:
            findings.append({"type": "suspicious_string_in_container", "severity": "high", "match": m.group(0)[:80]})
            score += 25
    if b"MZ" in raw[:65536] or raw.count(b"MZ") > 3:
        findings.append({"type": "executable_inside_container", "severity": "high",
                         "detail": "PE headers detected inside the container.", "mitre": "T1027"})
        score += 25
    return {"kind": "binary", "format": fmt.upper(), "score": min(score, 100), "findings": findings,
            "iocs": _iocs_from(full), "entropy": round(_entropy(raw), 2),
            "note": f"Contenitore {fmt.upper()}: analisi statica disponibile, estrazione per-file in Phase 2."}


# ─── Testo / binario generico ─────────────────────────────────────────────────

def _score_text(content: bytes, name: str) -> Dict[str, Any]:
    # Bound sul sorgente: 11 regex su 100 MB di log bloccherebbero il worker.
    truncated = len(content) > MAX_TEXT_SCAN_BYTES
    text = content[:MAX_TEXT_SCAN_BYTES].decode("utf-8", errors="ignore")
    findings: List[Dict[str, Any]] = []
    if truncated:
        findings.append({"type": "scan_truncated", "severity": "low",
                         "detail": f"Source is {len(content) // (1024 * 1024)} MB: first "
                                   f"{MAX_TEXT_SCAN_BYTES // (1024 * 1024)} MB analyzed."})
    score = 0
    for pname, pat in SECRET_PATTERNS.items():
        matches = pat.findall(text)
        if matches:
            findings.append({"type": "secret", "pattern": pname, "severity": "medium", "count": len(matches)})
            score += 20
    for pat in SUSPICIOUS_STRINGS:
        m = pat.search(text)
        if m:
            findings.append({"type": "suspicious_string", "match": m.group(0)[:80], "severity": "high"})
            score += 35
    findings.extend(_office_findings_from_text(text, "script") if _looks_like_script(text) else [])
    for ioc_name, pat in IOC_PATTERNS.items():
        matches = list(set(pat.findall(text)))[:8]
        if matches and ioc_name in ("url", "domain", "onion"):
            findings.append({"type": f"ioc_{ioc_name}", "severity": "low", "matches": matches[:5]})
    redacted = text
    for pat in SECRET_PATTERNS.values():
        redacted = pat.sub("[REDACTED_SECRET]", redacted)
    return {"score": min(score, 100), "findings": findings, "preview": redacted[:30000]}


def _looks_like_script(text: str) -> bool:
    low = text.lower()
    return any(k in low for k in ("powershell", "cmd.exe", "wscript", "createobject", "sub ", "function ", "#!/"))


def _analyze_binary(raw: bytes, fmt: str) -> Dict[str, Any]:
    strings = _extract_strings(raw)
    full = " ".join(strings)
    findings: List[Dict[str, Any]] = []
    score = 10
    ent = _entropy(raw)
    if ent > 7.5 and len(raw) > 4096:
        findings.append({"type": "high_entropy_blob", "severity": "medium",
                         "detail": f"Entropy {ent:.2f}: compressed/encrypted/packed content.", "mitre": "T1027"})
        score += 15
    for pat in SUSPICIOUS_STRINGS:
        m = pat.search(full)
        if m:
            findings.append({"type": "suspicious_string", "severity": "high", "match": m.group(0)[:80]})
            score += 25
    iocs = _iocs_from(full)
    return {
        "kind": "binary", "format": fmt.upper(), "score": min(score, 100), "findings": findings,
        "iocs": iocs, "entropy": round(ent, 2),
        "strings_preview": strings[:120],
        "hexdump": _hexdump_preview(raw),
        "note": f"No dedicated parser for {fmt.upper()}: entropy, strings, IOCs and an optional hexdump.",
    }


def _malformed_container(raw: bytes, fmt: str, detail: Dict[str, Any]) -> Dict[str, Any]:
    """Magic riconosciuto ma header non parabile: si analizza comunque.

    Prima questo caso usciva con `score 0` e verdict "clean": un file con i byte
    `MZ` e un header corrotto o troncato (tecnica di evasione da manuale)
    spegneva l'analisi perche' il dispatcher aveva gia' scelto il parser PE e il
    ramo generico non girava mai. Un campione con dentro `mimikatz`,
    `-EncodedCommand` e `CreateRemoteThread` risultava pulito.
    """
    generic = _analyze_binary(raw, f"{fmt} (malformed)")
    findings: List[Dict[str, Any]] = [{
        "type": "malformed_header", "severity": "medium",
        "detail": (f"{fmt} magic recognised but the header does not parse: analyzed "
                   "generically instead of being skipped."),
        "mitre": "T1027",
    }]
    findings.extend(detail.get("findings") or [])
    findings.extend(generic.get("findings") or [])
    generic["findings"] = findings
    generic["score"] = min(int(generic.get("score") or 0) + 15, 100)
    generic["format"] = fmt
    generic["malformed"] = True
    return generic


def _parse_failed(detail: Dict[str, Any]) -> bool:
    """Il parser ha riconosciuto il formato ma non ha estratto struttura."""
    return not detail.get("arch") and not detail.get("sections") and not detail.get("kind")


def _is_text_file(name: str, content: bytes) -> bool:
    low = name.lower()
    base = low.split("/")[-1]
    ext = "." + base.rsplit(".", 1)[-1] if "." in base else ""
    if ext in TEXT_EXTS or base in MANIFEST_NAMES or base.startswith("dockerfile"):
        return True
    if content[:2] == b"MZ":
        return False
    if content[:4] in (b"\x7fELF", b"\xd0\xcf\x11\xa0", b"PK\x03\x04"):
        return False
    if content[:4] == b"%PDF":
        return False
    if not content:
        return True
    sample = content[:4096]
    printable = sum(1 for b in sample if 32 <= b <= 126 or b in (9, 10, 13))
    return (printable / max(len(sample), 1)) > 0.82


def _detect_format(raw: bytes, name: str) -> str:
    """Magic-first: l'estensione non decide mai da sola (renaming banale)."""
    if not raw:
        return "text"
    if raw[:2] == b"MZ":
        return "pe"
    if raw[:4] == b"\x7fELF":
        return "elf"
    # CAFEBABE è ambiguo: Mach-O fat (big-endian) e Java .class condividono il
    # magic. nfat_arch plausibile (1..16) → Mach-O; altrimenti è una classe
    # Java (i byte 4-7 sono minor/major version, es. 0x00000034 = Java 8).
    if raw[:4] == b"\xca\xfe\xba\xbe" and len(raw) >= 8:
        nfat = struct.unpack_from(">I", raw, 4)[0]
        if not 1 <= nfat <= 16:
            return "class"
    if raw[:4] in MACHO_MAGICS:
        return "macho"
    if raw[:5] == b"%PDF-":
        return "pdf"
    if raw[:4] == b"\xd0\xcf\x11\xa0":
        return "ole"
    if raw[:8] == b"\x89PNG\r\n\x1a\n" or raw[:3] == b"\xff\xd8\xff" or raw[:6] in (b"GIF87a", b"GIF89a"):
        return "image"
    if raw[:4] == b"PK\x03\x04" or raw[:4] == b"PK\x05\x06":
        return "zip"
    if raw[:6] == b"7z\xbc\xaf'\x1c":
        return "7z"
    if raw[:4] == b"Rar!":
        return "rar"
    if raw[:2] == b"\x1f\x8b":
        return "gzip"
    if raw[:3] == b"BZh":
        return "bzip2"
    if raw[:6] == b"\xfd7zXZ\x00":
        return "xz"
    if raw[:5] == b"ustar" or raw[257:262] == b"ustar":
        return "tar"
    if raw[:4] == b"\xca\xfe\xba\xbe":
        return "class"
    if raw[:4] == b"\x00asm":
        return "wasm"
    if raw[:16].startswith(b"SQLite format 3\x00"):
        return "sqlite"
    if raw[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x0a\x0d\x0d\x0a"):
        return "pcap"
    if raw[:4] == b"L\x00\x00\x00":
        return "lnk"
    if raw[:5] == b"{\\rtf":
        return "rtf"
    if raw[:4] == b"MSCF" or raw[:4] == b"ISc(":
        return "cab"
    if raw[:4] == b"CD001" or raw[0x8001:0x8006] == b"CD001":
        return "iso"
    ext = ("." + name.rsplit(".", 1)[-1].lower()) if "." in name else ""
    if ext == ".lnk":
        return "lnk"
    if ext in (".7z",) and raw[:2] == b"7z":
        return "7z"
    if _is_text_file(name, raw):
        return "text"
    return "binary"


def _analyze_bytes(raw: bytes, name: str, *, allow_nested: bool, nested_depth: int = 0) -> Dict[str, Any]:
    """Router unico: formato → parser. Usato sia per upload singolo sia per zip."""
    fmt = _detect_format(raw, name)

    if fmt == "pe":
        detail = _analyze_pe(raw)
        if _parse_failed(detail):
            return _malformed_container(raw, "PE", detail)
        detail.update({"kind": "binary", "size": len(raw), "format": "PE",
                       "score": detail.pop("score_contribution", 0),
                       "note": "PE: sezioni/entropia, import, .NET, firma, IOC."})
        return detail
    if fmt == "elf":
        detail = _analyze_elf(raw)
        if _parse_failed(detail):
            return _malformed_container(raw, "ELF", detail)
        detail.update({"kind": "binary", "size": len(raw), "format": "ELF",
                       "score": detail.pop("score_contribution", 0)})
        return detail
    if fmt == "macho":
        detail = _analyze_macho(raw)
        if _parse_failed(detail):
            return _malformed_container(raw, "Mach-O", detail)
        detail.update({"kind": "binary", "size": len(raw), "format": "Mach-O",
                       "score": detail.pop("score_contribution", 0)})
        return detail
    if fmt == "ole":
        detail = _analyze_ole(raw)
        detail.update({"kind": "binary", "size": len(raw), "format": "OLE2/CFB",
                       "score": detail.pop("score_contribution", 0),
                       "note": "Documento OLE/Office legacy o pacchetto MSI."})
        return detail
    if fmt == "pdf":
        detail = _analyze_pdf(raw)
        detail.update({"kind": "binary", "size": len(raw), "format": "PDF",
                       "score": detail.pop("score_contribution", 0)})
        return detail
    if fmt == "rtf":
        detail = _analyze_rtf(raw)
        detail.update({"kind": "text", "size": len(raw), "format": "RTF",
                       "score": detail.pop("score_contribution", 0)})
        return detail
    if fmt == "zip":
        # Guardia anti-ricorsione: zip dentro zip dentro zip non si estrae
        # all'infinito (ogni livello costerebbe memoria e stack).
        if nested_depth >= MAX_NESTED_DEPTH:
            return _analyze_binary(raw, "ZIP")
        detail = _analyze_zip(raw, max_files=MAX_ANALYZED_MEMBERS,
                              max_bytes=MAX_ANALYZED_MEMBERS * 1024,
                              allow_nested=allow_nested)
        detail["kind"] = "binary"
        return detail
    if fmt in ("tar", "gzip", "bzip2", "xz"):
        if nested_depth >= MAX_NESTED_DEPTH:
            return _analyze_binary(raw, fmt.upper())
        detail = _analyze_tar_like(raw, fmt, name)
        if detail is None:
            detail = _analyze_binary(raw, fmt)
        detail.setdefault("kind", "binary")
        if detail.get("kind") == "archive":
            detail["kind"] = "binary"
        return detail
    if fmt in ("7z", "rar", "cab", "iso"):
        return _analyze_archive_other(raw, fmt)
    if fmt in ("class", "wasm"):
        detail = _analyze_binary(raw, fmt)
        detail["kind"] = "binary"
        return detail
    if fmt == "text":
        tri = _score_text(raw, name)
        return {"kind": "text", "format": "text", "size": len(raw), "score": tri["score"],
                "findings": tri["findings"], "preview": tri["preview"]}
    # image / sqlite / pcap / lnk / binary
    detail = _analyze_binary(raw, fmt)
    if fmt == "lnk":
        detail["findings"].append({"type": "windows_shortcut", "severity": "medium",
                                   "detail": "LNK: check target and arguments (classic LOLBin vector).",
                                   "mitre": "T1204.002"})
    return detail


@router.get("/formats")
async def supported_formats(user=Depends(get_current_user)):
    """Catalogo formati supportati (usato dalla UI per spiegare cosa può caricare)."""
    return {
        "formats": SUPPORTED_FORMATS,
        "limits": {
            "max_file_mb": settings.TOTAL_MAX_FILE_MB,
            "max_zip_mb": settings.TOTAL_MAX_ZIP_MB,
            "max_files_per_zip": settings.TOTAL_MAX_FILES_PER_ZIP,
            "retention_days": settings.TOTAL_RETENTION_DAYS,
        },
        "note": "No extension is rejected: every file receives static analysis "
                "(formats without a dedicated parser go through entropy/strings/IOC). "
                "Binaries are never retained: only hashes, findings and IOCs.",
    }


@router.get("/disclaimer")
async def get_disclaimer():
    return {"disclaimer": AEGIS_TOTAL_DISCLAIMER}


class TotalAcceptBody(BaseModel):
    accept: bool


@router.get("/reports")
async def list_reports(db: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    result = await db.execute(select(TotalReport).order_by(TotalReport.created_at.desc()).limit(50))
    return {"items": [
        {"id": r.id, "sha256": r.sha256, "filename": r.filename, "kind": r.kind,
         "score": r.score, "verdict": r.verdict,
         "created_at": r.created_at.isoformat() if r.created_at else None}
        for r in result.scalars().all()
    ]}


@router.get("/reports/{sha256}")
async def get_report(sha256: str, db: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    result = await db.execute(select(TotalReport).where(TotalReport.sha256 == sha256))
    r = result.scalars().first()
    if not r:
        raise HTTPException(status_code=404, detail="Report not found")
    return {"id": r.id, "sha256": r.sha256, "filename": r.filename, "kind": r.kind,
            "score": r.score, "verdict": r.verdict, "engines": r.engines,
            "files": r.files, "sbom": r.sbom, "ai_summary": r.ai_summary}


@router.delete("/reports/{sha256}")
async def delete_report(sha256: str, request: Request, db: AsyncSession = Depends(get_db), user=Depends(get_current_user)):
    """GDPR retention: delete report (binary was never stored, only hash+findings)."""
    result = await db.execute(select(TotalReport).where(TotalReport.sha256 == sha256))
    r = result.scalars().first()
    if not r:
        raise HTTPException(status_code=404, detail="Report not found")
    await db.delete(r)
    await db.commit()
    await log_audit(db, action="total_delete", resource="total_report", resource_id=sha256,
                    user_id=user.id, username=user.username,
                    ip_address=request.client.host if request else None)
    await db.commit()
    return {"status": "deleted", "sha256": sha256}


def _is_archive_single_stream(fmt: str) -> bool:
    return fmt in ("zip", "gzip", "bzip2", "xz", "tar", "7z", "rar", "cab", "iso")


@router.post("/upload")
async def upload_analyze(
    request: Request,
    file: UploadFile = File(...),
    accept_disclaimer: bool = Form(False),
    db: AsyncSession = Depends(get_db),
    user=Depends(get_current_user),
):
    if not accept_disclaimer:
        raise HTTPException(status_code=400, detail="Disclaimer must be accepted (accept_disclaimer=true)")

    raw = await file.read()
    max_single = settings.TOTAL_MAX_FILE_MB * 1024 * 1024
    max_zip = settings.TOTAL_MAX_ZIP_MB * 1024 * 1024
    filename = file.filename or "upload.bin"

    fmt = _detect_format(raw, filename)
    is_zip_upload = fmt == "zip"
    is_archive = _is_archive_single_stream(fmt) or filename.lower().endswith(
        (".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".apk", ".jar", ".war", ".ear", ".whl", ".xpi", ".ipa", ".oxt"))

    if len(raw) > max_single and not is_archive:
        raise HTTPException(
            status_code=413,
            detail=f"File too large: {len(raw) // (1024 * 1024)} MB (max {settings.TOTAL_MAX_FILE_MB}MB). "
                   f"Archives up to {settings.TOTAL_MAX_ZIP_MB}MB are accepted (configurable via TOTAL_MAX_FILE_MB/TOTAL_MAX_ZIP_MB).",
        )
    if is_archive and len(raw) > max_zip:
        raise HTTPException(status_code=413, detail=f"Archive too large: max {settings.TOTAL_MAX_ZIP_MB}MB")

    sha256 = hashlib.sha256(raw).hexdigest()

    # SHA256 dedup (cache) INVALIDATA dal cambio di engine: il report vecchio
    # resta altrimenti servito per sempre, e dopo una correzione delle regole
    # l'utente continuerebbe a vedere il verdetto precedente (notepad.exe
    # restava "malicious" con il vecchio punteggio).
    existing = await db.execute(select(TotalReport).where(TotalReport.sha256 == sha256))
    cached = existing.scalars().first()
    if cached:
        cached_engine = (cached.engines or {}).get("static_lite", {}).get("version")
        if cached_engine == ENGINE_VERSION:
            return {"sha256": sha256, "cached": True, "score": cached.score,
                    "verdict": cached.verdict, "report_id": cached.id}
        logger.info("total: report %s rigenerato (engine %s -> %s)",
                    sha256[:12], cached_engine, ENGINE_VERSION)
        await db.delete(cached)
        await db.flush()

    files_out: List[Dict[str, Any]] = []
    total_score = 0
    sbom: Dict[str, Any] = {"packages": []}
    all_iocs: Dict[str, List[str]] = {}
    all_imports_suspicious: List[Dict[str, Any]] = []
    truncated = False
    total_members = 0

    if is_zip_upload:
        # Il numero di membri analizzati è bounded (costo per-file reale):
        # oltre il cap il report lo dichiara invece di rifiutare l'upload.
        max_files = max(1, min(int(settings.TOTAL_MAX_FILES_PER_ZIP), MAX_ANALYZED_MEMBERS))
        zdetail = _analyze_zip(raw, max_files=max_files, max_bytes=max_zip, allow_nested=True)
        truncated = bool(zdetail.get("truncated"))
        total_members = int(zdetail.get("total_members") or 0)

        if zdetail.get("kind") == "office":
            # OOXML: report unico con le parti del documento
            files_out = [{
                "path": filename, "kind": "binary", "format": "OOXML (Office)",
                "size": len(raw), "sha256": sha256, "score": zdetail.get("score", 0),
                "findings": zdetail.get("findings", []), "iocs": zdetail.get("iocs", {}),
                "parts": zdetail.get("parts", []),
                "note": "Office OOXML document: analysis of macros, external relationships, embedded objects.",
            }]
            total_score = int(zdetail.get("score", 0))
            all_iocs = zdetail.get("iocs", {})
        else:
            for entry in zdetail.get("extracted", [])[: max(settings.TOTAL_MAX_FILES_PER_ZIP, 200)]:
                entry["path"] = entry.get("path", "(unnamed)")
                files_out.append(entry)
                total_score = max(total_score, int(entry.get("score") or 0))
                if entry.get("iocs"):
                    all_iocs.update(entry["iocs"])
                if entry.get("imports_suspicious"):
                    all_imports_suspicious.extend(entry["imports_suspicious"])
                low_name = entry["path"].lower().split("/")[-1]
                if low_name in MANIFEST_NAMES:
                    sbom["packages"].append({"manifest": entry["path"],
                                             "preview": (entry.get("preview") or "")[:5000]})
            top_findings = zdetail.get("findings", [])
            if top_findings:
                files_out.insert(0, {
                    "path": filename, "kind": "binary", "format": zdetail.get("format", "ZIP"),
                    "size": len(raw), "sha256": sha256, "score": zdetail.get("score", 0),
                    "findings": top_findings,
                    "analyzed_members": zdetail.get("analyzed_members"),
                    "total_members": zdetail.get("total_members"),
                    "truncated": truncated,
                    "note": f"Container: {zdetail.get('analyzed_members')} of "
                            f"{zdetail.get('total_members')} members analyzed.",
                })
        kind = "project"

    else:
        detail = _analyze_bytes(raw, filename, allow_nested=True)
        detail.setdefault("path", filename)
        detail.setdefault("size", len(raw))
        detail.setdefault("sha256", sha256)
        files_out = [detail]
        total_score = int(detail.get("score") or 0)
        all_iocs = detail.get("iocs", {}) or {}
        all_imports_suspicious = detail.get("imports_suspicious", []) or []
        kind = "file"
        if detail.get("truncated"):
            truncated = True
        if detail.get("total_members"):
            total_members = int(detail["total_members"])
        for pkg in (detail.get("extracted") or []):
            low_name = (pkg.get("path") or "").split("/")[-1].lower()
            if low_name in MANIFEST_NAMES:
                sbom["packages"].append({"manifest": pkg.get("path"),
                                         "preview": (pkg.get("preview") or "")[:5000]})

    if CRACK_NAMES.search(filename):
        files_out = [{"path": filename, "kind": "blocked", "format": "unknown",
                      "score": 0,
                      "note": "Crack/keygen pattern — full code viewer disabled by policy. Verdict only."}]
        total_score = 85

    # ── YARA (firme del SOC, tabella yara_rules) ─────────────────────────
    # La sandbox statica non e' solo euristica: le firme curate dal SOC
    # alzano lo score per FATTO. Fail-soft: senza yara-python o senza
    # regole, il report lo dichiara invece di fingere.
    yara_section: Dict[str, Any] = {"enabled": False, "matches": []}
    try:
        from app.database.models import YaraRule
        from app.services import yara_engine
        rules_res = await db.execute(select(YaraRule).where(YaraRule.is_active == True))  # noqa: E712
        active_rules = rules_res.scalars().all()
        if active_rules:
            compiled, cerrs = yara_engine.compile_rules([(r.name, r.content) for r in active_rules])
            if compiled:
                yara_section = yara_engine.scan_bytes(raw, compiled)
                err_list = yara_section.get("errors") or cerrs
                if err_list:
                    yara_section["errors"] = err_list[:10]
                if yara_section.get("matches"):
                    total_score, yfindings = yara_engine.score_impact(yara_section, total_score)
                    for f in files_out:
                        f.setdefault("findings", []).extend(yfindings)
        else:
            yara_section = {"enabled": True, "matches": [], "note": "no active rule"}
    except Exception as exc:
        logger.warning(f"YARA scan on upload failed (fail-soft): {exc}")
        yara_section = {"enabled": False, "matches": [], "error": str(exc)[:200]}

    verdict = "clean" if total_score < 20 else ("suspicious" if total_score < 60 else "malicious")

    engines = {
        "static_lite": {"score": total_score, "version": ENGINE_VERSION},
        "pe_parser": {"enabled": any(f.get("format") == "PE" for f in files_out)},
        "elf_parser": {"enabled": any(f.get("format") == "ELF" for f in files_out)},
        "macho_parser": {"enabled": any(f.get("format") == "Mach-O" for f in files_out)},
        "office_parser": {"enabled": any(
            (f.get("format") or "").upper().startswith(("OOXML", "OLE")) for f in files_out)},
        "pdf_parser": {"enabled": any(f.get("format") == "PDF" for f in files_out)},
        "archive_parser": {"enabled": bool(total_members) or any(
            f.get("kind") == "archive" for f in files_out)},
        "strings_scan": {"enabled": True},
        "secret_scan": {"enabled": True, "patterns": len(SECRET_PATTERNS)},
        "yara": yara_section,
        "iocs_found": all_iocs,
        "suspicious_imports": all_imports_suspicious[:20],
        "detected_format": fmt,
        "members_analyzed": total_members or None,
        "note": "Static sandbox complete: PE/ELF/Mach-O/Office/PDF + entropy + imports + secrets + IOC + YARA (SOC signatures).",
    }

    rec = TotalReport(
        sha256=sha256, filename=filename, kind=kind, score=total_score, verdict=verdict,
        engines=engines, files=files_out[:500], sbom=sbom,
        ai_summary=None, disclaimer_accepted_by=user.id, created_by=user.id,
    )
    db.add(rec)
    await db.commit()
    await db.refresh(rec)

    await log_audit(
        db, action="total_upload", resource="total_report", resource_id=sha256,
        details={"filename": filename, "kind": kind, "detected_format": fmt,
                 "score": total_score, "verdict": verdict, "n_files": len(files_out),
                 "truncated": truncated},
        user_id=user.id, username=user.username,
        ip_address=request.client.host if request else None,
    )
    await db.commit()

    return {"sha256": sha256, "cached": False, "score": total_score, "verdict": verdict,
            "kind": kind, "detected_format": fmt, "truncated": truncated,
            "files": files_out[:200], "sbom": sbom,
            "engines": engines, "report_id": rec.id,
            "disclaimer": AEGIS_TOTAL_DISCLAIMER,
            "retention": f"Binary auto-deleted after {settings.TOTAL_RETENTION_DAYS}d, report kept (hash+findings)."}
