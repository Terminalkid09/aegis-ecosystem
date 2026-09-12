"""M2: Aegis Total — internal VirusTotal + code/binary viewer.

Engines (Phase 1 — static, no external deps):
  - pe_analysis:  PE header parse, section entropy (packer detection),
                  import table triage, embedded PS/shellcode detection
  - elf_analysis: ELF magic + arch + suspicious strings
  - strings_scan: printable string extraction + IOC regex from binaries
  - static_lite:  secret scan, YARA-lite heuristics on text/scripts
  - sbom_lite:    manifest parsing from ZIP archives

Phase 2 (plug-in, same schema): YARA / ClamAV / capa / Ghidra / sandbox / LLM.
"""
import hashlib
import io
import math
import re
import struct
import zipfile
from typing import Any, Dict, List

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.audit import log_audit
from app.core.config import settings
from app.core.deps import get_current_user
from app.database.connection import get_db
from app.database.models import AEGIS_TOTAL_DISCLAIMER, TotalReport

router = APIRouter(tags=["Aegis Total"])

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
    "stripe_key":       re.compile(r"(sk|pk)_(live|test)_[A-Za-z0-9]{24,}"),
    "google_api_key":   re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "connection_string":re.compile(r"(?i)(mongodb|mysql|postgresql|redis|amqp)://[^\s\"'<>]+"),
}

SUSPICIOUS_STRINGS: List[re.Pattern] = [
    re.compile(r"(?i)(mimikatz|bloodhound|sharphound|rubeus|sekurlsa|kerberoast)"),
    re.compile(r"(?i)(powershell.*-enc|-encodedcommand|frombase64string|invoke-mimikatz|invoke-expression)"),
    re.compile(r"(?i)(disableamsi|amsi.*patch|etw.*patch|unhook.*ntdll|patch.*amsi)"),
    re.compile(r"(?i)(keylog|clipboardlog|credential.*dump|lsass.*dump|procdump)"),
    re.compile(r"(?i)(reverse.*shell|bind.*shell|nc\.exe|ncat|cobalt.*strike|metasploit|meterpreter)"),
    re.compile(r"(?i)(virtualalloc.*rwx|writeprocessmemory|createremotethread|ntcreatethreadex)"),
    re.compile(r"(?i)(regsvr32.*scrobj|mshta.*vbscript|certutil.*decode|bitsadmin.*transfer)"),
    re.compile(r"(?i)(wget.*\|\s*(bash|sh)|curl.*\|\s*(bash|sh))"),
    re.compile(r"(?i)(xmrig|stratum\+tcp|moneropool|ethermine|nanopool)"),
]

IOC_PATTERNS: Dict[str, re.Pattern] = {
    "ipv4":         re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"),
    "domain":       re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|net|org|io|xyz|top|ru|cn|tk|pw|cc|biz|info|online|site|shop|live|club)\b"),
    "url":          re.compile(r"https?://[^\s\"'<>\x00-\x1f]{10,200}"),
    "registry_key": re.compile(r"HKEY_(LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS)\\[^\s\"']{5,}"),
}

TEXT_EXTS = {".py", ".js", ".ts", ".jsx", ".tsx", ".ps1", ".psm1", ".sh", ".bash",
             ".bat", ".cmd", ".vba", ".vbs", ".java", ".go", ".rs", ".c", ".h", ".cpp",
             ".txt", ".json", ".yml", ".yaml", ".xml", ".toml", ".ini", ".cfg",
             ".rb", ".php", ".cs", ".swift", ".kt", ".lua", ".pl", ".r",
             ".dockerfile", ".makefile", ".gradle"}

MANIFEST_NAMES = {"requirements.txt", "package.json", "go.mod", "cargo.toml",
                  "pom.xml", "build.gradle", "pyproject.toml", "gemfile", "composer.json"}

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
}

# ─── Analysis helpers ─────────────────────────────────────────────────────────

def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq: Dict[int, int] = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _extract_strings(data: bytes, min_len: int = 6) -> List[str]:
    result: List[str] = []
    current: List[int] = []
    for b in data:
        if 0x20 <= b <= 0x7e:
            current.append(b)
        else:
            if len(current) >= min_len:
                result.append(bytes(current).decode("ascii"))
            current = []
    if len(current) >= min_len:
        result.append(bytes(current).decode("ascii"))
    return result[:3000]


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
        opt_hdr_size = struct.unpack_from("<H", raw, coff + 16)[0]
        result["arch"] = "x64" if machine == 0x8664 else ("x86" if machine == 0x14C else f"0x{machine:04X}")

        opt_off = coff + 20
        if opt_off < len(raw):
            opt_magic = struct.unpack_from("<H", raw, opt_off)[0]
            result["pe_type"] = "PE32+" if opt_magic == 0x20B else "PE32"

        # Sections + entropy
        sec_off = opt_off + opt_hdr_size
        high_ent_secs: List[str] = []
        for i in range(min(num_sections, 96)):
            base = sec_off + i * 40
            if base + 40 > len(raw):
                break
            sname = raw[base:base + 8].rstrip(b"\x00").decode("ascii", errors="replace").strip()
            virt_sz = struct.unpack_from("<I", raw, base + 16)[0]
            raw_off = struct.unpack_from("<I", raw, base + 20)[0]
            raw_sz = struct.unpack_from("<I", raw, base + 16)[0]
            ent = _entropy(raw[raw_off:raw_off + raw_sz]) if (raw_off and raw_sz) else 0.0
            result["sections"].append({"name": sname or "(unnamed)", "virtual_size": virt_sz, "entropy": round(ent, 2)})
            if ent > 7.0 and raw_sz > 512:
                high_ent_secs.append(sname)

        if high_ent_secs:
            result["entropy_alert"] = True
            result["findings"].append({
                "type": "packer_or_encrypted",
                "severity": "high",
                "detail": f"High-entropy sections: {', '.join(high_ent_secs)} — likely packed/encrypted (UPX, Themida…)",
                "mitre": "T1027",
            })
            result["score_contribution"] += 40

        # Strings + IOC extraction
        strings = _extract_strings(raw)
        full_str = " ".join(strings)

        iocs: Dict[str, List[str]] = {}
        for ioc_name, pat in IOC_PATTERNS.items():
            matches = list(set(pat.findall(full_str)))[:15]
            safe = {"127.0.0.1", "0.0.0.0", "255.255.255.255"}  # nosec B104 - indicator allowlist
            filtered = [m for m in matches if m not in safe]
            if filtered:
                iocs[ioc_name] = filtered
        result["iocs"] = iocs

        # Suspicious imports
        for fn, (cap, tid) in SUSPICIOUS_IMPORTS.items():
            if any(fn.lower() in s.lower() for s in strings):
                result["imports_suspicious"].append({"function": fn, "capability": cap, "mitre": tid})
                result["score_contribution"] = min(result["score_contribution"] + 15, 100)

        # Suspicious strings in binary
        for pat in SUSPICIOUS_STRINGS:
            m = pat.search(full_str)
            if m:
                result["findings"].append({"type": "suspicious_string_in_binary", "severity": "high", "match": m.group(0)[:80]})
                result["score_contribution"] = min(result["score_contribution"] + 25, 100)

        if iocs.get("url") or iocs.get("domain"):
            result["findings"].append({"type": "network_ioc", "severity": "medium",
                                       "detail": f"{len(iocs.get('url', []))} URL(s), {len(iocs.get('domain', []))} domain(s) embedded."})

        if b"powershell" in raw.lower() or b"invoke-expression" in raw.lower():
            result["findings"].append({"type": "embedded_powershell", "severity": "high",
                                       "detail": "PE contains embedded PowerShell — possible dropper.", "mitre": "T1059.001"})
            result["score_contribution"] = min(result["score_contribution"] + 30, 100)

    except Exception as ex:
        result["parse_error"] = str(ex)
    return result


def _analyze_elf(raw: bytes) -> Dict[str, Any]:
    result: Dict[str, Any] = {"format": "ELF", "findings": [], "score_contribution": 0, "iocs": {}}
    try:
        if len(raw) < 52:
            return result
        ei_class = raw[4]
        ei_data = raw[5]
        result["arch"] = ("ELF64" if ei_class == 2 else "ELF32") + (" LE" if ei_data == 1 else " BE")

        strings = _extract_strings(raw)
        full_str = " ".join(strings)
        for pat in SUSPICIOUS_STRINGS:
            m = pat.search(full_str)
            if m:
                result["findings"].append({"type": "suspicious_string_in_elf", "severity": "high", "match": m.group(0)[:80]})
                result["score_contribution"] = min(result["score_contribution"] + 25, 100)

        iocs: Dict[str, List[str]] = {}
        for ioc_name, pat in IOC_PATTERNS.items():
            matches = list(set(pat.findall(full_str)))[:10]
            if matches:
                iocs[ioc_name] = matches
        result["iocs"] = iocs

    except Exception as ex:
        result["parse_error"] = str(ex)
    return result


def _score_text(content: bytes, name: str) -> Dict[str, Any]:
    try:
        text = content.decode("utf-8", errors="ignore")
    except Exception:
        text = ""
    findings: List[Dict[str, Any]] = []
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
    for ioc_name, pat in IOC_PATTERNS.items():
        matches = list(set(pat.findall(text)))[:8]
        if matches and ioc_name in ("url", "domain"):
            findings.append({"type": f"ioc_{ioc_name}", "severity": "low", "matches": matches[:5]})
    redacted = text
    for pat in SECRET_PATTERNS.values():
        redacted = pat.sub("[REDACTED_SECRET]", redacted)
    return {"score": min(score, 100), "findings": findings, "preview": redacted[:30000]}


def _is_text_file(name: str, content: bytes) -> bool:
    low = name.lower()
    base = low.split("/")[-1]
    ext = "." + base.rsplit(".", 1)[-1] if "." in base else ""
    if ext in TEXT_EXTS or base in MANIFEST_NAMES:
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
    if raw[:2] == b"MZ":
        return "pe"
    if raw[:4] == b"\x7fELF":
        return "elf"
    if raw[:4] == b"%PDF":
        return "pdf"
    if raw[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
        return "zip"
    if raw[:4] == b"\xd0\xcf\x11\xa0":
        return "ole"
    if _is_text_file(name, raw):
        return "text"
    return "binary"


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
    filename = file.filename or "upload.bin"

    is_zip_upload = filename.lower().endswith(".zip") or raw[:4] in (b"PK\x03\x04", b"PK\x05\x06")
    if len(raw) > max_single and not is_zip_upload:
        raise HTTPException(status_code=413, detail=f"File too large (max {settings.TOTAL_MAX_FILE_MB}MB)")

    sha256 = hashlib.sha256(raw).hexdigest()

    # SHA256 dedup (30-day cache)
    existing = await db.execute(select(TotalReport).where(TotalReport.sha256 == sha256))
    cached = existing.scalars().first()
    if cached:
        return {"sha256": sha256, "cached": True, "score": cached.score,
                "verdict": cached.verdict, "report_id": cached.id}

    files_out: List[Dict[str, Any]] = []
    total_score = 0
    sbom: Dict[str, Any] = {"packages": []}
    all_iocs: Dict[str, List[str]] = {}
    all_imports_suspicious: List[Dict[str, Any]] = []

    if is_zip_upload:
        if len(raw) > settings.TOTAL_MAX_ZIP_MB * 1024 * 1024:
            raise HTTPException(status_code=413, detail=f"ZIP too large (max {settings.TOTAL_MAX_ZIP_MB}MB)")
        try:
            zf = zipfile.ZipFile(io.BytesIO(raw))
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid ZIP archive")

        infos = zf.infolist()
        if len(infos) > settings.TOTAL_MAX_FILES_PER_ZIP:
            raise HTTPException(status_code=413, detail="Too many files in ZIP")

        total_uncompressed = sum(i.file_size for i in infos)
        if total_uncompressed > 500 * 1024 * 1024:
            raise HTTPException(status_code=413, detail="ZIP decompresses to >500MB (possible zip-bomb)")

        for info in infos[:settings.TOTAL_MAX_FILES_PER_ZIP]:
            name = info.filename
            if name.startswith("/") or ".." in name or info.is_dir():
                continue
            try:
                content = zf.read(info.filename)
            except Exception:
                continue

            fmt = _detect_format(content, name)
            entry: Dict[str, Any] = {
                "path": name,
                "size": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
                "format": fmt,
            }

            if fmt == "text":
                tri = _score_text(content, name)
                entry.update({"kind": "text", "score": tri["score"],
                              "findings": tri["findings"], "preview": tri["preview"]})
                total_score = max(total_score, tri["score"])
            elif fmt == "pe":
                pe = _analyze_pe(content)
                entry.update({"kind": "binary", "score": pe["score_contribution"],
                              "findings": pe["findings"], "sections": pe["sections"],
                              "imports_suspicious": pe["imports_suspicious"],
                              "iocs": pe["iocs"],
                              "entropy_alert": pe.get("entropy_alert", False),
                              "arch": pe.get("arch"),
                              "pe_type": pe.get("pe_type"),
                              "note": "PE binary analyzed (static triage)"})
                all_iocs.update(pe.get("iocs", {}))
                all_imports_suspicious.extend(pe.get("imports_suspicious", []))
                total_score = max(total_score, pe["score_contribution"])
            elif fmt == "elf":
                elf = _analyze_elf(content)
                entry.update({"kind": "binary", "score": elf["score_contribution"],
                              "findings": elf["findings"], "iocs": elf.get("iocs", {}),
                              "arch": elf.get("arch"),
                              "note": "ELF binary analyzed (static triage)"})
                all_iocs.update(elf.get("iocs", {}))
                total_score = max(total_score, elf["score_contribution"])
            else:
                entry.update({"kind": "binary", "score": 5,
                              "note": f"Binary ({fmt.upper()}) — full decompile (Ghidra/capa) in Phase 2"})
                total_score = max(total_score, 5)

            # SBOM-lite: collect manifest files
            low_name = name.lower().split("/")[-1]
            if low_name in MANIFEST_NAMES or any(low_name.endswith(e) for e in (".txt", ".toml", ".mod", ".json")):
                if low_name in MANIFEST_NAMES:
                    try:
                        sbom["packages"].append({
                            "manifest": name,
                            "preview": content.decode("utf-8", errors="ignore")[:5000]
                        })
                    except Exception:
                        pass

            files_out.append(entry)

        kind = "project"

    else:
        # Single file analysis
        fmt = _detect_format(raw, filename)
        kind = "file"

        if CRACK_NAMES.search(filename):
            files_out = [{"path": filename, "kind": "blocked", "format": "unknown",
                          "score": 0,
                          "note": "Crack/keygen pattern — full code viewer disabled by policy. Verdict only."}]
            total_score = 85

        elif fmt == "pe":
            pe = _analyze_pe(raw)
            files_out = [{"path": filename, "kind": "binary", "format": "PE",
                          "size": len(raw), "sha256": sha256,
                          "score": pe["score_contribution"],
                          "findings": pe["findings"],
                          "sections": pe["sections"],
                          "imports_suspicious": pe["imports_suspicious"],
                          "iocs": pe["iocs"],
                          "entropy_alert": pe.get("entropy_alert", False),
                          "arch": pe.get("arch"),
                          "pe_type": pe.get("pe_type"),
                          "note": "PE binary — static triage complete. Ghidra/capa decompile in Phase 2."}]
            total_score = pe["score_contribution"]
            all_iocs = pe.get("iocs", {})
            all_imports_suspicious = pe.get("imports_suspicious", [])

        elif fmt == "elf":
            elf = _analyze_elf(raw)
            files_out = [{"path": filename, "kind": "binary", "format": "ELF",
                          "size": len(raw), "sha256": sha256,
                          "score": elf["score_contribution"],
                          "findings": elf["findings"],
                          "iocs": elf.get("iocs", {}),
                          "arch": elf.get("arch"),
                          "note": "ELF binary — static triage complete."}]
            total_score = elf["score_contribution"]
            all_iocs = elf.get("iocs", {})

        elif fmt == "text":
            tri = _score_text(raw, filename)
            files_out = [{"path": filename, "kind": "text", "format": "text",
                          "size": len(raw), "sha256": sha256,
                          "score": tri["score"], "findings": tri["findings"],
                          "preview": tri["preview"]}]
            total_score = tri["score"]

        else:
            ent = _entropy(raw)
            files_out = [{"path": filename, "kind": "binary", "format": fmt.upper(),
                          "size": len(raw), "sha256": sha256,
                          "score": 10, "entropy": round(ent, 2),
                          "note": f"Binary ({fmt.upper()}) — full analysis in Phase 2 worker."}]
            total_score = 10

    verdict = "clean" if total_score < 20 else ("suspicious" if total_score < 60 else "malicious")

    engines = {
        "static_lite": {"score": total_score, "version": "2.0"},
        "pe_parser": {"enabled": any(f.get("format") == "PE" for f in files_out)},
        "elf_parser": {"enabled": any(f.get("format") == "ELF" for f in files_out)},
        "strings_scan": {"enabled": True},
        "secret_scan": {"enabled": True, "patterns": len(SECRET_PATTERNS)},
        "iocs_found": all_iocs,
        "suspicious_imports": all_imports_suspicious[:20],
        "note": "Phase 2: YARA / ClamAV / capa / Ghidra / sandbox — same schema, plug in worker.",
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
        details={"filename": filename, "kind": kind, "score": total_score,
                 "verdict": verdict, "n_files": len(files_out)},
        user_id=user.id, username=user.username,
        ip_address=request.client.host if request else None,
    )
    await db.commit()

    return {"sha256": sha256, "cached": False, "score": total_score, "verdict": verdict,
            "kind": kind, "files": files_out[:200], "sbom": sbom,
            "engines": engines, "report_id": rec.id,
            "disclaimer": AEGIS_TOTAL_DISCLAIMER,
            "retention": f"Binary auto-deleted after {settings.TOTAL_RETENTION_DAYS}d, report kept (hash+findings)."}
