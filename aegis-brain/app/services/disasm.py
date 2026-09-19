"""Disassemblaggio mirato di un PE: codice all'entry point con le chiamate
risolte sugli import (Aegis Total).

Perché esiste
-------------
L'analisi PE dice *quanto* un binario è sospetto (entropia, import, header):
utile, ma resta una pagella. Qui si mostra *dove*: le istruzioni dalla entry
point, con ogni `call` annotata — ``KERNEL32!VirtualAllocEx`` invece di
``0x140001234`` — e le API pericolose evidenziate. È la parte che un analista
legge davvero quando vuole capire cosa fa un campione prima di detonarlo.

Perché è **fail-soft**, come il motore YARA
-------------------------------------------
capstone è una dipendenza nativa: se non è installata (immagine vecchia,
installazione parziale) o l'architettura non è supportata, il risultato lo
**dice** (`enabled=False` + motivo) invece di restituire una lista vuota che
sembrerebbe "nessuna chiamata sospetta". Un'assenza di dati non è un dato:
è la stessa regola applicata al path ignoto nelle regole di detection.

Perché uno **sweep lineare** e non un grafo di flusso
-----------------------------------------------------
Un disassembler completo segue i salti e ricostruisce le funzioni. Qui serve
leggibilità e prevedibilità: si decodifica dall'entry point fino a un `ret` o a
un tetto di istruzioni, dichiarando il troncamento. Fermarsi prima e dirlo è
meglio che inseguire indiretti e mostrare un grafo sbagliato.
"""
from __future__ import annotations

import struct
from typing import Any, Dict, List, Optional, Tuple

# Versione del motore: entra nell'impronta della cache dei report, cosi'
# cambiare il disassemblaggio non lascia in giro report senza la sezione.
ENGINE_VERSION = "1.0"

# Tetto di lavoro: finestra piccola e dichiarata, mai "tutto il file".
DEFAULT_MAX_INSTRUCTIONS = 120
DEFAULT_MAX_BYTES = 4096

# API che meritano un'occhiata: iniezione di codice in un altro processo,
# accesso a credenziali, anti-analisi, cifratura/exfil. La categoria serve a
# spiegare *perché* è evidenziata, non solo che lo è.
SUSPICIOUS_APIS: Dict[str, str] = {
    "virtualallocex": "cross-process memory allocation",
    "virtualprotect": "memory permission change (unpacking/injection)",
    "writeprocessmemory": "cross-process write",
    "createremotethread": "remote code execution",
    "createremotethreadex": "remote code execution",
    "ntunmapviewofsection": "process hollowing",
    "zwunmapviewofsection": "process hollowing",
    "setthreadcontext": "process hollowing / injection",
    "queueuserapc": "APC injection",
    "openprocess": "handle to another process",
    "setwindowshookexa": "input capture / injection",
    "setwindowshookexw": "input capture / injection",
    "getasynckeystate": "keystroke capture",
    "isdebuggerpresent": "anti-analysis",
    "checkremotedebuggerpresent": "anti-analysis",
    "ntqueryinformationprocess": "anti-analysis / debugger detection",
    "outputdebugstringa": "anti-analysis",
    "lsass": "credential access",
    "minidumpwritedump": "credential dumping",
    "credreada": "credential access",
    "credreadw": "credential access",
    "urldownloadtofilea": "payload download",
    "urldownloadtofilew": "payload download",
    "internetopenurla": "payload download",
    "internetopenurlw": "payload download",
    "winexec": "legacy process execution",
    "shellexecutea": "process execution",
    "shellexecutew": "process execution",
    "createprocessa": "process execution",
    "createprocessw": "process execution",
    "cryptencrypt": "encryption (ransomware behaviour)",
    "cryptgenkey": "encryption (ransomware behaviour)",
    "bcryptencrypt": "encryption (ransomware behaviour)",
    "regsetvalueexa": "registry persistence",
    "regsetvalueexw": "registry persistence",
    "schtasks": "scheduled task persistence",
    "wsastartup": "raw socket networking",
    "winhttpopen": "HTTP beaconing",
    "wininetopen": "HTTP beaconing",
}

_IMAGE_SCN_MEM_EXECUTE = 0x20000000


def _capstone():
    """Import pigro: ritorna ``(capstone, x86_const, errore)``.

    Le costanti degli operandi x86 vivono in ``capstone.x86_const``, non al
    livello superiore del pacchetto: prendere ``X86_REG_RIP`` dal modulo
    principale solleva AttributeError, e con un ``except`` generoso a valle il
    bersaglio delle call risultava semplicemente non risolto. Il disassemblaggio
    funzionava a metà (mnemonici senza nomi di API) senza dire niente.
    """
    try:
        import capstone  # type: ignore
        from capstone import x86_const  # type: ignore
        return capstone, x86_const, None
    except Exception as exc:  # pragma: no cover - dipende dall'immagine
        return None, None, f"capstone not installed ({exc.__class__.__name__})"


def available() -> Tuple[bool, Optional[str]]:
    """(disponibile?, motivo se no). Motivo esplicito, mai silenzio."""
    capstone, _x86, err = _capstone()
    if capstone is None:
        return False, err
    return True, None


def engine_fingerprint() -> str:
    """Identità del disassembler per l'invalidazione della cache dei report.

    Include la versione di capstone: se la libreria cambia (o sparisce da
    un'immagine), i report in cache smettono di essere validi invece di
    continuare a mostrare il disassemblaggio precedente.
    """
    capstone, _x86, err = _capstone()
    cap_version = "off" if capstone is None else getattr(capstone, "__version__", "unknown")
    return f"v{ENGINE_VERSION}:capstone={cap_version}:{err or ''}"


# ── Parsing PE minimale (solo ciò che serve al disassemblaggio) ──────────────

def _rva_to_offset(rva: int, sections: List[Dict[str, int]]) -> Optional[int]:
    for sec in sections:
        vaddr, vsize = sec["virtual_address"], sec["virtual_size"]
        size = max(vsize, sec["raw_size"])
        if vaddr <= rva < vaddr + size:
            if not (sec["raw_offset"] and sec["raw_size"]):
                return None
            return sec["raw_offset"] + (rva - vaddr)
    return None


def _section_of(rva: int, sections: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    for sec in sections:
        size = max(sec["virtual_size"], sec["raw_size"])
        if sec["virtual_address"] <= rva < sec["virtual_address"] + size:
            return sec
    return None


def _parse_headers(raw: bytes) -> Optional[Dict[str, Any]]:
    if len(raw) < 64 or raw[:2] != b"MZ":
        return None
    e_lfanew = struct.unpack_from("<I", raw, 0x3C)[0]
    if e_lfanew + 24 > len(raw) or raw[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return None
    coff = e_lfanew + 4
    machine = struct.unpack_from("<H", raw, coff)[0]
    num_sections = struct.unpack_from("<H", raw, coff + 2)[0]
    opt_size = struct.unpack_from("<H", raw, coff + 16)[0]
    opt_off = coff + 20
    if opt_off + 2 > len(raw):
        return None
    pe32plus = struct.unpack_from("<H", raw, opt_off)[0] == 0x20B
    entry_rva = struct.unpack_from("<I", raw, opt_off + 16)[0]
    if pe32plus:
        image_base = struct.unpack_from("<Q", raw, opt_off + 24)[0]
        dd_off = opt_off + 112
    else:
        image_base = struct.unpack_from("<I", raw, opt_off + 28)[0]
        dd_off = opt_off + 96

    sections: List[Dict[str, Any]] = []
    sec_off = opt_off + opt_size
    for i in range(min(num_sections, 96)):
        base = sec_off + i * 40
        if base + 40 > len(raw):
            break
        sections.append({
            "name": raw[base:base + 8].rstrip(b"\x00").decode("ascii", "replace") or "(unnamed)",
            "virtual_size": struct.unpack_from("<I", raw, base + 8)[0],
            "virtual_address": struct.unpack_from("<I", raw, base + 12)[0],
            "raw_size": struct.unpack_from("<I", raw, base + 16)[0],
            "raw_offset": struct.unpack_from("<I", raw, base + 20)[0],
            "characteristics": struct.unpack_from("<I", raw, base + 36)[0],
        })

    import_rva = iat_rva = 0
    if dd_off + 13 * 8 <= len(raw):
        import_rva = struct.unpack_from("<I", raw, dd_off + 1 * 8)[0]
        iat_rva = struct.unpack_from("<I", raw, dd_off + 12 * 8)[0]

    return {
        "machine": machine,
        "pe32plus": pe32plus,
        "image_base": image_base,
        "entry_rva": entry_rva,
        "sections": sections,
        "import_rva": import_rva,
        "iat_rva": iat_rva,
    }


def _imports_by_iat_slot(raw: bytes, headers: Dict[str, Any]) -> Dict[int, str]:
    """mappa rva dello slot IAT -> ``modulo!funzione``.

    Serve a trasformare ``call qword ptr [rip+0x2f1a]`` in
    ``call KERNEL32!VirtualAllocEx``: senza questa mappa il disassemblaggio è
    una lista di indirizzi e non dice nulla.
    """
    out: Dict[int, str] = {}
    import_rva = headers.get("import_rva") or 0
    if not import_rva:
        return out
    sections = headers["sections"]
    ptr = 8 if headers["pe32plus"] else 4
    off = _rva_to_offset(import_rva, sections)
    if off is None:
        return out
    for _ in range(256):  # bound: 256 descrittori sono già patologici
        if off + 20 > len(raw):
            break
        oft, _ts, _fwd, name_rva, first_thunk = struct.unpack_from("<IIIII", raw, off)
        if not (oft or name_rva or first_thunk):
            break
        name_off = _rva_to_offset(name_rva, sections)
        dll = ""
        if name_off is not None:
            end = raw.find(b"\x00", name_off, name_off + 256)
            dll = raw[name_off:end if end > 0 else name_off].decode("ascii", "replace")
        thunk_rva = oft or first_thunk
        thunk_off = _rva_to_offset(thunk_rva, sections)
        if thunk_off is not None:
            for i in range(4096):  # bound per riga import
                slot = thunk_off + i * ptr
                if slot + ptr > len(raw):
                    break
                value = int.from_bytes(raw[slot:slot + ptr], "little")
                if value == 0:
                    break
                if value & (1 << (ptr * 8 - 1)):
                    func = f"ordinal_{value & 0xFFFF}"
                else:
                    hint_off = _rva_to_offset(value, sections)
                    if hint_off is None or hint_off + 2 >= len(raw):
                        continue
                    end = raw.find(b"\x00", hint_off + 2, hint_off + 2 + 256)
                    func = raw[hint_off + 2:end if end > 0 else hint_off + 2].decode(
                        "ascii", "replace")
                out[first_thunk + i * ptr] = f"{dll}!{func}" if dll else func
        off += 20
    return out


def _flags_for(api: str) -> Optional[str]:
    low = api.rsplit("!", 1)[-1].lower()
    return SUSPICIOUS_APIS.get(low)


def disassemble_pe(raw: bytes, *, max_instructions: int = DEFAULT_MAX_INSTRUCTIONS,
                   max_bytes: int = DEFAULT_MAX_BYTES) -> Dict[str, Any]:
    """Disassembla la finestra dall'entry point, con le call annotate.

    Ritorna sempre un dizionario con `enabled`: se è ``False``, `reason` dice
    perché. Mai un risultato vuoto spacciato per "niente da segnalare".

    L'ordine dei controlli è deliberato: prima si valuta il **file**, poi la
    **libreria**. Un file che non è nemmeno un PE va detto come tale anche se
    capstone manca — altrimenti ogni campione non-PE direbbe "capstone non
    installato" e il motivo vero resterebbe nascosto.
    """
    headers = _parse_headers(raw)
    if headers is None:
        return {"enabled": False, "reason": "not a parsable PE image",
                "instructions": [], "suspicious_calls": []}

    machine = headers["machine"]
    if machine not in (0x8664, 0x14C):
        return {"enabled": False, "reason": f"unsupported architecture 0x{machine:04X}",
                "instructions": [], "suspicious_calls": []}

    entry_rva = headers["entry_rva"]
    if not entry_rva:
        return {"enabled": False, "reason": "no entry point (entry RVA is 0)",
                "instructions": [], "suspicious_calls": []}

    entry_off = _rva_to_offset(entry_rva, headers["sections"])
    if entry_off is None:
        return {"enabled": False, "reason": "entry point outside the file (packed/sectionless)",
                "instructions": [], "suspicious_calls": []}

    capstone, x86_const, err = _capstone()
    if capstone is None:
        return {"enabled": False, "reason": err, "instructions": [],
                "suspicious_calls": []}

    mode, arch = ((capstone.CS_MODE_64, "x64") if machine == 0x8664
                  else (capstone.CS_MODE_32, "x86"))

    code = raw[entry_off:entry_off + max_bytes]
    imports = _imports_by_iat_slot(raw, headers)
    image_base = headers["image_base"]

    md = capstone.Cs(capstone.CS_ARCH_X86, mode)
    md.detail = True
    instructions: List[Dict[str, Any]] = []
    suspicious: List[Dict[str, Any]] = []
    truncated = False

    try:
        for insn in md.disasm(code, image_base + entry_rva):
            if len(instructions) >= max_instructions:
                truncated = True
                break
            row: Dict[str, Any] = {
                "address": f"0x{insn.address:x}",
                "bytes": insn.bytes.hex(),
                "text": f"{insn.mnemonic} {insn.op_str}".strip(),
            }
            if insn.mnemonic.startswith(("call", "jmp")):
                # Un operando dalla forma inattesa non deve far perdere TUTTO il
                # disassemblaggio: si perde solo l'annotazione di quell'istruzione.
                try:
                    target = _branch_target_va(insn, capstone, x86_const)
                except Exception:
                    target = None
                if target is not None:
                    note = _annotate_target(target, image_base, imports,
                                            headers["sections"])
                    if note:
                        row["target"] = note
                        if insn.mnemonic.startswith("call") and note.get("import"):
                            flag = _flags_for(note["import"])
                            if flag:
                                row["flag"] = flag
                                suspicious.append({
                                    "api": note["import"],
                                    "address": row["address"],
                                    "reason": flag,
                                })
            instructions.append(row)
            if insn.mnemonic in ("ret", "retn") or insn.mnemonic.startswith("ret"):
                break
    except Exception as exc:  # capstone non deve mai far fallire un upload
        return {"enabled": False, "reason": f"decode failed: {exc}",
                "instructions": instructions, "suspicious_calls": suspicious}

    if not instructions:
        return {"enabled": False, "reason": "no instruction decoded at the entry point",
                "instructions": [], "suspicious_calls": []}

    return {
        "enabled": True,
        "reason": None,
        "arch": arch,
        "entrypoint": f"0x{image_base + entry_rva:x}",
        "instructions": instructions,
        "instructions_analyzed": len(instructions),
        "truncated": truncated,
        # La finestra e' quella *dichiarata* (quanto abbiamo chiesto di
        # disassemblare dall'entry point), non i byte effettivamente presenti
        # nel file: un PE piu' piccolo della finestra resta una finestra 4096.
        "window_bytes": max_bytes,
        "imports_resolved": len(imports),
        "suspicious_calls": suspicious,
    }


def _branch_target_va(insn, capstone, x86_const) -> Optional[int]:
    """Indirizzo assoluto del bersaglio di un call/jmp, se deterministico.

    Due forme contano davvero per gli import:
    * x64: ``call qword ptr [rip + disp]`` (relativo al PC) → la destinazione
      va calcolata con ``indirizzo + lunghezza + disp``;
    * x86: ``call dword ptr [imm]`` (indirizzo assoluto) → è già un VA.
    """
    for op in insn.operands:
        if op.type == capstone.CS_OP_IMM:
            return int(op.imm)
        if op.type == x86_const.X86_OP_MEM:
            if op.mem.base == x86_const.X86_REG_RIP:
                return insn.address + insn.size + op.mem.disp
            if not op.mem.base and not op.mem.index and op.mem.disp:
                return int(op.mem.disp)
    return None


def _annotate_target(target: int, image_base: int, imports: Dict[int, str],
                     sections: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Traduce un indirizzo in ``modulo!funzione`` o ``sezione+offset``."""
    if target <= 0:
        return None
    rva = target - image_base
    if rva in imports:
        return {"va": f"0x{target:x}", "import": imports[rva]}
    # IAT in mezzo: il valore può puntare al thunk, non allo slot esatto.
    for slot_rva, api in imports.items():
        if slot_rva <= rva < slot_rva + 16:
            return {"va": f"0x{target:x}", "import": api}
    sec = _section_of(rva, sections)
    if sec is not None:
        return {"va": f"0x{target:x}",
                "section": f"{sec['name']}+0x{rva - sec['virtual_address']:x}"}
    return {"va": f"0x{target:x}"}
