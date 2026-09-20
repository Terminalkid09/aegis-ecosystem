"""Disassembler PE: risoluzione delle call sugli import e fail-soft.

Il PE di prova è **costruito qui**, non preso dal sistema: un test che dipende
da `C:\\Windows\\System32\\notepad.exe` non è riproducibile e non può verificare
il caso che conta (una `call` che punta a un import noto). Il campione sintetico
contiene una sola chiamata: ``call qword ptr [rip+disp]`` verso lo slot IAT di
``KERNEL32.dll!VirtualAllocEx``.

I test che richiedono capstone vengono saltati se la libreria non è installata:
l'assenza è già coperta da `test_reports_disabled_when_capstone_missing`, che è
esattamente il comportamento fail-soft richiesto.
"""
import struct

import pytest

from app.services import disasm

CAPSTONE_OK, CAPSTONE_REASON = disasm.available()
needs_capstone = pytest.mark.skipif(
    not CAPSTONE_OK, reason=f"capstone non disponibile: {CAPSTONE_REASON}")

IMAGE_BASE = 0x140000000
ENTRY_RVA = 0x1000
TEXT_VA, TEXT_OFF = 0x1000, 0x200
IDATA_VA, IDATA_OFF = 0x2000, 0x400
IAT_SLOT_VA = IDATA_VA + 0x40          # rva dello slot IAT del primo import
DLL_NAME_VA, DLL_NAME_OFF = IDATA_VA + 0x60, IDATA_OFF + 0x60
THUNK_VA, THUNK_OFF = IDATA_VA + 0x30, IDATA_OFF + 0x30
HINTNAME_VA, HINTNAME_OFF = IDATA_VA + 0x80, IDATA_OFF + 0x80


def build_pe(symbol: str = "VirtualAllocEx", dll: str = "KERNEL32.dll",
             entry_rva: int = ENTRY_RVA, machine: int = 0x8664) -> bytes:
    """PE32+ minimale con una sezione di codice e una di import."""
    buf = bytearray(0x600)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x40)          # e_lfanew
    buf[0x40:0x44] = b"PE\x00\x00"
    coff = 0x44
    struct.pack_into("<H", buf, coff, machine)
    struct.pack_into("<H", buf, coff + 2, 2)          # numero sezioni
    struct.pack_into("<H", buf, coff + 16, 0xF0)      # size optional header
    struct.pack_into("<H", buf, coff + 18, 0x22)      # EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

    opt = coff + 20
    struct.pack_into("<H", buf, opt, 0x20B)           # PE32+
    struct.pack_into("<I", buf, opt + 16, entry_rva)  # AddressOfEntryPoint
    struct.pack_into("<Q", buf, opt + 24, IMAGE_BASE)
    dd = opt + 112
    struct.pack_into("<II", buf, dd + 1 * 8, IDATA_VA, 0x100)   # Import Table
    struct.pack_into("<II", buf, dd + 12 * 8, IAT_SLOT_VA, 8)   # IAT

    sec = opt + 0xF0
    for i, (name, va, vsize, off, size, ch) in enumerate((
            (b".text", TEXT_VA, 0x200, TEXT_OFF, 0x200, 0x60000020),
            (b".idata", IDATA_VA, 0x200, IDATA_OFF, 0x200, 0xC0000040))):
        base = sec + i * 40
        buf[base:base + 8] = name
        struct.pack_into("<I", buf, base + 8, vsize)
        struct.pack_into("<I", buf, base + 12, va)
        struct.pack_into("<I", buf, base + 16, size)
        struct.pack_into("<I", buf, base + 20, off)
        struct.pack_into("<I", buf, base + 36, ch)

    # .text: call qword ptr [rip + disp] ; ret
    disp = IAT_SLOT_VA - (ENTRY_RVA + 6)
    struct.pack_into("<BBiB", buf, TEXT_OFF, 0xFF, 0x15, disp, 0xC3)

    # .idata: descriptor -> thunk -> hint/name
    struct.pack_into("<IIIII", buf, IDATA_OFF, THUNK_VA, 0, 0, DLL_NAME_VA, IAT_SLOT_VA)
    struct.pack_into("<QQ", buf, THUNK_OFF, HINTNAME_VA, 0)
    struct.pack_into("<QQ", buf, IDATA_OFF + 0x40, HINTNAME_VA, 0)
    buf[DLL_NAME_OFF:DLL_NAME_OFF + len(dll) + 1] = dll.encode() + b"\x00"
    struct.pack_into("<H", buf, HINTNAME_OFF, 0)
    buf[HINTNAME_OFF + 2:HINTNAME_OFF + 2 + len(symbol) + 1] = symbol.encode() + b"\x00"
    return bytes(buf)


class TestAvailability:
    def test_reports_disabled_when_capstone_missing(self, monkeypatch):
        """L'assenza deve essere DICHIARATA, mai una lista vuota silenziosa."""
        monkeypatch.setattr(disasm, "_capstone",
                            lambda: (None, None, "capstone not installed (X)"))
        out = disasm.disassemble_pe(build_pe())
        assert out["enabled"] is False
        assert "capstone" in out["reason"]
        assert out["instructions"] == []

    def test_fingerprint_changes_with_version(self, monkeypatch):
        before = disasm.engine_fingerprint()
        assert "v" in before and "capstone=" in before
        monkeypatch.setattr(disasm, "ENGINE_VERSION", "9.9")
        assert disasm.engine_fingerprint() != before

    def test_fingerprint_never_empty(self):
        assert disasm.engine_fingerprint()


class TestHeaderParsing:
    def test_non_pe_rejected_with_reason(self):
        out = disasm.disassemble_pe(b"not a pe at all")
        assert out["enabled"] is False
        assert out["reason"]

    def test_entry_point_zero_declared(self):
        out = disasm.disassemble_pe(build_pe(entry_rva=0))
        assert out["enabled"] is False
        assert "entry" in out["reason"].lower()

    def test_entry_point_outside_file_declared(self):
        out = disasm.disassemble_pe(build_pe(entry_rva=0x9000))
        assert out["enabled"] is False
        assert out["reason"]

    def test_truncated_pe_does_not_crash(self):
        raw = build_pe()
        out = disasm.disassemble_pe(raw[:80])
        assert isinstance(out, dict) and "enabled" in out

    def test_rva_to_offset_maps_sections(self):
        headers = disasm._parse_headers(build_pe())
        assert headers is not None
        assert disasm._rva_to_offset(TEXT_VA + 4, headers["sections"]) == TEXT_OFF + 4
        assert disasm._rva_to_offset(IDATA_VA, headers["sections"]) == IDATA_OFF
        assert disasm._rva_to_offset(0x99999, headers["sections"]) is None


class TestImportResolution:
    def test_import_table_is_mapped_to_iat_slots(self):
        """La mappa è il pezzo che rende leggibile il disassemblaggio."""
        headers = disasm._parse_headers(build_pe())
        imports = disasm._imports_by_iat_slot(build_pe(), headers)
        assert imports.get(IAT_SLOT_VA) == "KERNEL32.dll!VirtualAllocEx"

    def test_import_map_is_empty_for_a_pe_without_imports(self):
        raw = bytearray(build_pe())
        struct.pack_into("<II", raw, 0x58 + 112 + 1 * 8, 0, 0)
        headers = disasm._parse_headers(bytes(raw))
        assert disasm._imports_by_iat_slot(bytes(raw), headers) == {}

    def test_import_by_ordinal_is_labelled(self):
        raw = bytearray(build_pe())
        struct.pack_into("<Q", raw, THUNK_OFF, (1 << 63) | 42)
        headers = disasm._parse_headers(bytes(raw))
        imports = disasm._imports_by_iat_slot(bytes(raw), headers)
        assert imports.get(IAT_SLOT_VA) == "KERNEL32.dll!ordinal_42"

    def test_suspicious_api_is_recognised(self):
        assert disasm._flags_for("KERNEL32.dll!VirtualAllocEx")
        assert disasm._flags_for("ntdll!NtUnmapViewOfSection")
        assert disasm._flags_for("KERNEL32.dll!GetLastError") is None

    def test_annotate_resolves_import_and_section(self):
        headers = disasm._parse_headers(build_pe())
        imports = disasm._imports_by_iat_slot(build_pe(), headers)
        note = disasm._annotate_target(IMAGE_BASE + IAT_SLOT_VA, IMAGE_BASE,
                                       imports, headers["sections"])
        assert note["import"] == "KERNEL32.dll!VirtualAllocEx"
        note2 = disasm._annotate_target(IMAGE_BASE + TEXT_VA + 0x10, IMAGE_BASE,
                                        imports, headers["sections"])
        assert note2["section"] == ".text+0x10"


@needs_capstone
class TestDisassembly:
    def test_entry_point_is_disassembled_with_import_annotation(self):
        out = disasm.disassemble_pe(build_pe())
        assert out["enabled"] is True, out["reason"]
        assert out["arch"] == "x64"
        assert out["instructions_analyzed"] >= 2
        call = out["instructions"][0]
        assert call["text"].startswith("call")
        assert call["target"]["import"] == "KERNEL32.dll!VirtualAllocEx"
        assert call["flag"] == "cross-process memory allocation"
        assert out["suspicious_calls"][0]["api"] == "KERNEL32.dll!VirtualAllocEx"

    def test_sweep_stops_at_ret_and_declares_window(self):
        out = disasm.disassemble_pe(build_pe())
        assert out["instructions"][-1]["text"].startswith("ret")
        assert out["window_bytes"] == 4096

    def test_benign_import_is_not_flagged(self):
        out = disasm.disassemble_pe(build_pe(symbol="GetLastError"))
        assert out["enabled"] is True
        assert out["instructions"][0]["target"]["import"] == "KERNEL32.dll!GetLastError"
        assert "flag" not in out["instructions"][0]
        assert out["suspicious_calls"] == []

    def test_max_instructions_is_respected(self):
        out = disasm.disassemble_pe(build_pe(), max_instructions=1)
        assert out["instructions_analyzed"] == 1
        assert out["truncated"] is True

    def test_unsupported_architecture_declared(self):
        out = disasm.disassemble_pe(build_pe(machine=0x0166))
        assert out["enabled"] is False
        assert "architecture" in out["reason"]

    def test_32bit_pe_is_disassembled(self):
        """PE32: la stessa call ma con indirizzamento assoluto."""
        raw = bytearray(build_pe(machine=0x14C))
        # PE32: ImageBase a 4 byte (offset 28) e data directory a +96, non +112.
        opt = 0x58
        struct.pack_into("<H", raw, opt, 0x10B)
        struct.pack_into("<I", raw, opt + 28, 0x400000)
        struct.pack_into("<I", raw, opt + 16, ENTRY_RVA)
        struct.pack_into("<I", raw, opt + 96 + 1 * 8, IDATA_VA)
        struct.pack_into("<I", raw, opt + 96 + 12 * 8, IAT_SLOT_VA)
        # call dword ptr [0x402040] dove 0x402040 = base(0x400000) + IAT_SLOT_VA
        struct.pack_into("<BBIB", raw, TEXT_OFF, 0xFF, 0x15, 0x400000 + IAT_SLOT_VA, 0xC3)
        out = disasm.disassemble_pe(bytes(raw))
        assert out["enabled"] is True, out["reason"]
        assert out["arch"] == "x86"
        assert out["instructions"][0]["target"]["import"] == "KERNEL32.dll!VirtualAllocEx"
