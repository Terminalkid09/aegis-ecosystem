"""Aegis Total: falsi positivi del punteggio e degli IOC.

`notepad.exe` di Windows finiva `verdict: malicious` con score 70 e due IOC
`6.0.0.0` / `5.1.0.0`. Non era un caso limite teorico: era il risultato di tre
difetti indipendenti, tutti riprodotti qui.

1. `etw.*patch` matchava 895 byte di nomi di API Windows: `etWindowExtEx`
   contiene "etw" e un "patch" lontano chiudeva il match. Il `.*` illimitato su
   stringhe concatenate e' un generatore di falsi positivi.
2. Tre import dual-use (`CreateProcessW`, `ShellExecute`, `RegSetValueEx`)
   valevano 15 punti ciascuno con peso fisso: 45 punti da sole, e con la stringa
   falsa si superava la soglia di "malicious" (60).
3. `version="5.1.0.0"` nel manifest veniva estratto come indirizzo IP.

La detection vera non deve indebolirsi: i campioni malevoli si riconoscono
ancora, e gli stessi pattern ora catturano il fenomeno reale.
"""
import os
import re

import pytest

from app.api.v1.total import (
    DUAL_USE_IMPORTS,
    ENGINE_VERSION,
    IMPORT_SCORE_CAP,
    POWERSHELL_EXEC_MARKERS,
    SUSPICIOUS_IMPORTS,
    SUSPICIOUS_STRINGS,
    VERSIONLIKE_IPV4,
    _analyze_bytes,
    _iocs_from,
)

# Soglie di verdict come in total.py: <20 clean, <60 suspicious, >=60 malicious.
MALICIOUS_THRESHOLD = 60


def _matches(text: str) -> list[str]:
    return [m.group(0) for pat in SUSPICIOUS_STRINGS if (m := pat.search(text))]


class TestSuspiciousStringsDoNotSpanUnrelatedText:
    def test_etw_inside_a_normal_word_is_not_etw_patching(self):
        """Il caso esatto di notepad.exe: 'etWindowExtEx' + un 'patch' distante."""
        benign = ("GetWindowExtEx\0LPtoDP\0SetBkMode\0GetTextMetricsW\0EndPage\0"
                  "AbortDoc\0EndDoc\0DispatchMessage\0RegSetValueEx\0"
                  "CreateProcessW\0ShellExecute\0" + "x" * 900 + "patch")
        assert _matches(benign) == []

    def test_a_real_etw_patch_still_matches(self):
        """Il fenomeno vero deve continuare a essere rilevato."""
        assert _matches("EtwEventWrite patch")
        assert _matches("AMSI_Bypass patch")
        assert _matches("unhook ntdll")

    def test_real_tooling_names_still_match(self):
        assert _matches("mimikatz")
        assert _matches("lsass dump via procdump")
        assert _matches("powershell -enc SQBFAFgA")
        assert _matches("virtualalloc rwx")
        assert _matches("certutil -decode payload.txt")

    def test_gap_is_bounded(self):
        """Con la distanza limitata, due parole lontane non fanno un match."""
        far = "etw" + ("z" * 500) + "patch"
        assert _matches(far) == []


class TestVersionNumbersAreNotIOCs:
    def test_manifest_version_is_not_an_ip(self):
        text = 'version="5.1.0.0"\rarchitecture="amd64"\rversion="6.0.0.0"'
        iocs = _iocs_from(text)
        assert iocs.get("ipv4") in (None, []), iocs

    def test_versionlike_shape_is_recognised(self):
        assert VERSIONLIKE_IPV4.match("5.1.0.0")
        assert VERSIONLIKE_IPV4.match("10.0.0.0")
        assert not VERSIONLIKE_IPV4.match("203.0.113.77")

    def test_a_real_c2_address_is_still_an_ioc(self):
        iocs = _iocs_from("beacon to 203.0.113.77:8443 every 60s")
        assert "203.0.113.77" in iocs.get("ipv4", [])

    def test_loopback_and_broadcast_stay_filtered(self):
        iocs = _iocs_from("127.0.0.1 and 0.0.0.0 and 255.255.255.255")
        assert iocs.get("ipv4") in (None, [])


class TestScoringCannotCallAFriendlyBinaryMalicious:
    def test_dual_use_imports_alone_stay_below_malicious(self):
        """notepad.exe importa tre API comuni: da sole non bastano."""
        assert IMPORT_SCORE_CAP < MALICIOUS_THRESHOLD
        dual = [f for f in ("CreateProcessW", "ShellExecute", "RegSetValueEx")
                if f in DUAL_USE_IMPORTS]
        assert len(dual) == 3, "le tre API del caso notepad.exe devono restare dual-use"

    def test_import_catalogue_is_split_and_coherent(self):
        """Ogni dual-use deve esistere in catalogo, e il catalogo non deve
        essere tutto dual-use (altrimenti non si rileva piu' nulla)."""
        assert DUAL_USE_IMPORTS <= set(SUSPICIOUS_IMPORTS)
        assert len(DUAL_USE_IMPORTS) < len(SUSPICIOUS_IMPORTS)
        # Le API che da sole indicano iniezione restano ad alto peso.
        for specific in ("CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx",
                         "MiniDumpWriteDump", "QueueUserAPC"):
            assert specific not in DUAL_USE_IMPORTS, specific

    def test_powershell_reference_without_flags_is_not_high(self):
        """Un riferimento a PowerShell non e' un dropper."""
        assert b"-encodedcommand" in POWERSHELL_EXEC_MARKERS
        sample = b"see https://aka.ms/powershell for details"
        assert not any(m in sample for m in POWERSHELL_EXEC_MARKERS)

    def test_powershell_with_execution_flags_is_recognised(self):
        for flags in (b"powershell -EncodedCommand SQBFAFgA",
                      b"powershell -nop -w hidden",
                      b"powershell -executionpolicy bypass",
                      b"IEX (New-Object Net.WebClient)"):
            assert any(m in flags.lower() for m in POWERSHELL_EXEC_MARKERS), flags


class TestMalformedContainerIsNotSkipped:
    """Un contenitore riconosciuto dal magic ma non parabile deve essere
    analizzato lo stesso: header corretti o troncati sono un'evasione classica.
    Prima usciva `score 0`, verdict "clean", con dentro mimikatz."""

    def _malformed_pe(self) -> bytes:
        return (b"MZ\x90\x00" + os.urandom(4096) +
                b"\r\nmimikatz sekurlsa::logonpasswords\r\n"
                b"powershell -nop -w hidden -EncodedCommand SQBFAFgA\r\n"
                b"CreateRemoteThread WriteProcessMemory VirtualAllocEx\r\n")

    def test_malformed_pe_with_real_markers_is_not_clean(self):
        d = _analyze_bytes(self._malformed_pe(), "sample.bin", allow_nested=False)
        assert d.get("malformed") is True
        assert d["score"] >= 60, d["score"]
        types = {f.get("type") for f in d.get("findings", [])}
        assert "malformed_header" in types
        assert "suspicious_string" in types

    def test_malformed_pe_still_gets_strings_iocs_and_hexdump(self):
        d = _analyze_bytes(self._malformed_pe(), "sample.bin", allow_nested=False)
        assert d.get("strings_preview")
        assert d.get("hexdump")
        assert "note" in d

    def test_c2_address_in_a_malformed_pe_is_extracted(self):
        raw = b"MZ\x90\x00" + os.urandom(2048) + b"beacon 203.0.113.77:8443"
        d = _analyze_bytes(raw, "sample.bin", allow_nested=False)
        assert "203.0.113.77" in (d.get("iocs") or {}).get("ipv4", [])

    def test_engine_version_is_declared_and_used_for_the_cache(self):
        """Il verdetto dipende dall'engine: la cache deve poterlo invalidare."""
        import inspect
        from app.api.v1 import total as mod
        src = inspect.getsource(mod.upload_analyze)
        assert "ENGINE_VERSION" in src, "la cache non considera la versione dell'engine"
        assert ENGINE_VERSION


class TestStrictPrefixesDoNotWeakenDetection:
    def test_xmrig_and_miner_pools_still_match(self):
        assert _matches("xmrig --donate-level 1")
        assert _matches("stratum+tcp://pool.example:3333")

    def test_cobalt_strike_beacon_still_matches(self):
        assert _matches("cobalt strike beacon")
        assert _matches("meterpreter session opened")

    @pytest.mark.parametrize("raw", [
        b"mimikatz", b"lsass dump", b"reverse shell", b"bind shell",
    ])
    def test_patterns_are_case_insensitive(self, raw):
        assert _matches(raw.decode().upper())


class TestRegexesAreBounded:
    def test_no_unbounded_dot_star_in_suspicious_strings(self):
        """Un `.*` senza limite su stringhe concatenate e' il difetto origine."""
        offenders = [p.pattern for p in SUSPICIOUS_STRINGS
                     if re.search(r"\.\*", p.pattern) and not re.search(r"\.\{\d+,\d*\}", p.pattern)]
        assert offenders == [], f"pattern con .* illimitato: {offenders}"
