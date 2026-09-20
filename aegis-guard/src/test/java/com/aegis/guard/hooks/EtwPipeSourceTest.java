package com.aegis.guard.hooks;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import com.aegis.guard.models.SystemEvent;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

class EtwPipeSourceTest {

    private static final String LINE =
        "{\"ts_ns\":1,\"pid\":101,\"ppid\":100,\"uid\":0,\"comm\":\"echo\"," +
        "\"filename\":\"/bin/echo\",\"event_type\":\"PROCESS_CREATED\"}";

    @Test
    void disabledSourceNeverCrashes() {
        EtwPipeSource src = new EtwPipeSource("a1", "1.0",
                false, Path.of("nonexistent-etw.exe"));
        assertFalse(src.probe());
        assertEquals("disabled", src.degradedReason());
        assertFalse(src.isAvailable());
        // Stream null-object: niente eccezioni.
        try (EtwPipeSource.EtwStream s = src.startStream(e -> fail("no events"))) {
            assertFalse(s.isRunning());
        }
    }

    @Test
    void missingBinaryDegrades() {
        EtwPipeSource src = new EtwPipeSource("a1", "1.0",
                true, Path.of("definitely-missing-aegis-etw.exe"));
        assertFalse(src.probe());
        assertFalse(src.degradedReason().isEmpty());
    }

    @Test
    void relativeBinaryRejectedEvenIfExecutable(@TempDir Path tmp) throws Exception {
        // Audit: niente esecuzione da workdir (hijack) — solo path assoluti.
        Path rel = Path.of("aegis-etw.exe");
        EtwPipeSource src = new EtwPipeSource("a1", "1.0", true, rel);
        if (System.getProperty("os.name", "").toLowerCase().contains("win")) {
            assertFalse(src.probe());
            assertEquals("relative-path", src.degradedReason());
        } else {
            assertFalse(src.probe());
        }
        assertNotNull(tmp);
    }

    @Test
    void unsignedBinaryRequiresExplicitOptIn(@TempDir Path tmp) throws Exception {
        // Regressione: l'ETW restava spento per chiunque non firmasse il
        // collector (trust check su Authenticode). Il default resta sicuro
        // (niente esecuzione di binari non firmati), ma esiste un opt-in
        // esplicito per il lab che NON tocca il caso firmato.
        Path fake = tmp.resolve("unsigned-aegis-etw.exe");
        Files.write(fake, new byte[]{0x4d, 0x5a});
        Path abs = fake.toAbsolutePath();

        EtwPipeSource strict = new EtwPipeSource("a1", "1.0", true, abs, false);
        EtwPipeSource lab = new EtwPipeSource("a1", "1.0", true, abs, true);

        String os = System.getProperty("os.name", "").toLowerCase();
        if (!os.contains("win")) {
            assertFalse(strict.probe());
            assertEquals("not-windows", strict.degradedReason());
            return;
        }
        if (!Files.isExecutable(abs)) {
            // Filesystem senza semantica di esecuzione: comportamento non
            // osservabile qui (guardato altrove).
            assertFalse(strict.probe());
            return;
        }
        assertFalse(strict.probe(), "binario non firmato senza opt-in = rifiutato");
        assertEquals("untrusted-binary", strict.degradedReason());
        assertFalse(strict.isAvailable());

        assertTrue(lab.probe(), "opt-in esplicito = accettato");
        assertTrue(lab.isAvailable());
        assertTrue(lab.degradedReason().isEmpty());
    }

    @Test
    void replayFileFeedsIngesterWithEtwProvenance() throws Exception {
        Path f = Files.createTempFile("etw-replay", ".jsonl");
        Files.write(f, (LINE + "\ngarbage\n" + LINE + "\n").getBytes(StandardCharsets.UTF_8));
        EtwPipeSource src = new EtwPipeSource("a1", "1.0",
                false, Path.of("aegis-etw.exe"));
        List<SystemEvent> got = new ArrayList<>();
        List<SystemEvent> events = src.readFile(f, got::add);
        assertEquals(2, events.size());
        assertEquals(2, got.size());
        assertEquals("etw", events.get(0).getProvenance());
        assertEquals(101, events.get(0).getPid());
        assertTrue(src.isAvailable());
    }

    @Test
    void diagnosticFromCollectorIsPreserved() {
        // Il collector stampa il motivo prima di uscire (senza admin:
        // "StartTrace: 5 (serve admin)"). La riga non e' JSON: deve finire
        // nella diagnostica e NON nel flusso eventi, altrimenti un ETW
        // degradato e' indistinguibile da un binario rotto.
        EtwPipeSource src = new EtwPipeSource("a1", "1.0",
                false, Path.of("aegis-etw.exe"));
        assertEquals("", src.lastDiagnostic());

        List<SystemEvent> got = new ArrayList<>();
        src.handleLine("StartTrace: 5 (serve admin)", got::add);
        assertEquals("StartTrace: 5 (serve admin)", src.lastDiagnostic());
        assertTrue(got.isEmpty());

        src.handleLine(LINE, got::add);
        assertEquals(1, got.size());
        assertEquals("etw", got.get(0).getProvenance());
        assertEquals(101, got.get(0).getPid());
        // La diagnostica resta la PRIMA riga (non viene sovrascritta).
        src.handleLine("altro rumore", got::add);
        assertEquals("StartTrace: 5 (serve admin)", src.lastDiagnostic());
        assertEquals(1, got.size());
    }

    @Test
    void unreadableFileDegrades() {
        EtwPipeSource src = new EtwPipeSource("a1", "1.0",
                false, Path.of("aegis-etw.exe"));
        List<SystemEvent> events = src.readFile(Path.of("no-such-file.jsonl"), null);
        assertTrue(events.isEmpty());
        assertFalse(src.isAvailable());
    }
}
