package com.aegis.guard.network;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

class FileSpoolTest {

    private static FileSpool spool(Path dir) throws Exception {
        return new FileSpool(dir, FileSpool.deriveKey("test-secret-xyz"));
    }

    @Test
    void roundTripSurvivesRestart() throws Exception {
        Path dir = Files.createTempDirectory("spool-rt");
        spool(dir).save(Arrays.asList("{\"a\":1}", "{\"b\":2}"));
        // Nuova istanza = reboot endpoint: i dati ci sono ancora.
        FileSpool reopened = spool(dir);
        assertTrue(reopened.hasData());
        FileSpool.LoadResult r = reopened.load(100);
        assertEquals(Arrays.asList("{\"a\":1}", "{\"b\":2}"), r.lines);
        assertEquals(0, r.corrupt);
        assertFalse(r.keyMismatch);
        assertFalse(reopened.hasData(), "righe consumate rimosse");
    }

    @Test
    void tamperedLineSkippedAndCounted() throws Exception {
        Path dir = Files.createTempDirectory("spool-tamper");
        FileSpool s = spool(dir);
        s.save(Arrays.asList("{\"ok\":true}"));
        // Manomissione: accoda spazzatura non cifrata.
        Files.write(dir.resolve("spool.jsonl"),
                Arrays.asList("TAMPERED-NOT-ENCRYPTED"),
                java.nio.charset.StandardCharsets.UTF_8,
                java.nio.file.StandardOpenOption.APPEND);
        FileSpool.LoadResult r = spool(dir).load(100);
        assertEquals(1, r.lines.size());
        assertEquals(1, r.corrupt);
        assertFalse(r.keyMismatch);
    }

    @Test
    void wrongKeyQuarantinesInsteadOfDeleting() throws Exception {
        Path dir = Files.createTempDirectory("spool-key");
        spool(dir).save(Arrays.asList("{\"a\":1}"));
        FileSpool other = new FileSpool(dir, FileSpool.deriveKey("different-secret!!"));
        FileSpool.LoadResult r = other.load(100);
        assertTrue(r.keyMismatch, "chiave diversa = quarantena, mai cancellazione");
        assertTrue(r.lines.isEmpty());
        assertFalse(other.hasData());
        assertEquals(1, Files.list(dir)
                .filter(p -> p.getFileName().toString().startsWith("spool.jsonl.bad-"))
                .count(), "file quarantena presente");
    }

    @Test
    void fullSpoolRefusesSave() throws Exception {
        Path dir = Files.createTempDirectory("spool-full");
        FileSpool s = new FileSpool(dir, FileSpool.deriveKey("k"), 0);
        try {
            s.save(Arrays.asList("{\"a\":1}"));
            fail("spool oltre il tetto deve rifiutare");
        } catch (java.io.IOException expected) {
            assertTrue(expected.getMessage().contains("spool full"));
        }
    }

    @Test
    void deriveKeyIsStableAndSized() {
        byte[] k1 = FileSpool.deriveKey("s");
        byte[] k2 = FileSpool.deriveKey("s");
        assertEquals(32, k1.length);
        assertArrayEquals(k1, k2);
        assertFalse(Arrays.equals(k1, FileSpool.deriveKey("other")));
    }

    @Test
    void windowsAclLockdownNeverThrows(@TempDir Path tmp) {
        // Audit P6: su Windows restringe, altrove no-op; mai eccezioni.
        // Su Windows verifica anche che la dir resti scrivibile dal processo.
        FileSpool.lockWindowsAcl(tmp);
        assertTrue(Files.isWritable(tmp));
    }
}
