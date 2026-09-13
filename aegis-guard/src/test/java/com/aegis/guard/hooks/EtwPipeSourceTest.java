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
    void unreadableFileDegrades() {
        EtwPipeSource src = new EtwPipeSource("a1", "1.0",
                false, Path.of("aegis-etw.exe"));
        List<SystemEvent> events = src.readFile(Path.of("no-such-file.jsonl"), null);
        assertTrue(events.isEmpty());
        assertFalse(src.isAvailable());
    }
}
