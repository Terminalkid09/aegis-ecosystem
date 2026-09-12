package com.aegis.guard.hooks;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class WindowsServiceSnapshotTest {

    private static final String SCHTASKS =
        "\"TaskName\",\"Next Run Time\",\"Status\"\r\n"
        + "\"\\Microsoft\\Windows\\Update\\Scheduled Start\",\"12/09/2026 03:00:00\",\"Ready\"\r\n"
        + "\"\\Evil, \"\"Quoted\"\" Task\",\"N/A\",\"Could not start\"\r\n"
        + "\"\\Broken\",\"only-two-fields\"\r\n";

    @Test
    void parseSchtasksCsv() {
        List<WindowsServiceSnapshot.Task> tasks = WindowsServiceSnapshot.parseSchtasksCsv(SCHTASKS);
        assertEquals(2, tasks.size());
        assertEquals("\\Microsoft\\Windows\\Update\\Scheduled Start", tasks.get(0).path());
        assertEquals("Ready", tasks.get(0).status());
        assertEquals("\\Evil, \"Quoted\" Task", tasks.get(1).path());
    }

    @Test
    void parseSchtasksCsvTolerant() {
        assertTrue(WindowsServiceSnapshot.parseSchtasksCsv(null).isEmpty());
        assertTrue(WindowsServiceSnapshot.parseSchtasksCsv("").isEmpty());
        assertTrue(WindowsServiceSnapshot.parseSchtasksCsv("TaskName\n").isEmpty());
        assertTrue(WindowsServiceSnapshot.parseSchtasksCsv("\"Nope\",\"X\"\n\"a\",\"b\"").isEmpty());
    }

    @Test
    void splitCsvLineHandlesQuotes() {
        List<String> cells = WindowsServiceSnapshot.splitCsvLine("\"a,b\",\"c\"\"d\",e");
        assertEquals(List.of("a,b", "c\"d", "e"), cells);
        Map<String, Integer> cols =
                WindowsServiceSnapshot.headerIndex("\"TaskName\",\"Next Run Time\"");
        assertEquals(0, cols.get("taskname"));
        assertEquals(1, cols.get("next run time"));
    }

    @Test
    void unquoteStrips() {
        assertEquals("x", WindowsServiceSnapshot.unquote("\"x\""));
        assertEquals("a\"b", WindowsServiceSnapshot.unquote("\"a\"\"b\""));
        assertEquals("", WindowsServiceSnapshot.unquote(null));
        assertEquals("plain", WindowsServiceSnapshot.unquote("  plain  "));
    }

    @Test
    void collectNeverThrows() {
        WindowsServiceSnapshot.Snapshot snap = WindowsServiceSnapshot.collect();
        assertNotNull(snap.services());
        assertNotNull(snap.tasks());
        String os = System.getProperty("os.name", "").toLowerCase();
        if (!os.contains("win")) {
            assertEquals("not-windows", snap.degraded());
        } else {
            assertEquals("", snap.degraded(), "nomi servizi leggibili: " + snap.degraded());
            assertFalse(snap.services().isEmpty(), "Windows reale ha servizi installati");
        }
    }
}
