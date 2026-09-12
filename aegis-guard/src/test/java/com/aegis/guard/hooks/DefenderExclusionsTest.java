package com.aegis.guard.hooks;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class DefenderExclusionsTest {

    @Test
    void looksDisabledOnFlagOne() {
        DefenderExclusions.Snapshot s = new DefenderExclusions.Snapshot(
                Map.of(), Map.of("DisableRealtimeMonitoring", "1"), "");
        assertTrue(DefenderExclusions.looksDisabled(s));
        DefenderExclusions.Snapshot ok = new DefenderExclusions.Snapshot(
                Map.of("Paths", List.of("C:\\Temp")), Map.of("DisableRealtimeMonitoring", "0"), "");
        assertFalse(DefenderExclusions.looksDisabled(ok));
        assertFalse(DefenderExclusions.looksDisabled(null));
    }

    @Test
    void collectNeverThrowsAndStructured() {
        DefenderExclusions.Snapshot snap = DefenderExclusions.collect();
        assertNotNull(snap.exclusions());
        assertNotNull(snap.tamperFlags());
        String os = System.getProperty("os.name", "").toLowerCase();
        if (!os.contains("win")) {
            assertEquals("not-windows", snap.degraded());
            assertTrue(snap.exclusions().isEmpty());
        }
    }

    @Test
    void liveReadDoesNotCrashThisMachine() {
        // Su Windows reale: solo struttura, mai assunzioni sul contenuto
        // (policy diverse per macchina; il SOC interpreta i valori).
        if (!System.getProperty("os.name", "").toLowerCase().contains("win")) return;
        DefenderExclusions.Snapshot snap = DefenderExclusions.collect();
        for (Map.Entry<String, List<String>> e : snap.exclusions().entrySet()) {
            assertNotNull(e.getKey());
            assertNotNull(e.getValue());
        }
    }
}
