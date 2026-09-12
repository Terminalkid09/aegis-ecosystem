package com.aegis.guard.hooks;

import java.util.ArrayList;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class WindowsPersistenceSnapshotTest {

    @Test
    void collectNeverThrowsAndReportsDegradedOffWindows() {
        WindowsPersistenceSnapshot.Snapshot snap = WindowsPersistenceSnapshot.collect();
        assertNotNull(snap.items());
        String os = System.getProperty("os.name", "").toLowerCase();
        if (!os.contains("win")) {
            assertEquals("not-windows", snap.degraded());
            assertTrue(snap.items().isEmpty());
        }
    }

    @Test
    void helpersNeverThrowOnGarbage() {
        assertDoesNotThrow(() -> WindowsPersistenceSnapshot.readRunKey(null, "x", new ArrayList<>()));
        assertDoesNotThrow(() -> WindowsPersistenceSnapshot.readRunKey(
                "HKCU\\No\\Such\\Key\\At\\All", "x", new ArrayList<>()));
        assertDoesNotThrow(() -> WindowsPersistenceSnapshot.listDir(null, "x", new ArrayList<>()));
        assertDoesNotThrow(() -> WindowsPersistenceSnapshot.listDir(
                new java.io.File("/definitely/not/here"), "x", new ArrayList<>()));
    }

    @Test
    void liveRunKeysReadableOnWindows() {
        if (!System.getProperty("os.name", "").toLowerCase().contains("win")) return;
        // Chiavi Run reali: devono leggersi (anche se vuote) — prima con
        // Preferences risultavano sempre vuote su Windows veri (bug Fase 2).
        java.util.List<WindowsPersistenceSnapshot.Item> out = new ArrayList<>();
        WindowsPersistenceSnapshot.readRunKey(
                "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "HKCU\\Run", out);
        for (WindowsPersistenceSnapshot.Item it : out) {
            assertFalse(it.name().isBlank());
        }
    }

    @Test
    void itemsAreRecordsWithLocation() {
        WindowsPersistenceSnapshot.Item it =
                new WindowsPersistenceSnapshot.Item("HKCU\\Run", "Name", "C:\\x.exe");
        assertEquals("HKCU\\Run", it.location());
        assertEquals("Name", it.name());
    }
}
