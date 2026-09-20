package com.aegis.guard.utils;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.util.List;

class IsolationManagerTest {

    @Test
    void extractBrainHostFromHttpsUrl() {
        assertEquals("aegis.local",
                IsolationManager.extractBrainHost("https://aegis.local/api/v1"));
    }

    @Test
    void extractBrainHostWithPort() {
        assertEquals("brain.example.com",
                IsolationManager.extractBrainHost("http://brain.example.com:8000/api/v1"));
    }

    @Test
    void extractBrainHostInvalidIsEmpty() {
        assertEquals("", IsolationManager.extractBrainHost(null));
        assertEquals("", IsolationManager.extractBrainHost(""));
        assertEquals("", IsolationManager.extractBrainHost("   "));
    }

    @Test
    void isolateCommandsContainBrainExceptionAndBlockAll() {
        List<String[]> cmds = IsolationManager.buildIsolateCommands("10.0.0.5");
        assertFalse(cmds.isEmpty());
        boolean hasBrain = cmds.stream().anyMatch(a -> String.join(" ", a).contains("10.0.0.5"));
        boolean hasBlock = cmds.stream().anyMatch(a -> {
            String s = String.join(" ", a).toLowerCase();
            return s.contains("block") || s.contains("drop");
        });
        assertTrue(hasBrain, "isolate must allow-list the brain");
        assertTrue(hasBlock, "isolate must contain a block/drop rule");
    }

    @Test
    void isolateWithoutBrainIsFailClosed() {
        List<String[]> cmds = IsolationManager.buildIsolateCommands("");
        assertFalse(cmds.isEmpty());
        boolean hasBlock = cmds.stream().anyMatch(a -> {
            String s = String.join(" ", a).toLowerCase();
            return s.contains("block") || s.contains("drop");
        });
        assertTrue(hasBlock, "without brain host, isolate must still block everything");
    }

    @Test
    void restoreCommandsRemoveIsolateRules() {
        List<String[]> cmds = IsolationManager.buildRestoreCommands("10.0.0.5");
        assertFalse(cmds.isEmpty());
        boolean removesBlock = cmds.stream().anyMatch(a -> {
            String s = String.join(" ", a).toLowerCase();
            return (s.contains("delete") || s.contains("-d")) && (s.contains("block") || s.contains("drop") || s.contains("aegis"));
        });
        assertTrue(removesBlock, "restore must remove the block rule");
    }
}
