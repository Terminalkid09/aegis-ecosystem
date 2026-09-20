package com.aegis.guard.hooks;

import java.util.Map;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class WindowsSensorKitTest {

    @Test
    void normalizePathHandlesVariants() {
        assertEquals("c:\\windows\\system32\\cmd.exe",
                WindowsSensorKit.normalizePath("C:/Windows/System32/cmd.exe"));
        assertEquals("c:\\x\\a.exe",
                WindowsSensorKit.normalizePath("\"C:\\x\\a.exe\""));
        assertEquals("c:\\x\\a.exe",
                WindowsSensorKit.normalizePath("\\\\?\\C:\\x\\a.exe"));
        assertEquals("c:\\x\\a.exe",
                WindowsSensorKit.normalizePath("C:\\\\x\\\\a.exe"));
        assertEquals("", WindowsSensorKit.normalizePath(null));
    }

    @Test
    void normalizeCmdlineCollapsesAndFolds() {
        assertEquals("powershell -enc abc",
                WindowsSensorKit.normalizeCmdline("  PowerShell   -Enc  abc "));
        assertEquals("", WindowsSensorKit.normalizeCmdline(null));
    }

    @Test
    void pidReuseKeyDistinguishesStarts() {
        assertEquals("pid:4@99", WindowsSensorKit.pidReuseKey(4, 99L));
        assertEquals("pid:4", WindowsSensorKit.pidReuseKey(4, null));
        assertEquals("pid:4", WindowsSensorKit.pidReuseKey(4, 0L));
        assertNotEquals(WindowsSensorKit.pidReuseKey(4, 1L),
                WindowsSensorKit.pidReuseKey(4, 2L));
    }

    @Test
    void parseWmicOutputExtractsSecondLine() {
        assertEquals("C:\\x\\a.exe -k",
                WindowsSensorKit.parseWmicOutput("CommandLine\r\nC:\\x\\a.exe -k\r\n"));
        assertEquals("", WindowsSensorKit.parseWmicOutput("garbage"));
        assertEquals("", WindowsSensorKit.parseWmicOutput(null));
        assertEquals("", WindowsSensorKit.parseWmicOutput("CommandLine\r\n  \r\n"));
    }

    @Test
    void parseNetstatLineTcp() {
        Map<String, String> c = WindowsSensorKit.parseNetstatLine(
                "  TCP    10.0.0.2:5001    93.184.216.34:443    ESTABLISHED    1234");
        assertEquals("TCP", c.get("proto"));
        assertEquals("93.184.216.34:443", c.get("remote"));
        assertEquals("ESTABLISHED", c.get("state"));
        assertEquals("1234", c.get("pid"));
        assertTrue(WindowsSensorKit.isSignificantConnection(c));
    }

    @Test
    void parseNetstatLineRejectsJunk() {
        assertTrue(WindowsSensorKit.parseNetstatLine(null).isEmpty());
        assertTrue(WindowsSensorKit.parseNetstatLine("Active Connections").isEmpty());
        assertTrue(WindowsSensorKit.parseNetstatLine("  Proto  Local  Remote  State  PID").isEmpty());
        assertTrue(WindowsSensorKit.parseNetstatLine("  TCP  a b C 0").isEmpty());
        Map<String, String> listen = WindowsSensorKit.parseNetstatLine(
                "  TCP    0.0.0.0:445    0.0.0.0:0    LISTENING    4");
        assertFalse(WindowsSensorKit.isSignificantConnection(listen));
    }

    @Test
    void procNameEqualsMatchesBasenameOnly() {
        assertTrue(WindowsSensorKit.procNameEquals("C:\\Windows\\System32\\CMD.EXE", "cmd.exe"));
        assertTrue(WindowsSensorKit.procNameEquals("cmd.exe", "CMD.EXE"));
        assertFalse(WindowsSensorKit.procNameEquals("C:\\Tools\\mycmd.exe", "cmd.exe"));
        assertFalse(WindowsSensorKit.procNameEquals("mywordviewer", "word"));
        assertEquals("notepad.exe", WindowsSensorKit.baseName("C:\\x\\NOTEPAD.EXE"));
    }
}
