package com.aegis.guard.utils;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.util.List;

class MonitorTuningTest {

    @Test
    void parseStatusSinglePass() {
        List<String> lines = List.of(
            "Name:\tjava",
            "Umask:\t0022",
            "PPid:\t1234",
            "Threads:\t42",
            "Uid:\t1000\t1000\t1000\t1000"
        );
        MonitorTuning.ProcStatus s = MonitorTuning.parseStatusLines(lines);
        assertEquals(1234, s.ppid());
        assertEquals(42, s.threads());
        assertEquals("1000", s.uid());
    }

    @Test
    void parseStatusMissingIsZero() {
        MonitorTuning.ProcStatus s = MonitorTuning.parseStatusLines(List.of("Name:\tx"));
        assertEquals(0, s.ppid());
        assertEquals(0, s.threads());
        assertEquals("", s.uid());
    }

    @Test
    void throttleFirstRunAlways() {
        assertTrue(MonitorTuning.shouldRefreshNetstat(-1, 1000, 5000));
    }

    @Test
    void throttleRespectsInterval() {
        assertFalse(MonitorTuning.shouldRefreshNetstat(1000, 3000, 5000));
        assertTrue(MonitorTuning.shouldRefreshNetstat(1000, 6000, 5000));
        assertTrue(MonitorTuning.shouldRefreshNetstat(1000, 6001, 5000));
    }

    @Test
    void uidCacheResolvesOnce() {        int[] calls = {0};
        MonitorTuning.UidCache c = new MonitorTuning.UidCache(uid -> {
            calls[0]++;
            return "user" + uid;
        });
        assertEquals("user1000", c.usernameFor("1000"));
        assertEquals("user1000", c.usernameFor("1000"));
        assertEquals("user0", c.usernameFor("0"));
        assertEquals(2, calls[0], "passwd si legge una volta per UID, non per processo");
        assertEquals("unknown", c.usernameFor(""));
        assertEquals("unknown", c.usernameFor(null));
    }

    @Test
    void parseStatStarttimeField22() {
        // pid (comm) state ppid ... starttime è il 20° campo dopo ')'.
        String stat = "1234 (myproc) R 1 1234 1234 0 -1 4194304 "
                + "100 0 0 0 10 5 0 0 20 0 4 0 56789 0 0";
        assertEquals(56789L, MonitorTuning.parseStatStarttime(stat).orElseThrow());
    }

    @Test
    void parseStatStarttimeToleratesSpacesInComm() {
        String stat = "9 (my prog (v2)) S 1 9 9 0 -1 4194304 "
                + "0 0 0 0 0 0 0 0 20 0 1 0 42 0 0";
        assertEquals(42L, MonitorTuning.parseStatStarttime(stat).orElseThrow());
    }

    @Test
    void parseStatStarttimeRejectsGarbage() {
        assertTrue(MonitorTuning.parseStatStarttime(null).isEmpty());
        assertTrue(MonitorTuning.parseStatStarttime("").isEmpty());
        assertTrue(MonitorTuning.parseStatStarttime("no parens here").isEmpty());
        assertTrue(MonitorTuning.parseStatStarttime("1 (x) R 1").isEmpty());
    }

    @Test
    void starttimeToNsScalesByHz() {
        long hz = MonitorTuning.userHz();
        assertTrue(hz > 0);
        assertEquals(1_000_000_000L, MonitorTuning.starttimeToNs(hz));
    }
}
