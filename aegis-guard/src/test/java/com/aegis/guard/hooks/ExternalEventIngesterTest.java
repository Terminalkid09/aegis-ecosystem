package com.aegis.guard.hooks;

import java.io.StringReader;
import java.util.List;

import com.aegis.guard.models.SystemEvent;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class ExternalEventIngesterTest {

    private static final String ECHO =
        "{\"ts_ns\":1,\"pid\":101,\"ppid\":100,\"uid\":0,\"comm\":\"echo\"," +
        "\"filename\":\"/bin/echo\",\"event_type\":\"PROCESS_CREATED\"}";

    @Test
    void mapsEbpfExecEvent() {
        SystemEvent e = ExternalEventIngester.fromJsonLine("a1", "Linux", "1.2.0", ECHO);
        assertNotNull(e);
        assertEquals(101, e.getPid());
        assertEquals(100, e.getParentPid());
        assertEquals("echo", e.getProcessName());
        assertEquals("/bin/echo", e.getProcessPath());
        assertEquals("PROCESS_CREATED", e.getEventType());
        assertEquals("Linux", e.getOs());
        assertNotNull(e.getAgentVersion());
    }

    @Test
    void mapsExitEvent() {
        SystemEvent e = ExternalEventIngester.fromJsonLine("a1", "Linux", "1.2.0",
            "{\"pid\":5,\"event_type\":\"PROCESS_EXITED\",\"exit_code\":0}");
        assertNotNull(e);
        assertEquals("PROCESS_EXITED", e.getEventType());
    }

    @Test
    void rejectsGarbageWithoutThrowing() {
        assertNull(ExternalEventIngester.fromJsonLine("a1", "Linux", "1.2.0", "not json"));
        assertNull(ExternalEventIngester.fromJsonLine("a1", "Linux", "1.2.0", "{\"foo\":1}"));
        assertNull(ExternalEventIngester.fromJsonLine("a1", "Linux", "1.2.0",
            "{\"pid\":1,\"event_type\":\"SOMETHING_ELSE\"}"));
        assertNull(ExternalEventIngester.fromJsonLine(null, "Linux", "1.2.0", ECHO));
        assertNull(ExternalEventIngester.fromJsonLine("a1", "Linux", "1.2.0", null));
    }

    @Test
    void readAllSkipsBadLines() {
        String stream = ECHO + "\ngarbage\n{\"pid\":2,\"event_type\":\"PROCESS_EXITED\"}\n";
        List<SystemEvent> out = ExternalEventIngester.readAll("a1", "Linux", "1.2.0", new StringReader(stream));
        assertEquals(2, out.size());
    }

    @Test
    void realCollectorSampleParses() {
        // Riga reale catturata dal collector eBPF nel kernel di test.
        String sample = "{\"ts_ns\":169883533955188,\"pid\":256087,\"ppid\":251118," +
            "\"uid\":0,\"comm\":\"echo\",\"filename\":\"/bin/echo\",\"event_type\":\"PROCESS_CREATED\"}";
        SystemEvent e = ExternalEventIngester.fromJsonLine("a1", "Linux", "1.2.0", sample);
        assertNotNull(e);
        assertEquals(256087, e.getPid());
        assertEquals(251118, e.getParentPid());
    }

    @Test
    void mapsV2FieldsWhenPresent() {
        String v2 = "{\"schema_version\":2,\"event_id\":\"evt-1\",\"agent_id\":\"a1\"," +
            "\"boot_id\":\"boot-9\",\"seq\":41,\"ts_ns\":111,\"ts_wall_ns\":222," +
            "\"pid\":9,\"ppid\":1,\"proc_start_ns\":100,\"comm\":\"sh\"," +
            "\"filename\":\"/bin/sh\",\"session\":\"tty1\",\"integrity\":\"high\"," +
            "\"provenance\":\"ebpf-full\",\"quality\":\"full\"," +
            "\"event_type\":\"PROCESS_CREATED\"}";
        SystemEvent e = ExternalEventIngester.fromJsonLine("a1", "Linux", "1.2.0", v2);
        assertNotNull(e);
        assertEquals("evt-1", e.getEventId());
        assertEquals(2, e.getSchemaVersion());
        assertEquals("boot-9", e.getBootId());
        assertEquals(41L, e.getSeq());
        assertEquals(111L, e.getTsMonotonicNs());
        assertEquals(222L, e.getTsWallNs());
        assertEquals(100L, e.getProcStartNs());
        assertEquals("tty1", e.getSessionId());
        assertEquals("high", e.getIntegrityLevel());
        assertEquals("ebpf-full", e.getProvenance());
        assertEquals("full", e.getQuality());
    }

    @Test
    void mapsConnectionEstablished() {
        String conn = "{\"pid\":9,\"comm\":\"curl\",\"remote\":\"93.184.216.34:443\"," +
            "\"proto\":\"tcp\",\"direction\":\"outbound\",\"event_type\":\"CONNECTION_ESTABLISHED\"}";
        SystemEvent e = ExternalEventIngester.fromJsonLine("a1", "Linux", "1.2.0", conn);
        assertNotNull(e);
        assertEquals("CONNECTION_ESTABLISHED", e.getEventType());
        assertEquals("tcp", e.getProto());
        assertEquals("outbound", e.getDirection());
        assertNotNull(e.getNetworkConnections());
        assertTrue(e.getNetworkConnections().toString().contains("93.184.216.34:443"));
        assertNotNull(e.getEventId(), "ogni evento ha idempotenza di default");
    }

    @Test
    void legacyV1WithoutV2FieldsKeepsGeneratedId() {
        SystemEvent e = ExternalEventIngester.fromJsonLine("a1", "Linux", "1.2.0", ECHO);
        assertNotNull(e.getEventId());
        assertEquals(2, e.getSchemaVersion());
    }
}
