package com.aegis.guard.models;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class SystemEventVersionTest {

    private static com.google.gson.Gson gson() {
        // Stesso adapter del client reale (AegisClient): Instant -> ISO-8601.
        return new com.google.gson.GsonBuilder()
                .registerTypeAdapter(java.time.Instant.class,
                        (com.google.gson.JsonSerializer<java.time.Instant>) (src, t, c) ->
                                new com.google.gson.JsonPrimitive(
                                        java.time.format.DateTimeFormatter.ISO_INSTANT.format(src)))
                .create();
    }

    @Test
    void agentVersionSerializesAsCamelCase() {
        SystemEvent e = new SystemEvent("a1", 0, 0, "", "aegis-guard", "", "", "Linux", "AGENT_HEARTBEAT");
        e.setAgentVersion("1.2.0");
        String json = gson().toJson(e);
        assertTrue(json.contains("\"agentVersion\":\"1.2.0\""), "brain expects camelCase agentVersion, got: " + json);
    }

    @Test
    void agentVersionDefaultsNull() {
        SystemEvent e = new SystemEvent("a1", 1, 0, "init", "cmd.exe", "C:\\x", "u", "Windows", "PROCESS_CREATED");
        assertNull(e.getAgentVersion());
    }

    @Test
    void newEventsCarryIdempotencyIdentity() {
        SystemEvent e = new SystemEvent("a1", 1, 0, "init", "sh", "/bin/sh", "u", "Linux", "PROCESS_CREATED");
        assertNotNull(e.getEventId(), "ogni evento nasce con event_id per dedup server-side");
        assertEquals(2, e.getSchemaVersion());
        SystemEvent other = new SystemEvent("a1", 1, 0, "init", "sh", "/bin/sh", "u", "Linux", "PROCESS_CREATED");
        assertNotEquals(e.getEventId(), other.getEventId(), "id univoci per evento");
    }

    @Test
    void v2FieldsSerializeCamelCase() {
        SystemEvent e = new SystemEvent("a1", 1, 0, "init", "sh", "/bin/sh", "u", "Linux", "PROCESS_CREATED");
        e.setBootId("boot-1");
        e.setSeq(7L);
        e.setProvenance("ebpf-full");
        String json = gson().toJson(e);
        assertTrue(json.contains("\"eventId\":"), "brain EventSchema usa alias eventId, got: " + json);
        assertTrue(json.contains("\"bootId\":\"boot-1\""), json);
        assertTrue(json.contains("\"schemaVersion\":2"), json);
    }
}
