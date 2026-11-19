package com.aegis.link.service;

import com.aegis.link.dto.EventRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import tools.jackson.databind.json.JsonMapper;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class EventSpoolServiceTest {

    @TempDir
    Path tempDir;

    private EventRequest event() {
        return EventRequest.builder()
                .agentId("agent-1")
                .pid(123)
                .processName("calc.exe")
                .os("Windows")
                .eventType("PROCESS_CREATED")
                .timestamp(Instant.now())
                .build();
    }

    @Test
    void spoolPersistsBeforeDrainAndDeletesOnlyAfterPush() throws Exception {
        RedisService redis = mock(RedisService.class);
        EventSpoolService service = new EventSpoolService(
                redis, JsonMapper.builder().build(), tempDir.toString(), true, 100, 10);

        assertTrue(service.spool(event()));
        try (var files = Files.list(tempDir)) {
            assertEquals(1, files.filter(p -> p.toString().endsWith(".json")).count());
        }

        when(redis.pushEventIfRoom(any(EventRequest.class))).thenReturn(true);
        service.drain();
        verify(redis).pushEventIfRoom(any(EventRequest.class));
        try (var files = Files.list(tempDir)) {
            assertEquals(0, files.filter(p -> p.toString().endsWith(".json")).count());
        }
    }

    @Test
    void failedDrainKeepsTheFileForRetry() throws Exception {
        RedisService redis = mock(RedisService.class);
        doThrow(new RuntimeException("Redis down")).when(redis).pushEventIfRoom(any());
        EventSpoolService service = new EventSpoolService(
                redis, JsonMapper.builder().build(), tempDir.toString(), true, 100, 10);

        assertTrue(service.spool(event()));
        service.drain();

        try (var files = Files.list(tempDir)) {
            assertEquals(1, files.filter(p -> p.toString().endsWith(".json")).count());
        }
    }

    @Test
    void disabledSpoolRejectsInsteadOfPretendingToPersist() {
        RedisService redis = mock(RedisService.class);
        EventSpoolService service = new EventSpoolService(
                redis, JsonMapper.builder().build(), tempDir.toString(), false, 100, 10);

        assertFalse(service.spool(event()));
    }

    @Test
    void maxFilesIsEnforced() throws Exception {
        RedisService redis = mock(RedisService.class);
        EventSpoolService service = new EventSpoolService(
                redis, JsonMapper.builder().build(), tempDir.toString(), true, 1, 10);

        assertTrue(service.spool(event()));
        assertFalse(service.spool(event()));
    }

    @Test
    void fullQueueKeepsTheFileForRetry() throws Exception {
        RedisService redis = mock(RedisService.class);
        when(redis.pushEventIfRoom(any(EventRequest.class))).thenReturn(false);
        EventSpoolService service = new EventSpoolService(
                redis, JsonMapper.builder().build(), tempDir.toString(), true, 100, 10);

        assertTrue(service.spool(event()));
        service.drain();

        try (var files = Files.list(tempDir)) {
            assertEquals(1, files.filter(p -> p.toString().endsWith(".json")).count());
        }
    }
}
