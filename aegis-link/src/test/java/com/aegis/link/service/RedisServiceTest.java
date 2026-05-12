package com.aegis.link.service;

import com.aegis.link.dto.EventRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.ListOperations;
import org.springframework.data.redis.core.RedisTemplate;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RedisServiceTest {

    @Mock
    private RedisTemplate<String, Object> redisTemplate;

    @Mock
    private ListOperations<String, Object> listOperations;

    @InjectMocks
    private RedisService redisService;

    @Test
    void pushEvent_Success() {
        EventRequest event = EventRequest.builder()
                .agentId("agent-1")
                .processName("calc.exe")
                .pid(123)
                .os("Windows")
                .eventType("PROCESS_CREATED")
                .timestamp(Instant.now())
                .build();

        when(redisTemplate.opsForList()).thenReturn(listOperations);

        redisService.pushEvent(event);

        verify(listOperations).leftPush(RedisService.EVENTS_QUEUE_KEY, event);
    }

    @Test
    void pushEvent_ThrowsException_WhenRedisFails() {
        EventRequest event = EventRequest.builder()
                .agentId("agent-1")
                .processName("calc.exe")
                .pid(123)
                .os("Windows")
                .eventType("PROCESS_CREATED")
                .timestamp(Instant.now())
                .build();

        when(redisTemplate.opsForList()).thenThrow(new RuntimeException("Redis down"));

        assertThrows(RuntimeException.class, () -> redisService.pushEvent(event));
    }

    @Test
    void getQueueSize_ReturnsCorrectSize() {
        when(redisTemplate.opsForList()).thenReturn(listOperations);
        when(listOperations.size(RedisService.EVENTS_QUEUE_KEY)).thenReturn(5L);

        long size = redisService.getQueueSize();

        assertEquals(5L, size);
    }

    @Test
    void getQueueSize_ReturnsZero_WhenSizeIsNull() {
        when(redisTemplate.opsForList()).thenReturn(listOperations);
        when(listOperations.size(RedisService.EVENTS_QUEUE_KEY)).thenReturn(null);

        long size = redisService.getQueueSize();

        assertEquals(0L, size);
    }
}
