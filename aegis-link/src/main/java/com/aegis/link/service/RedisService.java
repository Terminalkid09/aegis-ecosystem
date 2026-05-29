package com.aegis.link.service;

import com.aegis.link.dto.EventRequest;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class RedisService {

    private static final Logger log = LoggerFactory.getLogger(RedisService.class);
    public static final String EVENTS_QUEUE_KEY = "aegis:events";

    private final RedisTemplate<String, String> redisTemplate;
    private final ObjectMapper objectMapper;

    public void pushEvent(EventRequest event) {
        try {
            String eventJson = objectMapper.writeValueAsString(event);
            redisTemplate.opsForList().leftPush(EVENTS_QUEUE_KEY, eventJson);
            log.debug("Event pushed to Redis queue '{}': agent={} process={} pid={} hostname={}",
                    EVENTS_QUEUE_KEY, event.getAgentId(),
                    event.getProcessName(), event.getPid(), event.getHostname());
        } catch (Exception e) {
            log.error("Failed to push event to Redis for agent={} process={}: {}",
                    event.getAgentId(), event.getProcessName(), e.getMessage());
            throw new RuntimeException("Redis unavailable", e);
        }
    }

    public long getQueueSize() {
        Long size = redisTemplate.opsForList().size(EVENTS_QUEUE_KEY);
        return size != null ? size : 0L;
    }

    public String popCommand(String agentId) {
        String queueKey = "aegis:commands:" + agentId;
        try {
            return redisTemplate.opsForList().rightPop(queueKey);
        } catch (Exception e) {
            log.error("Failed to pop command from Redis for agent={}: {}", agentId, e.getMessage());
            return null;
        }
    }

    public String getAgentIdBySecret(String secret) {
        if (secret == null || secret.isBlank()) return null;
        try {
            return redisTemplate.opsForValue().get("auth:agent:" + secret);
        } catch (Exception e) {
            log.error("Failed to fetch agent auth from Redis: {}", e.getMessage());
            return null;
        }
    }
}
