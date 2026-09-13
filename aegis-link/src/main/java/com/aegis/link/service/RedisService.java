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
            // Audit: la chiave e' lo SHA-256 del secret (mai plaintext in Redis),
            // stesso formato del brain (hashlib.sha256 hex). Prima il brain
            // scriveva hash e link leggeva raw: cache mai hit per guard.
            return redisTemplate.opsForValue().get("auth:agent:" + sha256Hex(secret.strip()));
        } catch (Exception e) {
            log.error("Failed to fetch agent auth from Redis: {}", e.getMessage());
            return null;
        }
    }

    static String sha256Hex(String value) {
        try {
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            byte[] out = md.digest(value.getBytes(java.nio.charset.StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(out.length * 2);
            for (byte b : out) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
