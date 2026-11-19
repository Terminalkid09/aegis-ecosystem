package com.aegis.link.service;

import com.aegis.link.dto.EventRequest;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.node.ObjectNode;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
public class RedisService {

    private static final Logger log = LoggerFactory.getLogger(RedisService.class);
    public static final String EVENTS_QUEUE_KEY = "aegis:events";
    public static final long MAX_QUEUE_SIZE = 50000;

    /*
     * Check+push nello stesso script Lua: il vecchio LLEN seguito da LPUSH
     * lasciava una finestra in cui due producer potevano superare il cap.
     * Restituisce 1 se l'evento e' stato accodato, 0 se la coda e' piena.
     */
    private static final DefaultRedisScript<Long> PUSH_IF_ROOM = new DefaultRedisScript<>("""
            local depth = redis.call('LLEN', KEYS[1])
            if depth >= tonumber(ARGV[1]) then return 0 end
            redis.call('LPUSH', KEYS[1], ARGV[2])
            return 1
            """, Long.class);

    // StringRedisTemplate e' deliberato: Brain/Link si scambiano JSON grezzo.
    // Il precedente GenericJacksonRedisTemplate serializzava la stringa come
    // JSON string e poteva restituire una mappa invece del payload atteso.
    private final StringRedisTemplate redisTemplate;
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

    /**
     * Accoda solo se c'e' spazio, con check e push atomici.
     *
     * @return true se l'evento e' stato scritto, false se la coda e' al cap.
     */
    public boolean pushEventIfRoom(EventRequest event) {
        return pushEventIfRoom(event, MAX_QUEUE_SIZE);
    }

    public boolean pushEventIfRoom(EventRequest event, long maxQueueSize) {
        try {
            String eventJson = objectMapper.writeValueAsString(event);
            Long pushed = redisTemplate.execute(
                    PUSH_IF_ROOM,
                    List.of(EVENTS_QUEUE_KEY),
                    Long.toString(Math.max(1, maxQueueSize)),
                    eventJson);
            boolean written = pushed != null && pushed > 0;
            if (written) {
                log.debug("Event pushed to Redis queue '{}': agent={} process={} pid={} hostname={}",
                        EVENTS_QUEUE_KEY, event.getAgentId(),
                        event.getProcessName(), event.getPid(), event.getHostname());
            } else {
                log.warn("Event queue '{}' is full at {}; not pushed for agent={}",
                        EVENTS_QUEUE_KEY, maxQueueSize, event.getAgentId());
            }
            return written;
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
            // Audit L6: FIFO coerente col brain (RPUSH + LPOP). Prima era
            // rightPop -> LIFO: gli agenti serviti da link avrebbero eseguito
            // i comandi in ordine inverso (kill dopo quarantine, ecc.).
            String raw = redisTemplate.opsForList().leftPop(queueKey);
            if (raw == null) return null;
            // Brain 4.2 uses an envelope {id, command, attempts, claimed_at}.
            // Link still serves legacy syslog agents; unwrap the command and
            // expose the delivery id so a capable client can ack it later.
            try {
                JsonNode node = objectMapper.readTree(raw);
                if (node.isObject() && node.has("command") && node.get("command").isObject()) {
                    ObjectNode command = (ObjectNode) node.get("command");
                    if (node.hasNonNull("id")) command.put("delivery_id", node.get("id").asText());
                    if (node.has("attempts")) command.put("delivery_attempt", node.get("attempts").asInt());
                    return objectMapper.writeValueAsString(command);
                }
            } catch (Exception parseError) {
                log.warn("Command envelope parse failed for agent={}; returning raw payload", agentId);
            }
            return raw;
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
