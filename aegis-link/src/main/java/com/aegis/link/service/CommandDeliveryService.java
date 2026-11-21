package com.aegis.link.service;

import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.UUID;

/**
 * Consegna at-least-once dei comandi legacy serviti da Link.
 *
 * <p>Il Brain continua a scrivere la coda {@code aegis:commands:<agent>}. Link
 * sposta ogni comando in una processing list e in uno sorted set con scadenza.
 * L'operazione e' un unico script Lua: non esiste la finestra "LPOP riuscito,
 * crash prima di registrare il comando". Se l'agente non invia l'ack entro la
 * visibility timeout, il reaper lo rimette in coda. Dopo N tentativi finisce
 * nella DLQ; non viene mai dichiarato riuscito senza ack.</p>
 *
 * <p>Questa e' una garanzia at-least-once, non exactly-once: un crash tra
 * l'esecuzione dell'azione e l'ack puo' produrre un secondo tentativo.</p>
 */
@Service
@RequiredArgsConstructor
public class CommandDeliveryService {

    private static final Logger log = LoggerFactory.getLogger(CommandDeliveryService.class);

    static final String QUEUE_PREFIX = "aegis:commands:";
    static final String PROCESSING_PREFIX = "aegis:commands:processing:";
    static final String DEADLINES_PREFIX = "aegis:commands:deadlines:";
    static final String DLQ_PREFIX = "aegis:commands:dlq:";
    static final String AGENTS_KEY = "aegis:commands:processing:agents";

    private final StringRedisTemplate redisTemplate;

    @Value("${aegis.link.commands.visibility-ms:60000}")
    private long visibilityMs;

    @Value("${aegis.link.commands.max-attempts:5}")
    private long maxAttempts;

    @Value("${aegis.link.commands.reaper-batch:100}")
    private long reaperBatch;

    /*
     * Claim atomico:
     * - LPOP dalla coda del Brain;
     * - se il payload e' una busta {id, command, attempts}, restituisce il solo
     *   comando con delivery_id/attempts e conserva la busta originale;
     * - se e' un comando legacy puro, aggiunge un delivery_id generato;
     * - registra il raw nella processing list e la scadenza nello zset.
     * Il client che non conosce delivery_id continua a funzionare; per quel
     * client la consegna resta at-most-once, ma Link non lo dichiara ackato.
     */
    private static final DefaultRedisScript<String> CLAIM = new DefaultRedisScript<>("""
            local raw = redis.call('LPOP', KEYS[1])
            if not raw then return nil end

            local id = ARGV[1]
            local attempt = 1
            local payload = raw
            local ok, decoded = pcall(cjson.decode, raw)
            if ok and type(decoded) == 'table' then
              if type(decoded['command']) == 'table' then
                if decoded['id'] ~= nil then id = tostring(decoded['id']) end
                attempt = tonumber(decoded['attempts'] or 1)
                decoded['command']['delivery_id'] = id
                decoded['command']['delivery_attempt'] = attempt
                payload = cjson.encode(decoded['command'])
              else
                if decoded['delivery_id'] ~= nil then id = tostring(decoded['delivery_id']) end
                decoded['delivery_id'] = id
                decoded['delivery_attempt'] = attempt
                payload = cjson.encode(decoded)
              end
            end

            redis.call('HSET', KEYS[2], id, raw)
            redis.call('ZADD', KEYS[3], tonumber(ARGV[2]) + tonumber(ARGV[3]), id)
            redis.call('SADD', KEYS[4], ARGV[4])
            return payload
            """, String.class);

    /* Ack idempotente: il primo ack rimuove, i successivi non falliscono. */
    private static final DefaultRedisScript<Long> ACK = new DefaultRedisScript<>("""
            local removed = redis.call('HDEL', KEYS[1], ARGV[1])
            redis.call('ZREM', KEYS[2], ARGV[1])
            return removed
            """, Long.class);

    /*
     * Reaper: rimette in coda i comandi scaduti e incrementa attempts.
     * Oltre max-attempts il comando va in DLQ. Il raw aggiornato conserva
     * l'id originale, cosi' un ack tardivo resta idempotente.
     */
    private static final DefaultRedisScript<Long> REQUEUE = new DefaultRedisScript<>("""
            local now = tonumber(ARGV[1])
            local expired = redis.call('ZRANGEBYSCORE', KEYS[2], '-inf', now, 'LIMIT', 0, tonumber(ARGV[2]))
            local requeued = 0
            for _, id in ipairs(expired) do
              local raw = redis.call('HGET', KEYS[1], id)
              if raw then
                local attempt = 1
                local ok, decoded = pcall(cjson.decode, raw)
                if ok and type(decoded) == 'table' then
                  attempt = tonumber(decoded['attempts'] or 1) + 1
                  decoded['attempts'] = attempt
                  decoded['claimed_at'] = now
                  raw = cjson.encode(decoded)
                end
                if attempt > tonumber(ARGV[4]) then
                  redis.call('LPUSH', KEYS[4], raw)
                else
                  redis.call('LPUSH', KEYS[3], raw)
                  requeued = requeued + 1
                end
              end
              redis.call('HDEL', KEYS[1], id)
              redis.call('ZREM', KEYS[2], id)
            end
            return requeued
            """, Long.class);

    /** Restituisce il payload da consegnare, oppure null se la coda e' vuota. */
    public String claim(String agentId) {
        String id = UUID.randomUUID().toString();
        long now = System.currentTimeMillis();
        String payload = redisTemplate.execute(
                CLAIM,
                List.of(queueKey(agentId), processingKey(agentId), deadlinesKey(agentId), AGENTS_KEY),
                id,
                Long.toString(now),
                Long.toString(visibilityMs),
                agentId);
        if (payload != null) {
            log.debug("Command claimed for agent={} delivery={} visibilityMs={}",
                    agentId, id, visibilityMs);
        }
        return payload;
    }

    /**
     * @return true se questo ack ha rimosso il comando, false se era gia'
     *         scaduto/ackato. Entrambi i casi sono idempotenti per il client.
     */
    public boolean ack(String agentId, String deliveryId) {
        if (deliveryId == null || deliveryId.isBlank()) return false;
        Long removed = redisTemplate.execute(
                ACK,
                List.of(processingKey(agentId), deadlinesKey(agentId)),
                deliveryId);
        return removed != null && removed > 0;
    }

    /** Eseguito periodicamente; pubblico per il test e per l'health check. */
    @Scheduled(fixedDelayString = "${aegis.link.commands.reaper-ms:5000}")
    public void requeueExpired() {
        long now = System.currentTimeMillis();
        long total = 0;
        var agents = redisTemplate.opsForSet().members(AGENTS_KEY);
        if (agents == null || agents.isEmpty()) return;
        for (String agentId : agents) {
            Long requeued = redisTemplate.execute(
                    REQUEUE,
                    List.of(processingKey(agentId), deadlinesKey(agentId), queueKey(agentId), dlqKey(agentId)),
                    Long.toString(now),
                    Long.toString(reaperBatch),
                    Long.toString(visibilityMs),
                    Long.toString(maxAttempts));
            if (requeued != null) total += requeued;
        }
        if (total > 0) {
            log.warn("Requeued {} expired command(s)", total);
        }
    }

    static String queueKey(String agentId) {
        return QUEUE_PREFIX + agentId;
    }

    static String processingKey(String agentId) {
        return PROCESSING_PREFIX + agentId;
    }

    static String deadlinesKey(String agentId) {
        return DEADLINES_PREFIX + agentId;
    }

    static String dlqKey(String agentId) {
        return DLQ_PREFIX + agentId;
    }
}
