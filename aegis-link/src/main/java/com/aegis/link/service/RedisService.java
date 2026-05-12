package com.aegis.link.service;

import com.aegis.link.dto.EventRequest;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

/*
Servizio che gestisce il buffering degli eventi su Redis.

Pattern usato: Producer/Consumer con Redis List

aegis-link (Producer) → LPUSH aegis:events → Redis List                                                      ↓
aegis-brain (Consumer) ←────────────── BRPOP aegis:events
 *
Perché una List Redis invece di Pub/Sub?
- La List persiste i messaggi: se aegis-brain è temporaneamente offline,
        gli eventi non vengono persi.
- BRPOP è un'operazione bloccante e atomica: aegis-brain consuma un
        evento alla volta senza race conditions.
- Pub/Sub invece perde i messaggi se nessun subscriber è connesso.

La chiave Redis "aegis:events" usa il separatore ":" come convenzione
per creare namespace leggibili.
 */
@Service
@RequiredArgsConstructor    // Lombok: genera costruttore con tutti i campi final
public class RedisService {

    private static final Logger log = LoggerFactory.getLogger(RedisService.class);

    // Nome della coda Redis — deve corrispondere a quello usato da aegis-brain
    public static final String EVENTS_QUEUE_KEY = "aegis:events";

    // Iniettato da Spring grazie a @RequiredArgsConstructor
    private final RedisTemplate<String, String> redisTemplate;
    
    private final ObjectMapper objectMapper;

    /*
    Inserisce l'evento in testa alla lista Redis (LPUSH).
    aegis-brain leggerà con BRPOP dalla coda (FIFO).
    
    Serializza l'evento a JSON string prima di salvarlo in Redis
    per garantire la compatibilità con aegis-brain.
    
    @param event l'evento validato ricevuto dall'agente
    @throws RuntimeException se Redis non è raggiungibile
     */
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
            throw new RuntimeException("Redis unavailable — event could not be queued", e);
        }
    }

    /*
    Restituisce il numero di eventi attualmente in coda.
    Utile per monitoring e health check.
     */
    public long getQueueSize() {
        Long size = redisTemplate.opsForList().size(EVENTS_QUEUE_KEY);
        return size != null ? size : 0L;
    }

    /**
     * Preleva un comando dalla coda specifica dell'agente.
     * Pattern: RPOP (rimuove e restituisce l'ultimo elemento della lista).
     */
    public String popCommand(String agentId) {
        String queueKey = "aegis:commands:" + agentId;
        try {
            return redisTemplate.opsForList().rightPop(queueKey);
        } catch (Exception e) {
            log.error("Failed to pop command from Redis for agent={}: {}", agentId, e.getMessage());
            return null;
        }
    }
}
