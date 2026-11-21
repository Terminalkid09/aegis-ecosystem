package com.aegis.link.controllers;

import com.aegis.link.dto.EventRequest;
import com.aegis.link.dto.EventResponse;
import com.aegis.link.service.CommandDeliveryService;
import com.aegis.link.service.EventSpoolService;
import com.aegis.link.service.RedisService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/*
Controller REST che espone gli endpoint di ingestion per aegis-guard.

Endpoint disponibili:

POST /api/v1/events
Riceve un evento di sistema da un agente, lo valida e lo mette in coda
su Redis per il processing di aegis-brain.
Header obbligatorio: X-Agent-Id (identificativo univoco dell'agente)
Body: JSON serializzato di EventRequest
Response: 202 Accepted + EventResponse

GET /api/v1/health
Health check applicativo — verifica che il controller sia raggiungibile
e restituisce la dimensione attuale della coda Redis.
Response: 200 OK + info sulla coda

Codici HTTP usati:
202 Accepted  → evento ricevuto e messo in coda (non ancora processato)
400 Bad Request → payload non valido (gestito da GlobalExceptionHandler)
500 Internal Server Error → Redis non raggiungibile
*/
@RestController
@RequestMapping("/api/v1")
@RequiredArgsConstructor
public class IngestionController {

    private static final Logger log = LoggerFactory.getLogger(IngestionController.class);

    private final RedisService redisService;
    private final EventSpoolService spoolService;
    private final CommandDeliveryService commandDeliveryService;


    /*
    Riceve un evento da aegis-guard e lo accoda su Redis.
    
    @Valid attiva la validazione di Bean Validation sulle annotazioni
    di EventRequest (@NotBlank, @Positive, @NotNull).
    Se la validazione fallisce, GlobalExceptionHandler intercetta
    il MethodArgumentNotValidException e restituisce 400.
    
    L'header X-Agent-Id è usato solo per il logging — in futuro
    potrà essere usato per autenticare gli agenti registrati.
     */
    @PostMapping("/events")
    public ResponseEntity<EventResponse> receiveEvent(
            @RequestHeader("X-Agent-Id") String agentIdHeader,
            @Valid @RequestBody EventRequest event) {

        log.debug("Event received: agent={} process={} pid={} os={}",
                event.getAgentId(), event.getProcessName(),
                event.getPid(), event.getOs());

        // Sicurezza: l'agentId nel body deve corrispondere all'header e, per agenti,
        // alla secret validata dal filtro.
        if (!agentIdHeader.equals(event.getAgentId())) {
            log.warn("AgentId mismatch: header='{}' body='{}'",
                    agentIdHeader, event.getAgentId());
            return ResponseEntity
                    .status(HttpStatus.BAD_REQUEST)
                    .body(EventResponse.error("X-Agent-Id header does not match agentId in body"));
        }

        if (!isAuthorizedForAgent(agentIdHeader)) {
            log.warn("Authenticated principal is not allowed to publish for agent={}", agentIdHeader);
            return ResponseEntity
                    .status(HttpStatus.FORBIDDEN)
                    .body(EventResponse.error("Authenticated principal does not match agent"));
        }

        // Audit: tetto coda anti-OOM Redis (consumer brain fermo -> niente
        // accumulo infinito). Check e push sono atomici; oltre il tetto
        // l'evento va nello spool durevole: il 202 significa che Link lo ha
        // persistito, non che Redis lo ha già.
        try {
            if (redisService.pushEventIfRoom(event, RedisService.MAX_QUEUE_SIZE)) {
                return ResponseEntity.status(HttpStatus.ACCEPTED).body(EventResponse.accepted());
            }
        } catch (RuntimeException redisError) {
            if (spoolService.spool(event)) {
                return ResponseEntity.status(HttpStatus.ACCEPTED).body(EventResponse.spooled());
            }
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                    .body(EventResponse.error("Redis unavailable and spool write failed"));
        }

        if (spoolService.spool(event)) {
            return ResponseEntity.status(HttpStatus.ACCEPTED).body(EventResponse.spooled());
        }
        log.warn("Queue full ({}) and spool failed, rejecting agent={}",
                RedisService.MAX_QUEUE_SIZE, agentIdHeader);
        return ResponseEntity
                .status(HttpStatus.TOO_MANY_REQUESTS)
                .header(HttpHeaders.RETRY_AFTER, "5")
                .body(EventResponse.error("Ingestion queue full and spool unavailable, retry later"));
    }

    /*
    Health check applicativo con info sulla coda Redis.
    Complementa il /actuator/health di Spring Boot.
     */
    @GetMapping("/health")
    public ResponseEntity<String> health() {
        long queueSize = redisService.getQueueSize();
        return ResponseEntity.ok(
                String.format("aegis-link OK | Redis queue 'aegis:events' size: %d", queueSize)
        );
    }

    /**
     * Endpoint per il polling dei comandi da parte dell'agente.
     */
    @GetMapping("/commands")
    public ResponseEntity<String> getCommands(
            @RequestHeader("X-Agent-Id") String agentId) {
        if (!isAuthorizedForAgent(agentId)) {
            log.warn("Authenticated principal is not allowed to read commands for agent={}", agentId);
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Authenticated principal does not match agent");
        }
        
        String command = commandDeliveryService.claim(agentId);
        
        if (command == null) {
            return ResponseEntity.noContent().build();
        }

        // Audit: niente contenuto comandi nei log info (solo metadati).
        log.debug("Command dispatched to agent={}", agentId);
        return ResponseEntity.ok(command);
    }

    /**
     * Ack del comando legacy. Accetta sia /api/v1/commands/ack sia il path
     * usato dagli agenti NodeTrace quando il loro heartbeat punta a Link:
     * /api/v1/telemetry/commands/ack. L'ack e' idempotente.
     */
    @PostMapping({"/commands/ack", "/telemetry/commands/ack"})
    public ResponseEntity<Map<String, Object>> ackCommand(
            @RequestHeader("X-Agent-Id") String agentId,
            @RequestBody Map<String, Object> body) {
        if (!isAuthorizedForAgent(agentId)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body(Map.of("status", "error", "message", "Authenticated principal does not match agent"));
        }
        Object rawId = body == null ? null : body.get("delivery_id");
        if (rawId == null) rawId = body == null ? null : body.get("deliveryId");
        String deliveryId = rawId == null ? "" : rawId.toString();
        if (deliveryId.isBlank()) {
            return ResponseEntity.badRequest()
                    .body(Map.of("status", "error", "message", "delivery_id is required"));
        }
        boolean removed = commandDeliveryService.ack(agentId, deliveryId);
        log.debug("Command ack agent={} delivery={} new={}", agentId, deliveryId, removed);
        return ResponseEntity.ok(Map.of(
                "status", "acked",
                "delivery_id", deliveryId,
                "duplicate", !removed));
    }

    private boolean isAuthorizedForAgent(String agentId) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || authentication.getPrincipal() == null) {
            return false;
        }

        String principal = authentication.getPrincipal().toString();
        return "aegis-admin".equals(principal) || principal.equals(agentId);
    }
}
