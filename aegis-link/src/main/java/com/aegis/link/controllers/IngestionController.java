package com.aegis.link.controllers;

import com.aegis.link.dto.EventRequest;
import com.aegis.link.dto.EventResponse;
import com.aegis.link.service.RedisService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

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
            @RequestHeader(value = "X-Agent-Id", required = false) String agentIdHeader,
            @Valid @RequestBody EventRequest event) {

        log.info("Event received: agent={} process={} pid={} os={}",
                event.getAgentId(), event.getProcessName(),
                event.getPid(), event.getOs());

        // Sicurezza: l'agentId nel body deve corrispondere all'header
        if (agentIdHeader != null && !agentIdHeader.equals(event.getAgentId())) {
            log.warn("AgentId mismatch: header='{}' body='{}'",
                    agentIdHeader, event.getAgentId());
            return ResponseEntity
                    .status(HttpStatus.BAD_REQUEST)
                    .body(EventResponse.error("X-Agent-Id header does not match agentId in body"));
        }

        redisService.pushEvent(event);

        // 202 Accepted: l'evento è stato ricevuto e messo in coda,
        // ma non ancora processato da aegis-brain
        return ResponseEntity
                .status(HttpStatus.ACCEPTED)
                .body(EventResponse.accepted());
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
        
        String command = redisService.popCommand(agentId);
        
        if (command == null) {
            return ResponseEntity.noContent().build();
        }
        
        log.info("Command dispatched to agent={}: {}", agentId, command);
        return ResponseEntity.ok(command);
    }
}
