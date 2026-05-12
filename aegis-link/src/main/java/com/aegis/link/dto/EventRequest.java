package com.aegis.link.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Positive;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

/*
DTO (Data Transfer Object) che rappresenta un evento ricevuto da aegis-guard.

Corrisponde 1:1 al SystemEvent serializzato dall'agente.
Le annotazioni di validazione garantiscono che i campi obbligatori siano presenti
prima che l'evento venga passato al RedisService.

Campi obbligatori:  agentId, pid, processName, os, eventType, timestamp
Campi opzionali:    processPath, user, fileHash, hostname, ipAddress
*/
@Data                   // Lombok: genera getter, setter, equals, hashCode, toString
@Builder                // Lombok: genera il pattern Builder (utile nei test)
@NoArgsConstructor      // Lombok: costruttore vuoto richiesto da Jackson per la deserializzazione
@AllArgsConstructor     // Lombok: costruttore con tutti i campi (usato dal Builder)
public class EventRequest {

    @NotBlank(message = "agentId is required")
    private String agentId;

    @Positive(message = "pid must be a positive number")
    private long pid;

    @NotBlank(message = "processName is required")
    private String processName;

    // Opzionale: può essere vuoto per processi di sistema protetti
    private String processPath;

    // Opzionale: può essere null se non determinabile
    private String user;

    @NotBlank(message = "os is required")
    private String os;

    // Opzionale: SHA-256 dell'eseguibile; assente se il path non è accessibile
    private String fileHash;

    @NotBlank(message = "eventType is required")
    private String eventType;

    @NotNull(message = "timestamp is required")
    private Instant timestamp;

    // Opzionale: informazioni di sistema per il dashboard
    private String hostname;

    private String ipAddress;
}
