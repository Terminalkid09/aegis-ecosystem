package com.aegis.link.dto;

import lombok.AllArgsConstructor;
import lombok.Data;

/*
DTO di risposta inviato ad aegis-guard dopo la ricezione di un evento.

Struttura semplice: status + messaggio opzionale.
Esempi:
    { "status": "accepted", "message": "Event queued successfully" }
    { "status": "error",    "message": "processName is required"   }
*/
@Data
@AllArgsConstructor
public class EventResponse {

    // "accepted" | "error"
    private String status;

    // Dettaglio leggibile del risultato
    private String message;

    // Factory methods per convenienza

    public static EventResponse accepted() {
        return new EventResponse("accepted", "Event queued successfully");
    }

    public static EventResponse error(String message) {
        return new EventResponse("error", message);
    }
}
