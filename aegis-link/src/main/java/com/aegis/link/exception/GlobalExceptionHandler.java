package com.aegis.link.exception;

import com.aegis.link.dto.EventResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.stream.Collectors;

/*
Gestore globale delle eccezioni per tutti i controller REST.

@RestControllerAdvice intercetta le eccezioni non gestite nei controller
e le trasforma in risposte HTTP strutturate (JSON) invece del default
HTML di Spring Boot, che sarebbe inutilizzabile da un agente.

Eccezioni gestite:

MethodArgumentNotValidException → 400 Bad Request
Scattata quando @Valid fallisce su un @RequestBody.
Raccoglie tutti i messaggi di errore di validazione in una stringa
leggibile e la restituisce nel body.
Esempio: "processName is required; pid must be a positive number"

RuntimeException → 500 Internal Server Error
Cattura errori imprevisti (es. Redis non raggiungibile).
Logga il dettaglio dell'errore ma restituisce solo un messaggio generico al client per evitare information leakage.
 *
Exception (catch-all) → 500 Internal Server Error
Safety net per qualsiasi altra eccezione non gestita.
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    /*
     * Gestisce gli errori di validazione Bean Validation (@Valid).
     * Raccoglie tutti i field error in un'unica stringa separata da "; ".
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<EventResponse> handleValidationErrors(
            MethodArgumentNotValidException ex) {

        String errors = ex.getBindingResult()
                .getFieldErrors()
                .stream()
                .map(fe -> fe.getField() + ": " + fe.getDefaultMessage())
                .collect(Collectors.joining("; "));

        log.warn("Validation failed for incoming event: {}", errors);

        return ResponseEntity
                .status(HttpStatus.BAD_REQUEST)
                .body(EventResponse.error("Validation failed: " + errors));
    }

    /*
     * Gestisce errori di runtime (es. Redis non raggiungibile).
     * Returns generic message to avoid information leakage.
     */
    @ExceptionHandler(RuntimeException.class)
    public ResponseEntity<EventResponse> handleRuntimeException(RuntimeException ex) {
        log.error("Runtime error processing event: {}", ex.getMessage(), ex);
        return ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(EventResponse.error("Internal server error"));
    }

    /*
Safety net — cattura qualsiasi eccezione non gestita sopra.
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<EventResponse> handleGenericException(Exception ex) {
        log.error("Unexpected error: {}", ex.getMessage(), ex);
        return ResponseEntity
                .status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(EventResponse.error("An unexpected error occurred"));
    }
}
