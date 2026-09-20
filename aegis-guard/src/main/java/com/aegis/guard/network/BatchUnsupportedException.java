package com.aegis.guard.network;

import java.io.IOException;

/**
 * Il brain non ha l'endpoint batch (versione vecchia): il chiamante deve
 * usare il fallback per-evento invece dello spool. Distinta da IOException
 * generica (errore transitorio → spool persistente). M1 Fase 2.
 */
public class BatchUnsupportedException extends IOException {
    public BatchUnsupportedException(String message) {
        super(message);
    }
}
