package com.aegis.guard.utils;

import java.util.UUID;

/*
Configurazione globale dell'agente
I valori possono essere sovrascritti tramite variabili d'ambiente
*/

public class Config {

    private Config() {} // Prevent instantiation

    // ID univoco di questo agente
    public static final String AGENT_ID = getEnv(
            "AEGIS_AGENT_ID", "agent-" + UUID.randomUUID().toString()
    );

    // URL di aegis-link dove inviare gli eventi
    public static final String GATEWAY_URL = getEnv(
            "AEGIS_GATEWAY_URL", "http://localhost:8080/api/v1/events"
    );

    // Intervallo in ms tra una scansione e l'altra
    public static final int SCAN_INTERVAL_MS = Integer.parseInt(
            getEnv("AEGIS_SCAN_INTERVAL_MS", "1000")
    );

    private static String getEnv(String key, String defaultValue) {
        String val = System.getenv(key);
        return (val != null && !val.isBlank()) ? val : defaultValue;
    }
}