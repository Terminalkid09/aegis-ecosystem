package com.aegis.guard.utils;

import java.util.UUID;

public class Config {

    private Config() {}

    public static final String AGENT_ID = getEnv(
            "AEGIS_AGENT_ID", "agent-gen-" + UUID.randomUUID().toString().substring(0, 8)
    );

    public static final String GATEWAY_URL = getEnv(
            "AEGIS_GATEWAY_URL", "http://localhost:8000/api/v1/telemetry/report"
    );

    public static final String BRAIN_URL = getEnv(
            "AEGIS_BRAIN_URL", "http://localhost:8000/api/v1"
    );

    public static final String ENROLL_KEY = getEnvOrThrow(
            "AEGIS_ENROLL_KEY", "Enrollment key must be set via AEGIS_ENROLL_KEY environment variable"
    );

    public static final int SCAN_INTERVAL_MS = Integer.parseInt(
            getEnv("AEGIS_SCAN_INTERVAL_MS", "1000")
    );

    public static final String SECRET_FILE = getEnv(
            "AEGIS_SECRET_FILE", "secret.json"
    );

    private static String getEnv(String key, String defaultValue) {
        String val = System.getenv(key);
        return (val != null && !val.isBlank()) ? val : defaultValue;
    }

    private static String getEnvOrThrow(String key, String message) {
        String val = System.getenv(key);
        if (val == null || val.isBlank()) {
            throw new RuntimeException(message);
        }
        return val;
    }
}
