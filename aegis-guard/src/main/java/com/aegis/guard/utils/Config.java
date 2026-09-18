package com.aegis.guard.utils;

import java.util.UUID;

public class Config {

    private Config() {}

    public static final String AGENT_ID = getEnv(
            "AEGIS_AGENT_ID", "agent-gen-" + UUID.randomUUID().toString().substring(0, 8)
    );

    public static final String GATEWAY_URL = getEnv(
            "AEGIS_GATEWAY_URL", "https://aegis.local/api/v1/telemetry/report"
    );

    public static final String BRAIN_URL = getEnv(
            "AEGIS_BRAIN_URL", "https://aegis.local/api/v1"
    );

    public static final String ENROLL_KEY = getEnvOrThrow(
            "AEGIS_ENROLL_KEY", "Enrollment key must be set via AEGIS_ENROLL_KEY environment variable"
    );

    public static final int SCAN_INTERVAL_MS = Integer.parseInt(
            getEnv("AEGIS_SCAN_INTERVAL_MS", "1000")
    );

    /** Comandi costosi (ss/netstat): al massimo ogni N ms, non ogni ciclo. */
    public static final int NETSTAT_INTERVAL_MS = Integer.parseInt(
            getEnv("AEGIS_NETSTAT_INTERVAL_MS", "5000")
    );

    public static final String SECRET_FILE = getEnv(
            "AEGIS_SECRET_FILE", "secret.json"
    );

    public static final String AGENT_VERSION = getEnv(
            "AEGIS_AGENT_VERSION", "4.0.0"
    );

    /** Spool persistente outbox (M1 Fase 2): dir locale per eventi non recapitati. */
    public static final String SPOOL_DIR = getEnv(
            "AEGIS_SPOOL_DIR", "spool"
    );

    /** Tetto spool su disco: oltre, la perdita è contabilizzata (mai invisibile). */
    public static final long SPOOL_MAX_BYTES = Long.parseLong(
            getEnv("AEGIS_SPOOL_MAX_MB", "50")
    ) * 1024 * 1024;

    /** Pubblica Ed25519 manifest (base64 raw 32B): se assente, solo HMAC. */
    public static final String MANIFEST_PUBKEY = getEnv(
            "AEGIS_MANIFEST_PUBKEY", ""
    );

    /** Directory identità device mTLS (device.p12). Default: workdir. */
    public static final String IDENTITY_DIR = getEnv(
            "AEGIS_IDENTITY_DIR", "."
    );

    /** CA server pinnata per TLS mutuo (PEM). Assente = niente contesto mTLS. */
    public static final String SERVER_CA_FILE = getEnv(
            "AEGIS_SERVER_CA", ""
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
