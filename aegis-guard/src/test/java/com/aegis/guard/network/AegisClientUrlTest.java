package com.aegis.guard.network;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class AegisClientUrlTest {

    @Test
    void derivesBatchFromStandardReportUrl() {
        assertEquals("http://127.0.0.1:8000/api/v1/telemetry/report/batch",
                AegisClient.deriveBatchUrl("http://127.0.0.1:8000/api/v1/telemetry/report"));
    }

    @Test
    void derivesBatchFromTlsReportUrl() {
        assertEquals("https://aegis.local/api/v1/telemetry/report/batch",
                AegisClient.deriveBatchUrl("https://aegis.local/api/v1/telemetry/report"));
    }

    @Test
    void derivesBatchWhenReportIsInTheMiddleOfThePath() {
        assertEquals("https://aegis.local/api/v1/telemetry/report/batch/extra",
                AegisClient.deriveBatchUrl("https://aegis.local/api/v1/telemetry/report/extra"));
    }

    @Test
    void legacyGatewayUrlIsLeftAloneAndVisiblyWrong() {
        // Caso reale: AEGIS_GATEWAY_URL rimasta dall'architettura precedente
        // (http://aegis-link:8080/api/v1/events). Il vecchio replace non
        // cambiava nulla e i batch finivano sul path del singolo evento in
        // silenzio: qui si verifica che non venga fabbricato un URL fasullo.
        String legacy = "http://aegis-link:8080/api/v1/events";
        assertEquals(legacy, AegisClient.deriveBatchUrl(legacy));
        assertFalse(AegisClient.deriveBatchUrl(legacy).contains("/batch"));
    }

    @Test
    void nullIsHandled() {
        assertNull(AegisClient.deriveBatchUrl(null));
    }
}
