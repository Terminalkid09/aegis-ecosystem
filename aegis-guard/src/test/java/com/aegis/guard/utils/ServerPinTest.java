package com.aegis.guard.utils;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class ServerPinTest {

    @Test
    void sameServerOk() {
        assertNull(ServerPin.check("https://aegis.local/api/v1", "https://aegis.local/api/v1"));
        assertNull(ServerPin.check("https://aegis.local/api/v1/", "https://aegis.local/api/v1"));
        assertNull(ServerPin.check("HTTPS://AEGIS.LOCAL/API/V1", "https://aegis.local/api/v1"));
    }

    @Test
    void legacyWithoutStoredPinsSilently() {
        assertNull(ServerPin.check(null, "https://aegis.local/api/v1"));
        assertNull(ServerPin.check("", "https://aegis.local/api/v1"));
    }

    @Test
    void changedServerRefused() {
        String err = ServerPin.check("https://aegis.local/api/v1", "https://evil.example/api/v1");
        assertNotNull(err);
        assertTrue(err.contains("re-enroll"));
    }

    @Test
    void missingCurrentRefused() {
        assertNotNull(ServerPin.check("https://aegis.local/api/v1", ""));
        assertNotNull(ServerPin.check("https://aegis.local/api/v1", null));
    }
}
