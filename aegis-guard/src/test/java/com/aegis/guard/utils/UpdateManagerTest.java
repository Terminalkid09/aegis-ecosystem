package com.aegis.guard.utils;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import static org.junit.jupiter.api.Assertions.*;

import java.nio.file.Files;
import java.nio.file.Path;

class UpdateManagerTest {

    @Test
    void hmacRoundTrip() throws Exception {
        String sig = UpdateManager.hmacSign("abc123", "enroll-key-xyz");
        assertTrue(UpdateManager.verifySignature("abc123", sig, "enroll-key-xyz"));
    }

    @Test
    void wrongKeyFails() throws Exception {
        String sig = UpdateManager.hmacSign("abc123", "right-key");
        assertFalse(UpdateManager.verifySignature("abc123", sig, "wrong-key"));
    }

    @Test
    void tamperedShaFails() throws Exception {
        String sig = UpdateManager.hmacSign("abc123", "k");
        assertFalse(UpdateManager.verifySignature("abc124", sig, "k"));
    }

    @Test
    void nullInputsFailClosed() {
        assertFalse(UpdateManager.verifySignature(null, "x", "k"));
        assertFalse(UpdateManager.verifySignature("x", null, "k"));
        assertFalse(UpdateManager.verifySignature("x", "y", null));
        assertFalse(UpdateManager.verifySignature("x", "y", "  "));
    }

    @Test
    void versionCompare() {
        assertTrue(UpdateManager.isNewer("1.0.0", "1.0.1"));
        assertTrue(UpdateManager.isNewer("1.9.0", "1.10.0"));
        assertFalse(UpdateManager.isNewer("2.0.0", "1.9.9"));
        assertFalse(UpdateManager.isNewer("1.0.0", "1.0.0"));
        assertTrue(UpdateManager.isNewer("1.0.0", "latest"));
        assertTrue(UpdateManager.isNewer(null, "1.0.0"));
    }

    @Test
    void stageVerifiesSha(@TempDir Path tmp) throws Exception {
        Path pkg = tmp.resolve("agent.zip");
        Files.writeString(pkg, "fake-agent-bytes");
        String sha = UpdateManager.sha256File(pkg);
        Path staged = UpdateManager.stagePackage(pkg, sha, tmp);
        assertTrue(Files.exists(staged));
        assertFalse(Files.exists(pkg), "downloaded file must be moved, not copied");
    }

    @Test
    void stageRejectsMismatch(@TempDir Path tmp) throws Exception {
        Path pkg = tmp.resolve("agent.zip");
        Files.writeString(pkg, "fake-agent-bytes");
        assertThrows(SecurityException.class,
                () -> UpdateManager.stagePackage(pkg, "0".repeat(64), tmp));
        assertFalse(Files.exists(pkg), "tampered package must be deleted");
    }
}
