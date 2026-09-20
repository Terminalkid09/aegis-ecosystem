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

    // ── Audit F9: rollback, download interrotti, canonicalizzazione ──

    @Test
    void stageRejectsDowngrade(@TempDir Path tmp) throws Exception {
        Path pkg = tmp.resolve("agent.zip");
        Files.writeString(pkg, "fake-agent-bytes");
        String sha = UpdateManager.sha256File(pkg);
        assertThrows(SecurityException.class,
                () -> UpdateManager.stagePackage(pkg, sha, tmp, "2.0.0", "1.9.9"));
        assertFalse(Files.exists(pkg), "downgrade package must be deleted");
    }

    @Test
    void stageRejectsSameVersion(@TempDir Path tmp) throws Exception {
        Path pkg = tmp.resolve("agent.zip");
        Files.writeString(pkg, "fake-agent-bytes");
        String sha = UpdateManager.sha256File(pkg);
        assertThrows(SecurityException.class,
                () -> UpdateManager.stagePackage(pkg, sha, tmp, "1.5.0", "1.5.0"));
        assertFalse(Files.exists(pkg), "same-version package must be deleted");
    }

    @Test
    void stageAllowsUpgradeAndLatest(@TempDir Path tmp) throws Exception {
        for (String target : new String[]{"1.5.1", "latest", "LATEST"}) {
            Path pkg = tmp.resolve("agent-" + target.toLowerCase() + ".zip");
            Files.writeString(pkg, "fake-agent-bytes");
            String sha = UpdateManager.sha256File(pkg);
            Path staged = UpdateManager.stagePackage(pkg, sha, tmp, "1.5.0", target);
            assertTrue(Files.exists(staged));
        }
    }

    @Test
    void stageRejectsTruncatedDownload(@TempDir Path tmp) throws Exception {
        // Simula download interrotto: SHA calcolato sui byte completi,
        // file troncato prima dello stage.
        byte[] full = "fake-agent-bytes-complete-payload".getBytes(java.nio.charset.StandardCharsets.UTF_8);
        Path pkg = tmp.resolve("agent.zip");
        Files.write(pkg, full);
        String sha = UpdateManager.sha256File(pkg);
        Files.write(pkg, java.util.Arrays.copyOf(full, full.length / 2));
        assertThrows(SecurityException.class,
                () -> UpdateManager.stagePackage(pkg, sha, tmp));
        assertFalse(Files.exists(pkg), "truncated package must be deleted");
    }

    @Test
    void signatureCanonicalization() throws Exception {
        String sig = UpdateManager.hmacSign("abc123", "k");
        assertTrue(UpdateManager.verifySignature("abc123", "  " + sig.toUpperCase() + "  ", "k"));
        assertFalse(UpdateManager.verifySignature("abc123", "", "k"));
        assertFalse(UpdateManager.verifySignature("abc123", "zz", "k"));
    }

    // ── Audit P6: allowlist URL + state sigillato ──

    @Test
    void updateUrlAllowlist() {
        String brain = "https://aegis.local/api/v1";
        assertTrue(UpdateManager.isUpdateUrlAllowed(
                "https://aegis.local/api/v1/deploy/artifacts/guard-1.zip", brain));
        assertFalse(UpdateManager.isUpdateUrlAllowed(
                "https://evil.example/a.zip", brain));
        assertFalse(UpdateManager.isUpdateUrlAllowed(
                "https://aegis.local/api/v1/auth/login", brain));
        assertFalse(UpdateManager.isUpdateUrlAllowed(
                "http://aegis.local/api/v1/deploy/artifacts/guard-1.zip", brain));
        assertFalse(UpdateManager.isUpdateUrlAllowed("not-a-url", brain));
        assertFalse(UpdateManager.isUpdateUrlAllowed(null, brain));
        assertFalse(UpdateManager.isUpdateUrlAllowed(
                "https://aegis.local/api/v1/deploy/artifacts/guard-1.zip", null));
    }

    @Test
    void stagedStateSealRoundtrip(@TempDir Path tmp) throws Exception {
        UpdateManager.sealStagedState(tmp, "update.pending/agent.zip",
                "0".repeat(63) + "1", "device-secret-xyz");
        String[] parts = UpdateManager.verifyStagedState(tmp, "device-secret-xyz");
        assertEquals("update.pending/agent.zip", parts[0]);
        assertEquals("0".repeat(63) + "1", parts[1]);
    }

    @Test
    void stagedStateTamperRejected(@TempDir Path tmp) throws Exception {
        UpdateManager.sealStagedState(tmp, "update.pending/agent.zip", "a".repeat(64), "s3");
        // Manomissione staged path
        Path state = tmp.resolve(UpdateManager.STATE_FILE);
        String content = Files.readString(state).replace("agent.zip", "evil.zip");
        Files.writeString(state, content);
        assertThrows(SecurityException.class,
                () -> UpdateManager.verifyStagedState(tmp, "s3"));
        // Chiave sbagliata
        UpdateManager.sealStagedState(tmp, "update.pending/agent.zip", "a".repeat(64), "s3");
        assertThrows(SecurityException.class,
                () -> UpdateManager.verifyStagedState(tmp, "wrong"));
    }
}
