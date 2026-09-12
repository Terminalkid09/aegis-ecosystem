package com.aegis.guard.utils;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.util.HexFormat;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * Staged OTA update — verifica prima di toccare nulla.
 *
 * <p>Protocollo (condiviso col brain, {@code app/api/v1/deploy.py}):
 * <ol>
 *   <li>brain invia UPDATE_AGENT {url, sha256, signature} dove
 *       signature = HMAC_SHA256(AGENT_ENROLL_KEY, sha256).</li>
 *   <li>l'agente scarica in {@code update.pending/}, verifica HMAC con la
 *       propria enroll key, poi verifica SHA-256 del file.</li>
 *   <li>solo se entrambe passano: mette in stage + scrive {@code update.state}.</li>
 * </ol>
 * L'apply avviene al restart del servizio (il jar in esecuzione è lockato
 * su Windows — sostituirlo live corromperebbe l'agente). Fail-closed:
 * qualunque verifica fallita = niente stage, ack failed al SOC.
 */
public final class UpdateManager {

    private UpdateManager() {}

    public static final String PENDING_DIR = "update.pending";
    public static final String STATE_FILE = "update.state";

    /** HMAC-SHA256 esadecimale di {@code sha256} con la enroll key. */
    public static String hmacSign(String sha256, String enrollKey) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(enrollKey.getBytes(java.nio.charset.StandardCharsets.UTF_8), "HmacSHA256"));
        byte[] out = mac.doFinal(sha256.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        return HexFormat.of().formatHex(out);
    }

    /** Confronto a tempo costante (anti-timing). */
    public static boolean verifySignature(String sha256, String signature, String enrollKey) {
        if (sha256 == null || signature == null || enrollKey == null || enrollKey.isBlank()) return false;
        try {
            String expected = hmacSign(sha256.trim(), enrollKey);
            return MessageDigest.isEqual(
                    expected.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                    signature.trim().toLowerCase().getBytes(java.nio.charset.StandardCharsets.UTF_8));
        } catch (Exception e) {
            return false;
        }
    }

    /** SHA-256 esadecimale di un file. */
    public static String sha256File(Path file) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] data = Files.readAllBytes(file);
        return HexFormat.of().formatHex(md.digest(data));
    }

    /** true se {@code target} è più nuovo di {@code current} ("latest" = sempre). */
    public static boolean isNewer(String current, String target) {
        if (target == null || target.isBlank() || target.trim().equalsIgnoreCase("latest")) return true;
        if (current == null || current.isBlank()) return true;
        return compareVersions(current, target) < 0;
    }

    private static int[] normalize(String v) {
        String[] ps = v.trim().replaceFirst("^[vV]", "").split("\\.");
        int[] out = new int[ps.length];
        for (int i = 0; i < ps.length; i++) {
            try { out[i] = Integer.parseInt(ps[i].replaceAll("[^0-9].*$", "")); }
            catch (NumberFormatException e) { out[i] = 0; }
        }
        return out;
    }

    /** Confronto versioni: -1 se a&lt;b, 0 se uguali, 1 se a&gt;b. */
    static int compareVersions(String a, String b) {
        int[] na = normalize(a == null ? "" : a);
        int[] nb = normalize(b == null ? "" : b);
        int n = Math.max(na.length, nb.length);
        for (int i = 0; i < n; i++) {
            int av = i < na.length ? na[i] : 0;
            int bv = i < nb.length ? nb[i] : 0;
            if (av != bv) return Integer.compare(av, bv);
        }
        return 0;
    }

    /**
     * Mette in stage un pacchetto già scaricato: riverifica lo SHA e lo sposta
     * in {@code baseDir/update.pending/} + scrive {@code baseDir/update.state}.
     *
     * @return path dello staged file
     * @throws SecurityException se lo SHA non corrisponde (fail-closed)
     */
    public static Path stagePackage(Path downloaded, String expectedSha256, Path baseDir) throws Exception {
        String actual = sha256File(downloaded);
        if (!MessageDigest.isEqual(actual.getBytes(java.nio.charset.StandardCharsets.UTF_8),
                expectedSha256.trim().toLowerCase().getBytes(java.nio.charset.StandardCharsets.UTF_8))) {
            try { Files.deleteIfExists(downloaded); } catch (Exception ignored) {}
            throw new SecurityException("SHA-256 mismatch: expected=" + expectedSha256 + " actual=" + actual);
        }
        Path dir = baseDir.resolve(PENDING_DIR);
        Files.createDirectories(dir);
        Path staged = dir.resolve(downloaded.getFileName().toString());
        Files.move(downloaded, staged, StandardCopyOption.REPLACE_EXISTING);
        Files.writeString(baseDir.resolve(STATE_FILE),
                "staged=" + staged + "\nsha256=" + actual + "\nstatus=pending-restart\n");
        return staged;
    }

    /** Variante workdir-corrente (uso produzione). */
    public static Path stagePackage(Path downloaded, String expectedSha256) throws Exception {
        return stagePackage(downloaded, expectedSha256, Paths.get(""));
    }
}
