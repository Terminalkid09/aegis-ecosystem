package com.aegis.guard.network;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermission;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * Spool persistente cifrato per eventi non recapitati (M1 Fase 2).
 *
 * <p>Quando il server è irraggiungibile l'outbox salva qui i batch come
 * righe JSON cifrate (AES-256-GCM, una riga per evento) invece di perderli
 * in memoria: sopravvive al reboot dell'endpoint. La chiave deriva dal
 * device secret dell'agente ({@link #deriveKey}) quindi lo spool è leggibile
 * solo su questo endpoint e solo con le credenziali correnti.
 *
 * <p>Anti-tamper: GCM rifiuta righe modificate (contate come corrotte e
 * scartate, mai crash); se NESSUNA riga si decifra si presume rotazione del
 * secret e il file viene quarantinato ({@code spool.jsonl.bad-<ts>}) invece
 * di cancellato. Limite di spazio: oltre {@code maxBytes} i salvataggi
 * falliscono e il chiamante contabilizza la perdita (mai invisibile).
 *
 * <p>Classe pura (niente rete): ogni riga è JSON già serializzato dal
 * chiamante, qui solo cifratura e file. Thread-safe via synchronized.
 */
public final class FileSpool {

    static final String FILE_NAME = "spool.jsonl";
    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_TAG_BITS = 128;
    private static final int IV_BYTES = 12;

    /** Risultato di {@link #load}: righe consumate + diagnostica. */
    public static final class LoadResult {
        public final List<String> lines;
        public final int corrupt;
        public final boolean keyMismatch;

        LoadResult(List<String> lines, int corrupt, boolean keyMismatch) {
            this.lines = lines;
            this.corrupt = corrupt;
            this.keyMismatch = keyMismatch;
        }
    }

    private final Path file;
    private final byte[] key;
    private final long maxBytes;
    private final SecureRandom random = new SecureRandom();

    public FileSpool(Path dir, byte[] key) throws IOException {
        this(dir, key, 50L * 1024 * 1024);
    }

    FileSpool(Path dir, byte[] key, long maxBytes) throws IOException {
        if (key == null || key.length != 32) {
            throw new IllegalArgumentException("spool key must be 32 bytes (AES-256)");
        }
        Files.createDirectories(dir);
        bestEffortPrivatePerms(dir);
        this.file = dir.resolve(FILE_NAME);
        if (!Files.exists(file)) {
            Files.createFile(file);
            bestEffortPrivatePerms(file);
        }
        this.key = Arrays.copyOf(key, 32);
        this.maxBytes = maxBytes;
    }

    /**
     * Deriva la chiave spool dal device secret: nessun nuovo segreto da
     * distribuire, rotazione automatica col re-enroll (lo spool vecchio va
     * in quarantena invece di decifrarsi con la chiave sbagliata).
     */
    public static byte[] deriveKey(String agentSecret) {
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            sha.update("aegis-outbox-v1|".getBytes(StandardCharsets.UTF_8));
            sha.update(agentSecret.getBytes(StandardCharsets.UTF_8));
            return sha.digest();
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    public synchronized boolean hasData() {
        try {
            return Files.size(file) > 0;
        } catch (IOException e) {
            return false;
        }
    }

    public synchronized long pendingBytes() {
        try {
            return Files.size(file);
        } catch (IOException e) {
            return -1;
        }
    }

    /** Accoda righe cifrate. Lancia IOException se pieno o disco pieno. */
    public synchronized void save(List<String> jsonLines) throws IOException {
        if (jsonLines == null || jsonLines.isEmpty()) return;
        if (Files.size(file) >= maxBytes) {
            throw new IOException("spool full (" + maxBytes + " bytes cap)");
        }
        List<String> enc = new ArrayList<>(jsonLines.size());
        for (String line : jsonLines) {
            enc.add(encrypt(line));
        }
        Files.write(file, enc, StandardCharsets.UTF_8,
                StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        try (var ch = java.nio.channels.FileChannel.open(file, StandardOpenOption.WRITE)) {
            ch.force(true);
        }
    }

    /**
     * Legge fino a maxEvents eventi, rimuovendo le righe consumate.
     * Righe corrotte: scartate e contate. Chiave errata (zero successi su
     * file non vuoto): file in quarantena, niente cancellazioni.
     */
    public synchronized LoadResult load(int maxEvents) throws IOException {
        List<String> raw = Files.readAllLines(file, StandardCharsets.UTF_8);
        List<String> rawNonBlank = new ArrayList<>();
        for (String l : raw) {
            if (l != null && !l.isBlank()) rawNonBlank.add(l);
        }
        if (rawNonBlank.isEmpty()) {
            return new LoadResult(new ArrayList<>(), 0, false);
        }
        List<String> ok = new ArrayList<>();
        int corrupt = 0;
        for (String l : rawNonBlank) {
            try {
                ok.add(decrypt(l));
            } catch (Exception e) {
                corrupt++;
            }
        }
        if (ok.isEmpty()) {
            Path bad = file.resolveSibling(FILE_NAME + ".bad-" + System.currentTimeMillis());
            Files.move(file, bad);
            Files.createFile(file);
            bestEffortPrivatePerms(file);
            return new LoadResult(new ArrayList<>(), corrupt, true);
        }
        List<String> consumed = new ArrayList<>(ok.subList(0, Math.min(maxEvents, ok.size())));
        List<String> remainder = new ArrayList<>(ok.subList(consumed.size(), ok.size()));
        List<String> reEnc = new ArrayList<>(remainder.size());
        for (String line : remainder) {
            reEnc.add(encrypt(line));
        }
        Files.write(file, reEnc, StandardCharsets.UTF_8,
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        return new LoadResult(consumed, corrupt, false);
    }

    private String encrypt(String plain) throws IOException {
        try {
            byte[] iv = new byte[IV_BYTES];
            random.nextBytes(iv);
            Cipher c = Cipher.getInstance(TRANSFORMATION);
            c.init(Cipher.ENCRYPT_MODE,
                    new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(GCM_TAG_BITS, iv));
            byte[] ct = c.doFinal(plain.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(iv)
                    + "." + Base64.getEncoder().encodeToString(ct);
        } catch (Exception e) {
            throw new IOException("spool encrypt failed: " + e.getMessage(), e);
        }
    }

    private String decrypt(String line) throws IOException {
        try {
            int dot = line.indexOf('.');
            if (dot <= 0) throw new IOException("bad spool line format");
            byte[] iv = Base64.getDecoder().decode(line.substring(0, dot));
            byte[] ct = Base64.getDecoder().decode(line.substring(dot + 1));
            Cipher c = Cipher.getInstance(TRANSFORMATION);
            c.init(Cipher.DECRYPT_MODE,
                    new SecretKeySpec(key, "AES"),
                    new GCMParameterSpec(GCM_TAG_BITS, iv));
            return new String(c.doFinal(ct), StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new IOException("spool decrypt failed: " + e.getMessage(), e);
        }
    }

    private static void bestEffortPrivatePerms(Path p) {
        try {
            Set<PosixFilePermission> perms = EnumSet.of(
                    PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE,
                    PosixFilePermission.OWNER_EXECUTE);
            if (Files.isDirectory(p)) {
                Files.setPosixFilePermissions(p, perms);
            } else {
                Files.setPosixFilePermissions(p, EnumSet.of(
                        PosixFilePermission.OWNER_READ,
                        PosixFilePermission.OWNER_WRITE));
            }
        } catch (Exception ignored) {
            // Windows/non-POSIX: permessi gestiti dalle ACL di default.
        }
    }
}
