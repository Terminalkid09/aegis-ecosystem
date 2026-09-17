package com.aegis.guard.hooks;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 * Executor YARA per Guard.
 *
 * Perché yara64.exe spawnato e non un binding JNI: i binding Java per YARA
 * sono poco mantenuti e fragili a ogni release; lo standard de-fatto del
 * settore è lo strumento ufficiale (yara64.exe rules.yar target -r) con
 * output riga "rule_name namespace hash path".
 *
 * Il binario vive nel workdir Guard (bin/yara64.exe), deployato
 * dall'installazione (install.ps1 / aegis.bat). Se manca, la scansione
 * fallisce in modo pulito e l'ack riporta la causa — mai un fallback
 * silenzioso che sembra andato.
 */
public final class YaraScanner {

    private static final Logger log = LoggerFactory.getLogger(YaraScanner.class);
    private static final Path YARA_BIN = Paths.get(System.getProperty("user.dir"), "bin", "yara64.exe");
    private static final long TIMEOUT_SECONDS = 120;

    public static final class Match {
        public final String rule;
        public final String namespace;
        public final String fileSha256;
        public final String filePath;

        public Match(String rule, String namespace, String fileSha256, String filePath) {
            this.rule = rule;
            this.namespace = namespace;
            this.fileSha256 = fileSha256;
            this.filePath = filePath;
        }
    }

    public static final class ScanResult {
        public final boolean ok;
        public final List<Match> matches;
        public final String error;

        private ScanResult(boolean ok, List<Match> matches, String error) {
            this.ok = ok;
            this.matches = matches;
            this.error = error;
        }

        static ScanResult ok(List<Match> m) { return new ScanResult(true, m, null); }
        static ScanResult failed(String e) { return new ScanResult(false, null, e); }
    }

    /** Esegue la scansione. Mai eccezioni all'esterno: risultato esplicito. */
    public ScanResult scan(String rulesYara, List<String> targets) {
        if (!Files.isRegularFile(YARA_BIN)) {
            return ScanResult.failed("yara64.exe non disponibile (atteso in " + YARA_BIN + ")");
        }
        if (rulesYara == null || rulesYara.isBlank()) {
            return ScanResult.failed("regole YARA vuote");
        }
        if (targets == null || targets.isEmpty()) {
            return ScanResult.failed("nessun target di scansione");
        }
        Path rulesFile = null;
        try {
            rulesFile = Files.createTempFile("aegis_yara_", ".yar");
            Files.writeString(rulesFile, rulesYara, StandardCharsets.UTF_8);

            List<String> cmd = new ArrayList<>();
            cmd.add(YARA_BIN.toString());
            cmd.add("-w"); // warning non fatali
            cmd.add(rulesFile.toAbsolutePath().toString());
            cmd.addAll(targets);

            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.redirectErrorStream(true);
            Process p = pb.start();

            List<String> lines = new ArrayList<>();
            try (InputStream in = p.getInputStream()) {
                String out = new String(in.readAllBytes(), StandardCharsets.UTF_8);
                for (String line : out.split("\\R")) {
                    if (!line.isBlank()) lines.add(line);
                }
            }
            boolean finished = p.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            if (!finished) {
                p.destroyForcibly();
                return ScanResult.failed("timeout YARA dopo " + TIMEOUT_SECONDS + "s");
            }
            // Convenzione yara CLI: 0 = match trovati, 1 = nessun match,
            // >=2 = errore reale (regola invalida, file mancante, ...).
            if (p.exitValue() == 0) {
                return ScanResult.ok(parse(lines));
            }
            if (p.exitValue() == 1) {
                return ScanResult.ok(List.of());
            }
            return ScanResult.failed("yara64 exit=" + p.exitValue() + ": "
                    + String.join(" | ", lines).substring(0, Math.min(300, String.join(" | ", lines).length())));
        } catch (Exception e) {
            log.warn("[YARA] scan fallita: {}", e.getMessage());
            return ScanResult.failed(e.getMessage());
        } finally {
            try {
                if (rulesFile != null) Files.deleteIfExists(rulesFile);
            } catch (Exception ignored) { }
        }
    }

    /** Output ufficiale: "rule_name namespace hash path" (hash/path opzionali). */
    static List<Match> parse(List<String> lines) {
        List<Match> out = new ArrayList<>();
        for (String line : lines) {
            String[] parts = line.trim().split("\\s+", 4);
            if (parts.length >= 4) {
                out.add(new Match(parts[0], parts[1], parts[2], parts[3]));
            } else if (parts.length == 3) {
                out.add(new Match(parts[0], parts[1], null, parts[2]));
            } else if (parts.length == 2) {
                out.add(new Match(parts[0], parts[1], null, null));
            }
            // righe non conformi: log/warning di yara, scartate
        }
        return out;
    }
}
