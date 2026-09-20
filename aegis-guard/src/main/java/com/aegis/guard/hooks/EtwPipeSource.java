package com.aegis.guard.hooks;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;

import com.aegis.guard.models.SystemEvent;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Sorgente ETW event-driven (M2 Fase 3): legge righe JSON del consumer
 * {@code aegis-etw.exe} (contratto unico v2) e le immette nella pipeline
 * Guard via {@link ExternalEventIngester}.
 *
 * <p>Feature flag: {@code AEGIS_ETW_ENABLED=true} + binario in
 * {@code AEGIS_ETW_PATH} (path ASSOLUTO: un collector risolto dal workdir
 * verrebbe eseguito da una directory scrivibile, quindi si rifiuta).
 * Binario assente, flag spento, non-Windows o errore qualunque → sorgente
 * DEGRADATA (nessun crash del servizio, il polling Toolhelp32 resta):
 * {@link #isAvailable()} resta falso e il monitor marca
 * {@code quality=degraded:etw-...}.
 *
 * <p>Nota operativa: il consumer ETW apre una sessione di trace e richiede
 * privilegi amministrativi. Senza, il collector stampa il motivo ed esce
 * subito; {@link #lastDiagnostic()} lo riporta (es. {@code StartTrace: 5
 * (serve admin)}) cosi'il degrado e' DICHIARATO invece di sembrare un guasto.
 *
 * <p>Fallback senza admin: se il binario non può aprire la sessione kernel
 * esce subito e qui si legge solo EOF → degradata, niente loop infiniti
 * (tetto {@code MAX_LINES} per ciclo di lettura file).
 */
public final class EtwPipeSource {

    private static final Logger log = LoggerFactory.getLogger(EtwPipeSource.class);

    static final long MAX_LINES_PER_READ = 5000;

    private final String agentId;
    private final String agentVersion;
    private final boolean enabled;
    private final Path binary;
    private final boolean allowUnsigned;
    private volatile boolean available = false;
    private volatile String degradedReason = "disabled";
    // Il probe viene eseguito piu' volte (monitor + startStream): l'avviso
    // sull'opt-in non firmato si stampa una volta per processo.
    private static final java.util.concurrent.atomic.AtomicBoolean UNSIGNED_WARNED =
            new java.util.concurrent.atomic.AtomicBoolean(false);
    /** Prima riga non-JSON emessa dal collector (= motivo del fallimento). */
    private volatile String lastDiagnostic = "";

    public EtwPipeSource(String agentId, String agentVersion) {
        this(agentId, agentVersion,
                Boolean.parseBoolean(System.getenv().getOrDefault("AEGIS_ETW_ENABLED", "false")),
                Paths.get(System.getenv().getOrDefault("AEGIS_ETW_PATH", "aegis-etw.exe")),
                Boolean.parseBoolean(System.getenv().getOrDefault("AEGIS_ETW_ALLOW_UNSIGNED", "false")));
    }

    EtwPipeSource(String agentId, String agentVersion, boolean enabled, Path binary) {
        this(agentId, agentVersion, enabled, binary, false);
    }

    EtwPipeSource(String agentId, String agentVersion, boolean enabled, Path binary,
                  boolean allowUnsigned) {
        this.agentId = agentId;
        this.agentVersion = agentVersion;
        this.enabled = enabled;
        this.binary = binary;
        this.allowUnsigned = allowUnsigned;
    }

    public boolean isAvailable() {
        return available;
    }

    public String degradedReason() {
        return degradedReason;
    }

    /**
     * Motivo riportato dal collector quando non riesce ad aprire la sessione
     * (es. {@code StartTrace: 5 (serve admin)}), oppure stringa vuota.
     * Il collector scrive diagnostica su stdout prima di uscire: senza questo
     * un ETW non attivo sarebbe indistinguibile da un binario rotto.
     */
    public String lastDiagnostic() {
        return lastDiagnostic;
    }

    /**
     * Probe non distruttiva: binario eseguibile? Su non-Windows sempre no.
     * Non lancia mai eccezioni.
     */
    public boolean probe() {
        if (!enabled) {
            degradedReason = "disabled";
            available = false;
            return false;
        }
        String os = System.getProperty("os.name", "").toLowerCase();
        if (!os.contains("win")) {
            degradedReason = "not-windows";
            available = false;
            return false;
        }
        if (binary == null) {
            degradedReason = "binary-missing";
            available = false;
            return false;
        }
        // Audit: niente esecuzione da path relativo (hijack via workdir/
        // AEGIS_ETW_PATH) — prima ancora dell'existence check.
        if (!binary.isAbsolute()) {
            degradedReason = "relative-path";
            available = false;
            return false;
        }
        if (!Files.isExecutable(binary)) {
            degradedReason = "binary-missing";
            available = false;
            return false;
        }
        try {
            AuthenticodeVerifier.Result sig = AuthenticodeVerifier.verify(binary.toString());
            if (!sig.signed()) {
                // Default: NON si esegue un helper non firmato (un binario
                // lasciato in un workdir scrivibile e' hijackabile). Il lab
                // locale puo' accettarlo esplicitamente con
                // AEGIS_ETW_ALLOW_UNSIGNED=true — prima non c'era modo di
                // attivare l'ETW senza un certificato Authenticode, quindi la
                // capacita' documentata restava spenta per chiunque non
                // firmasse il binario.
                if (allowUnsigned) {
                    if (UNSIGNED_WARNED.compareAndSet(false, true)) {
                        log.warn("ETW: binario non firmato accettato (AEGIS_ETW_ALLOW_UNSIGNED=true) "
                                + "— uso di laboratorio, non deployare cosi' su host di produzione: {}",
                                binary);
                    }
                } else {
                    degradedReason = "untrusted-binary";
                    available = false;
                    return false;
                }
            }
        } catch (Exception e) {
            degradedReason = "verify-error";
            available = false;
            return false;
        }
        degradedReason = "";
        available = true;
        return true;
    }

    /**
     * Gestisce una riga del collector: evento valido → consumer con provenance
     * ETW; riga non-JSON → diagnostica (il collector scrive su stdout il motivo
     * del fallimento, es. {@code StartTrace: 5 (serve admin)}) conservata per
     * spiegare il degrado. Package-private: e' la logica testata direttamente.
     */
    void handleLine(String line, Consumer<SystemEvent> out) {
        if (line == null || line.isBlank()) return;
        SystemEvent e = ExternalEventIngester.fromJsonLine(agentId, "Windows", agentVersion, line);
        if (e != null) {
            if (e.getProvenance() == null) e.setProvenance("etw");
            if (out != null) out.accept(e);
            return;
        }
        if (lastDiagnostic.isEmpty()) {
            lastDiagnostic = line.length() > 200 ? line.substring(0, 200) : line;
        }
    }

    /**
     * Legge un file JSONL già catturato (replay lab / test): ogni riga valida
     * va al consumer con provenance ETW. Ritorna gli eventi validi.
     */
    public List<SystemEvent> readFile(Path jsonl, Consumer<SystemEvent> out) {
        List<SystemEvent> events = new ArrayList<>();
        if (jsonl == null || !Files.isReadable(jsonl)) {
            degradedReason = "file-unreadable";
            available = false;
            return events;
        }
        try (BufferedReader br = Files.newBufferedReader(jsonl, StandardCharsets.UTF_8)) {
            String line;
            long n = 0;
            while ((line = br.readLine()) != null && n++ < MAX_LINES_PER_READ) {
                SystemEvent e = ExternalEventIngester.fromJsonLine(agentId, "Windows", agentVersion, line);
                if (e != null) {
                    if (e.getProvenance() == null) e.setProvenance("etw");
                    events.add(e);
                    if (out != null) out.accept(e);
                }
            }
            degradedReason = "";
            available = true;
        } catch (IOException e) {
            log.warn("Lettura ETW fallita ({}): degradata", e.getMessage());
            degradedReason = "read-error";
            available = false;
        }
        return events;
    }

    /**
     * Avvia il consumer come sottoprocesso e ne inoltra lo stdout riga per
     * riga. Ritorna subito se non disponibile. Il processo viene terminato
     * con {@code stop()} — mai crash se il binario manca.
     */
    public EtwStream startStream(Consumer<SystemEvent> out) {
        if (!probe()) return new EtwStream(null);
        try {
            Process p = new ProcessBuilder(binary.toString()).redirectErrorStream(true).start();
            Thread t = new Thread(() -> {
                try (BufferedReader br = new BufferedReader(
                        new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
                    String line;
                    while ((line = br.readLine()) != null) {
                        handleLine(line, out);
                    }
                } catch (Exception ex) {
                    log.warn("Stream ETW interrotto: {}", ex.getMessage());
                }
            }, "etw-stream");
            t.setDaemon(true);
            t.start();
            return new EtwStream(p);
        } catch (Exception e) {
            log.warn("Avvio ETW fallito ({}): degradata", e.getMessage());
            degradedReason = "spawn-failed";
            available = false;
            return new EtwStream(null);
        }
    }

    /** Handle chiudibile dello stream (null-object se mai avviato). */
    public static final class EtwStream implements AutoCloseable {
        private final Process process;

        EtwStream(Process process) {
            this.process = process;
        }

        public boolean isRunning() {
            return process != null && process.isAlive();
        }

        @Override
        public void close() {
            if (process != null) process.destroy();
        }
    }
}
