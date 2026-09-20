package com.aegis.guard.hooks;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Snapshot read-only delle persistenze Windows più abusate (M2 Fase 3):
 * chiavi Run di HKCU/HKLM e cartelle Startup utente/comune.
 *
 * <p>Lettura via {@code reg.exe} ({@link RegistryReader}): {@code
 * java.util.prefs} su Windows è radicato in {@code ...\JavaSoft\Prefs} e
 * non vede le chiavi reali. Sola LETTURA (mai scritture: niente rimozioni
 * qui, quelle restano ai comandi SOAR auditati). Ogni accesso fallisce
 * soft: su non-Windows o senza permessi ritorna lista vuota con motivo in
 * {@link Snapshot#degraded}. Pensato per snapshot all'avvio + evidenza
 * forense, NON per polling.
 */
public final class WindowsPersistenceSnapshot {

    private static final Logger log = LoggerFactory.getLogger(WindowsPersistenceSnapshot.class);

    private WindowsPersistenceSnapshot() {}

    /** Voce di persistenza osservata (mai rimossa da qui). */
    public record Item(String location, String name, String value) {}

    /** Snapshot + motivo degrado (vuoto = completo). */
    public record Snapshot(List<Item> items, String degraded) {}

    private static final String HKCU_RUN = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    private static final String HKCU_RUNONCE =
            "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce";
    private static final String HKLM_RUN = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    private static final String HKLM_RUNONCE =
            "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce";

    public static Snapshot collect() {
        List<Item> items = new ArrayList<>();
        String degraded = "";
        if (!System.getProperty("os.name", "").toLowerCase().contains("win")) {
            return new Snapshot(items, "not-windows");
        }
        readRunKey(HKCU_RUN, "HKCU\\Run", items);
        readRunKey(HKCU_RUNONCE, "HKCU\\RunOnce", items);
        readRunKey(HKLM_RUN, "HKLM\\Run", items);
        readRunKey(HKLM_RUNONCE, "HKLM\\RunOnce", items);
        if (RegistryReader.queryKey(HKCU_RUN).isBlank()
                && RegistryReader.queryKey(HKLM_RUN).isBlank()) {
            // reg.exe assente o illeggibile (chiavi vuote legittime restano vuote
            // ma almeno l'header chiave viene stampato quando reg funziona).
            degraded = "registry-unreadable";
            log.debug("Run keys illeggibili (reg.exe assente o permessi)");
        }
        try {
            listDir(startupDir(true), "Startup\\User", items);
            listDir(startupDir(false), "Startup\\Common", items);
        } catch (Exception e) {
            if (degraded.isEmpty()) degraded = "startup-unreadable";
            log.debug("Startup illeggibili: {}", e.getMessage());
        }
        return new Snapshot(List.copyOf(items), degraded);
    }

    /** Legge una Run key via reg.exe. Mai throw. */
    static void readRunKey(String fullKey, String label, List<Item> out) {
        try {
            Map<String, String> values =
                    RegistryReader.parseValues(RegistryReader.queryKey(fullKey));
            for (Map.Entry<String, String> e : values.entrySet()) {
                if (e.getKey().equals("@default")) continue;
                out.add(new Item(label, e.getKey(), e.getValue()));
            }
        } catch (Exception e) {
            log.debug("Chiave {} illeggibile: {}", label, e.getMessage());
        }
    }

    static void listDir(File dir, String label, List<Item> out) {
        if (dir == null) return;
        File[] files;
        try {
            files = dir.listFiles();
        } catch (Exception e) {
            return;
        }
        if (files == null) return;
        for (File f : files) {
            if (f.isFile()) out.add(new Item(label, f.getName(), f.getAbsolutePath()));
        }
    }

    static File startupDir(boolean user) {
        String base = user ? System.getenv("APPDATA")
                : System.getenv("PROGRAMDATA");
        if (base == null || base.isBlank()) return null;
        return new File(base + File.separator + "Microsoft\\Windows\\Start Menu\\Programs\\Startup");
    }
}
