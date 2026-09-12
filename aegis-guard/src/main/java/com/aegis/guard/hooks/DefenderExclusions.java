package com.aegis.guard.hooks;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Lettura read-only delle esclusioni e degli stati di Windows Defender
 * (Fase 2, indicatori di tampering/disable).
 *
 * <p>Sorgenti (tutte best-effort, serve spesso admin):
 * <ul>
 *   <li>{@code HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\{Paths,
 *       Extensions, Processes}} — esclusioni configurate;</li>
 *   <li>{@code ...\Windows Defender\Real-Time Protection},
 *       {@code DisableAntiSpyware}, {@code DisableRealtimeMonitoring} —
 *       flag di disabilitazione (forte indicatore).</li>
 * </ul>
 * Mai scritture. Assenza permessi → {@code degraded} esplicito, mai crash.
 */
public final class DefenderExclusions {

    private static final Logger log = LoggerFactory.getLogger(DefenderExclusions.class);

    private DefenderExclusions() {}

    public record Snapshot(Map<String, List<String>> exclusions,
                           Map<String, String> tamperFlags,
                           String degraded) {}

    private static final String BASE = "SOFTWARE\\Microsoft\\Windows Defender";
    private static final String[] EXCLUSION_KINDS = {"Paths", "Extensions", "Processes"};

    public static Snapshot collect() {
        Map<String, List<String>> exclusions = new LinkedHashMap<>();
        Map<String, String> flags = new LinkedHashMap<>();
        if (!System.getProperty("os.name", "").toLowerCase().contains("win")) {
            return new Snapshot(exclusions, flags, "not-windows");
        }
        String degraded = "";
        try {
            for (String kind : EXCLUSION_KINDS) {
                List<String> values = readValueNames(BASE + "\\Exclusions\\" + kind);
                if (!values.isEmpty()) exclusions.put(kind, values);
            }
            readFlag(BASE, "DisableAntiSpyware", flags);
            readFlag(BASE + "\\Real-Time Protection", "DisableRealtimeMonitoring", flags);
            readFlag(BASE + "\\Real-Time Protection", "DisableBehaviorMonitoring", flags);
        } catch (Exception e) {
            degraded = "registry-unreadable";
            log.debug("Defender illeggibile: {}", e.getMessage());
        }
        if (exclusions.isEmpty() && flags.isEmpty() && degraded.isEmpty()) {
            degraded = "no-data-or-no-permission";
        }
        return new Snapshot(exclusions, flags, degraded);
    }

    /** Nomi valore di una chiave via reg.exe. Mai throw. */
    static List<String> readValueNames(String fullKey) {
        List<String> out = new ArrayList<>();
        try {
            Map<String, String> values =
                    RegistryReader.parseValues(RegistryReader.queryKey(fullKey));
            for (String name : values.keySet()) {
                if (!name.equals("@default")) out.add(name);
            }
        } catch (Exception e) {
            log.debug("Chiave {} illeggibile: {}", fullKey, e.getMessage());
        }
        return out;
    }

    static void readFlag(String fullKey, String value, Map<String, String> out) {
        readFlag(fullKey, value, value, out);
    }

    static void readFlag(String fullKey, String value, String label,
            Map<String, String> out) {
        try {
            Map<String, String> values =
                    RegistryReader.parseValues(RegistryReader.queryKey(fullKey));
            String raw = values.get(value);
            if (raw != null) out.put(label, raw);
        } catch (Exception e) {
            log.debug("Flag {} illeggibile: {}", label, e.getMessage());
        }
    }

    /** True se Defender risulta disabilitato o l'agente è escluso (da verificare). */
    public static boolean looksDisabled(Snapshot snap) {
        if (snap == null) return false;
        for (String v : snap.tamperFlags().values()) {
            if ("1".equals(v.trim())) return true;
        }
        return false;
    }
}
