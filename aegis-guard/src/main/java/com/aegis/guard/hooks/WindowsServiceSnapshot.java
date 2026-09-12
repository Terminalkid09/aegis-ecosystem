package com.aegis.guard.hooks;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Snapshot read-only di servizi e scheduled task (Fase 2, Tier-3 dichiarati).
 *
 * <p>Servizi: dump unico {@code reg query ...\Services /s} (ImagePath +
 * Start per servizio) — niente N+1 query, niente stato live (costoso).
 * Task: parse di {@code schtasks /query /fo csv} (best-effort, throttled dal
 * chiamante). WMI Event Subscriptions: SOLO documentate come Tier-2 futuro
 * (richiedono namespace root\subscription + admin; vedi OS_COMPATIBILITY).
 * Mai scritture, mai eccezioni.
 */
public final class WindowsServiceSnapshot {

    private static final Logger log = LoggerFactory.getLogger(WindowsServiceSnapshot.class);

    private WindowsServiceSnapshot() {}

    /** Servizio installato (configurazione, non stato live). */
    public record Service(String name, String imagePath, int startType) {}

    /** Scheduled task (da schtasks csv). */
    public record Task(String path, String nextRun, String status) {}

    public record Snapshot(List<Service> services, List<Task> tasks, String degraded) {}

    private static final String SERVICES_KEY =
            "HKLM\\SYSTEM\\CurrentControlSet\\Services";

    public static Snapshot collect() {
        List<Service> services = new ArrayList<>();
        String degraded = "";
        if (!System.getProperty("os.name", "").toLowerCase().contains("win")) {
            return new Snapshot(services, List.of(), "not-windows");
        }
        try {
            // Nomi in un colpo solo (veloce): il dump /s completo è troppo
            // pesante per lo startup (MB di output). Dettagli on-demand.
            String names = RegistryReader.queryKey(SERVICES_KEY);
            if (names.isBlank()) {
                return new Snapshot(services, List.of(), "services-unreadable");
            }
            for (String line : names.split("\\r?\\n")) {
                String t = line.trim();
                if (t.regionMatches(true, 0, "HKEY_", 0, 5)) {
                    String name = t.substring(t.lastIndexOf('\\') + 1);
                    if (!name.isEmpty() && !name.equalsIgnoreCase("Services")) {
                        services.add(new Service(name, "", -1));
                    }
                }
            }
        } catch (Exception e) {
            degraded = "registry-unreadable";
            log.debug("Services illeggibili: {}", e.getMessage());
        }
        return new Snapshot(List.copyOf(services), List.of(), degraded);
    }

    /**
     * Dettagli (ImagePath, Start, ...) solo per i nomi indicati, al massimo
     * {@code maxNames} query mirate. Per evidenza forense su nomi sospetti,
     * mai per l'intero albero.
     */
    public static Map<String, Map<String, String>> details(List<String> names, int maxNames) {
        Map<String, Map<String, String>> out = new java.util.LinkedHashMap<>();
        if (names == null || names.isEmpty() || maxNames <= 0) return out;
        if (!System.getProperty("os.name", "").toLowerCase().contains("win")) return out;
        int n = 0;
        for (String name : names) {
            if (n++ >= maxNames) break;
            if (name == null || name.isBlank() || name.contains("\\") || name.contains("/")) {
                continue; // niente path traversal verso altre chiavi
            }
            try {
                Map<String, String> vals = RegistryReader.parseValues(
                        RegistryReader.queryKey(SERVICES_KEY + "\\" + name));
                if (!vals.isEmpty()) out.put(name, vals);
            } catch (Exception e) {
                log.debug("Dettaglio servizio {} illeggibile: {}", name, e.getMessage());
            }
        }
        return out;
    }

    /** Parso puro di `schtasks /query /fo csv /v` (header variabile, virgolette). */
    public static List<Task> parseSchtasksCsv(String csv) {
        List<Task> out = new ArrayList<>();
        if (csv == null || csv.isBlank()) return out;
        String[] lines = csv.split("\\r?\\n");
        if (lines.length < 2) return out;
        Map<String, Integer> cols = headerIndex(lines[0]);
        Integer iTask = cols.get("taskname");
        Integer iNext = cols.get("next run time");
        Integer iStatus = cols.get("status");
        if (iTask == null) return out;
        int width = cols.size();
        for (int i = 1; i < lines.length; i++) {
            List<String> cells = splitCsvLine(lines[i]);
            if (cells.size() < width) continue; // riga malformata/tronca
            if (cells.size() <= iTask) continue;
            String path = unquote(cells.get(iTask));
            if (path.isEmpty()) continue;
            String next = (iNext != null && iNext < cells.size()) ? unquote(cells.get(iNext)) : "";
            String status = (iStatus != null && iStatus < cells.size()) ? unquote(cells.get(iStatus)) : "";
            out.add(new Task(path, next, status));
        }
        return out;
    }

    static Map<String, Integer> headerIndex(String header) {
        Map<String, Integer> cols = new LinkedHashMap<>();
        List<String> cells = splitCsvLine(header);
        for (int i = 0; i < cells.size(); i++) {
            cols.putIfAbsent(unquote(cells.get(i)).toLowerCase(), i);
        }
        return cols;
    }

    /** Split CSV con virgolette (doppi apici escaped ""), niente regex. */
    static List<String> splitCsvLine(String line) {
        List<String> cells = new ArrayList<>();
        StringBuilder cur = new StringBuilder();
        boolean inQuotes = false;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (c == '"') {
                if (inQuotes && i + 1 < line.length() && line.charAt(i + 1) == '"') {
                    cur.append('"');
                    i++;
                } else {
                    inQuotes = !inQuotes;
                }
            } else if (c == ',' && !inQuotes) {
                cells.add(cur.toString());
                cur.setLength(0);
            } else {
                cur.append(c);
            }
        }
        cells.add(cur.toString());
        return cells;
    }

    static String unquote(String s) {
        if (s == null) return "";
        s = s.trim();
        if (s.length() >= 2 && s.startsWith("\"") && s.endsWith("\"")) {
            s = s.substring(1, s.length() - 1).replace("\"\"", "\"");
        }
        return s.trim();
    }
}
