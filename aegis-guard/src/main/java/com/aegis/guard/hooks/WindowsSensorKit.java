package com.aegis.guard.hooks;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Helper puri del sensore Windows (M2 Fase 3): normalizzazione, parsing e
 * chiavi anti-PID-reuse. Tutto senza JNA né I/O — gira su qualunque OS in CI.
 *
 * <p>Regole:
 * <ul>
 *   <li>i path si confrontano normalizzati (separatore, case, prefissi
 *       estesi {@code \\?\}, virgolette), mai modificando l'originale;</li>
 *   <li>un PID da solo non identifica un processo: la chiave è
 *       {@code pid + start-time monotonico} (v2 {@code procStartNs});</li>
 *   <li>ogni parser fallisce soft (stringa vuota/lista vuota, mai eccezioni).</li>
 * </ul>
 */
public final class WindowsSensorKit {

    private WindowsSensorKit() {}

    /** Normalizza un path Windows per i confronti (match, whitelist, MITRE). */
    public static String normalizePath(String path) {
        if (path == null) return "";
        String p = path.trim();
        if (p.length() >= 2 && p.charAt(0) == '"' && p.charAt(p.length() - 1) == '"') {
            p = p.substring(1, p.length() - 1);
        }
        p = p.replace('/', '\\');
        for (String prefix : new String[]{"\\\\?\\", "\\??\\"}) {
            if (p.regionMatches(true, 0, prefix, 0, prefix.length())) {
                p = p.substring(prefix.length());
                break;
            }
        }
        while (p.contains("\\\\")) p = p.replace("\\\\", "\\");
        return p.toLowerCase(Locale.ROOT);
    }

    /** Normalizza una command line per i match (spazi collassati, case piegato). */
    public static String normalizeCmdline(String cmd) {
        if (cmd == null) return "";
        return cmd.trim().replaceAll("\\s+", " ").toLowerCase(Locale.ROOT);
    }

    /**
     * Chiave anti-PID-reuse: stesso PID con start diversi = processi diversi.
     * Senza start time (sorgente degradata) la chiave è il solo PID e il
     * chiamante deve marcarla come degradata.
     */
    public static String pidReuseKey(long pid, Long procStartNs) {
        if (procStartNs == null || procStartNs <= 0) return "pid:" + pid;
        return "pid:" + pid + "@" + procStartNs;
    }

    /** Estrae la command line dall'output di {@code wmic ... get commandline}. */
    public static String parseWmicOutput(String out) {
        if (out == null) return "";
        String t = out.trim();
        if (!t.toLowerCase(Locale.ROOT).contains("commandline")) return "";
        String[] lines = t.split("\\r?\\n");
        for (int i = 1; i < lines.length; i++) {
            String l = lines[i].trim();
            if (!l.isEmpty()) return l;
        }
        return "";
    }

    /** Parsa una riga di {@code netstat -ano} in {proto,local,remote,state,pid}. */
    public static Map<String, String> parseNetstatLine(String line) {
        Map<String, String> empty = new LinkedHashMap<>();
        if (line == null) return empty;
        String[] parts = line.trim().split("\\s+");
        if (parts.length < 5) return empty;
        if (parts[0].toLowerCase(Locale.ROOT).startsWith("proto")) return empty;
        long pid;
        try {
            pid = Long.parseLong(parts[parts.length - 1]);
        } catch (NumberFormatException e) {
            return empty;
        }
        if (pid <= 0) return empty;
        Map<String, String> conn = new LinkedHashMap<>();
        conn.put("proto", parts[0]);
        conn.put("local", parts[1]);
        conn.put("remote", parts[2]);
        conn.put("state", parts[3]);
        conn.put("pid", Long.toString(pid));
        return conn;
    }

    /** Filtra solo connessioni significative (niente LISTENING locali muti). */
    public static boolean isSignificantConnection(Map<String, String> conn) {
        if (conn == null || conn.isEmpty()) return false;
        String state = conn.getOrDefault("state", "");
        String remote = conn.getOrDefault("remote", "");
        if ("LISTENING".equalsIgnoreCase(state)) return false;
        return remote.contains(":");
    }

    /** Basename insensibile al case: {@code C:\x\CMD.EXE} → {@code cmd.exe}. */
    public static String baseName(String path) {
        String n = normalizePath(path);
        int i = Math.max(n.lastIndexOf('\\'), n.lastIndexOf('/'));
        return i >= 0 ? n.substring(i + 1) : n;
    }

    /** Paragona nomi processo al basename (evita match su path, ex FP word). */
    public static boolean procNameEquals(String actual, String wanted) {
        return baseName(actual).equals(baseName(wanted));
    }
}
