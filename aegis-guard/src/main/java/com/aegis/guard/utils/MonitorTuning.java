package com.aegis.guard.utils;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Throttling e parsing a costo minimo per i monitor user-mode.
 *
 * <p>Profilazione: prima di questa classe ogni ciclo di scan (default 1s)
 * rileggeva /proc/PID/status 3 volte per processo, scansionava /etc/passwd
 * per processo, ricalcolava lo SHA-256 di ogni binario e spawnava
 * ss/netstat. Su 300 processi = ~900 letture + 300 hash al secondo.
 * Ora: una lettura, UID in cache, hash solo sui processi NUOVI, netstat
 * al massimo ogni NETSTAT_INTERVAL_MS.
 */
public final class MonitorTuning {

    private MonitorTuning() {}

    /** Dati parsati in UN passaggio da /proc/PID/status. */
    public record ProcStatus(long ppid, int threads, String uid) {}

    /** Parsa le righe di status in un solo passaggio (niente 3 riletture). */
    public static ProcStatus parseStatusLines(List<String> lines) {
        long ppid = 0;
        int threads = 0;
        String uid = "";
        if (lines != null) {
            for (String line : lines) {
                if (line.startsWith("PPid:")) {
                    try { ppid = Long.parseLong(line.split("\\s+")[1]); }
                    catch (Exception ignored) {}
                } else if (line.startsWith("Threads:")) {
                    try { threads = Integer.parseInt(line.split("\\s+")[1]); }
                    catch (Exception ignored) {}
                } else if (line.startsWith("Uid:")) {
                    String[] parts = line.split("\\s+");
                    if (parts.length >= 2) uid = parts[1];
                }
            }
        }
        return new ProcStatus(ppid, threads, uid);
    }

    /**
     * Throttle per comandi costosi (ss/netstat): true se mai eseguito
     * (lastRefreshMs &lt; 0) o se è passato almeno intervalMs.
     */
    public static boolean shouldRefreshNetstat(long lastRefreshMs, long nowMs, long intervalMs) {
        if (lastRefreshMs < 0) return true;
        return nowMs - lastRefreshMs >= intervalMs;
    }

    /**
     * Start time da /proc/PID/stat (M3 Fase 4): con il PID forma la chiave
     * anti-reuse (v2 procStartNs). Il comm può contenere spazi/parens: si
     * cerca l'ULTIMA ')' e starttime è il 20° campo dopo (jiffies).
     * Ritorna vuoto su formato inatteso — mai eccezioni.
     */
    public static java.util.OptionalLong parseStatStarttime(String statContent) {
        if (statContent == null || statContent.isBlank()) return java.util.OptionalLong.empty();
        try {
            int close = statContent.lastIndexOf(')');
            if (close < 0) return java.util.OptionalLong.empty();
            String[] fields = statContent.substring(close + 1).trim().split("\\s+");
            if (fields.length < 20) return java.util.OptionalLong.empty();
            long ticks = Long.parseLong(fields[19]);
            if (ticks < 0) return java.util.OptionalLong.empty();
            return java.util.OptionalLong.of(ticks);
        } catch (Exception ignored) {
            return java.util.OptionalLong.empty();
        }
    }

    private static volatile long cachedUserHz = -1;

    /**
     * USER_HZ per convertire i jiffies in ns (quasi sempre 100 su x86 Linux).
     * Letto una volta via getconf, fallback 100 — mai eccezioni.
     */
    public static long userHz() {
        if (cachedUserHz > 0) return cachedUserHz;
        long hz = 100;
        try {
            Process p = new ProcessBuilder("getconf", "CLK_TCK")
                    .redirectErrorStream(true).start();
            String out = new String(p.getInputStream().readAllBytes()).trim();
            p.waitFor(2, java.util.concurrent.TimeUnit.SECONDS);
            long parsed = Long.parseLong(out.split("\\s+")[0]);
            if (parsed > 0 && parsed <= 10000) hz = parsed;
        } catch (Exception ignored) {
        }
        cachedUserHz = hz;
        return hz;
    }

    /** jiffies → ns monotonici dal boot (v2 procStartNs su Linux). */
    public static long starttimeToNs(long ticks) {
        return ticks * 1_000_000_000L / userHz();
    }

    /** Cache UID -> username: /etc/passwd si legge una volta sola. */    public static final class UidCache {
        private final Map<String, String> cache = new HashMap<>();
        private final java.util.function.Function<String, String> resolver;

        public UidCache(java.util.function.Function<String, String> resolver) {
            this.resolver = resolver;
        }

        public String usernameFor(String uid) {
            if (uid == null || uid.isEmpty()) return "unknown";
            return cache.computeIfAbsent(uid, resolver);
        }

        int size() {
            return cache.size();
        }
    }
}
