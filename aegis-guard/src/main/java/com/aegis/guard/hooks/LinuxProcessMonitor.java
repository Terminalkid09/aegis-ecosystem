package com.aegis.guard.hooks;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.aegis.guard.models.SystemEvent;
import com.aegis.guard.network.AegisClient;
import com.aegis.guard.utils.Config;
import com.aegis.guard.utils.HashCalculator;
import com.aegis.guard.utils.SystemInfoCollector;

/*
Implementazione Linux di ProcessMonitor.
Legge il filesystem virtuale /proc per enumerare i processi attivi.

Struttura usata:
/proc/<pid>/comm   → nome del processo
/proc/<pid>/exe    → symlink all'eseguibile (path reale)
/proc/<pid>/status → UID, PPID, thread count
/proc/<pid>/maps   → regioni di memoria mappate (per rilevamento injection)
*/
public class LinuxProcessMonitor implements ProcessMonitor {

    private static final Logger log  = LoggerFactory.getLogger(LinuxProcessMonitor.class);
    private static final Path   PROC = Path.of("/proc");

    private final AegisClient    client;
    private final HashCalculator hasher;
    private final String         agentId;
    private volatile boolean     running = false;
    private final Set<Long>      knownPids = new HashSet<>();

    private final String hostname;
    private final String ipAddress;

    private Map<Long, String> netstatCache = new HashMap<>();
    private long lastNetstatRefreshMs = -1;
    private com.aegis.guard.network.EventOutbox outbox;
    private final com.aegis.guard.utils.MonitorTuning.UidCache uidCache =
            new com.aegis.guard.utils.MonitorTuning.UidCache(this::resolveUid);

    public LinuxProcessMonitor(AegisClient client, HashCalculator hasher, String agentId) {
        this.client  = client;
        this.hasher  = hasher;
        this.agentId = agentId;
        this.hostname = SystemInfoCollector.getHostname();
        this.ipAddress = SystemInfoCollector.getIpAddress();
    }

    // ProcessMonitor

    @Override
    public void startMonitoring() {
        running = true;
        log.info("LinuxProcessMonitor started (interval {}ms)", Config.SCAN_INTERVAL_MS);

        scanProcesses().forEach(e -> knownPids.add(e.getPid()));
        outbox = new com.aegis.guard.network.EventOutbox(client);
        outbox.start();

        while (running) {
            try {
                // ss costa un processo nuovo: al massimo ogni NETSTAT_INTERVAL_MS
                long now = System.currentTimeMillis();
                if (com.aegis.guard.utils.MonitorTuning.shouldRefreshNetstat(
                        lastNetstatRefreshMs, now, Config.NETSTAT_INTERVAL_MS)) {
                    netstatCache = parseNetstat();
                    lastNetstatRefreshMs = now;
                }
                List<SystemEvent> current = scanProcesses();

                for (SystemEvent event : current) {
                    if (!knownPids.contains(event.getPid())) {
                        // Arricchimento costoso SOLO sui processi nuovi:
                        // exe + SHA + user + connessioni (non su tutti ogni secondo)
                        enrichNewEvent(event);
                        String conns = netstatCache.getOrDefault(event.getPid(), "[]");
                        event.setNetworkConnections(conns);

                        log.info("New process detected: {}", event);
                        outbox.add(event);
                        knownPids.add(event.getPid());
                    }
                }

                Set<Long> currentPids = new HashSet<>();
                current.forEach(e -> currentPids.add(e.getPid()));
                knownPids.retainAll(currentPids);

                Thread.sleep(Config.SCAN_INTERVAL_MS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            } catch (Exception e) {
                log.error("Error during Linux monitoring", e);
            }
        }
        log.info("LinuxProcessMonitor stopped.");
    }

    @Override
    public void stopMonitoring() {
        running = false;
        if (outbox != null) outbox.stop();
    }

    @Override
    public List<SystemEvent> scanProcesses() {
        List<SystemEvent> events = new ArrayList<>();

        File[] procEntries = PROC.toFile().listFiles(
                f -> f.isDirectory() && f.getName().matches("\\d+")
        );
        if (procEntries == null) return events;

        // Build pid → name map for parent resolution
        Map<Long, String> pidNameMap = new HashMap<>();
        List<ProcEntry> rawEntries = new ArrayList<>();

        for (File pidDir : procEntries) {
            try {
                long pid = Long.parseLong(pidDir.getName());
                String name = readComm(pidDir);
                if (name.isEmpty()) continue;

                // UNA sola lettura di status per PID (ppid+threads+uid insieme)
                com.aegis.guard.utils.MonitorTuning.ProcStatus st = readStatusOnce(pidDir);

                pidNameMap.put(pid, name);
                rawEntries.add(new ProcEntry(pid, st.ppid(), name, st.threads(), st.uid()));

            } catch (NumberFormatException ignored) {}
        }

        for (ProcEntry pe : rawEntries) {
            String parentName = pidNameMap.getOrDefault(pe.ppid, "unknown");

            // Scan leggero: niente exe/hash/user qui (solo sui NUOVI in enrichNewEvent)
            SystemEvent event = new SystemEvent(
                    agentId, pe.pid, pe.ppid, parentName, pe.name,
                    "", uidCache.usernameFor(pe.uid), "Linux", "PROCESS_CREATED"
            );
            event.setHostname(hostname);
            event.setIpAddress(ipAddress);
            event.setThreadCount(pe.threads);

            String conns = netstatCache.getOrDefault(pe.pid, "[]");
            event.setNetworkConnections(conns);
            event.setProvenance("proc");

            events.add(event);
        }

        return events;
    }

    /** Arricchimento costoso riservato ai processi nuovi (exe + SHA-256 + cmdline). */
    void enrichNewEvent(SystemEvent event) {
        try {
            File pidDir = new File(PROC.toFile(), String.valueOf(event.getPid()));
            String exePath = readExeSymlink(pidDir);
            if (!exePath.isEmpty()) {
                event.setProcessPath(exePath);
                event.setFileHash(hasher.calculateHash(exePath));
            }

            // Read cmdline from /proc/<pid>/cmdline (NUL-delimited args)
            String cmd = readCmdline(pidDir);
            if (!cmd.isEmpty()) {
                event.setCommandLine(cmd);
            }

            // Start time anti-PID-reuse (v2 procStartNs, ns dal boot).
            try {
                String stat = Files.readString(pidDir.toPath().resolve("stat")).trim();
                com.aegis.guard.utils.MonitorTuning.parseStatStarttime(stat)
                        .ifPresent(t -> event.setProcStartNs(
                                com.aegis.guard.utils.MonitorTuning.starttimeToNs(t)));
            } catch (Exception ignored) {
            }

            // Evaluate Behavioral Heuristics
            evaluateHeuristics(event);

        } catch (Exception e) {
            log.debug("Enrich failed for PID {}: {}", event.getPid(), e.getMessage());
        }
    }

    private String readCmdline(File pidDir) {
        try {
            byte[] bytes = Files.readAllBytes(pidDir.toPath().resolve("cmdline"));
            // NUL-separated args — replace \0 with space
            return new String(bytes).replace('\0', ' ').trim();
        } catch (IOException e) {
            return "";
        }
    }

    private void evaluateHeuristics(SystemEvent event) {
        String procName = event.getProcessName().toLowerCase();
        String parentName = event.getParentProcessName() != null ? event.getParentProcessName().toLowerCase() : "";
        String cmd = event.getCommandLine() != null ? event.getCommandLine().toLowerCase() : "";

        // 1. Suspicious shell spawned from document viewer / browser
        if (procName.equals("sh") || procName.equals("bash") || procName.equals("python") || procName.equals("python3")) {
            if (parentName.equals("libreoffice") || parentName.equals("evince") || parentName.equals("okular")) {
                event.addBehavioralTag("OFFICE_SPAWNED_SHELL");
            }
        }

        // 2. Suspicious command-line arguments
        if (cmd.contains("base64 -d") || cmd.contains("base64 --decode") || cmd.contains("eval")) {
            event.addBehavioralTag("SUSPICIOUS_POWERSHELL_ARGS");
        }
        if (cmd.contains("curl") && (cmd.contains("| bash") || cmd.contains("| sh"))) {
            event.addBehavioralTag("HIDDEN_OR_BYPASS_EXECUTION");
        }

        // 3. Credential dumping
        if (procName.contains("mimikatz") || procName.contains("lazagne") || procName.contains("secretsdump")) {
            event.addBehavioralTag("CREDENTIAL_DUMPING_TOOL_DETECTED");
        }
    }

    // Parse ss -tupn output into pid → JSON connections map
    private Map<Long, String> parseNetstat() {
        Map<Long, List<Map<String, String>>> connMap = new HashMap<>();
        try {
            ProcessBuilder pb = new ProcessBuilder("ss", "-tupn");
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes());
            p.waitFor(5, java.util.concurrent.TimeUnit.SECONDS);

            for (String line : out.split("\\r?\\n")) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("State") || line.startsWith("Netid")) continue;

                String[] parts = line.split("\\s+");
                if (parts.length >= 5) {
                    // Extract PID from the last field: users:(("process",pid,fd))
                    String peerField = parts[parts.length - 1];
                    java.util.regex.Matcher m = java.util.regex.Pattern.compile("pid=(\\d+)").matcher(peerField);
                    if (m.find()) {
                        long pid = Long.parseLong(m.group(1));
                        Map<String, String> conn = new LinkedHashMap<>();
                        conn.put("proto", parts[0]);
                        conn.put("local", parts[3]);
                        conn.put("remote", parts[4]);
                        conn.put("state", parts[1]);

                        connMap.computeIfAbsent(pid, k -> new ArrayList<>()).add(conn);
                    }
                }
            }
        } catch (Exception e) {
            log.warn("Failed to parse ss: {}", e.getMessage());
        }

        Map<Long, String> result = new HashMap<>();
        com.google.gson.Gson gson = new com.google.gson.Gson();
        for (Map.Entry<Long, List<Map<String, String>>> e : connMap.entrySet()) {
            result.put(e.getKey(), gson.toJson(e.getValue()));
        }
        return result;
    }

    //  Helpers

    private String readComm(File pidDir) {
        try {
            return Files.readString(pidDir.toPath().resolve("comm")).strip();
        } catch (IOException e) {
            return "";
        }
    }

    /** Una sola lettura di status: ppid + threads + uid in un passaggio. */
    private com.aegis.guard.utils.MonitorTuning.ProcStatus readStatusOnce(File pidDir) {
        try {
            List<String> lines = Files.readAllLines(pidDir.toPath().resolve("status"));
            return com.aegis.guard.utils.MonitorTuning.parseStatusLines(lines);
        } catch (IOException ignored) {
            return new com.aegis.guard.utils.MonitorTuning.ProcStatus(0, 0, "");
        }
    }

    private String readExeSymlink(File pidDir) {
        try {
            return Files.readSymbolicLink(pidDir.toPath().resolve("exe")).toString();
        } catch (IOException e) {
            return "";
        }
    }

    private String resolveUid(String uid) {
        try {
            List<String> lines = Files.readAllLines(Path.of("/etc/passwd"));
            for (String line : lines) {
                String[] parts = line.split(":");
                if (parts.length >= 3 && parts[2].equals(uid)) {
                    return parts[0];
                }
            }
        } catch (IOException ignored) {}
        return "uid:" + uid;
    }

    private static class ProcEntry {
        final long pid;
        final long ppid;
        final String name;
        final int threads;
        final String uid;

        ProcEntry(long pid, long ppid, String name, int threads, String uid) {
            this.pid = pid; this.ppid = ppid;
            this.name = name; this.threads = threads; this.uid = uid;
        }
    }
}
