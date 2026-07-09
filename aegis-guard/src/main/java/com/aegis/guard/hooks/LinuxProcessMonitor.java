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

        while (running) {
            try {
                netstatCache = parseNetstat();
                List<SystemEvent> current = scanProcesses();

                for (SystemEvent event : current) {
                    if (!knownPids.contains(event.getPid())) {
                        String conns = netstatCache.getOrDefault(event.getPid(), "[]");
                        event.setNetworkConnections(conns);

                        log.info("New process detected: {}", event);
                        client.sendEvent(event);
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

                long ppid = readPpid(pidDir);
                int threads = readThreadCount(pidDir);

                pidNameMap.put(pid, name);
                rawEntries.add(new ProcEntry(pid, ppid, name, threads));

            } catch (NumberFormatException ignored) {}
        }

        for (ProcEntry pe : rawEntries) {
            String parentName = pidNameMap.getOrDefault(pe.ppid, "unknown");
            String exePath = readExeSymlink(new File(PROC.toFile(), String.valueOf(pe.pid)));
            String user = readUser(new File(PROC.toFile(), String.valueOf(pe.pid)));

            SystemEvent event = new SystemEvent(
                    agentId, pe.pid, pe.ppid, parentName, pe.name,
                    exePath, user, "Linux", "PROCESS_CREATED"
            );
            event.setHostname(hostname);
            event.setIpAddress(ipAddress);
            event.setThreadCount(pe.threads);

            if (!exePath.isEmpty()) {
                event.setFileHash(hasher.calculateHash(exePath));
            }

            String conns = netstatCache.getOrDefault(pe.pid, "[]");
            event.setNetworkConnections(conns);

            events.add(event);
        }

        return events;
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

    private long readPpid(File pidDir) {
        try {
            List<String> lines = Files.readAllLines(pidDir.toPath().resolve("status"));
            for (String line : lines) {
                if (line.startsWith("PPid:")) {
                    return Long.parseLong(line.split("\\s+")[1]);
                }
            }
        } catch (IOException ignored) {}
        return 0;
    }

    private int readThreadCount(File pidDir) {
        try {
            List<String> lines = Files.readAllLines(pidDir.toPath().resolve("status"));
            for (String line : lines) {
                if (line.startsWith("Threads:")) {
                    return Integer.parseInt(line.split("\\s+")[1]);
                }
            }
        } catch (IOException ignored) {}
        return 0;
    }

    private String readExeSymlink(File pidDir) {
        try {
            return Files.readSymbolicLink(pidDir.toPath().resolve("exe")).toString();
        } catch (IOException e) {
            return "";
        }
    }

    private String readUser(File pidDir) {
        try {
            List<String> lines = Files.readAllLines(pidDir.toPath().resolve("status"));
            for (String line : lines) {
                if (line.startsWith("Uid:")) {
                    String[] parts = line.split("\\s+");
                    if (parts.length >= 2) {
                        return resolveUid(parts[1]);
                    }
                }
            }
        } catch (IOException ignored) {}
        return "unknown";
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

        ProcEntry(long pid, long ppid, String name, int threads) {
            this.pid = pid; this.ppid = ppid;
            this.name = name; this.threads = threads;
        }
    }
}
