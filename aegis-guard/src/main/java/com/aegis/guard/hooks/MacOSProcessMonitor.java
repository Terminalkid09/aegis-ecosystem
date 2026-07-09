package com.aegis.guard.hooks;

import java.util.*;
import java.util.stream.Collectors;
import java.nio.file.Files;
import java.nio.file.Path;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.aegis.guard.models.SystemEvent;
import com.aegis.guard.network.AegisClient;
import com.aegis.guard.utils.Config;
import com.aegis.guard.utils.HashCalculator;
import com.aegis.guard.utils.SystemInfoCollector;
import com.sun.jna.Library;
import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.Pointer;

/**
Implementazione macOS di ProcessMonitor.
Usa libproc (sysctl) tramite JNA per enumerare i processi attivi.
PPID ottenuto via ps per compatibilità.

API chiave:
proc_listallpids()  → lista di tutti i PID attivi
proc_pidpath()      → path dell'eseguibile dato un PID
 */
public class MacOSProcessMonitor implements ProcessMonitor {

    private static final Logger log = LoggerFactory.getLogger(MacOSProcessMonitor.class);

    // JNA binding per libproc 

    interface LibProc extends Library {
        LibProc INSTANCE = Native.load("proc", LibProc.class);

        int proc_listallpids(Pointer buffer, int buffersize);
        int proc_pidpath(int pid, Pointer pidPathBuffer, int bufferSize);
    }

    private static final int PROC_PIDPATHINFO_MAXSIZE = 4096;

    private final AegisClient    client;
    private final HashCalculator hasher;
    private final String         agentId;
    private volatile boolean     running = false;
    private final Set<Long>      knownPids = new HashSet<>();

    private final String hostname;
    private final String ipAddress;

    private Map<Long, String> netstatCache = new HashMap<>();

    public MacOSProcessMonitor(AegisClient client, HashCalculator hasher, String agentId) {
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
        log.info("MacOSProcessMonitor started (interval {}ms)", Config.SCAN_INTERVAL_MS);

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
                log.error("Error during macOS monitoring", e);
            }
        }
        log.info("MacOSProcessMonitor stopped.");
    }

    @Override
    public void stopMonitoring() {
        running = false;
    }

    @Override
    public List<SystemEvent> scanProcesses() {
        List<SystemEvent> events = new ArrayList<>();
        LibProc libProc = LibProc.INSTANCE;

        int count = libProc.proc_listallpids(Pointer.NULL, 0);
        if (count <= 0) return events;

        Memory pidBuffer = new Memory((long) (count + 16) * Integer.BYTES);
        int actual = libProc.proc_listallpids(pidBuffer, (int) pidBuffer.size());
        if (actual <= 0) return events;

        // Get PPID map from ps command
        Map<Long, Long> ppidMap = getPpidMap();

        String currentUser = System.getProperty("user.name");

        for (int i = 0; i < actual; i++) {
            int pid = pidBuffer.getInt((long) i * Integer.BYTES);
            if (pid <= 0) continue;

            String path = resolveProcessPath(libProc, pid);
            String name = extractName(path, pid);
            long ppid = ppidMap.getOrDefault((long) pid, 0L);
            String parentName = ppid > 0 ? getProcessNameByPid(ppid) : "unknown";

            SystemEvent event = new SystemEvent(
                    agentId, pid, ppid, parentName, name,
                    path, currentUser, "macOS", "PROCESS_CREATED"
            );
            event.setHostname(hostname);
            event.setIpAddress(ipAddress);

            if (!path.isEmpty()) {
                event.setFileHash(hasher.calculateHash(path));
            }

            String conns = netstatCache.getOrDefault((long) pid, "[]");
            event.setNetworkConnections(conns);

            events.add(event);
        }

        return events;
    }

    // Parse lsof or netstat for macOS
    private Map<Long, String> parseNetstat() {
        Map<Long, List<Map<String, String>>> connMap = new HashMap<>();
        try {
            // macOS: netstat -an -p tcp with -v for PID
            ProcessBuilder pb = new ProcessBuilder("lsof", "-i", "-P", "-n", "-T");
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes());
            p.waitFor(10, java.util.concurrent.TimeUnit.SECONDS);

            for (String line : out.split("\\r?\\n")) {
                String[] parts = line.trim().split("\\s+");
                if (parts.length >= 9 && parts[0].equals("COMMAND") == false) {
                    try {
                        long pid = Long.parseLong(parts[1]);
                        if (pid <= 0) continue;

                        Map<String, String> conn = new LinkedHashMap<>();
                        conn.put("proto", parts[parts.length - 4]);
                        conn.put("local", parts[8]);
                        conn.put("remote", parts.length >= 10 ? parts[8] : "");
                        conn.put("state", parts.length >= 9 ? parts[9] : "UNKNOWN");
                        conn.put("process", parts[0]);

                        connMap.computeIfAbsent(pid, k -> new ArrayList<>()).add(conn);
                    } catch (NumberFormatException ignored) {}
                }
            }
        } catch (Exception e) {
            log.warn("Failed to parse macOS lsof: {}", e.getMessage());
        }

        Map<Long, String> result = new HashMap<>();
        com.google.gson.Gson gson = new com.google.gson.Gson();
        for (Map.Entry<Long, List<Map<String, String>>> e : connMap.entrySet()) {
            result.put(e.getKey(), gson.toJson(e.getValue()));
        }
        return result;
    }

    // Get pid → ppid map from ps command
    private Map<Long, Long> getPpidMap() {
        Map<Long, Long> map = new HashMap<>();
        try {
            ProcessBuilder pb = new ProcessBuilder("ps", "-eo", "pid,ppid,comm");
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes());
            p.waitFor(5, java.util.concurrent.TimeUnit.SECONDS);

            for (String line : out.split("\\r?\\n")) {
                line = line.trim();
                if (line.isEmpty() || line.startsWith("PID")) continue;
                String[] parts = line.split("\\s+");
                if (parts.length >= 3) {
                    try {
                        long pid = Long.parseLong(parts[0]);
                        long ppid = Long.parseLong(parts[1]);
                        map.put(pid, ppid);
                    } catch (NumberFormatException ignored) {}
                }
            }
        } catch (Exception e) {
            log.warn("Failed to get PPID map: {}", e.getMessage());
        }
        return map;
    }

    // Get process name by PID from /proc or ps
    private String getProcessNameByPid(long pid) {
        try {
            // Check /proc first (if available)
            Path procPath = Path.of("/proc", String.valueOf(pid), "comm");
            if (procPath.toFile().exists()) {
                return Files.readString(procPath).strip();
            }
        } catch (Exception ignored) {}

        // Fallback: re-query ps for this PID
        try {
            ProcessBuilder pb = new ProcessBuilder("ps", "-p", String.valueOf(pid), "-o", "comm=");
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes()).strip();
            p.waitFor(3, java.util.concurrent.TimeUnit.SECONDS);
            if (!out.isEmpty()) return out;
        } catch (Exception ignored) {}
        return "unknown";
    }

    //  Helpers 

    private String resolveProcessPath(LibProc libProc, int pid) {
        Memory pathBuf = new Memory(PROC_PIDPATHINFO_MAXSIZE);
        int ret = libProc.proc_pidpath(pid, pathBuf, PROC_PIDPATHINFO_MAXSIZE);
        if (ret <= 0) return "";
        return pathBuf.getString(0).trim();
    }

    private String extractName(String path, int pid) {
        if (path.isEmpty()) return "pid-" + pid;
        int slash = path.lastIndexOf('/');
        return slash >= 0 ? path.substring(slash + 1) : path;
    }
}
