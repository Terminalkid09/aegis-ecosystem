package com.aegis.guard.hooks;

import java.util.*;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.aegis.guard.models.SystemEvent;
import com.aegis.guard.network.AegisClient;
import com.aegis.guard.utils.Config;
import com.aegis.guard.utils.HashCalculator;
import com.aegis.guard.utils.SystemInfoCollector;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.WinDef.DWORD;

/*
Implementazione Windows di ProcessMonitor.
Usa Toolhelp32 tramite JNA per enumerare i processi attivi.
Ad ogni ciclo rileva i processi NUOVI rispetto al ciclo precedente
e li invia come eventi PROCESS_CREATED ad aegis-link.
Include PPID, nome parent, thread count, e connessioni di rete.
*/
public class WindowsProcessMonitor implements ProcessMonitor {

    private static final Logger log = LoggerFactory.getLogger(WindowsProcessMonitor.class);

    private final AegisClient    client;
    private final HashCalculator hasher;
    private final String         agentId;
    private volatile boolean     running = false;

    // PID visti nell'ultimo ciclo — usati per rilevare nuovi processi.
    private final Set<Long> knownPids = new HashSet<>();
    
    private final String hostname;
    private final String ipAddress;

    // Cache netstat: mappa PID → JSON array di connessioni
    private Map<Long, String> netstatCache = new HashMap<>();

    public WindowsProcessMonitor(AegisClient client, HashCalculator hasher, String agentId) {
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
        log.info("WindowsProcessMonitor started (interval {}ms)", Config.SCAN_INTERVAL_MS);

        scanProcesses().forEach(e -> knownPids.add(e.getPid()));

        while (running) {
            try {
                // Refresh netstat cache every cycle
                netstatCache = parseNetstat();

                List<SystemEvent> current = scanProcesses();
                for (SystemEvent event : current) {
                    if (!knownPids.contains(event.getPid())) {
                        // Attach network connections for this PID
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
                log.error("Error during Windows monitoring", e);
            }
        }
        log.info("WindowsProcessMonitor stopped.");
    }

    @Override
    public void stopMonitoring() {
        running = false;
    }

    @Override
    public List<SystemEvent> scanProcesses() {
        List<SystemEvent> events = new ArrayList<>();
        WindowsKernel32 kernel32 = WindowsKernel32.INSTANCE;

        Pointer snapshot = kernel32.CreateToolhelp32Snapshot(
                WindowsKernel32.TH32CS_SNAPPROCESS, 0);

        if (snapshot == null || snapshot.equals(Pointer.createConstant(-1))) {
            log.error("CreateToolhelp32Snapshot failed");
            return events;
        }

        // First pass: build pid → name map for parent resolution
        Map<Long, String> pidNameMap = new HashMap<>();
        List<ProcessEntry> rawEntries = new ArrayList<>();

        try {
            WindowsKernel32.PROCESSENTRY32 entry = new WindowsKernel32.PROCESSENTRY32();
            entry.dwSize = entry.size();

            if (kernel32.Process32First(snapshot, entry)) {
                do {
                    long pid = (long) entry.th32ProcessID;
                    long ppid = (long) entry.th32ParentProcessID;
                    String name = Native.toString(entry.szExeFile);
                    int threads = entry.cntThreads;

                    pidNameMap.put(pid, name);
                    rawEntries.add(new ProcessEntry(pid, ppid, name, threads));

                } while (kernel32.Process32Next(snapshot, entry));
            }
        } finally {
            kernel32.CloseHandle(snapshot);
        }

        String currentUser = System.getProperty("user.name");

        for (ProcessEntry pe : rawEntries) {
            String parentName = pidNameMap.getOrDefault(pe.ppid, "unknown");

            SystemEvent event = new SystemEvent(
                    agentId, pe.pid, pe.ppid, parentName,
                    pe.name,
                    resolveProcessPath(pe.pid),
                    currentUser,
                    "Windows",
                    "PROCESS_CREATED"
            );
            event.setHostname(hostname);
            event.setIpAddress(ipAddress);
            event.setThreadCount(pe.threads);

            if (!event.getProcessPath().isEmpty()) {
                event.setFileHash(hasher.calculateHash(event.getProcessPath()));
            }

            // Attach cached netstat if available
            String conns = netstatCache.getOrDefault(pe.pid, "[]");
            event.setNetworkConnections(conns);

            events.add(event);
        }

        return events;
    }

    // Parse netstat -ano output into pid → JSON connections map
    private Map<Long, String> parseNetstat() {
        Map<Long, List<Map<String, String>>> connMap = new HashMap<>();
        try {
            ProcessBuilder pb = new ProcessBuilder("netstat", "-ano");
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes());
            p.waitFor(5, java.util.concurrent.TimeUnit.SECONDS);

            for (String line : out.split("\\r?\\n")) {
                line = line.trim();
                if (line.isEmpty()) continue;
                String[] parts = line.split("\\s+");
                // netstat -ano output: Proto LocalAddr RemoteAddr State PID
                if (parts.length >= 5) {
                    try {
                        long pid = Long.parseLong(parts[parts.length - 1]);
                        if (pid <= 0) continue;

                        Map<String, String> conn = new LinkedHashMap<>();
                        conn.put("proto", parts[0]);
                        conn.put("local", parts[1]);
                        conn.put("remote", parts[2]);
                        conn.put("state", parts.length >= 5 ? parts[3] : "UNKNOWN");

                        connMap.computeIfAbsent(pid, k -> new ArrayList<>()).add(conn);
                    } catch (NumberFormatException ignored) {}
                }
            }
        } catch (Exception e) {
            log.warn("Failed to parse netstat: {}", e.getMessage());
        }

        // Serialize to JSON
        Map<Long, String> result = new HashMap<>();
        com.google.gson.Gson gson = new com.google.gson.Gson();
        for (Map.Entry<Long, List<Map<String, String>>> e : connMap.entrySet()) {
            result.put(e.getKey(), gson.toJson(e.getValue()));
        }
        return result;
    }

    /*
    Tenta di risolvere il path dell'eseguibile tramite QueryFullProcessImageName.
    Se fallisce (es. processo di sistema protetto) restituisce stringa vuota.
    */
    private String resolveProcessPath(long pid) {
        WindowsKernel32 kernel32 = WindowsKernel32.INSTANCE;
        Pointer hProcess = kernel32.OpenProcess(
                WindowsKernel32.PROCESS_QUERY_LIMITED_INFORMATION,
                false,
                (int) pid
        );

        if (hProcess == null || hProcess.equals(Pointer.NULL)) {
            return "";
        }

        try {
            byte[] pathBuffer = new byte[1024];
            WindowsKernel32.IntByReference size = new WindowsKernel32.IntByReference();
            size.setValue(pathBuffer.length);

            if (kernel32.QueryFullProcessImageNameA(hProcess, 0, pathBuffer, size)) {
                return new String(pathBuffer, 0, size.getValue()).trim();
            }
        } finally {
            kernel32.CloseHandle(hProcess);
        }
        return "";
    }

    // Internal struct for parsed process data
    private static class ProcessEntry {
        final long pid;
        final long ppid;
        final String name;
        final int threads;

        ProcessEntry(long pid, long ppid, String name, int threads) {
            this.pid = pid; this.ppid = ppid;
            this.name = name; this.threads = threads;
        }
    }
}
