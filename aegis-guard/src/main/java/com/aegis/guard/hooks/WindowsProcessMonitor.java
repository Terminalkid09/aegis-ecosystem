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
    private com.aegis.guard.network.EventOutbox outbox;

    // Copertura reale (M2 Fase 3): Tier 1 ETW se disponibile, altrimenti
    // polling Toolhelp32 dichiarato come fallback.
    private volatile String coverageProvenance = "toolhelp";
    private volatile String coverageQuality = "full";

    private final String hostname;
    private final String ipAddress;

    // Cache netstat: mappa PID → JSON array di connessioni
    private Map<Long, String> netstatCache = new HashMap<>();
    private long lastNetstatRefreshMs = -1;

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
        outbox = new com.aegis.guard.network.EventOutbox(client);
        outbox.start();

        // Copertura reale: probe ETW (mai crash) + snapshot persistenze (read-only).
        try {
            EtwPipeSource etw = new EtwPipeSource(agentId, Config.AGENT_VERSION);
            if (etw.probe()) {
                coverageProvenance = "etw";
                coverageQuality = "full";
                log.info("ETW disponibile: telemetria event-driven");
            } else {
                coverageProvenance = "toolhelp";
                coverageQuality = "degraded:etw-" + etw.degradedReason();
                log.info("ETW non disponibile ({}): polling Toolhelp32 come fallback dichiarato",
                        etw.degradedReason());
            }
        } catch (Exception e) {
            coverageQuality = "degraded:etw-probe-failed";
            log.warn("Probe ETW fallita: polling come fallback ({})", e.getMessage());
        }
        try {
            WindowsPersistenceSnapshot.Snapshot snap = WindowsPersistenceSnapshot.collect();
            log.info("Persistenze osservate (read-only): {} voci{}",
                    snap.items().size(),
                    snap.degraded().isEmpty() ? "" : " [degraded:" + snap.degraded() + "]");
        } catch (Exception e) {
            log.debug("Snapshot persistenze fallito: {}", e.getMessage());
        }
        try {
            WindowsServiceSnapshot.Snapshot svc = WindowsServiceSnapshot.collect();
            log.info("Servizi installati (read-only): {}{}",
                    svc.services().size(),
                    svc.degraded().isEmpty() ? "" : " [degraded:" + svc.degraded() + "]");
        } catch (Exception e) {
            log.debug("Snapshot servizi fallito: {}", e.getMessage());
        }
        try {
            DefenderExclusions.Snapshot def = DefenderExclusions.collect();
            if (DefenderExclusions.looksDisabled(def)) {
                log.warn("Defender risulta DISABILITATO o con esclusioni: flags={} exclusions={}",
                        def.tamperFlags(), def.exclusions().keySet());
            } else {
                log.info("Defender: {} tipi esclusione{}",
                        def.exclusions().size(),
                        def.degraded().isEmpty() ? "" : " [degraded:" + def.degraded() + "]");
            }
        } catch (Exception e) {
            log.debug("Snapshot Defender fallito: {}", e.getMessage());
        }

        while (running) {
            try {
                // netstat spawna un processo: al massimo ogni NETSTAT_INTERVAL_MS
                long now = System.currentTimeMillis();
                if (com.aegis.guard.utils.MonitorTuning.shouldRefreshNetstat(
                        lastNetstatRefreshMs, now, Config.NETSTAT_INTERVAL_MS)) {
                    netstatCache = parseNetstat();
                    lastNetstatRefreshMs = now;
                }

                List<SystemEvent> current = scanProcesses();
                for (SystemEvent event : current) {
                    if (!knownPids.contains(event.getPid())) {
                        // Arricchimento costoso SOLO sui nuovi: path + hash
                        // (in scanProcesses() per non rompere il contratto)
                        enrichNewEvent(event);
                        // Chiave anti-PID-reuse (v2 procStartNs) + copertura.
                        try {
                            ProcessStartTime.creationFileTime(event.getPid())
                                    .ifPresent(event::setProcStartNs);
                        } catch (Exception ignored) {
                        }
                        event.setProvenance(coverageProvenance);
                        event.setQuality(coverageQuality);
                        // Attach network connections for this PID
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
                log.error("Error during Windows monitoring", e);
            }
        }
        log.info("WindowsProcessMonitor stopped.");
    }

    @Override
    public void stopMonitoring() {
        running = false;
        if (outbox != null) outbox.stop();
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

            // Scan leggero: path + hash si calcolano solo sui NUOVI
            // (enrichNewEvent) — non su tutti i processi ogni secondo.
            SystemEvent event = new SystemEvent(
                    agentId, pe.pid, pe.ppid, parentName,
                    pe.name,
                    "",
                    currentUser,
                    "Windows",
                    "PROCESS_CREATED"
            );
            event.setHostname(hostname);
            event.setIpAddress(ipAddress);
            event.setThreadCount(pe.threads);
            event.setProvenance(coverageProvenance);

            // Attach cached netstat if available
            String conns = netstatCache.getOrDefault(pe.pid, "[]");
            event.setNetworkConnections(conns);

            events.add(event);
        }

        return events;
    }

    /** Arricchimento costoso riservato ai processi nuovi (path + SHA-256 + Command Line). */
    void enrichNewEvent(SystemEvent event) {
        try {
            String path = resolveProcessPath(event.getPid());
            if (path != null && !path.isEmpty()) {
                event.setProcessPath(path);
                event.setFileHash(hasher.calculateHash(path));
                // Firma Authenticode (best-effort, cache interna): alimenta
                // detection firmate/falsi-positivi e prevalenza publisher.
                try {
                    AuthenticodeVerifier.Result sig = AuthenticodeVerifier.verify(path);
                    if (sig.signed()) {
                        event.setSignature("authenticode-trusted");
                        AuthenticodeVerifier.publisher(path).ifPresent(event::setPublisher);
                    } else if (!sig.error().isEmpty()
                            && !sig.error().equals("not-found")
                            && !sig.error().equals("not-windows")) {
                        event.setSignature("unsigned:" + sig.error());
                    }
                } catch (Exception ignored) {
                }
            }

            // Extract Command Line via WMIC
            String cmd = getCommandLine(event.getPid());
            if (cmd != null && !cmd.isEmpty()) {
                event.setCommandLine(cmd);
            }

            // Evaluate Behavioral Heuristics
            evaluateHeuristics(event);

        } catch (Exception e) {
            log.debug("Enrich failed for PID {}: {}", event.getPid(), e.getMessage());
        }
    }

    private String getCommandLine(long pid) {
        // WMIC prima (veloce dove presente), poi CIM via PowerShell (Win11
        // senza WMIC). Entrambi best-effort con timeout: mai bloccare lo scan.
        String cmd = runCapture(new String[]{
                "wmic", "process", "where", "processid=" + pid, "get", "commandline"}, 3);
        String parsed = WindowsSensorKit.parseWmicOutput(cmd);
        if (!parsed.isEmpty()) return parsed;
        String ps = runCapture(new String[]{
                "powershell", "-NoProfile", "-NonInteractive", "-Command",
                "(Get-CimInstance Win32_Process -Filter 'ProcessId=" + pid + "').CommandLine"}, 3);
        return ps.trim();
    }

    private String runCapture(String[] command, int timeoutSeconds) {
        try {
            ProcessBuilder pb = new ProcessBuilder(command);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes()).trim();
            p.waitFor(timeoutSeconds, java.util.concurrent.TimeUnit.SECONDS);
            return out;
        } catch (Exception e) {
            return "";
        }
    }

    private void evaluateHeuristics(SystemEvent event) {
        // Match su nomi normalizzati (basename, case-insensitive): niente più
        // FP su path che contengono la parola né miss su case diversi.
        String parentName = event.getParentProcessName() != null ? event.getParentProcessName() : "";
        String cmd = WindowsSensorKit.normalizeCmdline(event.getCommandLine());

        // 1. Process Hollowing / Suspicious Parents
        if (WindowsSensorKit.procNameEquals(event.getProcessName(), "svchost.exe")
                && !WindowsSensorKit.procNameEquals(parentName, "services.exe")) {
            event.addBehavioralTag("SUSPICIOUS_SVCHOST_PARENT");
        }
        if (WindowsSensorKit.procNameEquals(event.getProcessName(), "cmd.exe")
                || WindowsSensorKit.procNameEquals(event.getProcessName(), "powershell.exe")) {
            if (WindowsSensorKit.procNameEquals(parentName, "winword.exe")
                    || WindowsSensorKit.procNameEquals(parentName, "excel.exe")
                    || WindowsSensorKit.procNameEquals(parentName, "mshta.exe")) {
                event.addBehavioralTag("OFFICE_SPAWNED_SHELL");
            }
        }

        // 2. Suspicious Command Line Arguments
        if (cmd.contains("-enc") || cmd.contains("-encodedcommand") || cmd.contains("iex") || cmd.contains("invoke-expression")) {
            event.addBehavioralTag("SUSPICIOUS_POWERSHELL_ARGS");
        }
        if (cmd.contains("bypass") || cmd.contains("hidden")) {
            event.addBehavioralTag("HIDDEN_OR_BYPASS_EXECUTION");
        }

        // 3. Known Keyloggers / Credential Dumpers (Basic string matching)
        if (WindowsSensorKit.baseName(event.getProcessName()).contains("mimikatz")
                || WindowsSensorKit.baseName(event.getProcessName()).contains("lazagne")
                || cmd.contains("dumpcreds")) {
            event.addBehavioralTag("CREDENTIAL_DUMPING_TOOL_DETECTED");
        }
    }

    // Parse netstat -ano output into pid → JSON connections map
    private Map<Long, String> parseNetstat() {
        Map<Long, List<Map<String, String>>> connMap = new HashMap<>();
        String out = runCapture(new String[]{"netstat", "-ano"}, 5);
        for (String line : out.split("\\r?\\n")) {
            Map<String, String> conn = WindowsSensorKit.parseNetstatLine(line);
            if (conn.isEmpty()) continue;
            try {
                long pid = Long.parseLong(conn.get("pid"));
                Map<String, String> entry = new LinkedHashMap<>(conn);
                entry.remove("pid");
                connMap.computeIfAbsent(pid, k -> new ArrayList<>()).add(entry);
            } catch (NumberFormatException ignored) {}
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
            byte[] pathBuffer = new byte[32768];
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
