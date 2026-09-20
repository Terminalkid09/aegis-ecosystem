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
    // Audit PID-reuse: la chiave di novita' e' (pid, start-time), non il solo
    // PID (riciclato in <1s il secondo processo spariva). Cache TTL 5s sugli
    // start time per non interrogare il kernel a ogni scan per ogni processo.
    private final Set<String> knownKeys = new HashSet<>();
    private final Map<Long, long[]> startCache = new HashMap<>();
    private static final long START_CACHE_TTL_MS = 5000;
    private com.aegis.guard.network.EventOutbox outbox;

    // Copertura reale (M2 Fase 3): Tier 1 ETW se disponibile, altrimenti
    // polling Toolhelp32 dichiarato come fallback.
    private volatile String coverageProvenance = "toolhelp";
    private volatile String coverageQuality = "full";

    // Stream kernel ETW (consumer user-mode, nessun driver). Null finche' lo
    // start non riesce. L'ETW NON sostituisce il polling: il polling resta la
    // rete di sicurezza (persistenze, servizi, Defender, netstat) e l'ETW
    // aggiunge gli eventi kernel con latenza di millisecondi invece che del
    // ciclo di scan.
    private volatile EtwPipeSource.EtwStream etwStream;
    // Dedup ETW/polling: un processo visto dallo stream non deve essere
    // rimandato dal ciclo Toolhelp che lo vede qualche istante dopo. La
    // finestra copre il ritardo del polling (interval + jitter),
    // ampiamente sotto i 15s anche con scan lenti su host carichi.
    static final long ETW_DEDUP_MS = 15000;
    private final Map<Long, Long> etwSeen = new java.util.concurrent.ConcurrentHashMap<>();

    private final String hostname;
    private final String ipAddress;

    // Cache netstat: mappa PID → JSON array di connessioni.
    // volatile: la mappa viene pubblicata dal thread di polling e letta anche
    // dal thread dello stream ETW (la mappa non e' mai mutata dopo la
    // pubblicazione: se ne crea una nuova a ogni refresh).
    private volatile Map<Long, String> netstatCache = new HashMap<>();
    private long lastNetstatRefreshMs = -1;

    public WindowsProcessMonitor(AegisClient client, HashCalculator hasher, String agentId) {
        this.client  = client;
        this.hasher  = hasher;
        this.agentId = agentId;
        this.hostname = SystemInfoCollector.getHostname();
        this.ipAddress = SystemInfoCollector.getIpAddress();
    }

    // ProcessMonitor

    /** Start time con cache TTL (audit PID-reuse senza interrogare il kernel
     * a ogni scan). Ritorna null se illeggibile. */
    Long cachedStartNs(long pid) {
        long now = System.currentTimeMillis();
        long[] cached = startCache.get(pid);
        if (cached != null && now - cached[1] < START_CACHE_TTL_MS) return cached[0];
        Long start = null;
        try {
            java.util.OptionalLong t = ProcessStartTime.creationFileTime(pid);
            if (t.isPresent()) start = t.getAsLong();
        } catch (Exception ignored) {
        }
        startCache.put(pid, new long[]{start == null ? -1L : start, now});
        return start;
    }

    @Override
    public void startMonitoring() {
        running = true;
        log.info("WindowsProcessMonitor started (interval {}ms)", Config.SCAN_INTERVAL_MS);

        scanProcesses().forEach(e -> {
            knownPids.add(e.getPid());
            knownKeys.add(WindowsSensorKit.pidReuseKey(e.getPid(), cachedStartNs(e.getPid())));
        });
        outbox = new com.aegis.guard.network.EventOutbox(client);
        outbox.start();

        // Copertura reale: stream ETW (mai crash) + snapshot persistenze (read-only).
        // Audit: prima questa era solo una PROBE — il collector veniva
        // approvato e poi mai usato (nessuno chiamava startStream), quindi la
        // provenance restava "toolhelp" e la telemetria kernel non arrivava
        // mai al brain. Ora lo stream viene avviato sul serio e alimenta la
        // stessa pipeline di eventi del polling.
        try {
            EtwPipeSource etw = new EtwPipeSource(agentId, Config.AGENT_VERSION);
            if (!etw.probe()) {
                coverageProvenance = "toolhelp";
                coverageQuality = "degraded:etw-" + etw.degradedReason();
                log.info("ETW non disponibile ({}): polling Toolhelp32 come fallback dichiarato",
                        etw.degradedReason());
            } else {
                EtwPipeSource.EtwStream stream = etw.startStream(this::ingestEtwEvent);
                // Attesa breve: un collector senza privilegi amministrativi
                // stampa il motivo ed esce in pochi ms. Senza questo check lo
                // stream risulterebbe "vivo" per un istante e la dashboard
                // direbbe ETW attivo mentre non arriva nessun evento.
                try {
                    Thread.sleep(500);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                }
                if (stream.isRunning()) {
                    etwStream = stream;
                    coverageProvenance = "etw";
                    coverageQuality = "etw+toolhelp";
                    log.info("ETW kernel stream ATTIVO (Kernel-Process/Kernel-Network, "
                            + "consumer user-mode, nessun driver): eventi con provenance=etw");
                } else {
                    String why = etw.lastDiagnostic();
                    coverageProvenance = "toolhelp";
                    coverageQuality = "degraded:etw-stream-"
                            + (why.isEmpty() ? "ended" : why.replace(' ', '_'));
                    log.warn("ETW: il collector e' terminato subito ({}). La telemetria "
                            + "kernel richiede privilegi amministrativi: avvia Guard elevato "
                            + "o installalo come servizio. Polling Toolhelp32 come fallback.",
                            why.isEmpty() ? "nessuna diagnostica" : why);
                    stream.close();
                }
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
            // Audit: ImagePath prima mai letti (servizi-persistenza invisibili).
            // Dettagli bounded sui nomi sospetti; WARN se ImagePath fuori sistema.
            for (WindowsServiceSnapshot.Service s :
                    WindowsServiceSnapshot.suspiciousServices(20)) {
                log.warn("Servizio sospetto: {} -> {} (start={})",
                        s.name(), s.imagePath(), s.startType());
            }
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
                Set<String> currentKeys = new HashSet<>();
                pruneEtwSeen();
                for (SystemEvent event : current) {
                    Long startNs = cachedStartNs(event.getPid());
                    String key = WindowsSensorKit.pidReuseKey(event.getPid(), startNs);
                    currentKeys.add(key);
                    if (!knownKeys.contains(key)) {
                        // Gia' riportato dallo stream ETW con latenza di ms:
                        // il polling non duplica (e non lo riarricchisce).
                        if (recentlyReportedByEtw(event.getPid())) {
                            knownKeys.add(key);
                            continue;
                        }
                        // Arricchimento costoso SOLO sui nuovi: path + hash
                        // (in scanProcesses() per non rompere il contratto)
                        enrichNewEvent(event);
                        // Chiave anti-PID-reuse (v2 procStartNs) + copertura.
                        if (startNs != null && startNs > 0) {
                            event.setProcStartNs(startNs);
                        } else {
                            event.setQuality(coverageQuality + ";pid-reuse-unknown");
                        }
                        event.setProvenance(coverageProvenance);
                        if (event.getQuality() == null) event.setQuality(coverageQuality);
                        // Attach network connections for this PID
                        String conns = netstatCache.getOrDefault(event.getPid(), "[]");
                        event.setNetworkConnections(conns);

                        log.info("New process detected: {}", event);
                        outbox.add(event);
                        knownKeys.add(key);
                    }
                }
                Set<Long> currentPids = new HashSet<>();
                current.forEach(e -> currentPids.add(e.getPid()));
                knownPids.retainAll(currentPids);
                knownKeys.retainAll(currentKeys);
                startCache.keySet().retainAll(currentPids);

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
        EtwPipeSource.EtwStream s = etwStream;
        if (s != null) {
            s.close();
            etwStream = null;
        }
        if (outbox != null) outbox.stop();
    }

    @Override
    public boolean etwStreamActive() {
        EtwPipeSource.EtwStream s = etwStream;
        return s != null && s.isRunning();
    }

    /**
     * Evento proveniente dal collector ETW: stessa pipeline del polling
     * (path/hash/firma/command-line + euristica) ma con provenance {@code etw}
     * e senza il ritardo del ciclo di scan. Chiamato dal thread dello stream.
     */
    private void ingestEtwEvent(SystemEvent event) {
        if (event == null || !running) return;
        try {
            long pid = event.getPid();
            event.setProvenance("etw");
            if (event.getQuality() == null) event.setQuality("etw");
            event.setHostname(hostname);
            event.setIpAddress(ipAddress);

            if ("PROCESS_CREATED".equals(event.getEventType()) && pid > 0) {
                etwSeen.put(pid, System.currentTimeMillis());
                enrichNewEvent(event);
                Long startNs = cachedStartNs(pid);
                if (startNs != null && startNs > 0) {
                    event.setProcStartNs(startNs);
                } else {
                    event.setQuality(event.getQuality() + ";pid-reuse-unknown");
                }
                String conns = netstatCache.getOrDefault(pid, "[]");
                event.setNetworkConnections(conns);
                log.info("New process detected (ETW): {}", event);
            }
            // PROCESS_EXITED / CONNECTION_ESTABLISHED: nessun arricchimento
            // processuale, ma restano eventi kernel validi da inoltrare.
            outbox.add(event);
        } catch (Exception e) {
            log.debug("Ingest evento ETW fallito: {}", e.getMessage());
        }
    }

    /** True se lo stream ETW ha gia' riportato questo PID da poco. */
    boolean recentlyReportedByEtw(long pid) {
        Long t = etwSeen.get(pid);
        return t != null && System.currentTimeMillis() - t < ETW_DEDUP_MS;
    }

    /** Rimuove dalla finestra di dedup i PID piu' vecchi (bound sulla memoria). */
    private void pruneEtwSeen() {
        if (etwSeen.isEmpty()) return;
        long cutoff = System.currentTimeMillis() - ETW_DEDUP_MS;
        etwSeen.entrySet().removeIf(e -> e.getValue() < cutoff);
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
