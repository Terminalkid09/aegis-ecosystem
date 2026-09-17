package com.aegis.guard;

import com.aegis.guard.hooks.ProcessMonitor;
import com.aegis.guard.hooks.ProcessMonitorFactory;
import com.aegis.guard.models.SystemEvent;
import com.aegis.guard.network.AegisClient;
import com.aegis.guard.utils.Config;
import com.aegis.guard.utils.HashCalculator;
import com.aegis.guard.utils.SystemInfoCollector;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.*;

public class Main {

    private static final Logger log = LoggerFactory.getLogger(Main.class);
    private static final long HEARTBEAT_INTERVAL_SEC = 30;
    private static final long COMMAND_POLL_INTERVAL_SEC = 5;
    private static final ScheduledExecutorService SCHEDULER = Executors.newScheduledThreadPool(2);

    private static final String QUARANTINE_DIR = System.getProperty("user.dir") + File.separator + "quarantine";

    public static void main(String[] args) {
        log.info("Aegis-Guard Starting...");

        AegisClient client = new AegisClient();
        String agentId = Config.AGENT_ID;
        // 1. Enrollment Lifecycle
        File f = new File(Config.SECRET_FILE);
        if (f.exists()) {
            try (FileReader reader = new FileReader(f)) {
                JsonObject secretJson = JsonParser.parseReader(reader).getAsJsonObject();
                agentId = secretJson.get("agent_id").getAsString();
                client.setAgentSecret(secretJson.get("agent_secret").getAsString());
                log.info("Loaded credentials from {}. Agent ID: {}", Config.SECRET_FILE, agentId);
                // M6 Fase 7: pin del server — cambio silenzioso vietato.
                String storedServer = secretJson.has("server_url")
                        ? secretJson.get("server_url").getAsString() : null;
                String pinError = com.aegis.guard.utils.ServerPin.check(
                        storedServer, Config.BRAIN_URL);
                if (pinError != null && storedServer != null && !storedServer.isBlank()) {
                    log.error("[FATAL] {}", pinError);
                    System.exit(1);
                }
            } catch (Exception e) {
                log.error("Failed to read secret.json: {}. Retrying enrollment...", e.getMessage());
            }
        }

        if (client.fetchCommand(agentId) == null && !f.exists()) {
            log.info("No valid credentials found. Enrolling (key from env, never logged).");
            try {
                JsonObject resp = client.enroll(Config.ENROLL_KEY);
                agentId = resp.get("agent_id").getAsString();
                String secret = resp.get("agent_secret").getAsString();
                client.setAgentSecret(secret);

                File parent = f.getParentFile();
                if (parent != null) {
                    parent.mkdirs();
                }
                try (FileWriter writer = new FileWriter(f)) {
                    JsonObject save = new JsonObject();
                    save.addProperty("agent_id", agentId);
                    save.addProperty("agent_secret", secret);
                    save.addProperty("server_url", Config.BRAIN_URL);
                    writer.write(save.toString());
                }
                log.info("Enrollment successful. Credentials saved to {}", Config.SECRET_FILE);
            } catch (IOException e) {
                log.error("[FATAL] Enrollment failed: {}. Exiting.", e.getMessage());
                System.exit(1);
            }
        }

        // 2. Monitoring & Command loop
        HashCalculator hasher = new HashCalculator();
        ProcessMonitor monitor = ProcessMonitorFactory.create(client, hasher, agentId);

        final String finalAgentId = agentId;
        client.setAgentId(finalAgentId);

        // 2b. Identità device mTLS: bootstrap controllato (solo se assente o
        // in scadenza) + rinnovo orario. Mai overwrite di un'identità valida,
        // mai crash: senza identità l'agente lavora come prima (compat).
        ensureDeviceIdentity(client, finalAgentId);
        final java.util.concurrent.atomic.AtomicLong lastIdentityCheckMs =
                new java.util.concurrent.atomic.AtomicLong(System.currentTimeMillis());

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            log.info("Stopping monitor...");
            monitor.stopMonitoring();
            client.close();
        }));

        new Thread(monitor::startMonitoring, "process-monitor").start();

        // FIM: avviato vuoto; la watchlist arriva dal brain via FIM_SET_WATCH
        // (o dal ripristino della configurazione salvata, se implementata lato
        // install). Il monitor vive nel processo Guard: nessun componente extra.
        final com.aegis.guard.hooks.FileIntegrityMonitor fim =
                new com.aegis.guard.hooks.FileIntegrityMonitor(
                        finalAgentId, System.getProperty("os.name"),
                        Config.AGENT_VERSION, SystemInfoCollector.getHostname(), client);
        FIM.set(fim);

        // Heartbeat
        new Thread(() -> {
            while (true) {
                try {
                    // Rinnovo identità al massimo una volta all'ora.
                    long nowMs = System.currentTimeMillis();
                    if (nowMs - lastIdentityCheckMs.get() > 3600000L) {
                        lastIdentityCheckMs.set(nowMs);
                        ensureDeviceIdentity(client, finalAgentId);
                    }
                    SystemEvent hb = new SystemEvent(finalAgentId, 0, 0, "", "aegis-guard", "", "", System.getProperty("os.name"), "AGENT_HEARTBEAT");
                    hb.setHostname(SystemInfoCollector.getHostname());
                    hb.setAgentVersion(Config.AGENT_VERSION);
                    client.sendEvent(hb);
                    Thread.sleep(HEARTBEAT_INTERVAL_SEC * 1000);
                } catch (Exception e) {
                    log.warn("Heartbeat failed: {}", e.getMessage());
                }
            }
        }, "heartbeat").start();

        // Commands — drain adattivo: batch prima, singolo come fallback;
        // se il batch torna pieno si ripolla subito (niente sleep sotto burst).
        new Thread(() -> {
            while (true) {
                try {
                    boolean more = pollCommandsOnce(client, finalAgentId);
                    Thread.sleep(more ? 200 : COMMAND_POLL_INTERVAL_SEC * 1000);
                } catch (Exception e) {
                    // Audit L8: il catch vuoto rendeva invisibile un brain
                    // irraggiungibile e faceva girare il loop a vuoto
                    // (busy-loop, CPU + log flood altrove).
                    log.warn("Command poll loop error: {}", e.getMessage());
                    try { Thread.sleep(2000); } catch (InterruptedException ignored) { Thread.currentThread().interrupt(); }
                }
            }
        }, "commands").start();

        log.info("Aegis-Guard fully operational.");
    }

    // ----------------------------------------------------------------
    //  Command Dispatch
    // ----------------------------------------------------------------

    /** Un giro di poll: true se probabilmente c'è altro in coda (ripollare subito). */
    static boolean pollCommandsOnce(AegisClient client, String agentId) {
        java.util.List<String> batch = client.fetchCommandsBatch(agentId, 50);
        if (batch == null) {
            // Brain vecchio senza /batch: singolo comando come prima.
            String raw = client.fetchCommand(agentId);
            if (raw != null) processCommand(client, agentId, raw);
            return false;
        }
        for (String raw : batch) {
            try { processCommand(client, agentId, raw); }
            catch (Exception e) { log.warn("Command error: {}", e.getMessage()); }
        }
        return batch.size() >= 50;
    }

    private static void processCommand(AegisClient client, String agentId, String rawJson) {
        String type = "unknown";
        Long alertId = null;
        try {
            JsonObject cmd = JsonParser.parseString(rawJson).getAsJsonObject();
            type = cmd.get("command").getAsString();
            if (cmd.has("alert_id") && !cmd.get("alert_id").isJsonNull()) {
                try { alertId = cmd.get("alert_id").getAsLong(); } catch (Exception ignored) {}
            }

            switch (type) {
                case "KILL_PROCESS":
                    handleKillProcess(cmd);
                    break;
                case "KILL_PROCESS_TREE":
                    handleKillProcessTree(cmd);
                    break;
                case "BLOCK_IP":
                    handleBlockIp(cmd, false, 0);
                    break;
                case "BLOCK_IP_TEMPORAL":
                    int duration = cmd.has("duration_seconds") ? cmd.get("duration_seconds").getAsInt() : 3600;
                    handleBlockIp(cmd, true, duration);
                    break;
                case "QUARANTINE_BINARY":
                    handleQuarantineBinary(cmd);
                    break;
                case "REMOVE_PERSISTENCE":
                    handleRemovePersistence(cmd);
                    break;
                case "DNS_SINKHOLE":
                    handleDnsSinkhole(cmd);
                    break;
                case "COLLECT_IOC":
                    handleCollectIoc(cmd);
                    break;
                case "VERIFY":
                    handleVerify(cmd);
                    break;
                case "ISOLATE_HOST":
                    handleIsolateHost(cmd);
                    break;
                case "DEISOLATE_HOST":
                    handleDeisolateHost(cmd);
                    break;
                case "UPDATE_AGENT":
                    handleUpdateAgent(client, cmd);
                    break;
                case "FIM_SET_WATCH":
                    handleFimSetWatch(cmd);
                    break;
                case "YARA_SCAN":
                    handleYaraScan(client, agentId, cmd);
                    break;
                default:
                    log.info("[MITIGATION] Unknown command type: {}", type);
                    client.ackCommand(agentId, type, "failed", "Unknown command type", alertId);
                    return;
            }
            client.ackCommand(agentId, type, "ok", null, alertId);
        } catch (Exception e) {
            log.warn("[MITIGATION] Command processing error: {}", e.getMessage());
            try { client.ackCommand(agentId, type, "failed", e.getMessage(), alertId); }
            catch (Exception ignored) {}
        }
    }

    // ----------------------------------------------------------------
    //  Utility helpers
    // ----------------------------------------------------------------

    private static boolean isWindows() {
        return System.getProperty("os.name").toLowerCase().contains("win");
    }

    private static String exec(String... cmd) {
        try {
            ProcessBuilder pb = new ProcessBuilder(cmd);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            String out = new String(p.getInputStream().readAllBytes()).trim();
            p.waitFor(15, TimeUnit.SECONDS);
            return out;
        } catch (Exception e) {
            log.warn("[MITIGATION] exec failed: {} {}", String.join(" ", cmd), e.getMessage());
            return null;
        }
    }

    private static long getPid(JsonObject cmd) {
        return cmd.has("pid") ? cmd.get("pid").getAsLong() : 0;
    }

    private static String getProcessName(JsonObject cmd) {
        return cmd.has("process_name") ? cmd.get("process_name").getAsString() : "unknown";
    }

    private static Path getQuarantineDir() {
        Path dir = Paths.get(QUARANTINE_DIR);
        try { Files.createDirectories(dir); } catch (IOException ignored) {}
        return dir;
    }

    // ----------------------------------------------------------------
    //  KILL_PROCESS
    // ----------------------------------------------------------------

    /**
     * IP letterale valido (v4/v6). Audit L8: senza questo controllo qualunque
     * stringa finiva in `netsh`/`iptables` — compreso `any`, che blocca tutto,
     * o un valore iniettato che altera la regola di firewall.
     */
    static boolean isIpLiteral(String value) {
        if (value == null) return false;
        String candidate = value.trim();
        if (candidate.isEmpty() || candidate.length() > 45) return false;
        if (candidate.contains(":")) {
            return candidate.matches("[0-9a-fA-F:]{2,45}");
        }
        String[] octets = candidate.split("\\.", -1);
        if (octets.length != 4) return false;
        for (String octet : octets) {
            if (octet.isEmpty() || octet.length() > 3) return false;
            for (int i = 0; i < octet.length(); i++) {
                if (!Character.isDigit(octet.charAt(i))) return false;
            }
            if (Integer.parseInt(octet) > 255) return false;
        }
        return true;
    }

    private static void handleKillProcess(JsonObject cmd) {
        long pid = getPid(cmd);
        // Audit L8: prima un no-op usciva silenziosamente e il comando veniva
        // ack-ato "ok" al SOC (falso positivo di azione applicata).
        if (pid == 0) { throw new IllegalArgumentException("KILL_PROCESS: no PID provided"); }
        Optional<ProcessHandle> ph = ProcessHandle.of(pid);
        ph.ifPresent(ProcessHandle::destroyForcibly);
        log.info("[MITIGATION] KILL_PROCESS: PID {} terminated", pid);
    }

    // ----------------------------------------------------------------
    //  KILL_PROCESS_TREE
    // ----------------------------------------------------------------

    private static void handleKillProcessTree(JsonObject cmd) {
        long pid = getPid(cmd);
        if (pid == 0) { throw new IllegalArgumentException("KILL_PROCESS_TREE: no PID provided"); }

        if (isWindows()) {
            exec("taskkill", "/F", "/T", "/PID", String.valueOf(pid));
        } else {
            // Kill process group
            Optional<ProcessHandle> ph = ProcessHandle.of(pid);
            if (ph.isPresent()) {
                ph.get().children().forEach(child -> {
                    child.destroyForcibly();
                    log.info("[MITIGATION] KILL_PROCESS_TREE: child PID {} terminated", child.pid());
                });
                ph.get().destroyForcibly();
            }
        }
        log.info("[MITIGATION] KILL_PROCESS_TREE: PID {} and children terminated", pid);
    }

    // ----------------------------------------------------------------
    //  BLOCK_IP / BLOCK_IP_TEMPORAL
    // ----------------------------------------------------------------

    private static void handleBlockIp(JsonObject cmd, boolean temporal, int durationSeconds) {
        String ipRaw = cmd.has("ip") ? cmd.get("ip").getAsString() : null;
        if (ipRaw == null) { throw new IllegalArgumentException("BLOCK_IP: no IP provided"); }
        final String ip = ipRaw.trim();
        if (!isIpLiteral(ip)) {
            throw new IllegalArgumentException("BLOCK_IP: invalid IP literal '" + ip + "'");
        }
        // Non ci si taglia il ramo su cui si e' seduti: il brain deve restare
        // raggiungibile, altrimenti l'endpoint esce dal SOC.
        String brainHost = com.aegis.guard.utils.IsolationManager.extractBrainHost(
                com.aegis.guard.utils.Config.BRAIN_URL);
        if (!brainHost.isEmpty() && brainHost.equals(ip)) {
            throw new SecurityException("BLOCK_IP refused: target is the Aegis server (" + brainHost + ")");
        }

        if (isWindows()) {
            String ruleName = "Aegis_Block_" + ip.replace('.', '_');
            exec("netsh", "advfirewall", "firewall", "add", "rule",
                 "name=" + ruleName, "dir=in", "action=block", "remoteip=" + ip);
        } else {
            exec("iptables", "-A", "INPUT", "-s", ip, "-j", "DROP");
        }

        log.info("[MITIGATION] BLOCK_IP: {} blocked", ip);

        if (temporal && durationSeconds > 0) {
            SCHEDULER.schedule(() -> unblockIp(ip), durationSeconds, TimeUnit.SECONDS);
            log.info("[MITIGATION] BLOCK_IP_TEMPORAL: {} will unblock in {}s", ip, durationSeconds);
        }
    }

    private static void unblockIp(String ip) {
        if (isWindows()) {
            String ruleName = "Aegis_Block_" + ip.replace('.', '_');
            exec("netsh", "advfirewall", "firewall", "delete", "rule", "name=" + ruleName);
        } else {
            exec("iptables", "-D", "INPUT", "-s", ip, "-j", "DROP");
        }
        log.info("[MITIGATION] UNBLOCK_IP: {} unblocked after expiry", ip);
    }

    // ----------------------------------------------------------------
    //  QUARANTINE_BINARY
    // ----------------------------------------------------------------

    private static void handleQuarantineBinary(JsonObject cmd) {
        long pid = getPid(cmd);
        if (pid == 0) { throw new IllegalArgumentException("QUARANTINE_BINARY: no PID provided"); }

        String exePath = getProcessPath(pid);
        if (exePath == null) {
            throw new IllegalArgumentException("QUARANTINE_BINARY: could not locate binary for PID " + pid);
        }

        Path src = Paths.get(exePath);
        if (!Files.exists(src)) {
            throw new IllegalArgumentException("QUARANTINE_BINARY: binary not found at " + exePath);
        }

        try {
            String hash = sha256(src);
            String ts = Instant.now().toString().replace(":", "-").substring(0, 19);
            String fname = ts + "_" + hash.substring(0, 12) + "_" + src.getFileName();
            Path dest = getQuarantineDir().resolve(fname);
            Files.copy(src, dest, StandardCopyOption.REPLACE_EXISTING);

            // Restrict permissions
            if (isWindows()) {
                exec("icacls", exePath, "/deny", "Everyone:(R,W,X)");
            } else {
                src.toFile().setExecutable(false, false);
                src.toFile().setReadable(false, false);
                src.toFile().setWritable(false, false);
            }
            log.info("[MITIGATION] QUARANTINE_BINARY: {} -> {} (hash={})", exePath, dest, hash);
        } catch (Exception e) {
            log.warn("[MITIGATION] QUARANTINE_BINARY failed: {}", e.getMessage());
        }
    }

    private static String getProcessPath(long pid) {
        if (isWindows()) {
            String out = exec("wmic", "process", "where", "ProcessId=" + pid, "get", "ExecutablePath");
            if (out != null) {
                for (String line : out.split("\\r?\\n")) {
                    line = line.trim();
                    if (!line.isEmpty() && !line.equalsIgnoreCase("ExecutablePath")) return line;
                }
            }
            return null;
        } else {
            try {
                return new String(Files.readAllBytes(Paths.get("/proc/" + pid + "/cmdline"))).split("\0")[0];
            } catch (Exception e) {
                return null;
            }
        }
    }

    private static String sha256(Path file) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] data = Files.readAllBytes(file);
        byte[] digest = md.digest(data);
        StringBuilder sb = new StringBuilder();
        for (byte b : digest) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    // ----------------------------------------------------------------
    //  REMOVE_PERSISTENCE
    // ----------------------------------------------------------------

    private static void handleRemovePersistence(JsonObject cmd) {
        String processName = getProcessName(cmd);
        if (processName.isEmpty() || "unknown".equals(processName)) {
            throw new IllegalArgumentException("REMOVE_PERSISTENCE: no process_name provided");
        }

        List<String> removed = new ArrayList<>();

        if (isWindows()) {
            // Registry Run keys
            String[] regKeys = {
                "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
                "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices",
                "HKLM\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
            };
            for (String key : regKeys) {
                String out = exec("reg", "query", key, "/s");
                if (out != null && out.toLowerCase().contains(processName.toLowerCase())) {
                    exec("reg", "delete", key, "/f", "/va");
                    removed.add("registry:" + key);
                }
            }

            // Scheduled tasks
            String tasks = exec("schtasks", "/query", "/fo", "CSV");
            if (tasks != null) {
                String pn = processName.toLowerCase().replace(".exe", "");
                for (String line : tasks.split("\\r?\\n")) {
                    if (line.toLowerCase().contains(pn)) {
                        String taskName = line.contains(",") ? line.split(",")[0].replace("\"", "").trim() : line.trim();
                        exec("schtasks", "/delete", "/f", "/tn", taskName);
                        removed.add("scheduled_task:" + taskName);
                    }
                }
            }

            // Stop & delete services
            String services = exec("sc", "query", "type=", "service", "state=", "all");
            if (services != null) {
                for (String line : services.split("\\r?\\n")) {
                    if (line.toLowerCase().contains(processName.toLowerCase())) {
                        String[] parts = line.trim().split("\\s+");
                        String svcName = parts.length > 0 ? parts[parts.length - 1] : "";
                        if (!svcName.isEmpty()) {
                            exec("sc", "stop", svcName);
                            exec("sc", "delete", svcName);
                            removed.add("service:" + svcName);
                        }
                    }
                }
            }

            // Startup folder
            String appData = System.getenv("APPDATA");
            String progData = System.getenv("PROGRAMDATA");
            if (appData != null) {
                File startup = new File(appData + "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup");
                if (startup.isDirectory()) {
                    for (File sf : startup.listFiles()) {
                        if (sf.getName().toLowerCase().contains(processName.toLowerCase())) {
                            sf.delete();
                            removed.add("startup:" + sf.getAbsolutePath());
                        }
                    }
                }
            }
            if (progData != null) {
                File startup2 = new File(progData + "\\Microsoft\\Windows\\Start Menu\\Programs\\Startup");
                if (startup2.isDirectory()) {
                    for (File sf : startup2.listFiles()) {
                        if (sf.getName().toLowerCase().contains(processName.toLowerCase())) {
                            sf.delete();
                            removed.add("startup:" + sf.getAbsolutePath());
                        }
                    }
                }
            }
        } else {
            // Unix: crontab
            String cron = exec("crontab", "-l");
            if (cron != null) {
                for (String line : cron.split("\\r?\\n")) {
                    if (line.toLowerCase().contains(processName.toLowerCase())) {
                        removed.add("cron:" + line.trim());
                    }
                }
            }
            // systemd units
            for (String dir : new String[]{"/etc/systemd/system", "/lib/systemd/system"}) {
                File d = new File(dir);
                if (d.isDirectory()) {
                    for (File uf : d.listFiles()) {
                        if (uf.getName().toLowerCase().contains(processName.toLowerCase())) {
                            removed.add("systemd:" + uf.getName());
                        }
                    }
                }
            }
            // Shell init files
            String home = System.getProperty("user.home");
            for (String sf : new String[]{".bashrc", ".zshrc", ".profile", ".bash_profile"}) {
                File f = new File(home, sf);
                if (f.isFile()) {
                    try {
                        String content = new String(Files.readAllBytes(f.toPath()));
                        for (String line : content.split("\\r?\\n")) {
                            if (line.toLowerCase().contains(processName.toLowerCase())) {
                                removed.add("shell_init:" + sf + ":" + line.trim());
                            }
                        }
                    } catch (IOException ignored) {}
                }
            }
        }

        log.info("[MITIGATION] REMOVE_PERSISTENCE: {} entries removed for {}", removed.size(), processName);
    }

    // ----------------------------------------------------------------
    //  DNS_SINKHOLE
    // ----------------------------------------------------------------

    /**
     * Dominio DNS valido, senza spazi/newline. Audit L8: senza questo controllo
     * un valore come `evil.com\n0.0.0.0 mybank.com` iniettava righe arbitrarie
     * nel file hosts del'endpoint.
     */
    private static final java.util.regex.Pattern DOMAIN_RE = java.util.regex.Pattern.compile(
            "^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$");

    static boolean isDomainName(String value) {
        return value != null && value.length() <= 253 && DOMAIN_RE.matcher(value.trim()).matches();
    }

    private static void handleDnsSinkhole(JsonObject cmd) {
        String domain = cmd.has("domain") ? cmd.get("domain").getAsString() : null;
        if (domain == null) { throw new IllegalArgumentException("DNS_SINKHOLE: no domain provided"); }
        domain = domain.trim().toLowerCase();
        if (!isDomainName(domain)) {
            throw new IllegalArgumentException("DNS_SINKHOLE: invalid domain '" + domain + "'");
        }

        String hostsPath = isWindows()
            ? System.getenv("SystemRoot") + "\\System32\\drivers\\etc\\hosts"
            : "/etc/hosts";

        try {
            Path hp = Paths.get(hostsPath);
            String content = Files.readString(hp);
            if (content.contains(domain)) {
                log.info("[MITIGATION] DNS_SINKHOLE: {} already in hosts", domain);
                return;
            }
            String entry = "\n# Aegis block - " + Instant.now() + "\n0.0.0.0 " + domain + "\n";
            Files.writeString(hp, entry, StandardOpenOption.APPEND);
            log.info("[MITIGATION] DNS_SINKHOLE: {} -> 0.0.0.0 added to {}", domain, hostsPath);
        } catch (Exception e) {
            log.warn("[MITIGATION] DNS_SINKHOLE failed: {}", e.getMessage());
        }
    }

    // ----------------------------------------------------------------
    //  ISOLATE_HOST / DEISOLATE_HOST (contain & release, CrowdStrike-style)
    // ----------------------------------------------------------------

    private static void handleIsolateHost(JsonObject cmd) {
        String brain = com.aegis.guard.utils.IsolationManager.extractBrainHost(
                com.aegis.guard.utils.Config.BRAIN_URL);
        boolean ok = true;
        for (String[] argv : com.aegis.guard.utils.IsolationManager.buildIsolateCommands(brain)) {
            if (exec(argv) == null) ok = false;
        }
        try {
            String state = "isolated=true\nts=" + Instant.now() + "\nbrain=" + brain + "\n";
            Files.writeString(Paths.get(com.aegis.guard.utils.IsolationManager.STATE_FILE), state);
        } catch (IOException e) {
            log.warn("[MITIGATION] ISOLATE_HOST: state file write failed: {}", e.getMessage());
        }
        log.info("[MITIGATION] ISOLATE_HOST: {} (brain exception: {})",
                ok ? "host isolated" : "isolation PARTIAL — check firewall", brain.isEmpty() ? "none" : brain);
        if (!ok) throw new RuntimeException("Isolation partially applied — see logs");
    }

    private static void handleDeisolateHost(JsonObject cmd) {
        String brain = com.aegis.guard.utils.IsolationManager.extractBrainHost(
                com.aegis.guard.utils.Config.BRAIN_URL);
        boolean ok = true;
        for (String[] argv : com.aegis.guard.utils.IsolationManager.buildRestoreCommands(brain)) {
            if (exec(argv) == null) ok = false;
        }
        try { Files.deleteIfExists(Paths.get(com.aegis.guard.utils.IsolationManager.STATE_FILE)); }
        catch (IOException ignored) {}
        log.info("[MITIGATION] DEISOLATE_HOST: {}", ok ? "connectivity restored" : "restore PARTIAL — check firewall");
        if (!ok) throw new RuntimeException("Restore partially applied — see logs");
    }

    // ----------------------------------------------------------------
    //  FIM (File Integrity Monitoring)
    // ----------------------------------------------------------------

    /** Holder per il monitor FIM: il main lo crea, i comandi lo pilotano. */
    static final java.util.concurrent.atomic.AtomicReference<com.aegis.guard.hooks.FileIntegrityMonitor> FIM =
            new java.util.concurrent.atomic.AtomicReference<>();

    private static void handleFimSetWatch(JsonObject cmd) {
        com.aegis.guard.hooks.FileIntegrityMonitor fim = FIM.get();
        if (fim == null) {
            log.warn("[FIM] monitor non inizializzato: FIM_SET_WATCH ignorato");
            throw new IllegalStateException("FIM monitor not initialized");
        }
        java.util.List<String> paths = new java.util.ArrayList<>();
        if (cmd.has("paths") && cmd.get("paths").isJsonArray()) {
            for (var el : cmd.getAsJsonArray("paths")) {
                if (el.isJsonPrimitive()) paths.add(el.getAsString());
            }
        }
        boolean recursive = !cmd.has("recursive") || cmd.get("recursive").getAsBoolean();
        fim.applyWatchlist(paths, recursive);
        log.info("[FIM] watchlist applicata: {} percorso/i (recursive={})", paths.size(), recursive);
    }

    /** Scansione YARA on-demand: regole dal comando, target path espliciti. */
    private static void handleYaraScan(AegisClient client, String agentId, JsonObject cmd) {
        List<String> targets = new ArrayList<>();
        if (cmd.has("targets") && cmd.get("targets").isJsonArray()) {
            for (var el : cmd.getAsJsonArray("targets")) {
                if (el.isJsonPrimitive()) targets.add(el.getAsString());
            }
        }
        String rules = cmd.has("rules_yara") && !cmd.get("rules_yara").isJsonNull()
                ? cmd.get("rules_yara").getAsString() : null;
        com.aegis.guard.hooks.YaraScanner.ScanResult res =
                new com.aegis.guard.hooks.YaraScanner().scan(rules, targets);
        if (!res.ok) {
            log.warn("[YARA] scan failed: {}", res.error);
            throw new IllegalStateException("YARA scan failed: " + res.error);
        }
        // Ogni match diventa un evento sulla pipeline standard (ricercabile,
        // alertable, playbook-able), non un canale parallelo.
        for (com.aegis.guard.hooks.YaraScanner.Match m : res.matches) {
            SystemEvent ev = new SystemEvent(agentId, 0, 0, "",
                    m.rule, "YARA", System.getProperty("user.name"),
                    System.getProperty("os.name"), "YARA_MATCH");
            ev.setProcessPath("YARA");
            ev.setFileHash(m.fileSha256);
            ev.setCommandLine("[YARA] " + m.rule + " -> "
                    + (m.filePath != null ? m.filePath : "?"));
            client.sendEvent(ev);
        }
        log.info("[YARA] scan ok: {} match su {} target", res.matches.size(), targets.size());
    }

    // ----------------------------------------------------------------
    //  Identità device mTLS (bootstrap + rinnovo controllato)
    // ----------------------------------------------------------------

    /**
     * Garantisce un'identità valida: carica dal PKCS#12, oppure genera
     * chiave+CSR e chiede il certificato al SOC, oppure rinnova in scadenza.
     * Non tocca mai un'identità valida; non lancia mai (log + degrado).
     */
    static void ensureDeviceIdentity(AegisClient client, String agentId) {
        try {
            String secret = readDeviceSecret();
            if (secret == null || secret.isBlank()) {
                log.debug("Identità device: nessun secret, skip (pre-enroll)");
                return;
            }
            java.nio.file.Path dir = java.nio.file.Paths.get(Config.IDENTITY_DIR);
            char[] pw = com.aegis.guard.security.DeviceIdentity.deriveStorePassword(secret);
            com.aegis.guard.security.DeviceIdentity.LoadedIdentity id =
                    com.aegis.guard.security.DeviceIdentity.load(dir, pw);
            if (id != null && !com.aegis.guard.security.DeviceIdentity.needsRenewal(id.leaf())) {
                attachIdentity(client, id);
                return;
            }
            log.info("Identità device assente o in scadenza: bootstrap/rinnovo CSR...");
            java.security.KeyPair kp = com.aegis.guard.security.DeviceIdentity.generateKey();
            String csr = com.aegis.guard.security.DeviceIdentity.buildCsrPem(
                    kp.getPublic(), kp.getPrivate(), agentId);
            String certPem = client.postCsr(agentId, csr);
            java.security.cert.X509Certificate cert =
                    com.aegis.guard.security.DeviceIdentity.parseCertPem(certPem);
            com.aegis.guard.security.DeviceIdentity.store(
                    dir, kp.getPrivate(), new java.security.cert.X509Certificate[]{cert});
            log.info("Identità device emessa (serial {})", cert.getSerialNumber().toString(16));
            attachIdentity(client, new com.aegis.guard.security.DeviceIdentity.LoadedIdentity(
                    kp.getPrivate(), new java.security.cert.X509Certificate[]{cert}));
        } catch (Exception e) {
            log.warn("Identità device non disponibile ({}): agente senza mTLS", e.getMessage());
        }
    }

    /** Collega chiave+cert al client + contesto TLS se la CA è provisionata. */
    private static void attachIdentity(AegisClient client,
            com.aegis.guard.security.DeviceIdentity.LoadedIdentity id) {
        java.security.cert.X509Certificate serverCa = null;
        if (!Config.SERVER_CA_FILE.isBlank()) {
            serverCa = com.aegis.guard.security.DeviceTls.loadServerCa(
                    java.nio.file.Paths.get(Config.SERVER_CA_FILE));
            if (serverCa == null) {
                log.warn("AEGIS_SERVER_CA illeggibile: solo header X-Client-Cert, niente TLS mutuo");
            }
        }
        client.setIdentity(id.key(), id.chain(), serverCa);
    }

    private static String readDeviceSecret() {
        try (FileReader reader = new FileReader(new File(Config.SECRET_FILE))) {
            JsonObject o = JsonParser.parseReader(reader).getAsJsonObject();
            return o.has("agent_secret") ? o.get("agent_secret").getAsString() : null;
        } catch (Exception e) {
            return null;
        }
    }

    // ----------------------------------------------------------------
    //  UPDATE_AGENT (staged OTA — verify, stage, ack; apply on restart)
    // ----------------------------------------------------------------

    private static void handleUpdateAgent(AegisClient client, JsonObject cmd) {
        String url = cmd.has("url") && !cmd.get("url").isJsonNull() ? cmd.get("url").getAsString() : "";
        String sha = cmd.has("sha256") && !cmd.get("sha256").isJsonNull() ? cmd.get("sha256").getAsString() : "";
        String sig = cmd.has("signature") && !cmd.get("signature").isJsonNull() ? cmd.get("signature").getAsString() : "";
        String version = cmd.has("version") && !cmd.get("version").isJsonNull() ? cmd.get("version").getAsString() : "latest";
        if (url.isEmpty() || sha.isEmpty() || sig.isEmpty()) {
            throw new RuntimeException("UPDATE_AGENT: missing url/sha256/signature — refusing (fail-closed)");
        }
        // 1a. Allowlist URL (audit SSRF): solo artefatti del brain pinnato.
        if (!com.aegis.guard.utils.UpdateManager.isUpdateUrlAllowed(
                url, com.aegis.guard.utils.Config.BRAIN_URL)) {
            throw new SecurityException("UPDATE_AGENT: url fuori allowlist — refusing");
        }
        // 1. HMAC con la enroll key dell'agente (niente firma valida → stop)
        if (!com.aegis.guard.utils.UpdateManager.verifySignature(sha, sig, com.aegis.guard.utils.Config.ENROLL_KEY)) {
            throw new SecurityException("UPDATE_AGENT: bad signature — possible tampering, refusing");
        }
        // 1b. Manifest Ed25519 (M6 Fase 7): se il comando lo porta e la pubkey
        // è configurata, l'artefatto deve esserne coperto — altrimenti stop.
        // Senza pubkey configurata resta l'HMAC (compat, loggato).
        String manifest = cmd.has("manifest") && !cmd.get("manifest").isJsonNull()
                ? cmd.get("manifest").getAsString() : "";
        String manifestSig = cmd.has("manifest_sig") && !cmd.get("manifest_sig").isJsonNull()
                ? cmd.get("manifest_sig").getAsString() : "";
        String fileName = url.contains("/") ? url.substring(url.lastIndexOf('/') + 1) : url;
        if (!manifest.isEmpty() && !manifestSig.isEmpty()
                && !com.aegis.guard.utils.Config.MANIFEST_PUBKEY.isBlank()) {
            boolean okSig = com.aegis.guard.utils.ManifestVerifier.verifyEd25519(
                    manifest, manifestSig, com.aegis.guard.utils.Config.MANIFEST_PUBKEY);
            boolean covered = com.aegis.guard.utils.ManifestVerifier.manifestCovers(
                    manifest, fileName, sha);
            if (!okSig || !covered) {
                throw new SecurityException(
                        "UPDATE_AGENT: manifest Ed25519 invalido o artefatto non coperto — refusing");
            }
            log.info("[MITIGATION] UPDATE_AGENT: manifest Ed25519 verificato per {}", fileName);
        } else if (!com.aegis.guard.utils.Config.MANIFEST_PUBKEY.isBlank()) {
            log.warn("[MITIGATION] UPDATE_AGENT: comando senza manifest firmato, solo HMAC");
        }
        // 2. Download in temp + stage (riverifica SHA, sposta, scrive update.state)
        try {
            Path tmp = Files.createTempFile("aegis-update-", ".pkg");
            try {
                client.downloadFile(url, tmp);
                Path staged = com.aegis.guard.utils.UpdateManager.stagePackage(tmp, sha);
                // 2b. Sigillo anti-tampering a riposo (audit P6): l'apply al
                // restart riverifica il MAC prima di toccare il jar live.
                String secret = client.getAgentSecret();
                if (secret != null && !secret.isBlank()) {
                    com.aegis.guard.utils.UpdateManager.sealStagedState(
                            java.nio.file.Paths.get(""), staged.toString(), sha, secret);
                } else {
                    log.warn("[MITIGATION] UPDATE_AGENT: secret assente, state non sigillato");
                }
                log.info("[MITIGATION] UPDATE_AGENT: v{} staged at {} — restart service to apply", version, staged);
            } finally {
                try { Files.deleteIfExists(tmp); } catch (IOException ignored) {}
            }
        } catch (SecurityException se) {
            throw se;
        } catch (Exception e) {
            throw new RuntimeException("UPDATE_AGENT download/stage failed: " + e.getMessage(), e);
        }
    }

    // ----------------------------------------------------------------
    //  VERIFY
    // ----------------------------------------------------------------

    private static void handleVerify(JsonObject cmd) {
        long pid = getPid(cmd);
        if (pid == 0) { throw new IllegalArgumentException("VERIFY: no PID provided"); }
        boolean alive = ProcessHandle.of(pid).isPresent();
        log.info("[MITIGATION] VERIFY: PID {} {}", pid, alive ? "ALIVE" : "DEAD");
    }

    // ----------------------------------------------------------------
    //  COLLECT_IOC
    // ----------------------------------------------------------------

    private static void handleCollectIoc(JsonObject cmd) {
        long pid = getPid(cmd);
        String processName = getProcessName(cmd);
        if (pid == 0) { log.warn("[MITIGATION] COLLECT_IOC: no PID provided"); return; }

        JsonObject ioc = new JsonObject();
        ioc.addProperty("pid", pid);
        ioc.addProperty("process_name", processName);
        ioc.addProperty("timestamp", Instant.now().toString());

        // Executable path
        String exePath = getProcessPath(pid);
        ioc.addProperty("executable_path", exePath != null ? exePath : "unknown");

        // SHA256 hash + file size
        if (exePath != null) {
            Path fp = Paths.get(exePath);
            if (Files.exists(fp)) {
                try {
                    ioc.addProperty("sha256", sha256(fp));
                    ioc.addProperty("file_size", Files.size(fp));
                } catch (Exception ignored) {}
            }
        }

        // Network connections
        if (isWindows()) {
            String netstat = exec("netstat", "-ano");
            if (netstat != null) {
                var conns = new com.google.gson.JsonArray();
                String pidStr = String.valueOf(pid);
                for (String line : netstat.split("\\r?\\n")) {
                    if (line.contains(pidStr) && (line.contains("ESTABLISHED") || line.contains("LISTENING"))) {
                        String[] parts = line.trim().split("\\s+");
                        if (parts.length >= 5) {
                            JsonObject conn = new JsonObject();
                            conn.addProperty("proto", parts[0]);
                            conn.addProperty("local", parts[1]);
                            conn.addProperty("remote", parts[2]);
                            conn.addProperty("state", parts[3]);
                            conns.add(conn);
                        }
                    }
                }
                ioc.add("connections", conns);
            }
        } else {
            String ss = exec("ss", "-tupn");
            if (ss != null) ioc.addProperty("connections", ss);
        }

        // Command line
        if (isWindows()) {
            String wmic = exec("wmic", "process", "where", "ProcessId=" + pid, "get", "CommandLine");
            if (wmic != null) {
                for (String line : wmic.split("\\r?\\n")) {
                    line = line.trim();
                    if (!line.isEmpty() && !line.equalsIgnoreCase("CommandLine")) {
                        ioc.addProperty("command_line", line);
                        break;
                    }
                }
            }
        } else {
            try {
                String cl = new String(Files.readAllBytes(Paths.get("/proc/" + pid + "/cmdline"))).replace("\0", " ");
                ioc.addProperty("command_line", cl);
            } catch (IOException ignored) {}
        }

        log.info("[MITIGATION] COLLECT_IOC: collected {} fields for PID {}", ioc.size(), pid);
    }
}
