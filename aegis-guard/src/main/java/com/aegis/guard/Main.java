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
            } catch (Exception e) {
                log.error("Failed to read secret.json: {}. Retrying enrollment...", e.getMessage());
            }
        }

        if (client.fetchCommand(agentId) == null && !f.exists()) {
            log.info("No valid credentials found. Enrolling with key: {}", Config.ENROLL_KEY);
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

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            log.info("Stopping monitor...");
            monitor.stopMonitoring();
            client.close();
        }));

        new Thread(monitor::startMonitoring, "process-monitor").start();

        // Heartbeat
        new Thread(() -> {
            while (true) {
                try {
                    SystemEvent hb = new SystemEvent(finalAgentId, 0, 0, "", "aegis-guard", "", "", System.getProperty("os.name"), "AGENT_HEARTBEAT");
                    hb.setHostname(SystemInfoCollector.getHostname());
                    client.sendEvent(hb);
                    Thread.sleep(HEARTBEAT_INTERVAL_SEC * 1000);
                } catch (Exception e) {
                    log.warn("Heartbeat failed: {}", e.getMessage());
                }
            }
        }, "heartbeat").start();

        // Commands
        new Thread(() -> {
            while (true) {
                try {
                    String raw = client.fetchCommand(finalAgentId);
                    if (raw != null) processCommand(raw);
                    Thread.sleep(COMMAND_POLL_INTERVAL_SEC * 1000);
                } catch (Exception e) {}
            }
        }, "commands").start();

        log.info("Aegis-Guard fully operational.");
    }

    // ----------------------------------------------------------------
    //  Command Dispatch
    // ----------------------------------------------------------------

    private static void processCommand(String rawJson) {
        try {
            JsonObject cmd = JsonParser.parseString(rawJson).getAsJsonObject();
            String type = cmd.get("command").getAsString();

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
                default:
                    log.info("[MITIGATION] Unknown command type: {}", type);
            }
        } catch (Exception e) {
            log.warn("[MITIGATION] Command processing error: {}", e.getMessage());
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

    private static void handleKillProcess(JsonObject cmd) {
        long pid = getPid(cmd);
        if (pid == 0) { log.warn("[MITIGATION] KILL_PROCESS: no PID provided"); return; }
        Optional<ProcessHandle> ph = ProcessHandle.of(pid);
        ph.ifPresent(ProcessHandle::destroyForcibly);
        log.info("[MITIGATION] KILL_PROCESS: PID {} terminated", pid);
    }

    // ----------------------------------------------------------------
    //  KILL_PROCESS_TREE
    // ----------------------------------------------------------------

    private static void handleKillProcessTree(JsonObject cmd) {
        long pid = getPid(cmd);
        if (pid == 0) { log.warn("[MITIGATION] KILL_PROCESS_TREE: no PID provided"); return; }

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
        String ip = cmd.has("ip") ? cmd.get("ip").getAsString() : null;
        if (ip == null) { log.warn("[MITIGATION] BLOCK_IP: no IP provided"); return; }

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
        if (pid == 0) { log.warn("[MITIGATION] QUARANTINE_BINARY: no PID provided"); return; }

        String exePath = getProcessPath(pid);
        if (exePath == null) {
            log.warn("[MITIGATION] QUARANTINE_BINARY: could not locate binary for PID {}", pid);
            return;
        }

        Path src = Paths.get(exePath);
        if (!Files.exists(src)) {
            log.warn("[MITIGATION] QUARANTINE_BINARY: binary not found at {}", exePath);
            return;
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
            log.warn("[MITIGATION] REMOVE_PERSISTENCE: no process_name provided");
            return;
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

    private static void handleDnsSinkhole(JsonObject cmd) {
        String domain = cmd.has("domain") ? cmd.get("domain").getAsString() : null;
        if (domain == null) { log.warn("[MITIGATION] DNS_SINKHOLE: no domain provided"); return; }

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
    //  VERIFY
    // ----------------------------------------------------------------

    private static void handleVerify(JsonObject cmd) {
        long pid = getPid(cmd);
        if (pid == 0) { log.warn("[MITIGATION] VERIFY: no PID provided"); return; }
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
