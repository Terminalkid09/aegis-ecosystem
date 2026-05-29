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

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.time.Instant;
import java.util.Optional;

public class Main {

    private static final Logger log = LoggerFactory.getLogger(Main.class);
    private static final long HEARTBEAT_INTERVAL_SEC = 30;
    private static final long COMMAND_POLL_INTERVAL_SEC = 5;

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

        if (client.fetchCommand(agentId) == null && !f.exists()) { // Check if we need enrollment
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
                    SystemEvent hb = new SystemEvent(finalAgentId, 0, "aegis-guard", "", "", System.getProperty("os.name"), "AGENT_HEARTBEAT");
                    hb.setHostname(SystemInfoCollector.getHostname());
                    client.sendEvent(hb); // Assuming sendEvent handles the auth/heartbeat routing
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

    private static void processCommand(String rawJson) {
        try {
            JsonObject cmd = JsonParser.parseString(rawJson).getAsJsonObject();
            String type = cmd.get("command").getAsString();
            if ("KILL_PROCESS".equals(type)) {
                long pid = cmd.get("pid").getAsLong();
                Optional<ProcessHandle> ph = ProcessHandle.of(pid);
                ph.ifPresent(ProcessHandle::destroyForcibly);
                log.info("[MITIGATION] Executed KILL_PROCESS for PID {}", pid);
            }
        } catch (Exception e) {}
    }
}
