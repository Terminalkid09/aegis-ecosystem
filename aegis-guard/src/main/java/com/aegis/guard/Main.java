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

import java.time.Instant;
import java.util.Optional;

/*
Entry point di Aegis-guard

Flusso:
    Inizializzazione AegisClient (http verso aegis-link)
    Rileva l'OS e crea il ProcessMonitor corretto tramite factory
    Avvia il monitoraggio in un thread dedicato
    Rimane in attesa -> un shutdown hook ferma il monitor in modo pulito
    Heartbeat periodico aggiorna last_seen nel dashboard
*/
public class Main {

    private static final Logger log = LoggerFactory.getLogger(Main.class);
    private static final long HEARTBEAT_INTERVAL_SEC = 30;
    private static final long COMMAND_POLL_INTERVAL_SEC = 5;

    public static void main(String[] args) {
        log.info("╔══════════════════════════════════╗");
        log.info("║      Aegis-Guard  v1.0           ║");
        log.info("╚══════════════════════════════════╝");
        log.info("Agent ID    : {}", Config.AGENT_ID);
        log.info("Gateway URL : {}", Config.GATEWAY_URL);
        log.info("Scan interval: {}ms", Config.SCAN_INTERVAL_MS);

        AegisClient client = new AegisClient();
        HashCalculator hasher = new HashCalculator();

        ProcessMonitor monitor;
        try {
            monitor = ProcessMonitorFactory.create(client, hasher, Config.AGENT_ID);
        } catch (UnsupportedOperationException e) {
            log.error("Start failed: {}", e.getMessage());
            System.exit(1);
            return;
        }
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            log.info("Shutdown requested - stopping monitor...");
            monitor.stopMonitoring();
            client.close();
            log.info("Aegis-Guard stopped.");
        }, "shutdown.hook"));

        Thread monitorThread = new Thread(monitor::startMonitoring, "process-monitor");
        monitorThread.setDaemon(false);
        monitorThread.start();

        // Collect system info
        String hostname = SystemInfoCollector.getHostname();
        String ipAddress = SystemInfoCollector.getIpAddress();
        log.info("System info: hostname={}, ip={}", hostname, ipAddress);

        // Send agent registration event to notify dashboard of agent presence
        try {
            SystemEvent registrationEvent = new SystemEvent(
                    Config.AGENT_ID,
                    ProcessHandle.current().pid(),
                    "aegis-guard",
                    System.getProperty("java.home") + "/bin/java",
                    System.getProperty("user.name"),
                    System.getProperty("os.name"),
                    "AGENT_REGISTERED"
            );
            registrationEvent.setHostname(hostname);
            registrationEvent.setIpAddress(ipAddress);
            registrationEvent.setTimestamp(Instant.now());
            client.sendEvent(registrationEvent);
            log.info("Agent registration event sent to dashboard.");
        } catch (Exception e) {
            log.warn("Failed to send registration event: {}", e.getMessage());
        }

        // Start heartbeat thread to periodically update last_seen
        Thread heartbeatThread = new Thread(() -> {
            while (true) {
                try {
                    Thread.sleep(HEARTBEAT_INTERVAL_SEC * 1000);
                    SystemEvent heartbeat = new SystemEvent(
                            Config.AGENT_ID,
                            ProcessHandle.current().pid(),
                            "aegis-guard",
                            System.getProperty("java.home") + "/bin/java",
                            System.getProperty("user.name"),
                            System.getProperty("os.name"),
                            "AGENT_HEARTBEAT"
                    );
                    heartbeat.setHostname(hostname);
                    heartbeat.setIpAddress(ipAddress);
                    heartbeat.setTimestamp(Instant.now());
                    client.sendEvent(heartbeat);
                    log.debug("Heartbeat sent");
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                } catch (Exception e) {
                    log.warn("Heartbeat failed: {}", e.getMessage());
                }
            }
        }, "heartbeat");
        heartbeatThread.setDaemon(false);
        heartbeatThread.start();

        // Start command dispatcher thread to poll and execute mitigation commands
        Thread commandDispatcher = new Thread(() -> {
            log.info("Command dispatcher thread started (polling every {}s)", COMMAND_POLL_INTERVAL_SEC);
            while (true) {
                try {
                    String rawCommand = client.fetchCommand(Config.AGENT_ID);
                    if (rawCommand != null && !rawCommand.isBlank()) {
                        processCommand(rawCommand);
                    }
                    Thread.sleep(COMMAND_POLL_INTERVAL_SEC * 1000);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                } catch (Exception e) {
                    log.warn("Error in command dispatcher: {}", e.getMessage());
                }
            }
        }, "command-dispatcher");
        commandDispatcher.setDaemon(false);
        commandDispatcher.start();

        log.info("Aegis-Guard active. Press Ctrl+C to stop.");
    }

    private static void processCommand(String rawJson) {
        try {
            JsonObject cmd = JsonParser.parseString(rawJson).getAsJsonObject();
            String type = cmd.get("command").getAsString();

            if ("KILL_PROCESS".equals(type)) {
                long pid = cmd.get("pid").getAsLong();
                String name = cmd.get("process_name").getAsString();
                log.info("[MITIGATION] Received KILL_PROCESS for PID {} ({})", pid, name);
                
                Optional<ProcessHandle> process = ProcessHandle.of(pid);
                if (process.isPresent()) {
                    ProcessHandle ph = process.get();
                    // Verifica di sicurezza: il nome deve corrispondere (parzialmente)
                    String cmdLine = ph.info().command().orElse("");
                    if (cmdLine.toLowerCase().contains(name.toLowerCase()) || name.equalsIgnoreCase("unknown")) {
                        boolean success = ph.destroyForcibly();
                        if (success) {
                            log.info("[SUCCESS] Process {} (PID {}) terminated successfully.", name, pid);
                        } else {
                            log.error("[FAILED] Could not terminate process {} (PID {}).", name, pid);
                        }
                    } else {
                        log.warn("[SAFETY] PID {} does not match process name {}. Aborting kill.", pid, name);
                    }
                } else {
                    log.warn("[SKIP] Process with PID {} not found. It might have already exited.", pid);
                }
            }
        } catch (Exception e) {
            log.error("Failed to parse or execute command: {}", e.getMessage());
        }
    }
}
