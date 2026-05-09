package com.aegis.guard;

import com.aegis.guard.hooks.ProcessMonitor;
import com.aegis.guard.hooks.ProcessMonitorFactory;
import com.aegis.guard.network.AegisClient;
import com.aegis.guard.utils.Config;
import com.aegis.guard.utils.HashCalculator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/*
Entry point di Aegis-guard

Flusso:
    Inizializzazione AegisClient (http verso aegis-link)
    Rileva l'OS e crea il ProcessMonitor corretto tramite factory
    Avvia il monitoraggio in un thread dedicato
    Rimane in attesa -> un shutdown hook ferma il monitor in modo pulito
*/
public class Main {

    private static final Logger log = LoggerFactory.getLogger(Main.class);

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

        log.info("Aegis-Guard active. Press Ctrl+C to stop.");
    }
}
