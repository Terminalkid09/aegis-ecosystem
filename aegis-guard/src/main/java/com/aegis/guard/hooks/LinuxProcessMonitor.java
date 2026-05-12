package com.aegis.guard.hooks;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

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
/proc/<pid>/status → UID e altri metadati
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

        // Snapshot iniziale — non inviamo i processi già esistenti all'avvio
        scanProcesses().forEach(e -> knownPids.add(e.getPid()));

        while (running) {
            try {
                List<SystemEvent> current = scanProcesses();

                for (SystemEvent event : current) {
                    if (!knownPids.contains(event.getPid())) {
                        log.info("New process detected: {}", event);
                        client.sendEvent(event);
                        knownPids.add(event.getPid());
                    }
                }

                // Manteniamo solo i PID ancora attivi
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

        for (File pidDir : procEntries) {
            try {
                long pid = Long.parseLong(pidDir.getName());

                String name = readComm(pidDir);
                if (name.isEmpty()) continue;

                String exePath = readExeSymlink(pidDir);
                String user    = readUser(pidDir);

                SystemEvent event = new SystemEvent(
                        agentId, pid, name, exePath, user, "Linux", "PROCESS_CREATED"
                );
                event.setHostname(hostname);
                event.setIpAddress(ipAddress);

                if (!exePath.isEmpty()) {
                    event.setFileHash(hasher.calculateHash(exePath));
                }

                events.add(event);

            } catch (NumberFormatException ignored) {
                // directory non numerica in /proc — saltata
            }
        }

        return events;
    }

    //  Helpers

    // Legge /proc/<pid>/comm (nome processo, max 15 char). 
    private String readComm(File pidDir) {
        try {
            return Files.readString(pidDir.toPath().resolve("comm")).strip();
        } catch (IOException e) {
            return "";
        }
    }

    // Risolve il symlink /proc/<pid>/exe → path assoluto dell'eseguibile. 
    private String readExeSymlink(File pidDir) {
        try {
            return Files.readSymbolicLink(pidDir.toPath().resolve("exe")).toString();
        } catch (IOException e) {
            return ""; // processi di sistema o permessi insufficienti
        }
    }

    /*
    Legge l'UID reale da /proc/<pid>/status e lo converte in nome utente
    tramite i file di sistema standard.
     */
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

    // Converte UID numerico in nome utente leggendo /etc/passwd. 
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
}
