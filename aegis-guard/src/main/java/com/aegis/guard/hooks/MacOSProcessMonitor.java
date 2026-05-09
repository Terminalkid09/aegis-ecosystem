package com.aegis.guard.hooks;

import com.aegis.guard.models.SystemEvent;
import com.aegis.guard.network.AegisClient;
import com.aegis.guard.utils.Config;
import com.aegis.guard.utils.HashCalculator;
import com.sun.jna.Library;
import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.Pointer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
Implementazione macOS di ProcessMonitor.
Usa libproc (sysctl) tramite JNA per enumerare i processi attivi.

API chiave:
proc_listallpids()  → lista di tutti i PID attivi
proc_pidpath()      → path dell'eseguibile dato un PID
proc_pidinfo()      → info dettagliate (non usata qui, pronta per espansioni)
 */
public class MacOSProcessMonitor implements ProcessMonitor {

    private static final Logger log = LoggerFactory.getLogger(MacOSProcessMonitor.class);

    // JNA binding per libproc 

    interface LibProc extends Library {
        LibProc INSTANCE = Native.load("proc", LibProc.class);

        // Restituisce il numero di PID scritti nel buffer; -1 su errore. 
        int proc_listallpids(Pointer buffer, int buffersize);

        // Riempie pidPathBuffer con il path dell'eseguibile; 0 su errore. 
        int proc_pidpath(int pid, Pointer pidPathBuffer, int bufferSize);
    }

    private static final int PROC_PIDPATHINFO_MAXSIZE = 4096;

    // Campi
    private final AegisClient    client;
    private final HashCalculator hasher;
    private final String         agentId;
    private volatile boolean     running = false;
    private final Set<Long>      knownPids = new HashSet<>();

    public MacOSProcessMonitor(AegisClient client, HashCalculator hasher, String agentId) {
        this.client  = client;
        this.hasher  = hasher;
        this.agentId = agentId;
    }

    // ProcessMonitor 

    @Override
    public void startMonitoring() {
        running = true;
        log.info("MacOSProcessMonitor started (interval {}ms)", Config.SCAN_INTERVAL_MS);

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

        // Prima chiamata per sapere quanti PID ci sono
        int count = libProc.proc_listallpids(Pointer.NULL, 0);
        if (count <= 0) return events;

        // Allochiamo buffer: ogni PID è un int (4 byte), +16 di margine
        Memory pidBuffer = new Memory((long) (count + 16) * Integer.BYTES);
        int actual = libProc.proc_listallpids(pidBuffer, (int) pidBuffer.size());
        if (actual <= 0) return events;

        String currentUser = System.getProperty("user.name");

        for (int i = 0; i < actual; i++) {
            int pid = pidBuffer.getInt((long) i * Integer.BYTES);
            if (pid <= 0) continue;

            String path = resolveProcessPath(libProc, pid);
            String name = extractName(path, pid);

            SystemEvent event = new SystemEvent(
                    agentId, pid, name, path, currentUser, "macOS", "PROCESS_CREATED"
            );

            if (!path.isEmpty()) {
                event.setFileHash(hasher.calculateHash(path));
            }

            events.add(event);
        }

        return events;
    }

    // Helpers 

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
