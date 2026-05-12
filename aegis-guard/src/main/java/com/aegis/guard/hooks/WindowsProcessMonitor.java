package com.aegis.guard.hooks;

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
import com.sun.jna.Pointer;
import com.sun.jna.platform.win32.WinDef.DWORD;

/*
Implementazione Windows di ProcessMonitor.
Usa Toolhelp32 tramite JNA per enumerare i processi attivi.
Ad ogni ciclo rileva i processi NUOVI rispetto al ciclo precedente
e li invia come eventi PROCESS_CREATED ad aegis-link.
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

        // Popoliamo i PID già esistenti senza inviarli (solo i nuovi interessano)
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
                // Rimuoviamo i PID che non esistono più
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

        try {
            WindowsKernel32.PROCESSENTRY32 entry = new WindowsKernel32.PROCESSENTRY32();
            entry.dwSize = new DWORD(entry.size());

            if (kernel32.Process32First(snapshot, entry)) {
                do {
                    String name = new String(entry.szExeFile).trim().replace("\0", "");
                    long   pid  = entry.th32ProcessID.longValue();

                    SystemEvent event = new SystemEvent(
                            agentId, pid, name,
                            resolveProcessPath(pid),
                            System.getProperty("user.name"),
                            "Windows",
                            "PROCESS_CREATED"
                    );
                    event.setHostname(hostname);
                    event.setIpAddress(ipAddress);

                    // Hash opzionale — solo se abbiamo il path
                    if (!event.getProcessPath().isEmpty()) {
                        event.setFileHash(hasher.calculateHash(event.getProcessPath()));
                    }
                    events.add(event);

                } while (kernel32.Process32Next(snapshot, entry));
            }
        } finally {
            kernel32.CloseHandle(snapshot);
        }

        return events;
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
}
