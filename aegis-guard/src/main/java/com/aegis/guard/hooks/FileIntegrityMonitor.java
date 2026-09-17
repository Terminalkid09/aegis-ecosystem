package com.aegis.guard.hooks;

import com.aegis.guard.models.SystemEvent;
import com.aegis.guard.network.AegisClient;
import com.aegis.guard.utils.HashCalculator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * File Integrity Monitoring in-process (scelta architetturale: Guard e' gia'
 * un servizio LocalSystem con canale eventi — un collector separato
 * frammenterebbe l'agente senza aggiungere nulla).
 *
 * Cosa fa:
 *  - baseline iniziale (SHA256) dei percorsi in watchlist, bounded;
 *  - WatchService ricorsivo per directory, dedup storm con finestra temporale
 *    (un salvataggio genera spesso CREATE+MODIFY+MODIFY dello stesso file);
 *  - ogni modifica diventa un SystemEvent FILE_MODIFIED (processPath=FILE,
 *    processName=nome file, fileHash=SHA256) verso il canale telemetry
 *    standard: il brain lo normalizza in OCSF File Activity, lo rende
 *    ricercabile e lo passa a Sigma/correlazione/playbook.
 *
 * Limiti dichiarati (onesti, non nascosti):
 *  - hashing SOLO su file fino a MAX_HASH_BYTES (sopra: evento senza hash);
 *  - baseline SOLO su file fino a MAX_BASELINE_BYTES e MAX_BASELINE_FILES;
 *  - il watch non sostituisce un driver minifilter: e' user-mode, quindi un
 *    attacker con privilegio SYSTEM puo' fermarlo (e' telemetria, non prevention).
 */
public final class FileIntegrityMonitor {

    private static final Logger log = LoggerFactory.getLogger(FileIntegrityMonitor.class);
    private static final int MAX_HASH_BYTES = 8 * 1024 * 1024;      // 8 MB: hash completo
    private static final int MAX_BASELINE_FILES = 5_000;            // tetto baseline
    private static final long MAX_BASELINE_BYTES = 64L * 1024 * 1024;
    private static final long STORM_WINDOW_MS = 750;                // dedup modifiche ripetute
    private static final int MAX_WATCHED_DIRS = 64;

    private final String agentId;
    private final String os;
    private final String agentVersion;
    private final String hostname;
    private final AegisClient client;
    private final HashCalculator hasher = new HashCalculator();

    private final Map<Path, String> baseline = new ConcurrentHashMap<>();
    private final Map<String, Long> lastEventMs = new ConcurrentHashMap<>();
    private final Map<Path, Boolean> recursiveDirs = new ConcurrentHashMap<>();
    /** File singoli in watchlist: il watch è sulla DIR padre, qui filtro i falsi vicini. */
    private final Set<Path> singleFiles = ConcurrentHashMap.newKeySet();
    private volatile WatchService watchService;
    private volatile Thread watcherThread;
    private volatile boolean running;

    public FileIntegrityMonitor(String agentId, String os, String agentVersion,
                                String hostname, AegisClient client) {
        this.agentId = agentId;
        this.os = os;
        this.agentVersion = agentVersion;
        this.hostname = hostname;
        this.client = client;
    }

    /** Applica una nuova watchlist (sovrascrive i watch precedenti). */
    public synchronized void applyWatchlist(List<String> paths, boolean recursive) {
        stopWatching();
        if (paths == null || paths.isEmpty()) {
            log.info("[FIM] watchlist vuota: monitoraggio fermo (default agente)");
            return;
        }
        try {
            watchService = FileSystems.getDefault().newWatchService();
        } catch (IOException e) {
            log.error("[FIM] WatchService non disponibile: {}", e.getMessage());
            return;
        }
        int registered = 0;
        for (String raw : paths) {
            if (registered >= MAX_WATCHED_DIRS) {
                log.warn("[FIM] tetto {} directory raggiunto, restanti ignorate", MAX_WATCHED_DIRS);
                break;
            }
            Path dir = Paths.get(raw);
            if (!Files.exists(dir)) {
                log.warn("[FIM] percorso inesistente (non watchato): {}", raw);
                continue;
            }
            try {
                if (Files.isRegularFile(dir)) {
                    registerSingle(dir.getParent(), dir.getFileName(), recursive);
                    registered++;
                } else {
                    registerTree(dir, recursive);
                    registered++;
                }
            } catch (IOException e) {
                log.warn("[FIM] watch fallito su {}: {}", raw, e.getMessage());
            }
        }
        if (registered == 0) {
            log.info("[FIM] nessun percorso valido da monitorare");
            return;
        }
        running = true;
        watcherThread = new Thread(this::pollLoop, "fim-watcher");
        watcherThread.setDaemon(true);
        watcherThread.start();
        log.info("[FIM] attivo su {} percorso/i (recursive={})", registered, recursive);
    }

    private void registerSingle(Path dir, Path fileName, boolean recursive) throws IOException {
        Path target = (dir == null) ? fileName : dir.resolve(fileName);
        dir.register(watchService,
                StandardWatchEventKinds.ENTRY_CREATE,
                StandardWatchEventKinds.ENTRY_MODIFY,
                StandardWatchEventKinds.ENTRY_DELETE);
        singleFiles.add(target.toAbsolutePath().normalize());
        hashIntoBaseline(target);
    }

    private void registerTree(Path root, boolean recursive) throws IOException {
        if (recursive) {
            Files.walkFileTree(root, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) throws IOException {
                    if (recursiveDirs.size() >= MAX_WATCHED_DIRS) return FileVisitResult.SKIP_SUBTREE;
                    dir.register(watchService,
                            StandardWatchEventKinds.ENTRY_CREATE,
                            StandardWatchEventKinds.ENTRY_MODIFY,
                            StandardWatchEventKinds.ENTRY_DELETE);
                    recursiveDirs.put(dir, Boolean.TRUE);
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                    hashIntoBaseline(file);
                    return FileVisitResult.CONTINUE;
                }
            });
        } else {
            root.register(watchService,
                    StandardWatchEventKinds.ENTRY_CREATE,
                    StandardWatchEventKinds.ENTRY_MODIFY,
                    StandardWatchEventKinds.ENTRY_DELETE);
            recursiveDirs.put(root, Boolean.FALSE);
        }
    }

    private void hashIntoBaseline(Path file) {
        try {
            if (baseline.size() >= MAX_BASELINE_FILES) return;
            BasicFileAttributes attrs = Files.readAttributes(file, BasicFileAttributes.class);
            if (attrs.size() > MAX_BASELINE_BYTES) return;
            String h = hasher.calculateHash(file.toString());
            if (h != null && !h.isBlank()) baseline.put(file.toAbsolutePath().normalize(), h);
        } catch (Exception ignored) {
            // file temporaneo/permission: la baseline e' best-effort
        }
    }

    private void pollLoop() {
        while (running) {
            WatchKey key;
            try {
                key = watchService.take();
            } catch (ClosedWatchServiceException e) {
                return;
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            }
            for (WatchEvent<?> ev : key.pollEvents()) {
                try {
                    handleEvent(key, ev);
                } catch (Exception e) {
                    log.debug("[FIM] evento non processabile: {}", e.getMessage());
                }
            }
            key.reset();
        }
    }

    @SuppressWarnings("unchecked")
    private void handleEvent(WatchKey key, WatchEvent<?> ev) {
        WatchEvent<Path> pathEv = (WatchEvent<Path>) ev;
        Path dir = (Path) key.watchable();
        Path fileName = pathEv.context();
        Path full = (dir == null) ? fileName : dir.resolve(fileName);
        // Watch su file singolo: la chiave copre l'intera DIR — scarta i vicini.
        // Watch su file singolo: la chiave copre l'intera DIR padre — scarta
        // gli eventi dei file vicini non in watchlist (noisy neighbor).
        if (!singleFiles.isEmpty()) {
            Path norm = full.toAbsolutePath().normalize();
            boolean isWatchedFile = singleFiles.contains(norm);
            boolean dirHasSingles = dir != null
                    && singleFiles.stream().anyMatch(f -> f.getParent() != null
                            && f.getParent().equals(dir.toAbsolutePath().normalize()));
            if (!isWatchedFile && dirHasSingles) {
                return;
            }
        }
        String kind = ev.kind().name(); // ENTRY_CREATE / ENTRY_MODIFY / ENTRY_DELETE
        if (kind.equals(StandardWatchEventKinds.OVERFLOW.name())) {
            return; // overflow = eventi persi: non simuliamo cosa non abbiamo visto
        }

        String keyStr = full.toAbsolutePath().normalize() + ":" + kind;
        long now = System.currentTimeMillis();
        Long last = lastEventMs.get(keyStr);
        if (last != null && (now - last) < STORM_WINDOW_MS) {
            return; // storm dedup
        }
        lastEventMs.put(keyStr, now);
        if (lastEventMs.size() > 20_000) lastEventMs.clear(); // tetto memoria

        // Se e' una directory nuova e recursive, agganciala (persistenza via
        // nuovi Run key/task la scrivono in dir create DOPO il watch).
        if (Files.isDirectory(full) && Boolean.TRUE.equals(recursiveDirs.get(dir))) {
            try {
                full.register(watchService,
                        StandardWatchEventKinds.ENTRY_CREATE,
                        StandardWatchEventKinds.ENTRY_MODIFY,
                        StandardWatchEventKinds.ENTRY_DELETE);
                recursiveDirs.put(full, Boolean.TRUE);
            } catch (IOException ignored) { }
        }

        String change = kind.equals(StandardWatchEventKinds.ENTRY_CREATE.name()) ? "created"
                : kind.equals(StandardWatchEventKinds.ENTRY_DELETE.name()) ? "deleted" : "modified";

        String hash = null;
        if (!change.equals("deleted")) {
            try {
                BasicFileAttributes attrs = Files.readAttributes(full, BasicFileAttributes.class);
                if (attrs.isRegularFile() && attrs.size() <= MAX_HASH_BYTES) {
                    hash = hasher.calculateHash(full.toString());
                }
            } catch (Exception ignored) { }
        }

        String prevHash = baseline.put(full.toAbsolutePath().normalize(), hash == null ? "" : hash);
        boolean isNew = (prevHash == null || prevHash.isEmpty()) && !change.equals("deleted");

        SystemEvent event = new SystemEvent(agentId, 0, 0, "", fileName.toString(),
                "FILE", System.getProperty("user.name"), os, "FILE_MODIFIED");
        event.setProcessPath("FILE");
        event.setFileHash(hash);
        event.setHostname(hostname);
        if (agentVersion != null) event.setAgentVersion(agentVersion);
        // Il dettaglio FIM viaggia in commandLine (e fileHash): SystemEvent non
        // ha un campo extra arbitrario e aggiungerne uno e' rottura di schema.
        event.setCommandLine("[FIM] " + change + (isNew ? " new" : "") + ": "
                + full.toAbsolutePath().normalize());
        client.sendEvent(event);
    }

    private void stopWatching() {
        running = false;
        try { if (watchService != null) watchService.close(); } catch (IOException ignored) { }
        if (watcherThread != null) watcherThread.interrupt();
        watcherThread = null;
        watchService = null;
        recursiveDirs.clear();
        singleFiles.clear();
        baseline.clear();
        lastEventMs.clear();
    }

    public synchronized void shutdown() {
        stopWatching();
    }
}
