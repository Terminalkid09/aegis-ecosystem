package com.aegis.guard.network;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

import com.aegis.guard.models.SystemEvent;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonPrimitive;
import com.google.gson.JsonSerializer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Outbox batch per gli eventi: accumula fino a MAX_BATCH o FLUSH_MS e invia
 * con un solo POST a /telemetry/report/batch. Sotto storm di exec (compile,
 * boot) evita centinaia di POST singoli che intasano agente e brain.
 *
 * <p>M1 Fase 2 — affidabilità misurabile:
 * <ul>
 *   <li>buffer limitato (MAX_BUFFER): oltre, scarta i più vecchi e li CONTA
 *       (backpressure visibile, mai perdita invisibile);</li>
 *   <li>contatori esposti via {@link #stats()} (ricevuti, inviati, scartati,
 *       spoolati, rigiocati, corrotti, falliti);</li>
 *   <li>errore transitorio → spool cifrato su disco (sopravvive al reboot),
 *       rigiocato al flush successivo con ordine preservato;</li>
 *   <li>brain senza batch endpoint → fallback per-evento legacy (niente spool).</li>
 * </ul>
 *
 * <p>Il buffer puro ({@link BatchBuffer}) è testato senza rete; il flush
 * cade in per-evento se il batch non è supportato (brain vecchio).
 */
public class EventOutbox {

    private static final Logger log = LoggerFactory.getLogger(EventOutbox.class);

    static final int MAX_BATCH = 25;
    static final long FLUSH_MS = 500;
    /** Tetto buffer in memoria: anti-OOM sotto storm o server irraggiungibile. */
    static final int MAX_BUFFER = 2000;
    /** Eventi spool rigiocati per flush: evita di inchiodare il loop. */
    static final int SPOOL_REPLAY_MAX = 100;

    private final AegisClient client;
    private final Sender sender;
    private final BatchBuffer buffer = new BatchBuffer(MAX_BATCH);
    private final Gson gson;
    private volatile boolean running = false;
    private Thread flusher;

    // Contatori perdita/invio: la perdita è misurata, mai invisibile.
    private final AtomicLong received = new AtomicLong();
    private final AtomicLong sent = new AtomicLong();
    private final AtomicLong droppedBufferFull = new AtomicLong();
    private final AtomicLong spooled = new AtomicLong();
    private final AtomicLong spoolReplayed = new AtomicLong();
    private final AtomicLong spoolCorrupt = new AtomicLong();
    private final AtomicLong sendFailed = new AtomicLong();

    // Spool lazy: la chiave deriva dal device secret, noto solo dopo enroll.
    private volatile FileSpool spool;
    private volatile String spoolSecretUsed;
    private volatile boolean spoolDisabledLogged;

    /** Strategia di invio — iniettabile per i test (default: HTTP reale). */
    interface Sender {
        void sendBatch(List<SystemEvent> batch) throws Exception;
        void sendSingle(SystemEvent event);
    }

    public EventOutbox(AegisClient client) {
        this(client, new Sender() {
            @Override
            public void sendBatch(List<SystemEvent> batch) throws Exception {
                client.sendEventsBatch(batch);
            }
            @Override
            public void sendSingle(SystemEvent event) {
                try { client.sendEvent(event); } catch (Exception ignored) {}
            }
        });
    }

    EventOutbox(AegisClient client, Sender sender) {
        this(client, sender, null);
    }

    /** Test: spool iniettato (dir temporanea). */
    EventOutbox(AegisClient client, Sender sender, FileSpool spool) {
        this.client = client;
        this.sender = sender;
        this.spool = spool;
        this.gson = new GsonBuilder()
                .registerTypeAdapter(java.time.Instant.class,
                        (JsonSerializer<java.time.Instant>) (src, typeOfSrc, context) ->
                                new JsonPrimitive(java.time.format.DateTimeFormatter.ISO_INSTANT.format(src)))
                .registerTypeAdapter(java.time.Instant.class,
                        (JsonDeserializer<java.time.Instant>) (json, typeOfT, context) -> {
                            try {
                                return java.time.Instant.parse(json.getAsString());
                            } catch (Exception e) {
                                return java.time.Instant.now();
                            }
                        })
                .create();
    }

    public void start() {
        running = true;
        flusher = new Thread(() -> {
            while (running) {
                try {
                    Thread.sleep(FLUSH_MS);
                    flush();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                } catch (Exception e) {
                    log.warn("Outbox flush failed: {}", e.getMessage());
                }
            }
            try { flush(); } catch (Exception ignored) {}
        }, "event-outbox");
        flusher.setDaemon(true);
        flusher.start();
    }

    public void stop() {
        running = false;
        if (flusher != null) flusher.interrupt();
        try { flush(); } catch (Exception ignored) {}
    }

    /** Accoda con bound: oltre MAX_BUFFER scarta i più vecchi CONTANDOLI. */
    public void add(SystemEvent event) {
        if (event == null) return;
        received.incrementAndGet();
        boolean full;
        synchronized (buffer) {
            while (buffer.size() >= MAX_BUFFER) {
                buffer.dropOldest();
                long d = droppedBufferFull.incrementAndGet();
                if (d % 100 == 1) {
                    log.warn("Outbox buffer pieno: {} eventi scartati (i più vecchi)", d);
                }
            }
            buffer.add(event);
            full = buffer.isFull();
        }
        if (full) flush();
    }

    public void flush() {
        List<SystemEvent> batch;
        synchronized (buffer) {
            if (buffer.isEmpty()) batch = new ArrayList<>();
            else batch = buffer.drain();
        }
        FileSpool sp = spoolForUse();
        if (sp != null && sp.hasData()) {
            // Rigioca prima lo spool (ordine preservato): al primo errore
            // transitorio si ferma e riaccoda tutto, niente duplicati persi.
            FileSpool.LoadResult loaded;
            try {
                loaded = sp.load(SPOOL_REPLAY_MAX);
            } catch (Exception e) {
                log.warn("Spool illeggibile ({}), riprovo al prossimo flush", e.getMessage());
                sendFailed.incrementAndGet();
                loaded = null;
            }
            if (loaded != null) {
                if (loaded.keyMismatch) {
                    log.warn("Spool in quarantena (chiave cambiata?): {} righe",
                            loaded.corrupt);
                    spoolCorrupt.addAndGet(loaded.corrupt);
                } else {
                    spoolCorrupt.addAndGet(loaded.corrupt);
                    if (!loaded.lines.isEmpty()) {
                        List<SystemEvent> replayed = deserializeAll(loaded.lines);
                        try {
                            sender.sendBatch(replayed);
                            sent.addAndGet(replayed.size());
                            spoolReplayed.addAndGet(replayed.size());
                        } catch (BatchUnsupportedException e) {
                            sendSingles(replayed);
                            sendSingles(batch);
                            return;
                        } catch (Exception e) {
                            requeueToSpool(sp, replayed, batch);
                            return;
                        }
                    }
                }
            }
        }
        if (batch.isEmpty()) return;
        try {
            sender.sendBatch(batch);
            sent.addAndGet(batch.size());
        } catch (BatchUnsupportedException e) {
            log.debug("Batch non supportato, fallback per-evento");
            sendSingles(batch);
        } catch (Exception e) {
            log.warn("Batch send failed: {}", e.getMessage());
            if (!saveToSpool(sp, batch)) {
                // Spool assente/pieno: perdita CONTATA, mai silenziosa.
                sendFailed.addAndGet(batch.size());
                log.warn("Eventi persi senza spool: {} (server irraggiungibile)", batch.size());
            }
        }
    }

    /** Snapshot contatori per salute sensore e dashboard (Fase 8). */
    public String stats() {
        int buffered;
        synchronized (buffer) {
            buffered = buffer.size();
        }
        return "received=" + received.get()
                + " sent=" + sent.get()
                + " buffered=" + buffered
                + " droppedBufferFull=" + droppedBufferFull.get()
                + " spooled=" + spooled.get()
                + " spoolReplayed=" + spoolReplayed.get()
                + " spoolCorrupt=" + spoolCorrupt.get()
                + " sendFailed=" + sendFailed.get();
    }

    public long getReceived() { return received.get(); }
    public long getSent() { return sent.get(); }
    public long getDroppedBufferFull() { return droppedBufferFull.get(); }
    public long getSpooled() { return spooled.get(); }
    public long getSpoolReplayed() { return spoolReplayed.get(); }
    public long getSpoolCorrupt() { return spoolCorrupt.get(); }
    public long getSendFailed() { return sendFailed.get(); }
    public int getBuffered() {
        synchronized (buffer) {
            return buffer.size();
        }
    }

    private void sendSingles(List<SystemEvent> events) {
        for (SystemEvent e2 : events) {
            try {
                sender.sendSingle(e2);
                sent.incrementAndGet();
            } catch (Exception e) {
                sendFailed.incrementAndGet();
            }
        }
    }

    /** Spool lazy: creato al primo uso quando il secret è noto. */
    private FileSpool spoolForUse() {
        if (spool != null) return spool;
        String secret = client != null ? client.getAgentSecret() : null;
        if (secret == null || secret.isBlank()) return null;
        if (secret.equals(spoolSecretUsed)) return null; // tentativo già fallito con questo secret
        try {
            java.nio.file.Path dir = java.nio.file.Paths.get(
                    com.aegis.guard.utils.Config.SPOOL_DIR);
            FileSpool created = new FileSpool(dir, FileSpool.deriveKey(secret),
                    com.aegis.guard.utils.Config.SPOOL_MAX_BYTES);
            spool = created;
            spoolSecretUsed = secret;
            return spool;
        } catch (Exception e) {
            spoolSecretUsed = secret;
            if (!spoolDisabledLogged) {
                spoolDisabledLogged = true;
                log.warn("Spool disabilitato ({}): solo buffer in memoria", e.getMessage());
            }
            return null;
        }
    }

    private boolean saveToSpool(FileSpool sp, List<SystemEvent> batch) {
        if (sp == null) return false;
        try {
            sp.save(serializeAll(batch));
            spooled.addAndGet(batch.size());
            return true;
        } catch (Exception e) {
            log.warn("Spool pieno/non scrivibile: {}", e.getMessage());
            return false;
        }
    }

    private void requeueToSpool(FileSpool sp, List<SystemEvent> replayed, List<SystemEvent> batch) {
        List<SystemEvent> all = new ArrayList<>(replayed.size() + batch.size());
        all.addAll(replayed);
        all.addAll(batch);
        if (!saveToSpool(sp, all)) {
            sendFailed.addAndGet(all.size());
        }
    }

    private List<String> serializeAll(List<SystemEvent> events) {
        List<String> out = new ArrayList<>(events.size());
        for (SystemEvent e : events) {
            if (e.getTimestamp() == null) {
                e.setTimestamp(java.time.Instant.now());
            }
            out.add(gson.toJson(e));
        }
        return out;
    }

    private List<SystemEvent> deserializeAll(List<String> lines) {
        List<SystemEvent> out = new ArrayList<>(lines.size());
        for (String l : lines) {
            try {
                SystemEvent e = gson.fromJson(l, SystemEvent.class);
                if (e != null) out.add(e);
            } catch (Exception e) {
                spoolCorrupt.incrementAndGet();
            }
        }
        return out;
    }

    /** Buffer puro: accumula e drena. Nessun I/O — testabile. */
    static final class BatchBuffer {
        private final int max;
        private final List<SystemEvent> items = new ArrayList<>();

        BatchBuffer(int max) {
            this.max = max;
        }

        void add(SystemEvent e) {
            items.add(e);
        }

        boolean isFull() {
            return items.size() >= max;
        }

        boolean isEmpty() {
            return items.isEmpty();
        }

        int size() {
            return items.size();
        }

        List<SystemEvent> drain() {
            List<SystemEvent> out = new ArrayList<>(items);
            items.clear();
            return out;
        }

        /** Scarta il più vecchio (backpressure): il chiamante CONTA lo scarto. */
        void dropOldest() {
            if (!items.isEmpty()) items.remove(0);
        }
    }
}
