package com.aegis.guard.network;

import java.util.ArrayList;
import java.util.List;

import com.aegis.guard.models.SystemEvent;
import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

class EventOutboxTest {

    private static SystemEvent ev(long pid) {
        return new SystemEvent("a1", pid, 0, "", "p" + pid, "", "", "Linux", "PROCESS_CREATED");
    }

    static class FakeSender implements EventOutbox.Sender {
        final List<List<SystemEvent>> batches = new ArrayList<>();
        final List<SystemEvent> singles = new ArrayList<>();
        Exception batchFailure = null;
        boolean singleAck = true;

        @Override
        public void sendBatch(List<SystemEvent> batch) throws Exception {
            if (batchFailure != null) throw batchFailure;
            batches.add(new ArrayList<>(batch));
        }

        @Override
        public boolean sendSingle(SystemEvent event) {
            if (!singleAck) return false;
            singles.add(event);
            return true;
        }
    }

    @Test
    void bufferAccumulatesAndDrains() {
        EventOutbox.BatchBuffer b = new EventOutbox.BatchBuffer(3);
        assertTrue(b.isEmpty());
        b.add(ev(1));
        b.add(ev(2));
        assertEquals(2, b.size());
        assertFalse(b.isFull());
        b.add(ev(3));
        assertTrue(b.isFull());
        List<SystemEvent> out = b.drain();
        assertEquals(3, out.size());
        assertTrue(b.isEmpty());
    }

    @Test
    void addFlushesWhenFull() {
        FakeSender s = new FakeSender();
        EventOutbox box = new EventOutbox(null, s);
        for (int i = 1; i <= EventOutbox.MAX_BATCH; i++) box.add(ev(i));
        assertEquals(1, s.batches.size(), "raggiunto MAX_BATCH deve flushare subito");
        assertEquals(EventOutbox.MAX_BATCH, s.batches.get(0).size());
    }

    @Test
    void manualFlushSendsPartialBatch() {
        FakeSender s = new FakeSender();
        EventOutbox box = new EventOutbox(null, s);
        box.add(ev(1));
        box.add(ev(2));
        box.flush();
        assertEquals(1, s.batches.size());
        assertEquals(2, s.batches.get(0).size());
    }

    @Test
    void unsupportedBatchFallsBackToSingle() {
        FakeSender s = new FakeSender();
        s.batchFailure = new BatchUnsupportedException("no batch endpoint");
        EventOutbox box = new EventOutbox(null, s);
        box.add(ev(1));
        box.add(ev(2));
        box.flush();
        assertTrue(s.batches.isEmpty());
        assertEquals(2, s.singles.size(), "fallback per-evento su brain vecchio");
        assertEquals(2, box.getSent());
    }

    @Test
    void transientFailureSpoolsWhenSpoolPresent() throws Exception {
        java.nio.file.Path dir =
                java.nio.file.Files.createTempDirectory("outbox-spool");
        FileSpool spool = new FileSpool(dir, FileSpool.deriveKey("test-secret-xyz"));
        FakeSender s = new FakeSender();
        s.batchFailure = new java.io.IOException("server down");
        EventOutbox box = new EventOutbox(null, s, spool);
        box.add(ev(1));
        box.add(ev(2));
        box.flush();
        assertTrue(s.batches.isEmpty() && s.singles.isEmpty());
        assertTrue(spool.hasData(), "batch deve finire nello spool cifrato");
        assertEquals(2, box.getSpooled());

        // Server tornato: replay in ordine, niente duplicati.
        s.batchFailure = null;
        box.flush();
        assertEquals(1, s.batches.size());
        assertEquals(2, s.batches.get(0).size());
        assertEquals(2, box.getSpoolReplayed());
        assertEquals(0, box.getSendFailed());
    }

    @Test
    void transientFailureWithoutSpoolCountsLoss() {
        FakeSender s = new FakeSender();
        s.batchFailure = new java.io.IOException("server down");
        EventOutbox box = new EventOutbox(null, s);
        box.add(ev(1));
        box.flush();
        assertEquals(1, box.getSendFailed(), "perdita senza spool deve essere contata");
        assertEquals(0, box.getSent());
    }

    @Test
    void bufferBoundHoldsUnderConcurrentStorm() throws Exception {
        // Sender lento + 3 produttori concorrenti: lo storm reale in cui il
        // buffer potrebbe crescere. Invarianti (niente timing): mai oltre il
        // tetto, e ogni evento ricevuto è contato da qualche parte.
        FakeSender s = new FakeSender() {
            @Override
            public void sendBatch(List<SystemEvent> batch) throws Exception {
                try {
                    Thread.sleep(2);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
                super.sendBatch(batch);
            }
        };
        EventOutbox box = new EventOutbox(null, s);
        int producers = 3, perProducer = 300;
        Thread[] ts = new Thread[producers];
        for (int t = 0; t < producers; t++) {
            final long base = (long) t * perProducer;
            ts[t] = new Thread(() -> {
                for (long i = 1; i <= perProducer; i++) box.add(ev(base + i));
            });
            ts[t].start();
        }
        for (Thread t : ts) t.join(30000);
        box.flush();
        long received = box.getReceived();
        assertEquals((long) producers * perProducer, received);
        assertTrue(box.getBuffered() <= EventOutbox.MAX_BUFFER);
        assertEquals(received,
                box.getSent() + box.getDroppedBufferFull() + box.getSendFailed()
                        + box.getRejectedPermanent() + box.getBuffered(),
                "ogni evento deve essere contato (inviato/scartato/fallito/respinto/buffered), stats=" + box.stats());
    }

    @Test
    void clampForTransportTruncatesAndDeclaresIt() {
        // Un solo campo troppo lungo faceva rispondere 422 all'intero batch.
        SystemEvent e = ev(1);
        e.setCommandLine("x".repeat(12000));
        e.setProcessPath("C:\\" + "a".repeat(2000));
        EventOutbox.clampForTransport(e);
        assertEquals(4096, e.getCommandLine().length());
        assertEquals(1024, e.getProcessPath().length());
        assertTrue(e.getQuality().startsWith("truncated:"), e.getQuality());
        assertTrue(e.getQuality().contains("commandLine"), e.getQuality());
        assertTrue(e.getQuality().contains("processPath"), e.getQuality());
    }

    @Test
    void clampLeavesShortFieldsAndQualityUntouched() {
        SystemEvent e = ev(1);
        e.setCommandLine("notepad.exe");
        e.setProcessPath("C:\\Windows\\System32\\notepad.exe");
        EventOutbox.clampForTransport(e);
        assertEquals("notepad.exe", e.getCommandLine());
        assertNull(e.getQuality(), "nessuna troncatura = nessun marcatore");
    }

    @Test
    void permanentRejectDropsOnlyOffendingEvents() throws Exception {
        // Il 422 del brain indica l'indice colpevole: si scarta quello e si
        // conservano gli altri, invece di perdere l'intero batch.
        java.nio.file.Path dir =
                java.nio.file.Files.createTempDirectory("outbox-reject");
        FileSpool spool = new FileSpool(dir, FileSpool.deriveKey("test-secret-xyz"));
        FakeSender s = new FakeSender();
        s.batchFailure = new PermanentRejectException("HTTP 422",
                "{\"detail\":[{\"loc\":[\"body\",2,\"commandLine\"],"
                        + "\"msg\":\"String should have at most 4096 characters\"}]}");

        EventOutbox box = new EventOutbox(null, s, spool);
        for (long i = 1; i <= 5; i++) box.add(ev(i));
        box.flush();

        assertEquals(1, box.getRejectedPermanent(), "solo l'evento colpevole");
        assertEquals(4, box.getSpooled(), "i sani restano in coda, non persi");
        assertEquals(0, box.getSendFailed());
    }

    @Test
    void permanentlyRejectedEventInSpoolDoesNotBlockTheQueueForever() throws Exception {
        // Lo scenario osservato in esercizio: lo spool conteneva un evento che
        // il brain respingeva per contenuto. Riaccodato a ogni flush, restava
        // in testa alla coda: OGNI flush falliva di nuovo e nessun evento di
        // quel sensore arrivava mai. Ora il colpevole esce dalla coda e i sani
        // vengono consegnati.
        java.nio.file.Path dir =
                java.nio.file.Files.createTempDirectory("outbox-poison");
        FileSpool spool = new FileSpool(dir, FileSpool.deriveKey("test-secret-xyz"));
        FakeSender s = new FakeSender();

        s.batchFailure = new java.io.IOException("server down");
        EventOutbox box = new EventOutbox(null, s, spool);
        for (long i = 1; i <= 3; i++) box.add(ev(i));
        box.flush();
        assertEquals(3, box.getSpooled());

        // Brain tornato, ma respinge per contenuto l'elemento all'indice 1.
        s.batchFailure = new PermanentRejectException("HTTP 422",
                "{\"detail\":[{\"loc\":[\"body\",1,\"seq\"],"
                        + "\"msg\":\"Input should be greater than or equal to 0\"}]}");
        box.flush();
        assertEquals(1, box.getRejectedPermanent());
        assertTrue(spool.hasData(), "i 2 sani devono restare in coda");

        // Flush successivo: la coda si svuota davvero (prima era infinita).
        s.batchFailure = null;
        int sentBefore = s.batches.size();
        box.flush();
        assertEquals(sentBefore + 1, s.batches.size());
        List<SystemEvent> delivered = s.batches.get(s.batches.size() - 1);
        assertEquals(2, delivered.size());
        assertEquals(1, delivered.get(0).getPid(), "primo sano, ordine preservato");
        assertEquals(3, delivered.get(1).getPid(), "il colpevole (pid 2) e' uscito");
        assertFalse(spool.hasData(), "la coda non deve restare bloccata");
    }

    @Test
    void permanentRejectWithoutParseableIndexesDropsAndCounts() {
        // Corpo illeggibile: non si sa chi sia il colpevole. Si scarta e si
        // CONTA — l'alternativa (riaccodare tutto) era il ciclo infinito.
        FakeSender s = new FakeSender();
        s.batchFailure = new PermanentRejectException("HTTP 422", "<html>bad gateway</html>");
        EventOutbox box = new EventOutbox(null, s);
        box.add(ev(1));
        box.add(ev(2));
        box.flush();
        assertEquals(2, box.getRejectedPermanent());
        assertEquals(0, box.getSendFailed());
        assertTrue(box.stats().contains("rejectedPermanent=2"), box.stats());
    }

    @Test
    void permanentRejectIndexesAreParsedFromFastApiBody() {
        assertTrue(PermanentRejectException.parseIndexes(null).isEmpty());
        assertTrue(PermanentRejectException.parseIndexes("not json").isEmpty());
        assertEquals(List.of(2), PermanentRejectException
                .parseIndexes("{\"detail\":[{\"loc\":[\"body\",2,\"seq\"]}]}"));
        assertEquals(List.of(0, 5), PermanentRejectException
                .parseIndexes("[{\"loc\":[\"body\",5,\"seq\"]},"
                        + "{\"loc\":[\"body\",0,\"pid\"]}]"));
    }

    @Test
    void statsSnapshotCounts() {
        FakeSender s = new FakeSender();
        EventOutbox box = new EventOutbox(null, s);
        box.add(ev(1));
        box.flush();
        assertEquals(1, box.getReceived());
        assertEquals(1, box.getSent());
        assertTrue(box.stats().contains("received=1"));
        assertTrue(box.stats().contains("sent=1"));
    }

    @Test
    void emptyFlushIsNoop() {
        FakeSender s = new FakeSender();
        new EventOutbox(null, s).flush();
        assertTrue(s.batches.isEmpty() && s.singles.isEmpty());
    }

    @Test
    void unackedSinglesAreNotCountedAsSent() {
        // Audit: prima i singoli falliti incrementavano comunque `sent`.
        FakeSender s = new FakeSender();
        s.batchFailure = new BatchUnsupportedException("no batch");
        s.singleAck = false;
        EventOutbox box = new EventOutbox(null, s);
        box.add(ev(1));
        box.add(ev(2));
        box.flush();
        assertEquals(0, box.getSent());
        assertEquals(2, box.getSendFailed());
        assertTrue(s.singles.isEmpty());
    }
}
