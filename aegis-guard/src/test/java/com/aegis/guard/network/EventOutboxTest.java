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

        @Override
        public void sendBatch(List<SystemEvent> batch) throws Exception {
            if (batchFailure != null) throw batchFailure;
            batches.add(new ArrayList<>(batch));
        }

        @Override
        public void sendSingle(SystemEvent event) {
            singles.add(event);
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
                box.getSent() + box.getDroppedBufferFull() + box.getSendFailed() + box.getBuffered(),
                "ogni evento deve essere contato (inviato/scartato/fallito/buffered), stats=" + box.stats());
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
}
