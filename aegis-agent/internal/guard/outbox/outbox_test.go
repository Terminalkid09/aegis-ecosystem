package outbox

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/Terminalkid09/aegis-ecosystem/aegis-agent/internal/guard/spool"
	"github.com/Terminalkid09/aegis-ecosystem/aegis-agent/internal/transport"
)

type fakeSender struct {
	mu       sync.Mutex
	batches  [][][]byte
	ones     [][]byte
	err      error
	failNext int
}

func (f *fakeSender) SendBatch(ctx context.Context, events [][]byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failNext > 0 {
		f.failNext--
		return f.err
	}
	copied := make([][]byte, len(events))
	for i := range events {
		copied[i] = append([]byte(nil), events[i]...)
	}
	f.batches = append(f.batches, copied)
	return nil
}

func (f *fakeSender) SendOne(ctx context.Context, event []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failNext > 0 {
		f.failNext--
		return f.err
	}
	f.ones = append(f.ones, append([]byte(nil), event...))
	return nil
}

func TestFlushBatchAndPermanentDrop(t *testing.T) {
	sender := &fakeSender{}
	o := New(sender, nil, nil)
	if err := o.Add(map[string]int{"a": 1}); err != nil {
		t.Fatal(err)
	}
	if err := o.Add(map[string]int{"a": 2}); err != nil {
		t.Fatal(err)
	}
	if err := o.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(sender.batches) != 1 || len(sender.batches[0]) != 2 {
		t.Fatalf("batches = %+v", sender.batches)
	}

	sender.err = &transport.HTTPError{StatusCode: http.StatusUnprocessableEntity, Body: "poison"}
	sender.failNext = 1
	o2 := New(sender, nil, nil)
	_ = o2.Add(map[string]int{"poison": 1})
	if err := o2.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if o2.Stats().Dropped != 1 {
		t.Fatalf("dropped = %d", o2.Stats().Dropped)
	}
}

func TestTransientFailureSpoolsAndReplays(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.spool")
	sp, err := spool.New(path, "secret", 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	sender := &fakeSender{err: &transport.HTTPError{StatusCode: http.StatusInternalServerError}, failNext: 1}
	o := New(sender, sp, nil)
	_ = o.Add(map[string]string{"event": "one"})
	if err := o.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if o.Stats().Spooled != 1 {
		t.Fatalf("spooled = %d", o.Stats().Spooled)
	}
	if err := o.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if o.Stats().Replayed != 1 || o.Stats().Sent != 1 || len(sender.batches) != 1 {
		t.Fatalf("stats=%+v batches=%d", o.Stats(), len(sender.batches))
	}
}

func TestBatchUnsupportedFallsBackToSingles(t *testing.T) {
	sender := &fakeSender{err: &transport.HTTPError{StatusCode: http.StatusNotFound}, failNext: 1}
	o := New(sender, nil, nil)
	_ = o.Add(map[string]string{"event": "one"})
	if err := o.Flush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(sender.ones) != 1 || o.Stats().Sent != 1 {
		t.Fatalf("ones=%d stats=%+v", len(sender.ones), o.Stats())
	}
}

func TestBufferBoundCountsLoss(t *testing.T) {
	o := New(&fakeSender{}, nil, nil)
	o.bufferSize = 2
	for i := 0; i < 4; i++ {
		_ = o.Add(map[string]int{"n": i})
	}
	if o.Stats().Dropped != 2 || len(o.buffer) != 2 {
		t.Fatalf("dropped=%d buffer=%d", o.Stats().Dropped, len(o.buffer))
	}
}

func TestRunFlushesOnAddAndStops(t *testing.T) {
	sender := &fakeSender{}
	o := New(sender, nil, nil)
	o.flushEvery = time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	go o.Run(ctx)
	_ = o.Add(map[string]int{"n": 1})
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if o.Stats().Sent == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if o.Stats().Sent != 1 {
		t.Fatal(fmt.Sprintf("sent=%d", o.Stats().Sent))
	}
	_ = errors.New("keep imports stable")
}
