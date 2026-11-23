// Package outbox batches endpoint events and falls back to the encrypted
// spool on transient failures. It deliberately does not know HTTP endpoints:
// the caller supplies a Sender, which keeps retry/format tests local.
package outbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Terminalkid09/aegis-ecosystem/aegis-agent/internal/guard/spool"
	"github.com/Terminalkid09/aegis-ecosystem/aegis-agent/internal/transport"
)

const (
	DefaultBatchSize    = 25
	DefaultBufferSize   = 2000
	DefaultFlushEvery   = 500 * time.Millisecond
	DefaultReplayLimit  = 100
	spoolReplayAttempts = 3
)

type Sender interface {
	SendBatch(ctx context.Context, events [][]byte) error
	SendOne(ctx context.Context, event []byte) error
}

type Stats struct {
	Received  uint64
	Sent      uint64
	Dropped   uint64
	Spooled   uint64
	Replayed  uint64
	Corrupted uint64
	Failed    uint64
}

type Outbox struct {
	sender Sender
	spool  *spool.Spool
	log    *slog.Logger

	batchSize   int
	bufferSize  int
	flushEvery  time.Duration
	replayLimit int

	mu     sync.Mutex
	buffer [][]byte
	wake   chan struct{}
	done   chan struct{}

	running atomic.Bool
	stop    context.CancelFunc

	received  atomic.Uint64
	sent      atomic.Uint64
	dropped   atomic.Uint64
	spooled   atomic.Uint64
	replayed  atomic.Uint64
	corrupted atomic.Uint64
	failed    atomic.Uint64
}

func New(sender Sender, sp *spool.Spool, logger *slog.Logger) *Outbox {
	if logger == nil {
		logger = slog.Default()
	}
	return &Outbox{
		sender:      sender,
		spool:       sp,
		log:         logger,
		batchSize:   DefaultBatchSize,
		bufferSize:  DefaultBufferSize,
		flushEvery:  DefaultFlushEvery,
		replayLimit: DefaultReplayLimit,
		wake:        make(chan struct{}, 1),
		done:        make(chan struct{}),
	}
}

func (o *Outbox) Stats() Stats {
	return Stats{
		Received:  o.received.Load(),
		Sent:      o.sent.Load(),
		Dropped:   o.dropped.Load(),
		Spooled:   o.spooled.Load(),
		Replayed:  o.replayed.Load(),
		Corrupted: o.corrupted.Load(),
		Failed:    o.failed.Load(),
	}
}

func (o *Outbox) Add(value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("outbox marshal: %w", err)
	}
	o.mu.Lock()
	if len(o.buffer) >= o.bufferSize {
		// Bounded memory: drop the oldest and make the loss visible.
		o.buffer = o.buffer[1:]
		o.dropped.Add(1)
	}
	o.buffer = append(o.buffer, payload)
	o.mu.Unlock()
	o.received.Add(1)
	select {
	case o.wake <- struct{}{}:
	default:
	}
	return nil
}

// Run starts the flush loop and blocks until ctx is cancelled. It is safe to
// call once; Add may continue while it runs.
func (o *Outbox) Run(ctx context.Context) {
	if !o.running.CompareAndSwap(false, true) {
		return
	}
	runCtx, cancel := context.WithCancel(ctx)
	o.stop = cancel
	defer close(o.done)
	defer o.running.Store(false)
	ticker := time.NewTicker(o.flushEvery)
	defer ticker.Stop()

	_ = o.Flush(runCtx)
	for {
		select {
		case <-runCtx.Done():
			return
		case <-ticker.C:
			_ = o.Flush(runCtx)
		case <-o.wake:
			_ = o.Flush(runCtx)
		}
	}
}

func (o *Outbox) Stop() {
	if o.stop != nil {
		o.stop()
	}
}

// Flush sends spooled records first, then buffered records. A successful
// batch clears only what was sent. Transient failures are spooled; permanent
// 4xx payloads are dropped and counted, so one poison event never blocks the
// queue forever.
func (o *Outbox) Flush(ctx context.Context) error {
	if err := o.replaySpool(ctx); err != nil {
		return err
	}
	for {
		o.mu.Lock()
		if len(o.buffer) == 0 {
			o.mu.Unlock()
			return nil
		}
		n := o.batchSize
		if n > len(o.buffer) {
			n = len(o.buffer)
		}
		batch := make([][]byte, n)
		copy(batch, o.buffer[:n])
		o.buffer = o.buffer[n:]
		o.mu.Unlock()

		if err := o.deliver(ctx, batch); err != nil {
			return err
		}
	}
}

func (o *Outbox) replaySpool(ctx context.Context) error {
	if o.spool == nil {
		return nil
	}
	records, err := o.spool.ReadAll()
	if err != nil {
		if errors.Is(err, spool.ErrCorrupt) {
			o.corrupted.Add(1)
			_ = o.spool.Quarantine()
		}
		return nil
	}
	if len(records) == 0 {
		return nil
	}
	limit := o.replayLimit
	if limit > len(records) {
		limit = len(records)
	}
	attempts := 0
	for {
		if attempts >= spoolReplayAttempts {
			return nil
		}
		attempts++
		if err := o.deliver(ctx, records[:limit]); err != nil {
			return err
		}
		// All replay records delivered. Clear is safe because Add never writes
		// to the spool while the queue is healthy.
		if len(records) <= limit {
			if err := o.spool.Clear(); err != nil {
				o.failed.Add(1)
			} else {
				o.replayed.Add(uint64(len(records)))
			}
			return nil
		}
		records = records[limit:]
		if limit > len(records) {
			limit = len(records)
		}
	}
}

func (o *Outbox) deliver(ctx context.Context, batch [][]byte) error {
	if len(batch) == 0 {
		return nil
	}
	err := o.sender.SendBatch(ctx, batch)
	if err == nil {
		o.sent.Add(uint64(len(batch)))
		return nil
	}
	if batchUnsupported(err) {
		for _, event := range batch {
			if singleErr := o.sender.SendOne(ctx, event); singleErr != nil {
				if permanent(singleErr) {
					o.dropped.Add(1)
					o.failed.Add(1)
					continue
				}
				o.spoolOrDrop(batch)
				return nil
			}
			o.sent.Add(1)
		}
		return nil
	}
	if permanent(err) {
		o.dropped.Add(uint64(len(batch)))
		o.failed.Add(uint64(len(batch)))
		return nil
	}
	o.failed.Add(uint64(len(batch)))
	o.spoolOrDrop(batch)
	return nil
}

func (o *Outbox) spoolOrDrop(batch [][]byte) {
	if o.spool == nil {
		o.dropped.Add(uint64(len(batch)))
		return
	}
	for _, event := range batch {
		if err := o.spool.Append(event); err != nil {
			o.dropped.Add(1)
			o.failed.Add(1)
			continue
		}
		o.spooled.Add(1)
	}
}

func statusOf(err error) int {
	var httpErr *transport.HTTPError
	if errors.As(err, &httpErr) {
		return httpErr.StatusCode
	}
	return 0
}

func batchUnsupported(err error) bool {
	switch statusOf(err) {
	case http.StatusNotFound, http.StatusMethodNotAllowed, http.StatusNotImplemented:
		return true
	default:
		return false
	}
}

func permanent(err error) bool {
	switch statusOf(err) {
	case http.StatusBadRequest, http.StatusRequestEntityTooLarge, http.StatusUnsupportedMediaType, http.StatusUnprocessableEntity:
		return true
	default:
		return false
	}
}
