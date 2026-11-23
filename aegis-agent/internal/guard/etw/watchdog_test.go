package etw

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/Terminalkid09/aegis-ecosystem/aegis-agent/internal/event"
)

func TestNextBackoffIsBounded(t *testing.T) {
	if got := nextBackoff(0, 0); got != defaultBackoffMin {
		t.Fatalf("zero backoff = %s", got)
	}
	if got := nextBackoff(time.Second, 5*time.Second); got != 2*time.Second {
		t.Fatalf("double = %s", got)
	}
	if got := nextBackoff(4*time.Second, 5*time.Second); got != 5*time.Second {
		t.Fatalf("cap = %s", got)
	}
}

func TestSupervisorRestartsAfterStreamEnds(t *testing.T) {
	var mu sync.Mutex
	starts := 0
	s := &Supervisor{
		log:        slog.Default(),
		backoffMin: 5 * time.Millisecond,
		backoffMax: 20 * time.Millisecond,
		startFn: func(ctx context.Context, emit func(event.Event)) (*Stream, bool) {
			mu.Lock()
			starts++
			n := starts
			mu.Unlock()
			if n == 1 {
				stream := &Stream{done: make(chan struct{})}
				go func() {
					time.Sleep(10 * time.Millisecond)
					stream.Stop()
				}()
				return stream, true
			}
			return nil, false
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.Start(ctx)

	deadline := time.Now().Add(500 * time.Millisecond)
	for {
		mu.Lock()
		n := starts
		mu.Unlock()
		if n >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("watchdog did not restart after the stream ended")
		}
		time.Sleep(5 * time.Millisecond)
	}
	s.Stop()
	if s.Restarts() < 1 {
		t.Fatalf("restarts = %d", s.Restarts())
	}
	if s.Running() {
		t.Fatal("supervisor still reports running after Stop")
	}
}
