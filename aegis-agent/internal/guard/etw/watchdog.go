// Package etw's supervisor watches the helper process, not the kernel session.
// ETW remains a user-mode source: a local administrator can stop the agent or
// the watchdog itself. What this fixes is the ordinary failure mode where the
// helper exits or its session is closed and the endpoint would silently fall
// back to polling forever. The capability and sensor state expose the restart
// count and the last reason instead of pretending ETW is still active.
package etw

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/Terminalkid09/aegis-ecosystem/aegis-agent/internal/event"
)

const (
	defaultBackoffMin = 2 * time.Second
	defaultBackoffMax = 60 * time.Second
	stableRun         = 60 * time.Second
)

type Supervisor struct {
	source  *Source
	startFn func(context.Context, func(event.Event)) (*Stream, bool)
	emit    func(event.Event)
	log     *slog.Logger

	backoffMin time.Duration
	backoffMax time.Duration

	mu         sync.Mutex
	cancel     context.CancelFunc
	stream     *Stream
	attempts   int
	lastReason string
}

func NewSupervisor(source *Source, emit func(event.Event), logger *slog.Logger) *Supervisor {
	if logger == nil {
		logger = slog.Default()
	}
	var start func(context.Context, func(event.Event)) (*Stream, bool)
	if source != nil {
		start = source.Start
	}
	return &Supervisor{
		source: source, startFn: start, emit: emit, log: logger,
		backoffMin: defaultBackoffMin, backoffMax: defaultBackoffMax,
	}
}

func (s *Supervisor) Start(ctx context.Context) {
	if s == nil || s.startFn == nil {
		return
	}
	s.mu.Lock()
	if s.cancel != nil {
		s.mu.Unlock()
		return
	}
	runCtx, cancel := context.WithCancel(ctx)
	s.cancel = cancel
	s.mu.Unlock()
	go s.run(runCtx)
}

func (s *Supervisor) Stop() {
	if s == nil {
		return
	}
	s.mu.Lock()
	cancel := s.cancel
	stream := s.stream
	s.cancel = nil
	s.stream = nil
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if stream != nil {
		stream.Stop()
	}
}

func (s *Supervisor) Running() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.stream != nil && s.stream.Running()
}

func (s *Supervisor) Restarts() int {
	if s == nil {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.attempts <= 1 {
		return 0
	}
	return s.attempts - 1
}

func (s *Supervisor) LastReason() string {
	if s == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastReason
}

func (s *Supervisor) setReason(reason string) {
	s.mu.Lock()
	s.lastReason = reason
	s.mu.Unlock()
}

func (s *Supervisor) run(ctx context.Context) {
	backoff := s.backoffMin
	if backoff <= 0 {
		backoff = defaultBackoffMin
	}
	for {
		if ctx.Err() != nil {
			return
		}
		s.mu.Lock()
		s.attempts++
		s.mu.Unlock()
		stream, ok := s.startFn(ctx, s.emit)
		if !ok {
			reason := "start-failed"
			if s.source != nil {
				if available, why := s.source.Available(ctx); !available && why != "" {
					reason = why
				}
			}
			s.setReason(reason)
			s.log.Warn("ETW watchdog: collector not started", "reason", reason, "retry_in", backoff)
			if !sleepContext(ctx, backoff) {
				return
			}
			backoff = nextBackoff(backoff, s.backoffMax)
			continue
		}

		s.mu.Lock()
		s.stream = stream
		s.lastReason = ""
		s.mu.Unlock()
		started := time.Now()

		select {
		case <-ctx.Done():
			stream.Stop()
			return
		case <-stream.Done():
		}

		s.mu.Lock()
		if s.stream == stream {
			s.stream = nil
		}
		s.lastReason = "stream-ended"
		s.mu.Unlock()
		s.log.Warn("ETW watchdog: collector stream ended; restarting", "backoff", backoff)

		// A helper that stayed up for a while is likely a real session loss,
		// not a crash loop: restart quickly. A short-lived child keeps the
		// exponential backoff to avoid spinning on a policy/privilege error.
		if time.Since(started) >= stableRun {
			backoff = s.backoffMin
		}
		if !sleepContext(ctx, backoff) {
			return
		}
		backoff = nextBackoff(backoff, s.backoffMax)
	}
}

func nextBackoff(current, maximum time.Duration) time.Duration {
	if current <= 0 {
		return defaultBackoffMin
	}
	if maximum <= 0 {
		maximum = defaultBackoffMax
	}
	next := current * 2
	if next > maximum {
		return maximum
	}
	return next
}

func sleepContext(ctx context.Context, d time.Duration) bool {
	if d <= 0 {
		return ctx.Err() == nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
