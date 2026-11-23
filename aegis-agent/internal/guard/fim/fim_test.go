package fim

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Terminalkid09/aegis-ecosystem/aegis-agent/internal/event"
)

func TestFIMEmitsFileModified(t *testing.T) {
	dir := t.TempDir()
	events := make(chan event.Event, 8)
	m, err := New("agent-1", "Linux", "4.3", "host", func(ev event.Event) { events <- ev }, nil)
	if err != nil {
		t.Skipf("fsnotify non disponibile: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m.Start(ctx)
	defer m.Close()
	if count, missing, err := m.Apply([]string{dir}, false); err != nil || count != 1 || len(missing) != 0 {
		t.Fatalf("apply count=%d missing=%v err=%v", count, missing, err)
	}
	path := filepath.Join(dir, "new.txt")
	if err := os.WriteFile(path, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	select {
	case ev := <-events:
		if ev.EventType != "FILE_MODIFIED" || ev.ProcessPath != "FILE" || ev.FileHash == "" {
			t.Fatalf("event = %+v", ev)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("nessun evento FIM")
	}
	if m.Available() != true {
		t.Fatal("monitor non disponibile")
	}
}
