package agent

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestPIDLockStaleAndAlien(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.pid")
	if err := os.WriteFile(path, []byte("99999999\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	lock, err := AcquirePID(path)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(data)) != strconv.Itoa(os.Getpid()) {
		t.Fatalf("pid file = %q", data)
	}
	lock.Release()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("pid file non rimosso")
	}
}
