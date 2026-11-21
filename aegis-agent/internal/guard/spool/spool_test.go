package spool

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestSpoolRoundTripAndCorruptQuarantine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.spool")
	s, err := New(path, "device-secret", 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	payloads := [][]byte{[]byte(`{"a":1}`), []byte(`{"b":"due"}`)}
	for _, payload := range payloads {
		if err := s.Append(payload); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(payloads) {
		t.Fatalf("got %d records, want %d", len(got), len(payloads))
	}
	for i := range got {
		if !bytes.Equal(got[i], payloads[i]) {
			t.Fatalf("record %d = %q, want %q", i, got[i], payloads[i])
		}
	}
	if err := s.Clear(); err != nil {
		t.Fatal(err)
	}
	got, err = s.ReadAll()
	if err != nil || len(got) != 0 {
		t.Fatalf("after clear: %v %d", err, len(got))
	}
}

func TestSpoolRejectsMissingSecretAndFull(t *testing.T) {
	if _, err := New(filepath.Join(t.TempDir(), "x"), "", 100); err == nil {
		t.Fatal("expected missing secret error")
	}
	path := filepath.Join(t.TempDir(), "events.spool")
	s, err := New(path, "secret", 100)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Append(bytes.Repeat([]byte("x"), 30)); err != nil {
		t.Fatal(err)
	}
	if err := s.Append(bytes.Repeat([]byte("x"), 30)); !errors.Is(err, ErrFull) {
		t.Fatalf("expected ErrFull, got %v", err)
	}
}

func TestSpoolCorruptRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.spool")
	s, err := New(path, "secret", 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Append([]byte("payload")); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	data[len(data)-1] ^= 0xff
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReadAll(); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("expected corrupt, got %v", err)
	}
	if err := s.Quarantine(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".corrupt"); err != nil {
		t.Fatal(err)
	}
}
