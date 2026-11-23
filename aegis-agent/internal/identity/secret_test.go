package identity

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestSecretStoreRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret.json")
	store := NewSecretStore(path)
	if _, err := store.Load(); err != ErrNotFound {
		t.Fatalf("missing error = %v", err)
	}
	secret := Secret{AgentID: "guard-1", AgentSecret: "s3cret", ServerURL: "https://aegis.local/api/v1"}
	if err := store.Save(secret); err != nil {
		t.Fatal(err)
	}
	got, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got != secret {
		t.Fatalf("secret = %#v", got)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0o077 != 0 {
			t.Fatalf("permessi secret = %o", info.Mode().Perm())
		}
	}
}

func TestSecretValidation(t *testing.T) {
	if err := (Secret{AgentID: "a"}).Validate(); err == nil {
		t.Fatal("secret senza agent_secret accettato")
	}
	if err := (Secret{AgentSecret: "s"}).Validate(); err == nil {
		t.Fatal("secret senza agent_id accettato")
	}
}
