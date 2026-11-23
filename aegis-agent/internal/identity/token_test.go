package identity

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestStoreSaveLoadAndReplace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "token.json")
	store := NewStore(path)
	token := Token{
		Token:     "nt-test",
		DeviceID:  "7c9e6679-7425-40de-944b-e07fc1f90ae7",
		ServerURL: "https://aegis.local/api/v1/register",
	}
	if err := store.Save(token); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded != token {
		t.Fatalf("token caricato = %+v", loaded)
	}

	token.Token = "nt-replaced"
	if err := store.Save(token); err != nil {
		t.Fatal(err)
	}
	loaded, err = store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if loaded.Token != "nt-replaced" {
		t.Fatalf("token dopo replace = %q", loaded.Token)
	}
}

func TestLoadMissing(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "token.json"))
	_, err := store.Load()
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("errore = %v", err)
	}
}

func TestCheckServerPin(t *testing.T) {
	if err := CheckServerPin("https://aegis.local/api/v1/register/", "https://AEGIS.local/api/v1/register"); err != nil {
		t.Fatal(err)
	}
	if err := CheckServerPin("", "https://aegis.local/api/v1/register"); err != nil {
		t.Fatal(err)
	}
	if err := CheckServerPin("https://old.local/api/v1/register", "https://aegis.local/api/v1/register"); err == nil {
		t.Fatal("cambio server accettato")
	}
}

func TestCheckServerPinBaseAcceptsLegacyGuardSecret(t *testing.T) {
	if err := CheckServerPinBase("https://aegis.local/api/v1", "https://AEGIS.local/api/v1/enroll/enroll"); err != nil {
		t.Fatal(err)
	}
	if err := CheckServerPinBase("https://aegis.local/api/v1/enroll/enroll", "https://aegis.local/api/v1"); err != nil {
		t.Fatal(err)
	}
	if err := CheckServerPinBase("https://aegis.local/api/v1/enroll/enroll", "https://other.local/api/v1/enroll/enroll"); err == nil {
		t.Fatal("cambio host accettato")
	}
}
