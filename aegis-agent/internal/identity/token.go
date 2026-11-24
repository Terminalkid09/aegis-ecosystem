package identity

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var ErrNotFound = errors.New("agent token not found")

// Token is the legacy NodeTrace identity format. Keeping it byte-compatible
// lets the Go sensor replace the Python runtime without a new Brain record.
type Token struct {
	Token     string `json:"token"`
	DeviceID  string `json:"device_id"`
	ServerURL string `json:"server_url,omitempty"`
}

func (t Token) Validate() error {
	if strings.TrimSpace(t.Token) == "" {
		return fmt.Errorf("token mancante")
	}
	if strings.TrimSpace(t.DeviceID) == "" {
		return fmt.Errorf("device_id mancante")
	}
	return nil
}

// Store reads and writes token.json. The path is always absolute in the
// caller; a relative path is rejected to avoid the legacy cwd-identity bug.
type Store struct {
	Path string
}

func NewStore(path string) *Store {
	return &Store{Path: path}
}

func (s *Store) Load() (Token, error) {
	if s == nil || strings.TrimSpace(s.Path) == "" {
		return Token{}, fmt.Errorf("token path mancante")
	}
	data, err := os.ReadFile(s.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return Token{}, ErrNotFound
		}
		return Token{}, fmt.Errorf("token %s is not readable: %w", s.Path, err)
	}
	var token Token
	if err := json.Unmarshal(data, &token); err != nil {
		return Token{}, fmt.Errorf("token %s corrotto: %w", s.Path, err)
	}
	if err := token.Validate(); err != nil {
		return Token{}, fmt.Errorf("token %s invalido: %w", s.Path, err)
	}
	return token, nil
}

func (s *Store) Save(token Token) error {
	if s == nil || strings.TrimSpace(s.Path) == "" {
		return fmt.Errorf("token path mancante")
	}
	if err := token.Validate(); err != nil {
		return err
	}
	parent := filepath.Dir(s.Path)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return fmt.Errorf("creazione directory token: %w", err)
	}

	tmp, err := os.CreateTemp(parent, ".token-*.tmp")
	if err != nil {
		return fmt.Errorf("creazione token temporaneo: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}

	if err := tmp.Chmod(0o600); err != nil && !errors.Is(err, os.ErrPermission) {
		cleanup()
		return fmt.Errorf("permessi token temporaneo: %w", err)
	}
	encoder := json.NewEncoder(tmp)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(token); err != nil {
		cleanup()
		return fmt.Errorf("scrittura token: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("sync token: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("chiusura token: %w", err)
	}
	if err := os.Rename(tmpName, s.Path); err != nil {
		// Windows can fail to replace an existing file; retry after removing
		// the destination. The temp file is still private.
		if removeErr := os.Remove(s.Path); removeErr != nil && !os.IsNotExist(removeErr) {
			_ = os.Remove(tmpName)
			return fmt.Errorf("sostituzione token: %w", err)
		}
		if err := os.Rename(tmpName, s.Path); err != nil {
			_ = os.Remove(tmpName)
			return fmt.Errorf("sostituzione token: %w", err)
		}
	}
	_ = os.Chmod(s.Path, 0o600)
	return nil
}

// CheckServerPin refuses a silent server change. An empty stored URL is a
// legacy token: the pin starts from the current server.
func CheckServerPin(stored, current string) error {
	current = strings.TrimSpace(current)
	if current == "" {
		return fmt.Errorf("server URL is not configured")
	}
	stored = strings.TrimSpace(stored)
	if stored == "" {
		return nil
	}
	if !strings.EqualFold(strings.TrimRight(stored, "/"), strings.TrimRight(current, "/")) {
		return fmt.Errorf("server cambiato (stored=%s current=%s): re-enroll richiesto", stored, current)
	}
	return nil
}

// CheckServerPinBase compares a legacy secret, whose server_url may be either
// the API base or a full enrollment endpoint, with the current API base. The
// path suffix is not part of the server identity; host, port and API prefix
// are.
func CheckServerPinBase(stored, current string) error {
	return CheckServerPin(serverPinBase(stored), serverPinBase(current))
}

func serverPinBase(raw string) string {
	raw = strings.TrimRight(strings.TrimSpace(raw), "/")
	for _, suffix := range []string{
		"/telemetry/report/batch", "/telemetry/report",
		"/telemetry/commands/ack", "/telemetry/commands",
		"/enroll/enroll", "/enroll/csr",
		"/register", "/update", "/heartbeat",
	} {
		if strings.HasSuffix(raw, suffix) {
			return strings.TrimSuffix(raw, suffix)
		}
	}
	return raw
}
