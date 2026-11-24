package identity

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Secret is the legacy Guard secret.json format. It is intentionally
// separate from NodeTrace token.json: cutover B must preserve the existing
// Guard agent_id/agent_secret record.
type Secret struct {
	AgentID     string `json:"agent_id"`
	AgentSecret string `json:"agent_secret"`
	ServerURL   string `json:"server_url,omitempty"`
}

func (s Secret) Validate() error {
	if strings.TrimSpace(s.AgentID) == "" {
		return fmt.Errorf("agent_id mancante")
	}
	if strings.TrimSpace(s.AgentSecret) == "" {
		return fmt.Errorf("agent_secret mancante")
	}
	return nil
}

type SecretStore struct {
	Path string
}

func NewSecretStore(path string) *SecretStore {
	return &SecretStore{Path: path}
}

func (s *SecretStore) Load() (Secret, error) {
	if s == nil || strings.TrimSpace(s.Path) == "" {
		return Secret{}, fmt.Errorf("secret path mancante")
	}
	data, err := os.ReadFile(s.Path)
	if err != nil {
		if os.IsNotExist(err) {
			return Secret{}, ErrNotFound
		}
		return Secret{}, fmt.Errorf("secret %s is not readable: %w", s.Path, err)
	}
	var secret Secret
	if err := json.Unmarshal(data, &secret); err != nil {
		return Secret{}, fmt.Errorf("secret %s corrotto: %w", s.Path, err)
	}
	if err := secret.Validate(); err != nil {
		return Secret{}, fmt.Errorf("secret %s invalido: %w", s.Path, err)
	}
	return secret, nil
}

func (s *SecretStore) Save(secret Secret) error {
	if s == nil || strings.TrimSpace(s.Path) == "" {
		return fmt.Errorf("secret path mancante")
	}
	if err := secret.Validate(); err != nil {
		return err
	}
	parent := filepath.Dir(s.Path)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return fmt.Errorf("creazione directory secret: %w", err)
	}
	tmp, err := os.CreateTemp(parent, ".secret-*.tmp")
	if err != nil {
		return fmt.Errorf("creazione secret temporaneo: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}
	if err := tmp.Chmod(0o600); err != nil && !os.IsPermission(err) {
		cleanup()
		return fmt.Errorf("permessi secret temporaneo: %w", err)
	}
	encoder := json.NewEncoder(tmp)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(secret); err != nil {
		cleanup()
		return fmt.Errorf("scrittura secret: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		cleanup()
		return fmt.Errorf("sync secret: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("chiusura secret: %w", err)
	}
	if err := os.Rename(tmpName, s.Path); err != nil {
		if removeErr := os.Remove(s.Path); removeErr != nil && !os.IsNotExist(removeErr) {
			_ = os.Remove(tmpName)
			return fmt.Errorf("sostituzione secret: %w", err)
		}
		if err := os.Rename(tmpName, s.Path); err != nil {
			_ = os.Remove(tmpName)
			return fmt.Errorf("sostituzione secret: %w", err)
		}
	}
	_ = os.Chmod(s.Path, 0o600)
	return nil
}
