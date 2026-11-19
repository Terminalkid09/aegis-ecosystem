// Package spool implements Guard's at-rest encrypted event spool.
//
// The format is intentionally simple: every record is a 4-byte big-endian
// ciphertext length followed by AES-256-GCM nonce+ciphertext. The key is
// derived from the device secret, so copying the spool to another host does
// not reveal queued telemetry. A truncated/corrupt record is treated as a
// hard error; the caller quarantines the file instead of silently losing
// events.
package spool

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

const (
	DefaultMaxBytes int64 = 50 * 1024 * 1024
	recordHeader          = 4
)

var (
	ErrDisabled = errors.New("spool disabilitato")
	ErrFull     = errors.New("spool pieno")
	ErrCorrupt  = errors.New("spool corrotto")
)

type Spool struct {
	path     string
	key      []byte
	maxBytes int64

	mu sync.Mutex
}

// New derives a 32-byte key from secret. An empty secret is rejected: an
// unencrypted spool would put command output and process telemetry at rest in
// clear text.
func New(path, secret string, maxBytes int64) (*Spool, error) {
	if path == "" {
		return nil, ErrDisabled
	}
	if secret == "" {
		return nil, fmt.Errorf("spool: device secret mancante")
	}
	if maxBytes <= 0 {
		maxBytes = DefaultMaxBytes
	}
	digest := sha256.Sum256([]byte(secret))
	return &Spool{
		path:     path,
		key:      append([]byte(nil), digest[:]...),
		maxBytes: maxBytes,
	}, nil
}

func (s *Spool) Path() string { return s.path }

func (s *Spool) Size() (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	info, err := os.Stat(s.path)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return info.Size(), nil
}

// Append encrypts one payload and appends it. The write is fsynced so a
// process crash after a successful return does not lose the record.
func (s *Spool) Append(payload []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("spool directory: %w", err)
	}
	record, err := s.seal(payload)
	if err != nil {
		return err
	}
	info, err := os.Stat(s.path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	current := int64(0)
	if info != nil {
		current = info.Size()
	}
	if current+int64(len(record)) > s.maxBytes {
		return ErrFull
	}
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("spool open: %w", err)
	}
	defer f.Close()
	if _, err := f.Write(record); err != nil {
		return fmt.Errorf("spool write: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("spool sync: %w", err)
	}
	return nil
}

func (s *Spool) seal(payload []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("spool nonce: %w", err)
	}
	ciphertext := aead.Seal(nil, nonce, payload, nil)
	record := make([]byte, recordHeader+len(nonce)+len(ciphertext))
	binary.BigEndian.PutUint32(record[:recordHeader], uint32(len(nonce)+len(ciphertext)))
	copy(record[recordHeader:], nonce)
	copy(record[recordHeader+len(nonce):], ciphertext)
	return record, nil
}

// ReadAll decrypts every record in order. It never returns a partially
// decrypted list: one bad record makes the whole file corrupt so the caller
// can preserve it for forensics.
func (s *Spool) ReadAll() ([][]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.readAllLocked()
}

func (s *Spool) readAllLocked() ([][]byte, error) {
	data, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	out := make([][]byte, 0)
	for offset := 0; offset < len(data); {
		if len(data)-offset < recordHeader {
			return nil, ErrCorrupt
		}
		length := int(binary.BigEndian.Uint32(data[offset : offset+recordHeader]))
		offset += recordHeader
		if length < aead.NonceSize() || offset+length > len(data) {
			return nil, ErrCorrupt
		}
		nonce := data[offset : offset+aead.NonceSize()]
		ciphertext := data[offset+aead.NonceSize() : offset+length]
		plain, err := aead.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return nil, ErrCorrupt
		}
		out = append(out, plain)
		offset += length
	}
	return out, nil
}

// Clear truncates after all records have been delivered.
func (s *Spool) Clear() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return os.Truncate(s.path, 0)
}

// Quarantine moves a corrupt spool aside. It is used when decryption fails so
// an operator can inspect the bytes instead of the agent deleting them.
func (s *Spool) Quarantine() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	dest := s.path + ".corrupt"
	_ = os.Remove(dest)
	return os.Rename(s.path, dest)
}
