package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	KeyFile  = "device.key"
	CertFile = "device.crt"
	RenewFor = 30 * 24 * time.Hour
)

var ErrNoDeviceIdentity = errors.New("identità device assente")

func DevicePaths(dir string) (keyPath, certPath string) {
	return filepath.Join(dir, KeyFile), filepath.Join(dir, CertFile)
}

// BuildCSR creates a new EC P-256 key and a CSR with CN=agentID. The private
// key never leaves the host.
func BuildCSR(agentID string) (keyPEM, csrPEM []byte, err error) {
	if strings.TrimSpace(agentID) == "" {
		return nil, nil, fmt.Errorf("agent_id mancante per la CSR")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generazione chiave EC: %w", err)
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: agentID},
	}, key)
	if err != nil {
		return nil, nil, fmt.Errorf("creazione CSR: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal chiave: %w", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	csrPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	return keyPEM, csrPEM, nil
}

func SaveDeviceIdentity(dir string, keyPEM, certPEM []byte) (string, string, error) {
	if strings.TrimSpace(dir) == "" {
		return "", "", fmt.Errorf("identity dir mancante")
	}
	if !strings.Contains(string(keyPEM), "PRIVATE KEY") ||
		!strings.Contains(string(certPEM), "CERTIFICATE") {
		return "", "", fmt.Errorf("identità non PEM valida")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", "", fmt.Errorf("creazione identity dir: %w", err)
	}
	keyPath, certPath := DevicePaths(dir)
	if err := writePrivate(keyPath, keyPEM); err != nil {
		return "", "", err
	}
	if err := writePrivate(certPath, certPEM); err != nil {
		return "", "", err
	}
	return keyPath, certPath, nil
}

func LoadDeviceIdentity(dir string) (keyPEM, certPEM []byte, err error) {
	keyPath, certPath := DevicePaths(dir)
	keyPEM, err = os.ReadFile(keyPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, ErrNoDeviceIdentity
		}
		return nil, nil, fmt.Errorf("lettura device.key: %w", err)
	}
	certPEM, err = os.ReadFile(certPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, ErrNoDeviceIdentity
		}
		return nil, nil, fmt.Errorf("lettura device.crt: %w", err)
	}
	if !strings.Contains(string(keyPEM), "PRIVATE KEY") ||
		!strings.Contains(string(certPEM), "CERTIFICATE") {
		quarantine(keyPath)
		quarantine(certPath)
		return nil, nil, ErrNoDeviceIdentity
	}
	return keyPEM, certPEM, nil
}

func NeedsRenewal(certPEM []byte, now time.Time) bool {
	if len(certPEM) == 0 {
		return true
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return true
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return true
	}
	return !cert.NotAfter.After(now.Add(RenewFor))
}

func CertB64DER(certPEM []byte) (string, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", fmt.Errorf("certificato non PEM")
	}
	return base64.StdEncoding.EncodeToString(block.Bytes), nil
}

func CertFingerprint(certPEM []byte) (string, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", fmt.Errorf("certificato non PEM")
	}
	sum := sha256.Sum256(block.Bytes)
	return hex.EncodeToString(sum[:]), nil
}

func writePrivate(path string, data []byte) error {
	parent := filepath.Dir(path)
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return fmt.Errorf("creazione directory %s: %w", parent, err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("scrittura %s: %w", path, err)
	}
	_ = os.Chmod(path, 0o600)
	return nil
}

func quarantine(path string) {
	_ = os.Rename(path, path+".bad")
}
