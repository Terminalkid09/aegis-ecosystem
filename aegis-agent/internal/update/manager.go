package update

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	PendingDir = "update.pending"
	StateFile  = "update.state"
)

type Artifact struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
}

type Manifest struct {
	Artifacts []Artifact `json:"artifacts"`
	KeyID     string     `json:"key_id,omitempty"`
}

func VerifyManifest(manifest []byte, signatureHex, pubkeyB64 string) error {
	if len(manifest) == 0 || strings.TrimSpace(signatureHex) == "" || strings.TrimSpace(pubkeyB64) == "" {
		return fmt.Errorf("manifest, firma o chiave mancanti")
	}
	pubRaw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(pubkeyB64))
	if err != nil || len(pubRaw) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid Ed25519 public key")
	}
	sig, err := hex.DecodeString(strings.TrimSpace(signatureHex))
	if err != nil || len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("invalid Ed25519 signature")
	}
	if !ed25519.Verify(ed25519.PublicKey(pubRaw), manifest, sig) {
		return fmt.Errorf("invalid Ed25519 manifest")
	}
	return nil
}

func ManifestCovers(manifest []byte, name, expectedSHA string) bool {
	if len(manifest) == 0 || name == "" || expectedSHA == "" {
		return false
	}
	var doc Manifest
	if err := json.Unmarshal(manifest, &doc); err != nil {
		return false
	}
	for _, artifact := range doc.Artifacts {
		if artifact.Name == name && strings.EqualFold(artifact.SHA256, expectedSHA) {
			return true
		}
	}
	return false
}

func SHA256File(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func IsNewer(current, target string) bool {
	if strings.TrimSpace(target) == "" || strings.EqualFold(strings.TrimSpace(target), "latest") {
		return true
	}
	if strings.TrimSpace(current) == "" {
		return true
	}
	return compareVersion(target, current) > 0
}

func compareVersion(a, b string) int {
	left, right := versionParts(a), versionParts(b)
	for i := 0; i < len(left) || i < len(right); i++ {
		var l, r int
		if i < len(left) {
			l = left[i]
		}
		if i < len(right) {
			r = right[i]
		}
		if l < r {
			return -1
		}
		if l > r {
			return 1
		}
	}
	return 0
}

func versionParts(raw string) []int {
	raw = strings.TrimLeft(strings.TrimSpace(raw), "vV")
	parts := strings.Split(raw, ".")
	out := make([]int, 0, len(parts))
	for _, part := range parts {
		value := 0
		for _, char := range part {
			if char < '0' || char > '9' {
				break
			}
			value = value*10 + int(char-'0')
		}
		out = append(out, value)
	}
	return out
}

// Stage verifies SHA-256 and version, then moves the package into
// update.pending/ and records update.state. Apply is deliberately deferred to
// restart, as in NodeTrace.
func Stage(downloadedPath, expectedSHA, baseDir, currentVersion, targetVersion string) (string, error) {
	if targetVersion != "" && !IsNewer(currentVersion, targetVersion) {
		_ = os.Remove(downloadedPath)
		return "", fmt.Errorf("rollback rifiutato: current=%s target=%s", currentVersion, targetVersion)
	}
	actual, err := SHA256File(downloadedPath)
	if err != nil {
		return "", fmt.Errorf("SHA-256: %w", err)
	}
	if !strings.EqualFold(actual, strings.TrimSpace(expectedSHA)) {
		_ = os.Remove(downloadedPath)
		return "", fmt.Errorf("SHA-256 mismatch: expected=%s actual=%s", expectedSHA, actual)
	}
	pending := filepath.Join(baseDir, PendingDir)
	if err := os.MkdirAll(pending, 0o700); err != nil {
		return "", fmt.Errorf("creazione update.pending: %w", err)
	}
	staged := filepath.Join(pending, filepath.Base(downloadedPath))
	if err := os.Rename(downloadedPath, staged); err != nil {
		return "", fmt.Errorf("stage package: %w", err)
	}
	state := fmt.Sprintf("staged=%s\nsha256=%s\nstatus=pending-restart\n", staged, actual)
	if err := os.WriteFile(filepath.Join(baseDir, StateFile), []byte(state), 0o600); err != nil {
		return "", fmt.Errorf("scrittura update.state: %w", err)
	}
	return staged, nil
}

func SealState(baseDir, secret string) error {
	if strings.TrimSpace(secret) == "" {
		return fmt.Errorf("secret mancante")
	}
	path := filepath.Join(baseDir, StateFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if strings.Contains(string(data), "mac=") {
		return fmt.Errorf("update.state già sigillato")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(data)
	sealed := append(data, []byte(fmt.Sprintf("mac=%s\n", hex.EncodeToString(mac.Sum(nil))))...)
	return os.WriteFile(path, sealed, 0o600)
}

func VerifyState(baseDir, secret string) (staged, sha string, err error) {
	if strings.TrimSpace(secret) == "" {
		return "", "", fmt.Errorf("secret mancante")
	}
	data, err := os.ReadFile(filepath.Join(baseDir, StateFile))
	if err != nil {
		return "", "", err
	}
	values := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if ok {
			values[strings.TrimSpace(key)] = strings.TrimSpace(value)
		}
	}
	if values["staged"] == "" || values["sha256"] == "" || values["mac"] == "" {
		return "", "", fmt.Errorf("update.state incompleto o manomesso")
	}
	body := fmt.Sprintf("staged=%s\nsha256=%s\nstatus=pending-restart\n", values["staged"], values["sha256"])
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(body))
	if !hmac.Equal([]byte(hex.EncodeToString(mac.Sum(nil))), []byte(strings.ToLower(values["mac"]))) {
		return "", "", fmt.Errorf("update.state MAC invalido: possibile tampering")
	}
	return values["staged"], values["sha256"], nil
}

// AllowURL is the fail-closed SSRF gate: same origin as the pinned Brain and
// only the artifact path.
func AllowURL(brainOrigin, raw string) bool {
	brain, err := url.Parse(strings.TrimSpace(brainOrigin))
	if err != nil || brain.Scheme == "" || brain.Host == "" {
		return false
	}
	target, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || target.Scheme == "" || target.Host == "" {
		return false
	}
	if !strings.EqualFold(brain.Scheme, target.Scheme) || !strings.EqualFold(brain.Host, target.Host) {
		return false
	}
	return strings.HasPrefix(target.Path, "/api/v1/deploy/artifacts/")
}

func Download(ctx context.Context, client *http.Client, artifactURL, destination, token, agentID, certHeader string) error {
	if client == nil {
		client = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, artifactURL, nil)
	if err != nil {
		return err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if agentID != "" {
		req.Header.Set("X-Agent-Id", agentID)
	}
	if certHeader != "" {
		req.Header.Set("X-Client-Cert-Hash", certHeader)
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download artifact: HTTP %d", resp.StatusCode)
	}
	file, err := os.Create(destination)
	if err != nil {
		return err
	}
	if _, err := io.Copy(file, resp.Body); err != nil {
		_ = file.Close()
		_ = os.Remove(destination)
		return err
	}
	return file.Close()
}

func ArtifactName(rawURL string) string {
	if parsed, err := url.Parse(rawURL); err == nil {
		if name := filepath.Base(parsed.Path); name != "." && name != "/" {
			return name
		}
	}
	return filepath.Base(rawURL)
}

func TempDownloadPath(dir string) (string, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	file, err := os.CreateTemp(dir, "aegis-update-*.pkg")
	if err != nil {
		return "", err
	}
	name := file.Name()
	if err := file.Close(); err != nil {
		return "", err
	}
	return name, nil
}

// WaitForDownload is a small helper for tests and future retry wrappers.
func WaitForDownload(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
