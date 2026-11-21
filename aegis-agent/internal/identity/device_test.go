package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func TestBuildCSRHasAgentCN(t *testing.T) {
	keyPEM, csrPEM, err := BuildCSR("agent-42")
	if err != nil {
		t.Fatal(err)
	}
	if len(keyPEM) == 0 || len(csrPEM) == 0 {
		t.Fatal("CSR vuota")
	}
	block, _ := pem.Decode(csrPEM)
	if block == nil {
		t.Fatal("CSR non PEM")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if csr.Subject.CommonName != "agent-42" {
		t.Fatalf("CN = %q", csr.Subject.CommonName)
	}
	if err := csr.CheckSignature(); err != nil {
		t.Fatal(err)
	}
}

func TestDeviceIdentityRoundTripAndRenewal(t *testing.T) {
	dir := t.TempDir()
	keyPEM, certPEM := selfSigned(t, 400)
	if _, _, err := SaveDeviceIdentity(dir, keyPEM, certPEM); err != nil {
		t.Fatal(err)
	}
	gotKey, gotCert, err := LoadDeviceIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotKey) != string(keyPEM) || string(gotCert) != string(certPEM) {
		t.Fatal("identità non round-trip")
	}
	if NeedsRenewal(gotCert, time.Now().UTC()) {
		t.Fatal("certificato a 400 giorni marcato in scadenza")
	}
	shortKey, shortCert := selfSigned(t, 10)
	if _, _, err := SaveDeviceIdentity(dir, shortKey, shortCert); err != nil {
		t.Fatal(err)
	}
	gotCert, err = func() ([]byte, error) { _, c, e := LoadDeviceIdentity(dir); return c, e }()
	if err != nil {
		t.Fatal(err)
	}
	if !NeedsRenewal(gotCert, time.Now().UTC()) {
		t.Fatal("certificato a 10 giorni non marcato in scadenza")
	}
	if b64, err := CertB64DER(gotCert); err != nil || b64 == "" {
		t.Fatalf("b64 = %q err=%v", b64, err)
	}
	if fp, err := CertFingerprint(gotCert); err != nil || len(fp) != 64 {
		t.Fatalf("fingerprint = %q err=%v", fp, err)
	}
}

func TestMachineIDIsStableAndNeverRaises(t *testing.T) {
	first := MachineID()
	if first != MachineID() {
		t.Fatal("machine id non stabile")
	}
}

func TestMissingDeviceIdentity(t *testing.T) {
	_, _, err := LoadDeviceIdentity(t.TempDir())
	if err != ErrNoDeviceIdentity {
		t.Fatalf("errore = %v", err)
	}
}

func selfSigned(t *testing.T, days int) ([]byte, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "agent-1"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(time.Duration(days) * 24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}
