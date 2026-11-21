package update

import (
	"os"
	"path/filepath"
	"testing"
)

const interopPub = "l2EBppcwnLG+lH4IW/2QB0iC3mxiMHmpWP+ty2nGWCg="
const interopManifest = `{"artifacts":[{"name":"aegis-guard-3.0.1.zip","sha256":"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"}],"key_id":"aegis-manifest-v1"}`
const interopSig = "2c39d931ed3accac06e98b5d55a0d726d21eadc7727f0f79aa2a7fcb1d69fcaf96f4627fef934b595bca1842733b4261d891beb18b3bb336d12e7a31bcb1d606"

func TestVerifyManifestInterop(t *testing.T) {
	if err := VerifyManifest([]byte(interopManifest), interopSig, interopPub); err != nil {
		t.Fatal(err)
	}
	if err := VerifyManifest([]byte(interopManifest+" "), interopSig, interopPub); err == nil {
		t.Fatal("manifest alterato accettato")
	}
	if !ManifestCovers([]byte(interopManifest), "aegis-guard-3.0.1.zip", "9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08") {
		t.Fatal("manifest non copre l'artefatto")
	}
	if ManifestCovers([]byte(interopManifest), "evil.zip", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08") {
		t.Fatal("manifest accetta nome errato")
	}
}

func TestStageAndSeal(t *testing.T) {
	dir := t.TempDir()
	pkg := filepath.Join(dir, "agent.pkg")
	if err := os.WriteFile(pkg, []byte("fake-agent-bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	sha, err := SHA256File(pkg)
	if err != nil {
		t.Fatal(err)
	}
	staged, err := Stage(pkg, sha, dir, "1.0.0", "1.0.1")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(staged); err != nil {
		t.Fatal(err)
	}
	if err := SealState(dir, "device-secret"); err != nil {
		t.Fatal(err)
	}
	gotStaged, gotSHA, err := VerifyState(dir, "device-secret")
	if err != nil {
		t.Fatal(err)
	}
	if gotStaged != staged || gotSHA != sha {
		t.Fatalf("state = %s/%s", gotStaged, gotSHA)
	}
	if _, _, err := VerifyState(dir, "wrong-secret"); err == nil {
		t.Fatal("segreto errato accettato")
	}
}

func TestStageRejectsMismatchAndDowngrade(t *testing.T) {
	dir := t.TempDir()
	pkg := filepath.Join(dir, "agent.pkg")
	if err := os.WriteFile(pkg, []byte("bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Stage(pkg, "0000000000000000000000000000000000000000000000000000000000000000", dir, "", ""); err == nil {
		t.Fatal("SHA errato accettato")
	}
	if _, err := os.Stat(pkg); !os.IsNotExist(err) {
		t.Fatal("file non rimosso dopo SHA errato")
	}
	pkg2 := filepath.Join(dir, "agent2.pkg")
	if err := os.WriteFile(pkg2, []byte("bytes2"), 0o600); err != nil {
		t.Fatal(err)
	}
	sha2, _ := SHA256File(pkg2)
	if _, err := Stage(pkg2, sha2, dir, "2.0.0", "1.9.9"); err == nil {
		t.Fatal("downgrade accettato")
	}
}

func TestAllowURL(t *testing.T) {
	brain := "https://aegis.local"
	if !AllowURL(brain, "https://aegis.local/api/v1/deploy/artifacts/agent.zip") {
		t.Fatal("URL Brain rifiutato")
	}
	if AllowURL(brain, "https://evil.example/api/v1/deploy/artifacts/agent.zip") {
		t.Fatal("origine esterna accettata")
	}
	if AllowURL(brain, "http://aegis.local/api/v1/deploy/artifacts/agent.zip") {
		t.Fatal("schema diverso accettato")
	}
	if AllowURL(brain, "https://aegis.local/api/v1/auth/login") {
		t.Fatal("path non artifact accettato")
	}
}

func TestVersionOrdering(t *testing.T) {
	if !IsNewer("1.9.0", "1.10.0") || IsNewer("2.0.0", "1.9.9") || IsNewer("1.0.0", "1.0.0") {
		t.Fatal("ordinamento versioni errato")
	}
}
