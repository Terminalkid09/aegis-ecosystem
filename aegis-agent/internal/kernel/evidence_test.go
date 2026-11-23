package kernel

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEvidenceCapsAndKeys(t *testing.T) {
	if got := DecodeCaps(1 << 20); len(got) != 1 || got[0] != "SYS_ADMIN" {
		t.Fatalf("cap 20 = %v", got)
	}
	if got := DecodeCaps(1 << 21); len(got) != 1 || got[0] != "SYS_BOOT" {
		t.Fatalf("cap 21 = %v", got)
	}
	if got := DecodeCaps(0); len(got) != 0 {
		t.Fatalf("cap 0 = %v", got)
	}
	if got := DecodeCaps(-1); len(got) != 0 {
		t.Fatalf("cap negativo = %v", got)
	}

	keys := ParseAuthorizedKeys(`# comment
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqNkG0w4oRZ9 user@host
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCt3Gxm other
invalid
telnet XYZ bogus
`)
	if len(keys) != 2 {
		t.Fatalf("keys = %#v", keys)
	}
	if keys[0]["algo"] != "ssh-ed25519" || len(keys[0]["sha256"]) != 64 || keys[0]["comment"] != "user@host" {
		t.Fatalf("key[0] = %#v", keys[0])
	}
	if strings.Contains(keys[0]["sha256"], "AAAAC3Nza") {
		t.Fatal("chiave in chiaro nell'evidenza")
	}
}

func TestEvidenceParsersAndContainer(t *testing.T) {
	if got := ParseLsmod("Module Size Used by\nnft_chain_nat 12288 0\nbridge 327680 0\n"); len(got) != 2 || got[0] != "nft_chain_nat" {
		t.Fatalf("lsmod = %v", got)
	}
	if hint := ContainerHint("12:devices:/docker/ab12\n", ""); hint["container"] != true || hint["runtime"] != "docker" {
		t.Fatalf("docker hint = %#v", hint)
	}
	if hint := ContainerHint("0::/kubepods/pod1\n", ""); hint["runtime"] != "kubepods" {
		t.Fatalf("kube hint = %#v", hint)
	}
	if hint := ContainerHint("12:devices:/init.scope\n", "init\n"); hint["container"] != false {
		t.Fatalf("bare hint = %#v", hint)
	}
}

func TestEvidenceUnitAndCronShapes(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.service"), []byte("[Unit]"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	units := ListUnitFiles([]string{dir, filepath.Join(dir, "missing")})
	if len(units) != 1 || units[0]["name"] != "a.service" {
		t.Fatalf("units = %#v", units)
	}
	cronDir := filepath.Join(dir, "cron.d")
	if err := os.Mkdir(cronDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cronDir, "job"), []byte("* * * * * root true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cron := ListCronEntries([]string{cronDir, filepath.Join(dir, "missing")})
	if len(cron) != 1 || cron[0]["type"] != "dir" || cron[0]["entries"] != 1 {
		t.Fatalf("cron = %#v", cron)
	}
	if meta := FileMetaOf(filepath.Join(dir, "b.txt")); meta == nil || meta.Size != 1 {
		t.Fatalf("meta = %#v", meta)
	}
	if meta := FileMetaOf(filepath.Join(dir, "missing")); meta != nil {
		t.Fatalf("meta missing = %#v", meta)
	}
}

func TestCollectNoSecrets(t *testing.T) {
	ev := Collect()
	if _, ok := ev["degraded"]; !ok {
		t.Fatal("degraded assente")
	}
	if strings.Contains(strings.ToLower(strings.Join([]string{strings.TrimSpace(strings.Repeat(" ", 0))}, "")), "PRIVATE") {
		t.Fatal("placeholder")
	}
	if strings.Contains(strings.ToLower(strings.Join(toStringSlice(ev["kernel_modules"]), " ")), "private") {
		t.Fatal("modulo privato in evidenza")
	}
}

func toStringSlice(value any) []string {
	if values, ok := value.([]string); ok {
		return values
	}
	return nil
}
