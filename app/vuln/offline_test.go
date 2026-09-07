package vuln

import (
	"archive/zip"
	"os"
	"path/filepath"
	"testing"
)

const recordOpenSSL = `{
  "id": "DSA-5000-1",
  "aliases": ["CVE-2024-0001"],
  "summary": "openssl: buffer overflow",
  "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
  "affected": [{
    "package": {"ecosystem": "Debian:12", "name": "openssl"},
    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.0.13-1"}]}]
  }]
}`

const recordUnrelated = `{
  "id": "DSA-9999-1",
  "affected": [{
    "package": {"ecosystem": "Debian:12", "name": "some-package-not-installed"},
    "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}]}]
  }]
}`

func wanted() map[string]bool { return map[string]bool{"openssl": true} }

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoadOfflineJSONArray(t *testing.T) {
	path := writeTemp(t, "all.json", "[\n"+recordOpenSSL+",\n"+recordUnrelated+"\n]")

	db, err := LoadOffline(path, wanted(), "Debian:12")
	if err != nil {
		t.Fatal(err)
	}
	if db.Scanned != 2 {
		t.Errorf("scanned = %d, want 2", db.Scanned)
	}
	// Filtering at load time is what keeps a full OSV export usable.
	if db.Indexed != 1 {
		t.Errorf("indexed = %d, want 1 (only installed packages)", db.Indexed)
	}
	if len(db.Lookup("openssl")) != 1 {
		t.Error("openssl should be indexed")
	}
	if len(db.Lookup("some-package-not-installed")) != 0 {
		t.Error("an uninstalled package must not be indexed")
	}
}

func TestLoadOfflineNDJSON(t *testing.T) {
	path := writeTemp(t, "all.jsonl", recordOpenSSL+"\n"+recordUnrelated+"\n")

	db, err := LoadOffline(path, wanted(), "Debian:12")
	if err != nil {
		t.Fatal(err)
	}
	if db.Scanned != 2 || db.Indexed != 1 {
		t.Errorf("scanned/indexed = %d/%d, want 2/1", db.Scanned, db.Indexed)
	}
}

func TestLoadOfflineDirectory(t *testing.T) {
	dir := t.TempDir()
	nested := filepath.Join(dir, "debian")
	if err := os.MkdirAll(nested, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nested, "DSA-5000-1.json"), []byte(recordOpenSSL), 0o600); err != nil {
		t.Fatal(err)
	}

	db, err := LoadOffline(dir, wanted(), "Debian:12")
	if err != nil {
		t.Fatal(err)
	}
	if db.Indexed != 1 {
		t.Errorf("indexed = %d, want 1", db.Indexed)
	}
}

func TestLoadOfflineZip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "all.zip")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}

	archive := zip.NewWriter(file)
	entry, err := archive.Create("DSA-5000-1.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := entry.Write([]byte(recordOpenSSL)); err != nil {
		t.Fatal(err)
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	file.Close()

	db, err := LoadOffline(path, wanted(), "Debian:12")
	if err != nil {
		t.Fatal(err)
	}
	if db.Indexed != 1 {
		t.Errorf("indexed = %d, want 1", db.Indexed)
	}
}

func TestLoadOfflineFiltersByEcosystem(t *testing.T) {
	path := writeTemp(t, "all.json", recordOpenSSL)

	// A Debian advisory must not be indexed for an Alpine host.
	db, err := LoadOffline(path, wanted(), "Alpine:v3.19")
	if err != nil {
		t.Fatal(err)
	}
	if db.Indexed != 0 {
		t.Errorf("indexed = %d, want 0 across ecosystems", db.Indexed)
	}
}

func TestLoadOfflineMissingPath(t *testing.T) {
	if _, err := LoadOffline(filepath.Join(t.TempDir(), "nope.json"), wanted(), "Debian:12"); err == nil {
		t.Error("a missing dataset must be an error, not an empty result")
	}
}
