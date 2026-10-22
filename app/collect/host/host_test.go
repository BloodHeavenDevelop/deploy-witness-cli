package host

import (
	"os"
	"path/filepath"
	"testing"
)

// DW-86: whether the host has IPv6 decides whether a publish with no host_ip also
// lands on [::]; a missing IPv6 tree is a kernel without IPv6.
func TestIPv6Posture(t *testing.T) {
	root := t.TempDir()
	if ipv6, _ := ipv6Posture(filepath.Join(root, "absent")); ipv6 != "disabled" {
		t.Errorf("no IPv6 tree: %q", ipv6)
	}
	if err := os.MkdirAll(filepath.Join(root, "conf", "all"), 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(name, value string) {
		if err := os.WriteFile(filepath.Join(root, name), []byte(value+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("conf/all/disable_ipv6", "0")
	write("bindv6only", "0")
	if ipv6, only := ipv6Posture(root); ipv6 != "enabled" || only != "0" {
		t.Errorf("enabled: %q %q", ipv6, only)
	}
	write("conf/all/disable_ipv6", "1")
	if ipv6, _ := ipv6Posture(root); ipv6 != "disabled" {
		t.Errorf("disabled: %q", ipv6)
	}
}

// DW-88: a bind source is examined by stat alone — and never created.
func TestStatPathNeverCreates(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "app.conf")
	if err := os.WriteFile(file, []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "current")
	dangling := filepath.Join(dir, "broken")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "nowhere"), dangling); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "data", "pg")

	for path, want := range map[string]string{
		dir: "exists/directory", file: "exists/file", link: "exists/file", dangling: "exists/symlink", missing: "missing/",
	} {
		info := StatPath(path)
		if got := info.State + "/" + info.Type; got != want {
			t.Errorf("%s: %s, want %s", path, got, want)
		}
	}
	if info := StatPath(file); info.Mode != "0640" || info.UID != os.Getuid() {
		t.Errorf("mode/owner: %+v", info)
	}
	if info := StatPath(link); info.SymlinkTarget != file {
		t.Errorf("symlink target: %+v", info)
	}
	if !StatPath(dangling).Dangling {
		t.Error("a dangling symlink must say so")
	}
	if _, err := os.Stat(filepath.Join(dir, "data")); !os.IsNotExist(err) {
		t.Fatal("examining a missing source created it")
	}

	if os.Geteuid() != 0 {
		locked := filepath.Join(dir, "locked")
		if err := os.Mkdir(locked, 0o000); err != nil {
			t.Fatal(err)
		}
		defer func() { _ = os.Chmod(locked, 0o700) }()
		if info := StatPath(filepath.Join(locked, "inside")); info.State != "unknown" || info.Error == "" {
			t.Errorf("a path this account cannot reach is unknown, not missing: %+v", info)
		}
	}
}
