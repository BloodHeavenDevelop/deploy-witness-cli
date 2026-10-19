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
