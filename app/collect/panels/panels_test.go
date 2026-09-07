package panels

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
)

// Every test here builds a fake root under t.TempDir(). Nothing reads the machine
// the tests run on: a detector that needed a host in a particular state would only
// ever be exercised on the developer's laptop.

// touchDir creates a directory, with parents.
func touchDir(t *testing.T, root, rel string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(root, rel), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", rel, err)
	}
}

// touchFile creates a file with the given content, with parents.
func touchFile(t *testing.T, root, rel, content string) {
	t.Helper()
	path := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(rel), err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
}

func TestDetect(t *testing.T) {
	cases := []struct {
		name string
		// build populates the fake root.
		build func(t *testing.T, root string)
		// wantName is the panel expected, and the only one expected.
		wantName string
		// wantVersion is exact; "" means the panel hides it.
		wantVersion string
		// wantEvidencePath is the marker the evidence must name.
		wantEvidencePath string
		// wantEvidenceHas are substrings the evidence must contain.
		wantEvidenceHas []string
		wantPorts       []int
	}{
		{
			name: "plesk from its installation root",
			build: func(t *testing.T, root string) {
				touchDir(t, root, "usr/local/psa")
				touchFile(t, root, "usr/local/psa/version", "18.0.62 Ubuntu 20.04 1800240321.09\n")
			},
			wantName:         "Plesk",
			wantVersion:      "18.0.62",
			wantEvidencePath: "usr/local/psa",
			wantPorts:        []int{80, 443, 8443, 8880},
		},
		{
			name: "cpanel from its installation root",
			build: func(t *testing.T, root string) {
				touchDir(t, root, "usr/local/cpanel")
				touchFile(t, root, "usr/local/cpanel/version", "11.126.0.14\n")
			},
			wantName:         "cPanel/WHM",
			wantVersion:      "11.126.0.14",
			wantEvidencePath: "usr/local/cpanel",
			wantPorts:        []int{80, 443, 2082, 2083, 2086, 2087, 2095, 2096},
		},
		{
			name: "directadmin hides its version and is still present",
			build: func(t *testing.T, root string) {
				touchDir(t, root, "usr/local/directadmin")
			},
			wantName:         "DirectAdmin",
			wantVersion:      "",
			wantEvidencePath: "usr/local/directadmin",
			wantPorts:        []int{80, 443, 2222},
		},
		{
			name: "ispmanager from mgr5",
			build: func(t *testing.T, root string) {
				touchDir(t, root, "usr/local/mgr5")
			},
			wantName:         "ISPmanager",
			wantEvidencePath: "usr/local/mgr5",
			wantPorts:        []int{80, 443, 1500},
		},
		{
			name: "hestia version comes out of its shell config",
			build: func(t *testing.T, root string) {
				touchDir(t, root, "usr/local/hestia")
				touchFile(t, root, "usr/local/hestia/conf/hestia.conf",
					"WEB_SYSTEM='nginx'\nVERSION='1.8.11'\nDB_SYSTEM='mysql'\n")
			},
			wantName:         "HestiaCP",
			wantVersion:      "1.8.11",
			wantEvidencePath: "usr/local/hestia",
			wantPorts:        []int{80, 443, 8083},
		},
		{
			name: "vestacp is not mistaken for hestia",
			build: func(t *testing.T, root string) {
				touchDir(t, root, "usr/local/vesta")
				touchFile(t, root, "usr/local/vesta/conf/vesta.conf", "VERSION='0.9.8'\n")
			},
			wantName:         "VestaCP",
			wantVersion:      "0.9.8",
			wantEvidencePath: "usr/local/vesta",
			wantPorts:        []int{80, 443, 8083},
		},
		{
			name: "webmin does not claim the web server's ports",
			build: func(t *testing.T, root string) {
				touchDir(t, root, "usr/libexec/webmin")
				touchFile(t, root, "etc/webmin/version", "2.111\n")
			},
			wantName:         "Webmin",
			wantVersion:      "2.111",
			wantEvidencePath: "usr/libexec/webmin",
			wantPorts:        []int{10000, 20000},
		},
		{
			name: "cyberpanel version survives a json version file",
			build: func(t *testing.T, root string) {
				touchDir(t, root, "usr/local/CyberCP")
				touchFile(t, root, "usr/local/CyberCP/version.txt", `{"version": "2.3", "build": 5}`)
			},
			wantName:         "CyberPanel",
			wantVersion:      "2.3",
			wantEvidencePath: "usr/local/CyberCP",
			wantPorts:        []int{80, 443, 7080, 8090},
		},
		{
			name: "ispconfig",
			build: func(t *testing.T, root string) {
				touchDir(t, root, "usr/local/ispconfig")
			},
			wantName:         "ISPConfig",
			wantEvidencePath: "usr/local/ispconfig",
			wantPorts:        []int{80, 443, 8080},
		},
		{
			name: "coolify from its install manifest",
			build: func(t *testing.T, root string) {
				touchFile(t, root, "data/coolify/source/docker-compose.yml", "services: {}\n")
			},
			wantName:         "Coolify",
			wantEvidencePath: "data/coolify/source/docker-compose.yml",
			wantEvidenceHas:  []string{"further marker"},
			wantPorts:        []int{80, 443, 6001, 6002, 8000},
		},
		{
			name: "caprover from its captain config",
			build: func(t *testing.T, root string) {
				touchFile(t, root, "captain/data/config-captain.json", "{}\n")
			},
			wantName:         "CapRover",
			wantEvidencePath: "captain/data/config-captain.json",
			wantPorts:        []int{80, 443, 996, 3000},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			c.build(t, root)

			found, concerns := detect(root)
			if len(concerns) != 0 {
				t.Fatalf("detect reported concerns on a readable fixture: %v", concerns)
			}
			if len(found) != 1 {
				t.Fatalf("detect found %d panel(s), want exactly 1: %+v", len(found), found)
			}

			panel := found[0]
			if panel.Name != c.wantName {
				t.Errorf("name = %q, want %q", panel.Name, c.wantName)
			}
			if panel.Version != c.wantVersion {
				t.Errorf("version = %q, want %q", panel.Version, c.wantVersion)
			}
			if want := filepath.Join(root, c.wantEvidencePath); !strings.Contains(panel.Evidence, want) {
				t.Errorf("evidence = %q, want it to name %q", panel.Evidence, want)
			}
			for _, want := range c.wantEvidenceHas {
				if !strings.Contains(panel.Evidence, want) {
					t.Errorf("evidence = %q, want it to contain %q", panel.Evidence, want)
				}
			}
			if !equalInts(panel.OwnsPorts, c.wantPorts) {
				t.Errorf("ownsPorts = %v, want %v", panel.OwnsPorts, c.wantPorts)
			}
			// Running is never established by detect: it takes systemd or a
			// container state, and a filesystem marker is neither.
			if panel.Running {
				t.Error("running = true from a filesystem marker alone")
			}
		})
	}
}

func TestDetectPleskEvidenceIsExactlyTheMarker(t *testing.T) {
	root := t.TempDir()
	touchDir(t, root, "usr/local/psa")

	found, _ := detect(root)
	if len(found) != 1 {
		t.Fatalf("found %d panel(s), want 1", len(found))
	}
	if want := filepath.Join(root, "usr/local/psa"); found[0].Evidence != want {
		t.Errorf("evidence = %q, want exactly %q", found[0].Evidence, want)
	}
}

func TestDetectEmptyRootFindsNothing(t *testing.T) {
	found, concerns := detect(t.TempDir())
	if len(found) != 0 {
		t.Errorf("found %d panel(s) on an empty root: %+v", len(found), found)
	}
	if len(concerns) != 0 {
		t.Errorf("concerns on an empty root: %v", concerns)
	}
}

// A data directory outlives the panel that made it, so presence established from
// one has to say that it was inferred rather than observed.
func TestDetectWeakMarkerLowersTheClaim(t *testing.T) {
	cases := []struct {
		name  string
		build func(t *testing.T, root string)
		panel string
	}{
		{
			name:  "coolify data directory only",
			build: func(t *testing.T, root string) { touchDir(t, root, "data/coolify") },
			panel: "Coolify",
		},
		{
			name: "portainer docker volume only",
			build: func(t *testing.T, root string) {
				touchDir(t, root, "var/lib/docker/volumes/portainer_data")
			},
			panel: "Portainer",
		},
		{
			name: "a leftover unit file only",
			build: func(t *testing.T, root string) {
				touchFile(t, root, "usr/lib/systemd/system/portainer.service", "[Unit]\n")
			},
			panel: "Portainer",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			c.build(t, root)

			found, _ := detect(root)
			if len(found) != 1 || found[0].Name != c.panel {
				t.Fatalf("detect = %+v, want exactly %s", found, c.panel)
			}
			if !strings.Contains(found[0].Evidence, "inferred") {
				t.Errorf("evidence = %q, want it to admit the presence was inferred",
					found[0].Evidence)
			}
		})
	}
}

// An unreadable marker is a gap, not an absence — and how loudly it is reported
// depends on what it would have proved. /var/lib/docker is root-only on most
// hosts, and degrading the whole section because Portainer's data directory could
// not be checked would make the status useless on every unprivileged run.
func TestDetectUnreadableMarkerIsAConcernSizedToTheMarker(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: no path is unreadable, so there is nothing to observe")
	}

	root := t.TempDir()
	touchDir(t, root, "var/lib/docker/volumes")
	closed := filepath.Join(root, "var/lib/docker/volumes")
	if err := os.Chmod(closed, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(closed, 0o755) })

	found, concerns := detect(root)
	if len(found) != 0 {
		t.Errorf("found %+v; an unreadable marker must not become a panel", found)
	}
	if len(concerns) == 0 {
		t.Fatal("no concern raised for an unreadable marker path")
	}
	for _, c := range concerns {
		if c.critical {
			t.Errorf("concern %q is critical; a weak marker only feeds an inference", c.message)
		}
		if !strings.Contains(c.message, "Portainer") {
			t.Errorf("concern %q does not say which panel could not be ruled out", c.message)
		}
	}
}

// The same failure on a strong marker does degrade: an entire panel could be
// hiding behind it.
func TestDetectUnreadableStrongMarkerIsCritical(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: no path is unreadable, so there is nothing to observe")
	}

	root := t.TempDir()
	touchDir(t, root, "usr/local")
	closed := filepath.Join(root, "usr/local")
	if err := os.Chmod(closed, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(closed, 0o755) })

	_, concerns := detect(root)
	var critical int
	for _, c := range concerns {
		if c.critical {
			critical++
		}
	}
	if critical == 0 {
		t.Errorf("concerns = %v; an unreadable /usr/local hides Plesk, cPanel and more, "+
			"and has to degrade the section", concerns)
	}
}

func TestDetectAaPanelReadsItsAdminPort(t *testing.T) {
	root := t.TempDir()
	touchDir(t, root, "www/server/panel/class")
	touchFile(t, root, "www/server/panel/data/port.pl", "7801\n")

	found, _ := detect(root)
	if len(found) != 1 || found[0].Name != "aaPanel" {
		t.Fatalf("detect = %+v, want aaPanel", found)
	}
	if !containsInt(found[0].OwnsPorts, 7801) {
		t.Errorf("ownsPorts = %v, want the port from port.pl (7801)", found[0].OwnsPorts)
	}
	// The documented defaults are kept as well: the file says where the panel is
	// now, not where it was when the vhosts were written.
	for _, port := range []int{80, 443, 888} {
		if !containsInt(found[0].OwnsPorts, port) {
			t.Errorf("ownsPorts = %v, want it to include %d", found[0].OwnsPorts, port)
		}
	}
}

func TestDetectTwoPanelsAtOnce(t *testing.T) {
	root := t.TempDir()
	touchDir(t, root, "usr/local/psa")
	touchDir(t, root, "var/lib/portainer")

	found, _ := detect(root)
	if len(found) != 2 {
		t.Fatalf("found %d panel(s), want 2: %+v", len(found), found)
	}
	// Sorted by name, so the order is stable across runs.
	if found[0].Name != "Plesk" || found[1].Name != "Portainer" {
		t.Errorf("names = %q, %q; want Plesk, Portainer", found[0].Name, found[1].Name)
	}
}

func TestVirtualminIsReportedSeparatelyFromWebmin(t *testing.T) {
	root := t.TempDir()
	touchFile(t, root, "etc/webmin/virtual-server/config", "\n")
	touchFile(t, root, "etc/webmin/miniserv.conf", "port=10000\n")

	found, _ := detect(root)
	names := map[string]model.Panel{}
	for _, panel := range found {
		names[panel.Name] = panel
	}
	virtualmin, ok := names["Virtualmin"]
	if !ok {
		t.Fatalf("Virtualmin not detected: %+v", found)
	}
	// Virtualmin generates the vhosts, so unlike plain Webmin it owns 80 and 443.
	if !containsInt(virtualmin.OwnsPorts, 443) {
		t.Errorf("Virtualmin ownsPorts = %v, want 443 among them", virtualmin.OwnsPorts)
	}
	if _, ok := names["Webmin"]; !ok {
		t.Errorf("Webmin not detected alongside Virtualmin: %+v", found)
	}
}

func TestDetectContainers(t *testing.T) {
	containers := []model.Container{
		{Name: "coolify", Image: "ghcr.io/coollabsio/coolify:4.0.0-beta.300", State: "running"},
		{Name: "coolify-proxy", Image: "traefik:v3.1", State: "running"},
		{Name: "unrelated-app", Image: "nginx:1.27", State: "running"},
	}

	found := detectContainers(containers)
	if len(found) != 1 {
		t.Fatalf("found %d panel(s), want 1: %+v", len(found), found)
	}
	panel := found[0]
	if panel.Name != "Coolify" {
		t.Errorf("name = %q, want Coolify", panel.Name)
	}
	if panel.Version != "4.0.0-beta.300" {
		t.Errorf("version = %q, want the image tag 4.0.0-beta.300", panel.Version)
	}
	if !panel.Running {
		t.Error("running = false for a running container")
	}
	if !strings.Contains(panel.Evidence, "container coolify") {
		t.Errorf("evidence = %q, want it to name the container", panel.Evidence)
	}
	if !containsInt(panel.OwnsPorts, 443) {
		t.Errorf("ownsPorts = %v, want 443 among them", panel.OwnsPorts)
	}
}

func TestDetectContainersIgnoresLatestAsAVersion(t *testing.T) {
	found := detectContainers([]model.Container{
		{Name: "portainer", Image: "portainer/portainer-ce:latest", State: "exited"},
	})
	if len(found) != 1 {
		t.Fatalf("found %d panel(s), want 1", len(found))
	}
	if found[0].Version != "" {
		t.Errorf("version = %q, want empty: `latest` names no version", found[0].Version)
	}
	if found[0].Running {
		t.Error("running = true for an exited container")
	}
}

// The filesystem and the container evidence are complementary, and a panel found
// twice must be reported once, with both.
func TestMergeKeepsBothPiecesOfEvidence(t *testing.T) {
	root := t.TempDir()
	touchDir(t, root, "data/coolify")

	fromDisk, _ := detect(root)
	merged := merge(fromDisk, detectContainers([]model.Container{
		{Name: "coolify", Image: "ghcr.io/coollabsio/coolify:4.0.0", State: "running"},
	}))

	if len(merged) != 1 {
		t.Fatalf("merged into %d panel(s), want 1: %+v", len(merged), merged)
	}
	if !strings.Contains(merged[0].Evidence, "data/coolify") ||
		!strings.Contains(merged[0].Evidence, "container coolify") {
		t.Errorf("evidence = %q, want both the directory and the container", merged[0].Evidence)
	}
	if !merged[0].Running {
		t.Error("running = false although a container is running")
	}
	if merged[0].Version != "4.0.0" {
		t.Errorf("version = %q, want 4.0.0 from the container", merged[0].Version)
	}
}

func TestImageTag(t *testing.T) {
	cases := map[string]string{
		"portainer/portainer-ce:2.19.4":        "2.19.4",
		"ghcr.io/coollabsio/coolify:4.0.0":     "4.0.0",
		"registry:5000/panel":                  "",
		"portainer/portainer-ce":               "",
		"portainer/portainer-ce@sha256:abcdef": "",
		"":                                     "",
	}
	for image, want := range cases {
		if got := imageTag(image); got != want {
			t.Errorf("imageTag(%q) = %q, want %q", image, got, want)
		}
	}
}

func equalInts(got, want []int) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func containsInt(haystack []int, needle int) bool {
	for _, v := range haystack {
		if v == needle {
			return true
		}
	}
	return false
}
