// Package pkgmgr abstracts the host package manager behind one interface, so the
// updates and vulnerability collectors never branch on the distribution.
package pkgmgr

import (
	"fmt"
	"strings"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/run"
)

// Package is one installed package.
type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Arch    string `json:"arch"`
}

// Manager is the contract every distribution backend fulfils.
//
// Each method returns whatever it managed to collect alongside its error, so a
// partially readable host still contributes rows. Never assume a non-nil error
// means an empty slice.
type Manager interface {
	// Name is the tool identifier written into the CSV `source` column.
	Name() string
	// Ecosystem is the OSV ecosystem for this host, or "" when OSV has none.
	Ecosystem() string
	// PURLType is the package-URL type used when querying the OSV API.
	PURLType() string
	// Installed lists every installed package.
	Installed() ([]Package, error)
	// Updates lists upgradable packages from metadata already on disk.
	Updates() ([]model.Update, error)
	// Advisories lists vulnerabilities the distribution itself reports.
	Advisories() ([]model.Vulnerability, error)
	// Comparator is the version ordering this ecosystem uses.
	Comparator() Compare
}

// base carries what every backend needs.
type base struct {
	runner *run.Runner
	os     model.OSRelease
}

// Detect picks the package manager for this host.
//
// Binary presence decides, not the os-release ID: a container image can report
// one distribution while shipping another's tooling, and derivatives (Manjaro on
// pacman, Mint on apt) are then handled without enumerating them. The os-release
// family only breaks ties on hosts carrying two managers, where the declared
// distribution is the one whose metadata is actually maintained.
func Detect(os model.OSRelease, runner *run.Runner) (Manager, error) {
	type candidate struct {
		binary string
		build  func() Manager
	}

	candidates := []candidate{
		{"apt-get", func() Manager { return &aptManager{base{runner, os}} }},
		{"dnf", func() Manager { return &dnfManager{base{runner, os}, "dnf"} }},
		{"yum", func() Manager { return &dnfManager{base{runner, os}, "yum"} }},
		{"zypper", func() Manager { return &zypperManager{base{runner, os}} }},
		{"pacman", func() Manager { return &pacmanManager{base{runner, os}} }},
		{"apk", func() Manager { return &apkManager{base{runner, os}} }},
	}

	// Preferred order for the declared family, so a tie goes to the distribution
	// the host claims to be.
	preferred := map[string][]string{
		"debian": {"apt-get"},
		"rhel":   {"dnf", "yum"},
		"suse":   {"zypper"},
		"arch":   {"pacman"},
		"alpine": {"apk"},
	}[os.Family()]

	for _, want := range preferred {
		for _, c := range candidates {
			if c.binary == want && run.Available(c.binary) {
				return c.build(), nil
			}
		}
	}
	for _, c := range candidates {
		if run.Available(c.binary) {
			return c.build(), nil
		}
	}
	return nil, fmt.Errorf("no supported package manager found (looked for apt-get, dnf, yum, zypper, pacman, apk)")
}

// osvEcosystem maps the host onto an OSV ecosystem string.
//
// An empty result is a real answer, not a failure: OSV publishes no ecosystem for
// Arch or Fedora packages, and inventing one would make every lookup silently
// return nothing while the report implied it had been checked.
func osvEcosystem(os model.OSRelease) string {
	major := os.MajorVersion()

	switch strings.ToLower(os.ID) {
	case "debian":
		if major == "" {
			return "Debian"
		}
		return "Debian:" + major
	case "ubuntu":
		if os.VersionID == "" {
			return "Ubuntu"
		}
		return "Ubuntu:" + os.VersionID
	case "alpine":
		return alpineEcosystem(os.VersionID)
	case "rocky":
		return "Rocky Linux:" + major
	case "almalinux":
		return "AlmaLinux:" + major
	case "rhel", "centos":
		return "Red Hat"
	case "opensuse", "opensuse-leap", "opensuse-tumbleweed":
		return "openSUSE"
	case "sles", "sled":
		return "SUSE"
	}

	// Derivatives declare their base in ID_LIKE.
	for _, like := range strings.Fields(os.IDLike) {
		switch strings.ToLower(like) {
		case "debian":
			return "Debian"
		case "ubuntu":
			return "Ubuntu"
		case "alpine":
			return alpineEcosystem(os.VersionID)
		}
	}
	return ""
}

func alpineEcosystem(versionID string) string {
	parts := strings.Split(versionID, ".")
	if len(parts) >= 2 {
		return "Alpine:v" + parts[0] + "." + parts[1]
	}
	return "Alpine"
}
