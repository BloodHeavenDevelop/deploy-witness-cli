package model

import (
	"bufio"
	"os"
	"strings"
)

// OSRelease is the parsed /etc/os-release. It lives in model rather than in the
// system collector because the package-manager layer needs ID/VERSION_ID to name
// the OSV ecosystem, and the vulnerability layer needs the ecosystem.
type OSRelease struct {
	ID         string `json:"id"`
	IDLike     string `json:"idLike"`
	Name       string `json:"name"`
	PrettyName string `json:"prettyName"`
	Version    string `json:"version"`
	VersionID  string `json:"versionId"`
	Codename   string `json:"codename"`
	BuildID    string `json:"buildId"`
}

// osReleasePaths is the search order defined by the os-release specification.
var osReleasePaths = []string{"/etc/os-release", "/usr/lib/os-release"}

// ReadOSRelease parses the first os-release file that exists. A host without one
// yields a zero value and no error — the audit still runs, it just cannot name
// the distribution.
func ReadOSRelease() (OSRelease, error) {
	var rel OSRelease
	var lastErr error

	for _, path := range osReleasePaths {
		f, err := os.Open(path)
		if err != nil {
			lastErr = err
			continue
		}
		defer f.Close()

		values := map[string]string{}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			kv := strings.SplitN(line, "=", 2)
			if len(kv) != 2 {
				continue
			}
			values[kv[0]] = strings.Trim(strings.TrimSpace(kv[1]), `"'`)
		}
		if err := scanner.Err(); err != nil {
			return rel, err
		}

		rel = OSRelease{
			ID:         values["ID"],
			IDLike:     values["ID_LIKE"],
			Name:       values["NAME"],
			PrettyName: values["PRETTY_NAME"],
			Version:    values["VERSION"],
			VersionID:  values["VERSION_ID"],
			Codename:   values["VERSION_CODENAME"],
			BuildID:    values["BUILD_ID"],
		}
		return rel, nil
	}
	return rel, lastErr
}

// Family collapses a distribution onto its packaging family via ID and ID_LIKE,
// so derivatives (Manjaro, Linux Mint, Rocky) resolve without being enumerated.
func (o OSRelease) Family() string {
	candidates := append([]string{o.ID}, strings.Fields(o.IDLike)...)
	for _, c := range candidates {
		switch strings.ToLower(c) {
		case "debian", "ubuntu":
			return "debian"
		case "rhel", "fedora", "centos", "rocky", "almalinux":
			return "rhel"
		case "arch", "archlinux":
			return "arch"
		case "alpine":
			return "alpine"
		case "suse", "opensuse", "sles":
			return "suse"
		}
	}
	return strings.ToLower(o.ID)
}

// MajorVersion returns VERSION_ID truncated at the first dot.
func (o OSRelease) MajorVersion() string {
	if i := strings.Index(o.VersionID, "."); i > 0 {
		return o.VersionID[:i]
	}
	return o.VersionID
}
