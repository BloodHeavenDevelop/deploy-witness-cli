package pkgmgr

import (
	"regexp"
	"strings"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/run"
)

type dnfManager struct {
	base
	binary string // "dnf" or "yum"
}

func (m *dnfManager) Name() string        { return m.binary }
func (m *dnfManager) PURLType() string    { return "rpm" }
func (m *dnfManager) Comparator() Compare { return CompareRPM }
func (m *dnfManager) Ecosystem() string   { return osvEcosystem(m.os) }

func (m *dnfManager) Installed() ([]Package, error) {
	out, err := m.runner.Output("rpm", "-qa",
		"--qf", "%{NAME}\t%{EPOCH}:%{VERSION}-%{RELEASE}\t%{ARCH}\n")
	if err != nil {
		return nil, err
	}

	var pkgs []Package
	for _, line := range run.Lines(out) {
		fields := strings.Split(line, "\t")
		if len(fields) < 3 {
			continue
		}
		version := strings.TrimPrefix(fields[1], "(none):")
		pkgs = append(pkgs, Package{
			Name:    fields[0],
			Version: version,
			Arch:    fields[2],
		})
	}
	return pkgs, nil
}

// Updates reads the metadata cache only (-C). Without it dnf refreshes the
// repositories over the network, which the tool is not allowed to do.
func (m *dnfManager) Updates() ([]model.Update, error) {
	// check-update exits 100 when updates exist and 0 when none do.
	out, _, err := m.runner.OutputAllowExit([]int{100}, m.binary, "-C", "-q", "check-update")
	if err != nil {
		return nil, err
	}

	security := m.securityIndex()

	var updates []model.Update
	for _, line := range run.Lines(out) {
		// The obsoletes block below this marker describes replacements, not
		// upgrades, and its indented second lines would parse as bogus packages.
		if strings.HasPrefix(line, "Obsoleting Packages") {
			break
		}
		if strings.HasPrefix(line, "Last metadata expiration") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) != 3 || !strings.Contains(fields[0], ".") {
			continue
		}

		name, arch := splitNameArch(fields[0])
		update := model.Update{
			Package:    name,
			Available:  fields[1],
			Arch:       arch,
			Repository: fields[2],
			Severity:   model.SeverityUnknown,
			Source:     m.binary + " check-update",
		}
		if adv, ok := security[name]; ok {
			update.Security = true
			update.Severity = adv.severity
			update.Advisory = adv.id
		}
		updates = append(updates, update)
	}

	// check-update does not print the installed version, so fill it in from rpm.
	if installed, err := m.Installed(); err == nil {
		byName := map[string]string{}
		for _, p := range installed {
			byName[p.Name] = p.Version
		}
		for i := range updates {
			updates[i].Installed = byName[updates[i].Package]
		}
	}
	return updates, nil
}

type dnfAdvisory struct {
	id       string
	severity model.Severity
}

// securityIndex maps package name to its pending security advisory.
func (m *dnfManager) securityIndex() map[string]dnfAdvisory {
	index := map[string]dnfAdvisory{}
	for _, v := range m.parseUpdateinfo() {
		name := v.Package
		if _, exists := index[name]; !exists || v.Severity.Rank() > index[name].severity.Rank() {
			index[name] = dnfAdvisory{id: v.Id, severity: v.Severity}
		}
	}
	return index
}

var cvePattern = regexp.MustCompile(`^CVE-\d{4}-\d{4,}$`)

// Advisories reads dnf's updateinfo, the richest offline security feed any
// distribution ships: advisory id, CVE and vendor severity, all from cache.
func (m *dnfManager) Advisories() ([]model.Vulnerability, error) {
	vulns := m.parseUpdateinfo()
	if len(vulns) == 0 {
		// Distinguish "no advisories" from "updateinfo is unavailable" — a
		// repository configured without an updateinfo.xml yields nothing here,
		// and reporting that as a clean host would be wrong.
		if _, _, err := m.runner.OutputAllowExit([]int{100, 1},
			m.binary, "-C", "-q", "updateinfo", "list", "--security"); err != nil {
			return nil, err
		}
	}
	return vulns, nil
}

func (m *dnfManager) parseUpdateinfo() []model.Vulnerability {
	out, _, err := m.runner.OutputAllowExit([]int{100, 1},
		m.binary, "-C", "-q", "updateinfo", "list", "--security", "--with-cve")
	if err != nil {
		// Older yum builds reject --with-cve; retry without it and lose only the
		// CVE column.
		out, _, err = m.runner.OutputAllowExit([]int{100, 1},
			m.binary, "-C", "-q", "updateinfo", "list", "--security")
		if err != nil {
			return nil
		}
	}

	installed := map[string]string{}
	if pkgs, perr := m.Installed(); perr == nil {
		for _, p := range pkgs {
			installed[p.Name] = p.Version
		}
	}

	var vulns []model.Vulnerability
	for _, line := range run.Lines(out) {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		// The layout has moved between dnf4, dnf5 and yum; identify columns by
		// what they contain rather than by position.
		var advisory, cve, severity string
		nevra := fields[len(fields)-1]
		for i, f := range fields[:len(fields)-1] {
			switch {
			case cvePattern.MatchString(f):
				cve = f
			case strings.Contains(f, "/Sec") || isSeverityWord(f):
				severity = f
			case i == 0:
				advisory = f
			}
		}
		if advisory == "" && cve == "" {
			continue
		}

		name, _ := splitNameArch(stripNEVR(nevra))
		id := cve
		if id == "" {
			id = advisory
		}
		vulns = append(vulns, model.Vulnerability{
			Package:   name,
			Installed: installed[name],
			Severity:  model.ParseSeverity(severity),
			Id:        id,
			Aliases:   strings.TrimSpace(advisory + " " + cve),
			Summary:   advisory,
			Ecosystem: m.Ecosystem(),
			Source:    model.VulnSourceDistro,
			Reference: cveReference(cve),
		})
	}
	return vulns
}

func isSeverityWord(f string) bool {
	switch strings.ToLower(strings.TrimSuffix(f, ".")) {
	case "critical", "important", "moderate", "low", "high", "medium", "none":
		return true
	}
	return false
}

// splitNameArch splits "openssl.x86_64" into name and arch. A package name may
// legitimately contain dots (perl-Test-Simple has none, but java-1.8.0-openjdk
// does), so only a known architecture suffix is stripped.
func splitNameArch(field string) (string, string) {
	i := strings.LastIndex(field, ".")
	if i < 0 {
		return field, ""
	}
	arch := field[i+1:]
	switch arch {
	case "x86_64", "i686", "i386", "noarch", "aarch64", "armv7hl", "ppc64le", "s390x", "src":
		return field[:i], arch
	}
	return field, ""
}

// stripNEVR reduces "openssl-1:3.0.7-27.el9.x86_64" to "openssl.x86_64" by
// removing the version-release the advisory names.
func stripNEVR(nevra string) string {
	arch := ""
	if i := strings.LastIndex(nevra, "."); i >= 0 {
		if _, a := splitNameArch(nevra); a != "" {
			arch = a
			nevra = nevra[:i]
		}
	}
	// Drop release, then version: both are dash-separated and always trail.
	for n := 0; n < 2; n++ {
		if i := strings.LastIndex(nevra, "-"); i > 0 {
			nevra = nevra[:i]
		}
	}
	if arch != "" {
		return nevra + "." + arch
	}
	return nevra
}

func cveReference(cve string) string {
	if cve == "" {
		return ""
	}
	return "https://nvd.nist.gov/vuln/detail/" + cve
}
