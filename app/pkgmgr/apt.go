package pkgmgr

import (
	"regexp"
	"strings"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/run"
)

type aptManager struct{ base }

func (m *aptManager) Name() string        { return "apt" }
func (m *aptManager) PURLType() string    { return "deb" }
func (m *aptManager) Comparator() Compare { return CompareDebian }
func (m *aptManager) Ecosystem() string   { return osvEcosystem(m.os) }

func (m *aptManager) Installed() ([]Package, error) {
	out, err := m.runner.Output("dpkg-query", "-W",
		"-f=${Package}\t${Version}\t${Architecture}\t${db:Status-Status}\n")
	if err != nil {
		return nil, err
	}

	var pkgs []Package
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Split(line, "\t")
		if len(fields) < 4 {
			continue
		}
		// Removed-but-not-purged packages keep a dpkg record and no files; they
		// are not installed and must not be audited as if they were.
		if strings.TrimSpace(fields[3]) != "installed" {
			continue
		}
		pkgs = append(pkgs, Package{
			Name:    strings.TrimSpace(fields[0]),
			Version: strings.TrimSpace(fields[1]),
			Arch:    strings.TrimSpace(fields[2]),
		})
	}
	return pkgs, nil
}

// aptInstLine matches the simulated-upgrade output:
//
//	Inst libssl3 [3.0.11-1~deb12u2] (3.0.13-1~deb12u1 Debian-Security:12/stable [amd64])
//	Inst linux-image-6.1 (6.1.99-1 Debian:12.5/stable [amd64])
var aptInstLine = regexp.MustCompile(`^Inst\s+(\S+)(?:\s+\[([^\]]*)\])?\s+\(([^\s]+)\s+(.*)\)\s*$`)

// Updates simulates a dist-upgrade against the package lists already on disk.
//
// `apt list --upgradable` is the obvious alternative and is not used: it names no
// origin, and the origin is the only thing that distinguishes a security update
// from a routine one without network access.
func (m *aptManager) Updates() ([]model.Update, error) {
	out, err := m.runner.Output("apt-get",
		"-s", "-q",
		"-o", "Debug::NoLocking=1",
		"-o", "APT::Get::Show-User-Simulation-Note=0",
		"dist-upgrade")
	if err != nil {
		return nil, err
	}

	var updates []model.Update
	for _, line := range run.Lines(out) {
		match := aptInstLine.FindStringSubmatch(line)
		if match == nil {
			continue
		}

		origin := strings.TrimSpace(match[4])
		arch := ""
		if i := strings.LastIndex(origin, "["); i >= 0 {
			arch = strings.Trim(origin[i:], "[] ")
			origin = strings.TrimSpace(origin[:i])
		}

		updates = append(updates, model.Update{
			Package:    match[1],
			Installed:  match[2],
			Available:  match[3],
			Arch:       arch,
			Repository: origin,
			Security:   isSecurityOrigin(origin),
			Severity:   model.SeverityUnknown,
			Source:     "apt-get -s dist-upgrade",
		})
	}
	return updates, nil
}

// isSecurityOrigin recognises the security archives of Debian, Ubuntu and their
// derivatives from the origin string apt prints.
func isSecurityOrigin(origin string) bool {
	lower := strings.ToLower(origin)
	return strings.Contains(lower, "security")
}

// debsecanLine matches debsecan's summary format:
//
//	CVE-2011-3374 apt (remotely exploitable, low urgency)
var debsecanLine = regexp.MustCompile(`^(\S+)\s+(\S+)\s*(?:\(([^)]*)\))?\s*$`)

// Advisories prefers debsecan, which maps installed Debian packages to CVEs from
// a local snapshot. Without it, the only offline signal apt has is that an update
// comes from a security archive — reported as an unrated finding rather than
// dropped, because "we cannot grade it" and "it is not there" are different
// answers.
func (m *aptManager) Advisories() ([]model.Vulnerability, error) {
	if run.Available("debsecan") {
		vulns, err := m.debsecan()
		if err == nil {
			return vulns, nil
		}
		// Fall through: a debsecan that cannot run must not cost us the origin
		// signal we can still derive from apt itself.
		fallback, ferr := m.securityOriginFindings()
		if ferr != nil {
			return nil, err
		}
		return fallback, err
	}
	return m.securityOriginFindings()
}

func (m *aptManager) debsecan() ([]model.Vulnerability, error) {
	args := []string{"--format", "summary"}
	if suite := m.suite(); suite != "" {
		args = append(args, "--suite", suite)
	}

	out, _, err := m.runner.OutputAllowExit([]int{1}, "debsecan", args...)
	if err != nil {
		return nil, err
	}

	installed := map[string]string{}
	if pkgs, perr := m.Installed(); perr == nil {
		for _, p := range pkgs {
			installed[p.Name] = p.Version
		}
	}

	var vulns []model.Vulnerability
	for _, line := range run.Lines(out) {
		match := debsecanLine.FindStringSubmatch(line)
		if match == nil || !strings.HasPrefix(match[1], "CVE-") {
			continue
		}
		vulns = append(vulns, model.Vulnerability{
			Package:   match[2],
			Installed: installed[match[2]],
			Severity:  urgencyToSeverity(match[3]),
			Id:        match[1],
			Summary:   strings.TrimSpace(match[3]),
			Ecosystem: m.Ecosystem(),
			Source:    model.VulnSourceDistro,
			Reference: "https://security-tracker.debian.org/tracker/" + match[1],
		})
	}
	return vulns, nil
}

// urgencyToSeverity maps the Debian security tracker's urgency vocabulary.
func urgencyToSeverity(flags string) model.Severity {
	lower := strings.ToLower(flags)
	switch {
	case strings.Contains(lower, "high urgency"):
		return model.SeverityHigh
	case strings.Contains(lower, "medium urgency"):
		return model.SeverityMedium
	case strings.Contains(lower, "low urgency"):
		return model.SeverityLow
	case strings.Contains(lower, "unimportant"), strings.Contains(lower, "not yet assigned"):
		return model.SeverityNone
	default:
		return model.SeverityUnknown
	}
}

// securityOriginFindings turns pending security-archive updates into unrated
// vulnerability rows.
func (m *aptManager) securityOriginFindings() ([]model.Vulnerability, error) {
	updates, err := m.Updates()
	if err != nil {
		return nil, err
	}

	var vulns []model.Vulnerability
	for _, u := range updates {
		if !u.Security {
			continue
		}
		vulns = append(vulns, model.Vulnerability{
			Package:   u.Package,
			Installed: u.Installed,
			FixedIn:   u.Available,
			Severity:  model.SeverityUnknown,
			Id:        "",
			Summary:   "pending security update from " + u.Repository + " (install debsecan for CVE detail)",
			Ecosystem: m.Ecosystem(),
			Source:    model.VulnSourceDistro,
		})
	}
	return vulns, nil
}

// suite is the release codename debsecan needs to pick its snapshot.
func (m *aptManager) suite() string {
	if m.os.Codename != "" {
		return m.os.Codename
	}
	out, err := m.runner.Output("lsb_release", "-cs")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}
