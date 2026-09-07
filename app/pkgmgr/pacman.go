package pkgmgr

import (
	"encoding/json"
	"strings"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/run"
)

type pacmanManager struct{ base }

func (m *pacmanManager) Name() string        { return "pacman" }
func (m *pacmanManager) PURLType() string    { return "pacman" }
func (m *pacmanManager) Comparator() Compare { return CompareGeneric }

// Ecosystem is deliberately empty: OSV has no Arch ecosystem, so both the
// offline dataset and the API would return nothing. arch-audit, read by
// Advisories, is the only vulnerability feed Arch actually publishes.
func (m *pacmanManager) Ecosystem() string { return "" }

func (m *pacmanManager) Installed() ([]Package, error) {
	out, err := m.runner.Output("pacman", "-Q")
	if err != nil {
		return nil, err
	}

	var pkgs []Package
	for _, line := range run.Lines(out) {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		pkgs = append(pkgs, Package{Name: fields[0], Version: fields[1]})
	}
	return pkgs, nil
}

// Updates reads the sync databases already on disk. It deliberately does not run
// `pacman -Sy`: refreshing them is a network operation, and a partial sync is the
// documented way to break an Arch system.
func (m *pacmanManager) Updates() ([]model.Update, error) {
	// Exit 1 means "nothing to upgrade", which is a successful audit.
	out, _, err := m.runner.OutputAllowExit([]int{1}, "pacman", "-Qu")
	if err != nil {
		return nil, err
	}

	repos := m.repoIndex()

	var updates []model.Update
	for _, line := range run.Lines(out) {
		// "name 1.0-1 -> 1.1-1", optionally suffixed with "[ignored]".
		ignored := strings.Contains(line, "[ignored]")
		line = strings.TrimSpace(strings.ReplaceAll(line, "[ignored]", ""))

		fields := strings.Fields(line)
		if len(fields) < 4 || fields[2] != "->" {
			continue
		}
		repo := repos[fields[0]]
		if ignored {
			repo = strings.TrimSpace(repo + " (ignored)")
		}
		updates = append(updates, model.Update{
			Package:    fields[0],
			Installed:  fields[1],
			Available:  fields[3],
			Repository: repo,
			Severity:   model.SeverityUnknown,
			Source:     "pacman -Qu",
		})
	}
	return updates, nil
}

// repoIndex maps package name to sync repository in a single pass. Resolving
// repositories one package at a time would spawn a process per upgradable
// package; on a rolling release that is routinely several hundred.
//
// A package missing from the index (an orphan dropped from the repos) simply gets
// no repository name.
func (m *pacmanManager) repoIndex() map[string]string {
	index := map[string]string{}

	out, err := m.runner.Output("pacman", "-Sl")
	if err != nil {
		return index
	}
	for _, line := range run.Lines(out) {
		// "core linux 6.12.1-1 [installed]"
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		if _, exists := index[fields[1]]; !exists {
			index[fields[1]] = fields[0]
		}
	}
	return index
}

// archAuditEntry covers both shapes arch-audit has emitted: older builds name a
// single `package`, newer ones list `packages`, and the CVE list has been called
// both `cves` and `issues`.
type archAuditEntry struct {
	Name     string   `json:"name"`
	Package  string   `json:"package"`
	Packages []string `json:"packages"`
	Version  string   `json:"version"`
	Affected string   `json:"affected"`
	Fixed    string   `json:"fixed"`
	Severity string   `json:"severity"`
	Status   string   `json:"status"`
	Ticket   string   `json:"ticket"`
	CVEs     []string `json:"cves"`
	Issues   []string `json:"issues"`
	Type     string   `json:"type"`
}

// Advisories reads arch-audit, the Arch Security Tracker client. It is not
// installed by default; when it is missing the section reports that instead of an
// empty, reassuring table.
func (m *pacmanManager) Advisories() ([]model.Vulnerability, error) {
	if !run.Available("arch-audit") {
		return nil, run.ErrNotFound
	}

	out, _, err := m.runner.OutputAllowExit([]int{1}, "arch-audit", "--json")
	if err != nil {
		return nil, err
	}
	out = strings.TrimSpace(out)
	if out == "" {
		return nil, nil
	}

	var entries []archAuditEntry
	if err := json.Unmarshal([]byte(out), &entries); err != nil {
		return nil, err
	}

	installed := map[string]string{}
	if pkgs, perr := m.Installed(); perr == nil {
		for _, p := range pkgs {
			installed[p.Name] = p.Version
		}
	}

	var vulns []model.Vulnerability
	for _, e := range entries {
		names := e.Packages
		if len(names) == 0 {
			for _, n := range []string{e.Package, e.Name} {
				if n != "" {
					names = []string{n}
					break
				}
			}
		}

		ids := e.CVEs
		if len(ids) == 0 {
			ids = e.Issues
		}
		primary := e.Ticket
		if primary == "" && len(ids) > 0 {
			primary = ids[0]
		}
		if primary == "" {
			primary = e.Name
		}

		severity := model.ParseSeverity(e.Severity)
		for _, name := range names {
			version := installed[name]
			if version == "" {
				version = firstNonEmpty(e.Version, e.Affected)
			}
			vulns = append(vulns, model.Vulnerability{
				Package:   name,
				Installed: version,
				FixedIn:   e.Fixed,
				Severity:  severity,
				Id:        primary,
				Aliases:   strings.Join(ids, " "),
				Summary:   strings.TrimSpace(e.Type + " " + e.Status),
				Ecosystem: "arch",
				Source:    model.VulnSourceDistro,
				Reference: archReference(e.Ticket),
			})
		}
	}
	return vulns, nil
}

func archReference(ticket string) string {
	if ticket == "" {
		return ""
	}
	return "https://security.archlinux.org/" + ticket
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
