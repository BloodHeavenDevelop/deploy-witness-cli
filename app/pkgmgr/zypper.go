package pkgmgr

import (
	"strings"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/run"
)

type zypperManager struct{ base }

func (m *zypperManager) Name() string        { return "zypper" }
func (m *zypperManager) PURLType() string    { return "rpm" }
func (m *zypperManager) Comparator() Compare { return CompareRPM }
func (m *zypperManager) Ecosystem() string   { return osvEcosystem(m.os) }

// Installed reads rpm directly. zypper's own listing is slower and adds nothing.
func (m *zypperManager) Installed() ([]Package, error) {
	dnf := &dnfManager{base: m.base, binary: "zypper"}
	return dnf.Installed()
}

func (m *zypperManager) Updates() ([]model.Update, error) {
	out, _, err := m.runner.OutputAllowExit([]int{100, 101, 102, 103},
		"zypper", "--non-interactive", "--quiet", "list-updates")
	if err != nil {
		return nil, err
	}

	var updates []model.Update
	for _, row := range parsePipeTable(out) {
		name := firstOf(row, "Name")
		if name == "" {
			continue
		}
		updates = append(updates, model.Update{
			Package:    name,
			Installed:  firstOf(row, "Current Version"),
			Available:  firstOf(row, "Available Version"),
			Arch:       firstOf(row, "Arch"),
			Repository: firstOf(row, "Repository"),
			Severity:   model.SeverityUnknown,
			Source:     "zypper list-updates",
		})
	}
	return updates, nil
}

func (m *zypperManager) Advisories() ([]model.Vulnerability, error) {
	out, _, err := m.runner.OutputAllowExit([]int{100, 101, 102, 103},
		"zypper", "--non-interactive", "--quiet", "list-patches", "--category", "security", "--cve")
	if err != nil {
		return nil, err
	}

	var vulns []model.Vulnerability
	for _, row := range parsePipeTable(out) {
		patch := firstOf(row, "Patch", "Name")
		cve := firstOf(row, "Issue", "CVE", "No.")
		if patch == "" && cve == "" {
			continue
		}
		id := cve
		if id == "" {
			id = patch
		}
		vulns = append(vulns, model.Vulnerability{
			Package:   patch,
			Severity:  model.ParseSeverity(firstOf(row, "Severity")),
			Id:        id,
			Aliases:   strings.TrimSpace(patch + " " + cve),
			Summary:   firstOf(row, "Summary", "Status"),
			Ecosystem: m.Ecosystem(),
			Source:    model.VulnSourceDistro,
			Reference: cveReference(cve),
		})
	}
	return vulns, nil
}

// parsePipeTable reads zypper's pipe-delimited tables into header-keyed rows.
// Columns are addressed by name because zypper reorders and renames them between
// releases and between subcommands.
func parsePipeTable(out string) []map[string]string {
	var headers []string
	var rows []map[string]string

	for _, line := range run.Lines(out) {
		if !strings.Contains(line, "|") {
			continue
		}
		// The rule separating header from body is made of dashes and plusses.
		if strings.Trim(line, "-+ ") == "" {
			continue
		}

		cells := strings.Split(line, "|")
		for i := range cells {
			cells[i] = strings.TrimSpace(cells[i])
		}

		if headers == nil {
			headers = cells
			continue
		}
		row := map[string]string{}
		for i, cell := range cells {
			if i < len(headers) {
				row[headers[i]] = cell
			}
		}
		rows = append(rows, row)
	}
	return rows
}

func firstOf(row map[string]string, keys ...string) string {
	for _, k := range keys {
		if v, ok := row[k]; ok && v != "" {
			return v
		}
	}
	return ""
}
