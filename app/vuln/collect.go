package vuln

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/pkgmgr"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/run"
)

// Options configures one vulnerability collection.
type Options struct {
	// Ecosystem overrides the OSV ecosystem derived from the host.
	Ecosystem   string
	VulnDB      string
	Online      bool
	OSVEndpoint string
	MaxLookups  int
	MinSeverity model.Severity
	Timeout     time.Duration
	UserAgent   string
}

// Collect merges the three feeds into one deduplicated, severity-sorted table.
//
// The feeds disagree by design, and the disagreement is informative: the
// distribution knows which fixes were backported into a version whose number
// never changed, while OSV knows about flaws the distribution has not triaged
// yet. Neither is a superset of the other, so both are reported and the `source`
// column says which produced each row.
func Collect(
	manager pkgmgr.Manager,
	packages []pkgmgr.Package,
	opts Options,
	result *model.SectionResult,
) []model.Vulnerability {
	merged := newMerger()

	ecosystem := opts.Ecosystem
	if ecosystem == "" {
		ecosystem = manager.Ecosystem()
	}

	// 1. The distribution's own security metadata.
	advisories, err := manager.Advisories()
	switch {
	case errors.Is(err, run.ErrNotFound):
		result.Degrade(fmt.Sprintf(
			"%s ships no local security metadata reader; distribution advisories were not collected", manager.Name()))
	case err != nil:
		result.Degrade(fmt.Sprintf("%s advisories: %v", manager.Name(), err))
	}
	installedVersions := map[string]string{}
	for _, p := range packages {
		installedVersions[p.Name] = p.Version
	}
	for _, v := range advisories {
		if v.Installed == "" {
			v.Installed = installedVersions[v.Package]
		}
		merged.add(v)
	}

	// 2. The offline OSV dataset, if one was supplied.
	if opts.VulnDB != "" {
		if ecosystem == "" {
			result.Degrade(fmt.Sprintf(
				"--vuln-db ignored: OSV publishes no ecosystem for this distribution (%s); pass --ecosystem to force one",
				manager.Name()))
		} else {
			wanted := map[string]bool{}
			for _, p := range packages {
				wanted[strings.ToLower(p.Name)] = true
			}

			db, err := LoadOffline(opts.VulnDB, wanted, ecosystem)
			if err != nil {
				result.Degrade(fmt.Sprintf("offline dataset %s: %v", opts.VulnDB, err))
			}
			if db != nil {
				result.Note(fmt.Sprintf(
					"offline dataset: %d records scanned, %d relevant to this host", db.Scanned, db.Indexed))
				for _, entry := range matchOffline(db, packages, ecosystem, manager.Comparator()) {
					merged.add(entry)
				}
			}
		}
	}

	// 3. The OSV API, only when explicitly asked for.
	if opts.Online {
		client := NewOSVClient(opts.OSVEndpoint, opts.Timeout, opts.MaxLookups, opts.UserAgent)
		ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout*10)
		defer cancel()

		matches, notes, err := client.Query(ctx, packages, ecosystem)
		for _, note := range notes {
			result.Degrade(note)
		}
		if err != nil {
			result.Degrade(fmt.Sprintf("OSV API: %v", err))
		}
		for _, m := range matches {
			merged.add(fromEntry(m.Entry, m.Package, ecosystem, model.VulnSourceOSVAPI, ""))
		}
	}

	return sortAndFilter(merged.rows(), opts.MinSeverity)
}

func matchOffline(
	db *OfflineDB,
	packages []pkgmgr.Package,
	ecosystem string,
	cmp pkgmgr.Compare,
) []model.Vulnerability {
	var out []model.Vulnerability
	for _, p := range packages {
		for _, entry := range db.Lookup(p.Name) {
			fixed, ok := entry.Match(ecosystem, p.Name, p.Version, cmp)
			if !ok {
				continue
			}
			out = append(out, fromEntry(entry, p, ecosystem, model.VulnSourceOffline, fixed))
		}
	}
	return out
}

func fromEntry(
	entry Entry,
	p pkgmgr.Package,
	ecosystem, source, fixed string,
) model.Vulnerability {
	severity, score := entry.Grade()
	if fixed == "" {
		fixed = firstFixedFor(entry, p.Name)
	}

	summary := entry.Summary
	if summary == "" {
		summary = firstLine(entry.Details)
	}

	return model.Vulnerability{
		Package:   p.Name,
		Installed: p.Version,
		FixedIn:   fixed,
		Severity:  severity,
		Score:     score,
		Id:        entry.PrimaryId(),
		Aliases:   strings.Join(append([]string{entry.Id}, entry.Aliases...), " "),
		Summary:   summary,
		Ecosystem: ecosystem,
		Source:    source,
		Reference: entry.AdvisoryURL(),
	}
}

func firstFixedFor(entry Entry, name string) string {
	for _, affected := range entry.Affected {
		if !strings.EqualFold(affected.Package.Name, name) {
			continue
		}
		if fixed := firstFixed(affected.Ranges); fixed != "" {
			return fixed
		}
	}
	return ""
}

func firstLine(s string) string {
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSpace(s)
	if len(s) > 240 {
		return s[:240] + "…"
	}
	return s
}

// merger folds rows describing the same flaw in the same package into one,
// keeping the first feed's verdict and recording every feed that saw it.
type merger struct {
	index map[string]int
	items []model.Vulnerability
}

func newMerger() *merger {
	return &merger{index: map[string]int{}}
}

func (m *merger) add(v model.Vulnerability) {
	if v.Package == "" {
		return
	}
	key := strings.ToLower(v.Package) + "|" + strings.ToUpper(v.Id)

	i, exists := m.index[key]
	if !exists {
		m.index[key] = len(m.items)
		m.items = append(m.items, v)
		return
	}

	existing := &m.items[i]
	// Provenance is appended rather than overwritten: a finding confirmed by two
	// independent feeds is stronger evidence than one seen only by OSV, and the
	// operator can only see that if both are named.
	if !strings.Contains(existing.Source, v.Source) {
		existing.Source += "+" + v.Source
	}
	// An ungraded row adopts a grade; a graded one is never overruled, because
	// the distribution's rating accounts for its own build configuration.
	if existing.Severity == model.SeverityUnknown && v.Severity != model.SeverityUnknown {
		existing.Severity = v.Severity
		existing.Score = v.Score
	}
	fillEmpty(&existing.FixedIn, v.FixedIn)
	fillEmpty(&existing.Installed, v.Installed)
	fillEmpty(&existing.Summary, v.Summary)
	fillEmpty(&existing.Reference, v.Reference)
	fillEmpty(&existing.Aliases, v.Aliases)
	fillEmpty(&existing.Ecosystem, v.Ecosystem)
}

func (m *merger) rows() []model.Vulnerability { return m.items }

func fillEmpty(dst *string, value string) {
	if *dst == "" {
		*dst = value
	}
}

// sortAndFilter drops rows below the severity floor and orders the rest so the
// worst finding is the first line an operator reads.
//
// `unknown` is never dropped: a finding nobody has graded is not a finding that
// has been graded harmless.
func sortAndFilter(items []model.Vulnerability, min model.Severity) []model.Vulnerability {
	var kept []model.Vulnerability
	for _, v := range items {
		if v.Severity != model.SeverityUnknown && v.Severity.Rank() < min.Rank() {
			continue
		}
		kept = append(kept, v)
	}

	sort.SliceStable(kept, func(i, j int) bool {
		a, b := kept[i], kept[j]
		if a.Severity.Rank() != b.Severity.Rank() {
			return a.Severity.Rank() > b.Severity.Rank()
		}
		if a.Package != b.Package {
			return a.Package < b.Package
		}
		return a.Id < b.Id
	})
	return kept
}
