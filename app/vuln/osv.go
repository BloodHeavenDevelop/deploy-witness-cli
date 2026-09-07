// Package vuln resolves installed packages to known vulnerabilities from three
// independent feeds: the distribution's own metadata, an offline OSV dataset and
// the OSV API.
package vuln

import (
	"strconv"
	"strings"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/pkgmgr"
)

// Entry is an OSV record. Only the fields this tool acts on are decoded; the
// schema carries considerably more.
type Entry struct {
	Id               string         `json:"id"`
	Aliases          []string       `json:"aliases"`
	Summary          string         `json:"summary"`
	Details          string         `json:"details"`
	Modified         string         `json:"modified"`
	Withdrawn        string         `json:"withdrawn"`
	Severity         []OSVSeverity  `json:"severity"`
	Affected         []Affected     `json:"affected"`
	References       []Reference    `json:"references"`
	DatabaseSpecific map[string]any `json:"database_specific"`
}

// OSVSeverity is a machine-readable severity, always a vector or score string.
type OSVSeverity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

// Affected ties one package to the version ranges a vulnerability applies to.
type Affected struct {
	Package           OSVPackage     `json:"package"`
	Ranges            []Range        `json:"ranges"`
	Versions          []string       `json:"versions"`
	EcosystemSpecific map[string]any `json:"ecosystem_specific"`
	DatabaseSpecific  map[string]any `json:"database_specific"`
}

// OSVPackage identifies a package within an ecosystem.
type OSVPackage struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	PURL      string `json:"purl"`
}

// Range is a version interval expressed as ordered events.
type Range struct {
	Type   string  `json:"type"`
	Events []Event `json:"events"`
}

// Event is one boundary in a Range.
type Event struct {
	Introduced   string `json:"introduced"`
	Fixed        string `json:"fixed"`
	LastAffected string `json:"last_affected"`
	Limit        string `json:"limit"`
}

// Reference is an advisory link.
type Reference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// Match reports whether an installed version falls inside this record, and the
// version that fixes it if the record names one.
func (e Entry) Match(ecosystem, name, version string, cmp pkgmgr.Compare) (fixed string, matched bool) {
	// A withdrawn record was retracted by its publisher; acting on it would
	// produce a finding the upstream database no longer stands behind.
	if e.Withdrawn != "" {
		return "", false
	}

	for _, affected := range e.Affected {
		if !strings.EqualFold(affected.Package.Name, name) {
			continue
		}
		if !EcosystemMatches(affected.Package.Ecosystem, ecosystem) {
			continue
		}

		for _, v := range affected.Versions {
			if v == version {
				return firstFixed(affected.Ranges), true
			}
		}
		for _, r := range affected.Ranges {
			// GIT ranges address commits, not package versions; evaluating them
			// with a version comparator produces nonsense.
			if strings.EqualFold(r.Type, "GIT") {
				continue
			}
			if hit, fix := matchRange(r, version, cmp); hit {
				return fix, true
			}
		}
	}
	return "", false
}

// matchRange walks a range's events in order, per the OSV specification: each
// `introduced` opens the interval, each `fixed`/`last_affected`/`limit` closes it.
func matchRange(r Range, version string, cmp pkgmgr.Compare) (bool, string) {
	affected := false
	fixed := ""

	for _, e := range r.Events {
		switch {
		case e.Introduced != "":
			if e.Introduced == "0" || cmp(version, e.Introduced) >= 0 {
				affected = true
			}
		case e.Fixed != "":
			fixed = e.Fixed
			if cmp(version, e.Fixed) >= 0 {
				affected = false
			}
		case e.LastAffected != "":
			if cmp(version, e.LastAffected) > 0 {
				affected = false
			}
		case e.Limit != "":
			if cmp(version, e.Limit) >= 0 {
				affected = false
			}
		}
	}
	return affected, fixed
}

func firstFixed(ranges []Range) string {
	for _, r := range ranges {
		for _, e := range r.Events {
			if e.Fixed != "" {
				return e.Fixed
			}
		}
	}
	return ""
}

// Grade extracts a severity and its supporting score text.
//
// The CVSS vector is preferred over the vendor's qualitative label because the
// label is missing from most records, and a computed 9.8 is comparable across
// distributions in a way that "Important" is not.
func (e Entry) Grade() (model.Severity, string) {
	best := model.SeverityUnknown
	score := ""

	for _, s := range e.Severity {
		value, ok := model.ScoreFromVector(s.Score)
		if !ok {
			continue
		}
		graded := model.SeverityFromScore(value)
		if graded.Rank() > best.Rank() || best == model.SeverityUnknown {
			best = graded
			score = formatScore(value) + " (" + s.Type + ")"
		}
	}
	if best != model.SeverityUnknown {
		return best, score
	}

	// Fall back to whatever qualitative label the databases attached.
	for _, source := range append([]map[string]any{e.DatabaseSpecific}, affectedSpecifics(e)...) {
		if label := stringField(source, "severity"); label != "" {
			if parsed := model.ParseSeverity(label); parsed != model.SeverityUnknown {
				return parsed, label
			}
		}
	}
	return model.SeverityUnknown, ""
}

func affectedSpecifics(e Entry) []map[string]any {
	var out []map[string]any
	for _, a := range e.Affected {
		out = append(out, a.DatabaseSpecific, a.EcosystemSpecific)
	}
	return out
}

func stringField(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

// formatScore renders a base score with the one decimal CVSS uses.
func formatScore(v float64) string {
	return strconv.FormatFloat(v, 'f', 1, 64)
}

// PrimaryId prefers a CVE over a database-local identifier, so rows from
// different feeds describing the same flaw collapse onto one key.
func (e Entry) PrimaryId() string {
	if strings.HasPrefix(e.Id, "CVE-") {
		return e.Id
	}
	for _, alias := range e.Aliases {
		if strings.HasPrefix(alias, "CVE-") {
			return alias
		}
	}
	return e.Id
}

// AdvisoryURL picks the most useful link a record carries.
func (e Entry) AdvisoryURL() string {
	ranked := []string{"ADVISORY", "REPORT", "WEB", "FIX"}
	for _, want := range ranked {
		for _, ref := range e.References {
			if strings.EqualFold(ref.Type, want) && ref.URL != "" {
				return ref.URL
			}
		}
	}
	if len(e.References) > 0 {
		return e.References[0].URL
	}
	return ""
}

// EcosystemMatches compares an OSV ecosystem against the host's.
//
// OSV writes distribution ecosystems as "Family:Version" ("Debian:12"). A record
// scoped to the family with no version applies to every version of it, so the
// comparison is on the family when either side omits the version — but never
// across families, which would map a Debian advisory onto an Alpine package.
func EcosystemMatches(entry, host string) bool {
	if host == "" || entry == "" {
		return false
	}
	if strings.EqualFold(entry, host) {
		return true
	}

	entryFamily, entryVersion := splitEcosystem(entry)
	hostFamily, hostVersion := splitEcosystem(host)
	if !strings.EqualFold(entryFamily, hostFamily) {
		return false
	}
	return entryVersion == "" || hostVersion == ""
}

func splitEcosystem(v string) (string, string) {
	if i := strings.Index(v, ":"); i >= 0 {
		return v[:i], v[i+1:]
	}
	return v, ""
}
