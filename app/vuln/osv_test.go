package vuln

import (
	"testing"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/pkgmgr"
)

func entryWithRange(events ...Event) Entry {
	return Entry{
		Id: "CVE-2024-0001",
		Affected: []Affected{{
			Package: OSVPackage{Ecosystem: "Debian:12", Name: "openssl"},
			Ranges:  []Range{{Type: "ECOSYSTEM", Events: events}},
		}},
	}
}

func TestMatchRangeIntroducedAndFixed(t *testing.T) {
	entry := entryWithRange(
		Event{Introduced: "0"},
		Event{Fixed: "3.0.13-1"},
	)
	cmp := pkgmgr.CompareDebian

	fixed, matched := entry.Match("Debian:12", "openssl", "3.0.11-1", cmp)
	if !matched {
		t.Error("a version below the fix should match")
	}
	if fixed != "3.0.13-1" {
		t.Errorf("fixed = %q, want 3.0.13-1", fixed)
	}

	if _, matched := entry.Match("Debian:12", "openssl", "3.0.13-1", cmp); matched {
		t.Error("the fixed version itself must not match")
	}
	if _, matched := entry.Match("Debian:12", "openssl", "3.0.14-1", cmp); matched {
		t.Error("a version above the fix must not match")
	}
}

func TestMatchRangeLastAffected(t *testing.T) {
	entry := entryWithRange(
		Event{Introduced: "2.0"},
		Event{LastAffected: "3.0"},
	)
	cmp := pkgmgr.CompareDebian

	if _, matched := entry.Match("Debian:12", "openssl", "1.9", cmp); matched {
		t.Error("a version below the introduction must not match")
	}
	if _, matched := entry.Match("Debian:12", "openssl", "3.0", cmp); !matched {
		t.Error("the last affected version must match")
	}
	if _, matched := entry.Match("Debian:12", "openssl", "3.1", cmp); matched {
		t.Error("a version above last_affected must not match")
	}
}

func TestMatchExactVersionList(t *testing.T) {
	entry := Entry{
		Id: "CVE-2024-0002",
		Affected: []Affected{{
			Package:  OSVPackage{Ecosystem: "Debian:12", Name: "curl"},
			Versions: []string{"7.88.1-10", "7.88.1-11"},
		}},
	}

	if _, matched := entry.Match("Debian:12", "curl", "7.88.1-10", pkgmgr.CompareDebian); !matched {
		t.Error("an exactly listed version must match")
	}
	if _, matched := entry.Match("Debian:12", "curl", "7.88.1-12", pkgmgr.CompareDebian); matched {
		t.Error("a version outside the list must not match")
	}
}

func TestWithdrawnRecordsNeverMatch(t *testing.T) {
	entry := entryWithRange(Event{Introduced: "0"})
	entry.Withdrawn = "2024-01-01T00:00:00Z"

	if _, matched := entry.Match("Debian:12", "openssl", "1.0", pkgmgr.CompareDebian); matched {
		t.Error("a withdrawn record must not produce a finding")
	}
}

func TestGitRangesAreIgnored(t *testing.T) {
	entry := Entry{
		Affected: []Affected{{
			Package: OSVPackage{Ecosystem: "Debian:12", Name: "openssl"},
			Ranges: []Range{{
				Type:   "GIT",
				Events: []Event{{Introduced: "0"}, {Fixed: "abc123def"}},
			}},
		}},
	}

	if _, matched := entry.Match("Debian:12", "openssl", "3.0.11-1", pkgmgr.CompareDebian); matched {
		t.Error("commit ranges must not be evaluated with a version comparator")
	}
}

func TestEcosystemMatches(t *testing.T) {
	cases := []struct {
		entry, host string
		want        bool
	}{
		{"Debian:12", "Debian:12", true},
		{"Debian", "Debian:12", true}, // family-wide record
		{"Debian:12", "Debian", true}, // family-wide host
		{"Debian:11", "Debian:12", false},
		{"Ubuntu:22.04", "Debian:12", false},
		{"Alpine:v3.19", "Alpine:v3.19", true},
		{"", "Debian:12", false},
		{"Debian:12", "", false},
	}

	for _, c := range cases {
		if got := EcosystemMatches(c.entry, c.host); got != c.want {
			t.Errorf("EcosystemMatches(%q, %q) = %v, want %v", c.entry, c.host, got, c.want)
		}
	}
}

func TestGradePrefersComputedCVSS(t *testing.T) {
	entry := Entry{
		Severity: []OSVSeverity{{
			Type:  "CVSS_V3",
			Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		}},
		DatabaseSpecific: map[string]any{"severity": "LOW"},
	}

	severity, score := entry.Grade()
	if severity != model.SeverityCritical {
		t.Errorf("severity = %q, want critical", severity)
	}
	if score == "" {
		t.Error("the supporting score should be recorded")
	}
}

func TestGradeFallsBackToLabel(t *testing.T) {
	entry := Entry{DatabaseSpecific: map[string]any{"severity": "MODERATE"}}
	if severity, _ := entry.Grade(); severity != model.SeverityMedium {
		t.Errorf("severity = %q, want medium", severity)
	}

	if severity, _ := (Entry{}).Grade(); severity != model.SeverityUnknown {
		t.Errorf("an ungradable record should be unknown, got %q", severity)
	}
}

func TestPrimaryIdPrefersCVE(t *testing.T) {
	entry := Entry{Id: "GHSA-xxxx", Aliases: []string{"CVE-2024-1234"}}
	if got := entry.PrimaryId(); got != "CVE-2024-1234" {
		t.Errorf("PrimaryId = %q, want the CVE alias", got)
	}

	entry = Entry{Id: "DSA-5000-1"}
	if got := entry.PrimaryId(); got != "DSA-5000-1" {
		t.Errorf("PrimaryId = %q, want the record id", got)
	}
}

func TestSortAndFilterKeepsUnknown(t *testing.T) {
	items := []model.Vulnerability{
		{Package: "a", Severity: model.SeverityLow},
		{Package: "b", Severity: model.SeverityUnknown},
		{Package: "c", Severity: model.SeverityCritical},
		{Package: "d", Severity: model.SeverityMedium},
	}

	got := sortAndFilter(items, model.SeverityHigh)
	if len(got) != 2 {
		t.Fatalf("expected critical + unknown to survive, got %d: %+v", len(got), got)
	}
	if got[0].Severity != model.SeverityCritical {
		t.Errorf("the worst finding must sort first, got %q", got[0].Severity)
	}
	if got[1].Severity != model.SeverityUnknown {
		t.Errorf("an ungraded finding must never be filtered out, got %q", got[1].Severity)
	}
}

func TestMergerRecordsEveryFeed(t *testing.T) {
	m := newMerger()
	m.add(model.Vulnerability{
		Package: "openssl", Id: "CVE-2024-0001",
		Severity: model.SeverityUnknown, Source: model.VulnSourceDistro,
	})
	m.add(model.Vulnerability{
		Package: "openssl", Id: "CVE-2024-0001", FixedIn: "3.0.13",
		Severity: model.SeverityCritical, Source: model.VulnSourceOSVAPI,
	})

	rows := m.rows()
	if len(rows) != 1 {
		t.Fatalf("the same flaw in the same package must collapse to one row, got %d", len(rows))
	}
	if rows[0].Source != model.VulnSourceDistro+"+"+model.VulnSourceOSVAPI {
		t.Errorf("provenance = %q, want both feeds named", rows[0].Source)
	}
	// An ungraded distro row should adopt the grade the API supplied.
	if rows[0].Severity != model.SeverityCritical {
		t.Errorf("severity = %q, want critical", rows[0].Severity)
	}
	if rows[0].FixedIn != "3.0.13" {
		t.Errorf("fixedIn = %q, want the value the second feed contributed", rows[0].FixedIn)
	}
}

func TestMergerKeepsDistroGrade(t *testing.T) {
	m := newMerger()
	m.add(model.Vulnerability{
		Package: "openssl", Id: "CVE-2024-0001",
		Severity: model.SeverityLow, Source: model.VulnSourceDistro,
	})
	m.add(model.Vulnerability{
		Package: "openssl", Id: "CVE-2024-0001",
		Severity: model.SeverityCritical, Source: model.VulnSourceOffline,
	})

	// The distribution rates against its own build configuration; an upstream
	// score must not overwrite it.
	if got := m.rows()[0].Severity; got != model.SeverityLow {
		t.Errorf("severity = %q, want the distribution's own rating (low)", got)
	}
}
