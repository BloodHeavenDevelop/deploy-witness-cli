package audit

import (
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/run"
)

// What every section read, as observations (DW-82).
//
// A section that finished without a finding has to be able to prove it: "no
// pending updates" is a conclusion, and the reader is owed what it rests on — the
// package manager that was asked, the number it answered, the moment it answered
// and whether it answered in full. Until DW-82 only the witness section's Docker
// sources were observations, so a host audit went out with none and every host
// check that found nothing looked unsupported on the receiving side.
//
// Naming: an observation's source is `<section>` (what the section read, with the
// values it got) or `<section>:<detail>` (one source within it — a fact category,
// a command). The receiving service matches an observation to its collector by
// the part before the colon; the Docker sources of a preflight keep their own
// names (`containers`, `sockets`, …), as they always had.
//
// What is deliberately not in a note: package names, versions, CVE identifiers,
// port numbers, unit names. The contract leaves the inventory in the CSV (see
// report.Contract), and an observation is not a side door for it — counts are
// the values that prove a result, and they are what goes out.

// maxObservationNote keeps one note readable and the upload small. A note that
// had to be cut says so.
const maxObservationNote = 600

// observeSection records what one section read. journalFrom is the length of the
// command journal before the section started, so the commands it ran are the
// entries from there on; collectedAt is when the collector returned — the last
// moment the data it holds was read.
func (a *Auditor) observeSection(report *model.Report, result *model.SectionResult, journalFrom int,
	collectedAt time.Time) {
	section := string(result.Section)
	note := sectionValues(a, report, result.Section)
	if len(result.Notes) > 0 {
		note += "; notes: " + strings.Join(result.Notes, "; ")
	}
	a.observe(section, sectionState(result.Status), note, collectedAt)

	if result.Section == model.SectionSystem {
		for _, o := range factObservations(report.System, collectedAt) {
			a.observe(o.Source, o.State, o.Note, collectedAt)
		}
	}

	entries := a.runner.Journal()
	if journalFrom > len(entries) {
		journalFrom = len(entries)
	}
	a.observations = append(a.observations, commandObservations(section, entries[journalFrom:])...)
}

func (a *Auditor) observe(source string, state model.ObservationState, note string, at time.Time) {
	a.observations = append(a.observations, model.Observation{
		Source: source, State: state, Note: clip(note), ObservedAt: at.UTC().Format(time.RFC3339),
	})
}

// sectionState maps how a section ended onto how completely its sources were read.
func sectionState(status model.Status) model.ObservationState {
	switch status {
	case model.StatusOk:
		return model.ObservedComplete
	case model.StatusPartial:
		return model.ObservedPartial
	case model.StatusFailed:
		return model.ObservedFailed
	default:
		return model.ObservedNotCollected
	}
}

// sectionValues is what the section read and the values it got, in a sentence.
func sectionValues(a *Auditor, report *model.Report, section model.Section) string {
	manager := "no supported package manager"
	if a.manager != nil {
		manager = a.manager.Name()
	}
	switch section {
	case model.SectionSystem:
		categories := map[string]int{}
		var names []string
		for _, f := range report.System {
			if categories[f.Category] == 0 {
				names = append(names, f.Category)
			}
			categories[f.Category]++
		}
		return fmt.Sprintf("%d host facts read in %d categories (%s); per-category values in system:<category>",
			len(report.System), len(names), orNone(strings.Join(names, ", ")))
	case model.SectionUpdates:
		security := 0
		for _, u := range report.Updates {
			if u.Security {
				security++
			}
		}
		return fmt.Sprintf("%s: %d pending update(s), %d from a security channel", manager, len(report.Updates), security)
	case model.SectionVulnerabilities:
		critical, high := gradeCounts(report.Vulnerabilities)
		bySource := map[string]int{}
		for _, v := range report.Vulnerabilities {
			bySource[v.Source]++
		}
		installed := "installed packages not listed"
		if a.packagesRead {
			installed = fmt.Sprintf("%d installed package(s)", len(a.packages))
		}
		online := "offline (no --online)"
		if a.cfg.Online {
			online = "--online"
		}
		return fmt.Sprintf("%s via %s checked, %s: %d advisory row(s) (%d critical, %d high)%s",
			installed, manager, online, len(report.Vulnerabilities), critical, high, counts(" by feed", bySource))
	case model.SectionPorts:
		byProto, byExposure := map[string]int{}, map[string]int{}
		for _, p := range report.Ports {
			byProto[p.Protocol]++
			byExposure[p.Exposure]++
		}
		return fmt.Sprintf("/proc/net/{tcp,tcp6,udp,udp6}: %d listening socket(s)%s%s",
			len(report.Ports), counts(" by protocol", byProto), counts(" by exposure", byExposure))
	case model.SectionServices:
		byManager, byActive := map[string]int{}, map[string]int{}
		for _, s := range report.Services {
			byManager[s.Manager]++
			byActive[s.Active]++
		}
		scope := "running and failed units"
		if a.cfg.ServicesAll {
			scope = "every unit (--services-all)"
		}
		return fmt.Sprintf("%s: %d service unit(s)%s%s", scope, len(report.Services),
			counts(" by init system", byManager), counts(" by state", byActive))
	case model.SectionWitness:
		byOutcome := map[string]int{}
		for _, r := range report.Rules {
			byOutcome[string(r.Outcome)]++
		}
		problems, _ := findingCounts(report.Findings)
		return fmt.Sprintf("%d rule(s) compared the plan with this host%s; %d finding(s), %d blocker(s); the "+
			"host sources compared are the observations named without a section prefix",
			len(report.Rules), counts(" by outcome", byOutcome), len(report.Findings), problems)
	}
	return ""
}

// quotedCategories are the fact categories whose values go into an observation:
// the posture a check concludes from (operating system, kernel, clock, SSH
// settings, hardening switches, the package manager). The others — interfaces
// and addresses, account names, hardware, mounts, the host's identity — are an
// inventory of the machine, and the contract leaves the inventory in the local
// CSV: their observation names the keys read and quotes a value only when it is
// a bare count. /etc/machine-id is never quoted; it goes out only as the salted
// server fingerprint.
var quotedCategories = map[string]bool{
	"os": true, "kernel": true, "time": true, "ssh": true, "hardening": true, "packages": true,
}

// factValue is how one fact appears in its category's observation.
func factValue(f model.Fact) string {
	if quotedCategories[f.Category] {
		return f.Key + "=" + shortValue(f.Value)
	}
	if _, err := strconv.Atoi(strings.TrimSpace(f.Value)); err == nil && f.Key != "machine-id" {
		return f.Key + "=" + strings.TrimSpace(f.Value)
	}
	if f.Category == "accounts" {
		// An account list is counted, not quoted: "uid-0: 1 entry" proves the
		// check without naming anyone.
		return fmt.Sprintf("%s: %d entr(ies)", f.Key, len(strings.FieldsFunc(f.Value, func(r rune) bool {
			return r == ',' || r == '|'
		})))
	}
	return f.Key
}

// factObservations is one observation per fact category of the system section:
// the keys read, their values and the files or commands they came from. A category
// is complete when it holds facts — a source that could not be read leaves no fact
// and a note in the section instead.
func factObservations(facts []model.Fact, at time.Time) []model.Observation {
	type group struct {
		values  []string
		sources []string
	}
	groups := map[string]*group{}
	var order []string
	for _, f := range facts {
		g := groups[f.Category]
		if g == nil {
			g = &group{}
			groups[f.Category] = g
			order = append(order, f.Category)
		}
		g.values = append(g.values, factValue(f))
		if !contains(g.sources, f.Source) {
			g.sources = append(g.sources, f.Source)
		}
	}
	out := make([]model.Observation, 0, len(order))
	for _, category := range order {
		g := groups[category]
		note := fmt.Sprintf("%d fact(s): %s (from %s)", len(g.values), strings.Join(g.values, ", "),
			strings.Join(g.sources, ", "))
		if !quotedCategories[category] {
			note += "; values other than counts stay in system.csv"
		}
		out = append(out, model.Observation{
			Source:     "system:" + category,
			State:      model.ObservedComplete,
			Note:       clip(note),
			ObservedAt: at.UTC().Format(time.RFC3339),
		})
	}
	return out
}

// commandObservations is one observation per program a section ran: every
// invocation of it, with outcome, exit code and duration, timed at the latest
// launch. A program that is not installed is not-collected — an answer about the
// host, not a failure of the tool.
func commandObservations(section string, entries []run.JournalEntry) []model.Observation {
	type group struct {
		runs          []string
		ok, missing   int
		failed, total int
		last          time.Time
	}
	groups := map[string]*group{}
	var order []string
	for _, e := range entries {
		fields := strings.Fields(e.Command)
		if len(fields) == 0 {
			continue
		}
		name := filepath.Base(fields[0])
		g := groups[name]
		if g == nil {
			g = &group{}
			groups[name] = g
			order = append(order, name)
		}
		g.total++
		switch e.Outcome {
		case run.OutcomeOK:
			g.ok++
		case run.OutcomeMissing:
			g.missing++
		default:
			g.failed++
		}
		if e.StartedAt.After(g.last) {
			g.last = e.StartedAt
		}
		g.runs = append(g.runs, fmt.Sprintf("`%s` %s, exit %d, %s", e.Command, e.Outcome, e.ExitCode, e.Duration))
	}
	out := make([]model.Observation, 0, len(order))
	for _, name := range order {
		g := groups[name]
		state := model.ObservedPartial
		switch {
		case g.ok == g.total:
			state = model.ObservedComplete
		case g.missing == g.total:
			state = model.ObservedNotCollected
		case g.ok == 0 && g.failed > 0:
			state = model.ObservedFailed
		}
		out = append(out, model.Observation{
			Source:     section + ":" + name,
			State:      state,
			Note:       clip(fmt.Sprintf("%d run(s): %s", g.total, strings.Join(g.runs, "; "))),
			ObservedAt: g.last.UTC().Format(time.RFC3339),
		})
	}
	return out
}

// allObservations is every observation of the run in the order the host was read:
// the sections' own and the witness section's host sources.
func allObservations(sections []model.Observation, caps *model.Capabilities) []model.Observation {
	out := append([]model.Observation(nil), sections...)
	if caps != nil {
		out = append(out, caps.Observations...)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ObservedAt < out[j].ObservedAt })
	return out
}

// counts renders a tally as " label: a 3, b 1", or "" for an empty one.
func counts(label string, tally map[string]int) string {
	if len(tally) == 0 {
		return ""
	}
	keys := make([]string, 0, len(tally))
	for k := range tally {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s %d", orNone(k), tally[k]))
	}
	return fmt.Sprintf(";%s: %s", label, strings.Join(parts, ", "))
}

const maxFactValue = 60

func shortValue(v string) string {
	v = strings.Join(strings.Fields(v), " ")
	if len(v) > maxFactValue {
		cut := maxFactValue
		for cut > 0 && !utf8Start(v[cut]) {
			cut--
		}
		return v[:cut] + "…"
	}
	return v
}

func clip(s string) string {
	if len(s) <= maxObservationNote {
		return s
	}
	cut := maxObservationNote
	for cut > 0 && !utf8Start(s[cut]) {
		cut--
	}
	return s[:cut] + " … (cut at " + fmt.Sprint(maxObservationNote) + " characters; the full record is in the local CSV)"
}

// utf8Start reports whether b begins a UTF-8 sequence, so a cut never splits one.
func utf8Start(b byte) bool { return b&0xC0 != 0x80 }

func orNone(s string) string {
	if strings.TrimSpace(s) == "" {
		return "none"
	}
	return s
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
