// Package score turns a bench run into quality figures per rule, compares two runs
// scenario by scenario, and decides whether a version may be released (DW-84).
//
// Three rules keep the figures honest, and each is enforced here rather than left to
// whoever reads them:
//
//   - Unknown is never a detection. A staged problem the CLI answered "unknown" for
//     counts against the detection rate, not for it, so a version cannot look better
//     by deciding less.
//   - Only scenarios whose ground truth Docker confirmed are scored for accuracy. A
//     scenario where Docker did not behave as the scenario says proves nothing about
//     the CLI, and fails the gate until the scenario is fixed.
//   - Versions are compared on the same scenarios. A scenario of the baseline that
//     is missing from the new run is a removed test, and fails the gate: deleting the
//     hard cases must not read as an improvement.
package score

import (
	"fmt"
	"sort"
	"strings"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/bench/result"
)

// RuleScore is the quality of one rule on one run.
type RuleScore struct {
	Rule string `json:"rule"`
	// Scenarios counts every scenario of the rule; Scored the ones whose ground
	// truth held (no bench error, Docker as expected or advisory).
	Scenarios int `json:"scenarios"`
	Scored    int `json:"scored"`
	// On staged problems: Detected (predicted problem, or the plan refused),
	// Missed (predicted no-problem or not-applicable — said clean),
	// UnknownOnProblem (predicted unknown or manual-check — undecided, and not a
	// detection).
	Problems         int `json:"problems"`
	Detected         int `json:"detected"`
	Missed           int `json:"missed"`
	UnknownOnProblem int `json:"unknownOnProblem"`
	// On staged clean situations: FalseFindings (predicted problem),
	// UnknownOnClean (predicted unknown — unjustified).
	Clean          int `json:"clean"`
	FalseFindings  int `json:"falseFindings"`
	UnknownOnClean int `json:"unknownOnClean"`
	// On staged insufficient data: CorrectUnknown (predicted unknown), Guessed
	// (predicted problem or no-problem — a conclusion without the data).
	InsufficientData int `json:"insufficientData"`
	CorrectUnknown   int `json:"correctUnknown"`
	Guessed          int `json:"guessed"`
	// Unknown counts every unknown prediction of the rule.
	Unknown int `json:"unknown"`
	// Situations says which of the three defining situations the rule's scenarios
	// stage: "problem,no-problem,unknown" is full coverage.
	Situations string `json:"situations"`
	// AsSpecified counts the scenarios whose prediction equals their expectation.
	AsSpecified int `json:"asSpecified"`
}

// DetectionRate is Detected over staged problems; Unknown counts against it.
func (r RuleScore) DetectionRate() float64 { return ratio(r.Detected, r.Problems) }

// FalseFindingRate is FalseFindings over staged clean situations.
func (r RuleScore) FalseFindingRate() float64 { return ratio(r.FalseFindings, r.Clean) }

func ratio(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return float64(a) / float64(b)
}

// Report is the quality of a whole run.
type Report struct {
	CLIVersion  string      `json:"cliVersion"`
	Environment string      `json:"environment"`
	Rules       []RuleScore `json:"rules"`
	Total       RuleScore   `json:"total"`
	// BenchErrors, SideEffects and DockerDisagreements are scenarios that prove
	// nothing about the CLI until fixed.
	BenchErrors         []string `json:"benchErrors"`
	SideEffects         []string `json:"sideEffects"`
	DockerDisagreements []string `json:"dockerDisagreements"`
}

// Score computes the per-rule figures of a run.
func Score(run *result.Run) Report {
	rep := Report{CLIVersion: run.CLIVersion, Environment: fmt.Sprintf("%s (Docker %s, Compose %s)",
		run.Environment, run.DockerVersion, run.ComposeVersion)}
	byRule := map[string]*RuleScore{}
	situations := map[string]map[result.Situation]bool{}
	for _, o := range run.Results {
		rule := o.Scenario.Rule
		if byRule[rule] == nil {
			byRule[rule] = &RuleScore{Rule: rule}
			situations[rule] = map[result.Situation]bool{}
		}
		r := byRule[rule]
		r.Scenarios++
		situations[rule][o.Scenario.Situation] = true
		if o.Predicted == "unknown" {
			r.Unknown++
		}
		switch {
		case o.BenchError != "":
			rep.BenchErrors = append(rep.BenchErrors, o.Scenario.ID+": "+o.BenchError)
			continue
		case o.DockerMatch != nil && !*o.DockerMatch:
			rep.DockerDisagreements = append(rep.DockerDisagreements, o.Scenario.ID)
			continue
		}
		if len(o.SideEffects) > 0 {
			rep.SideEffects = append(rep.SideEffects, o.Scenario.ID+": "+strings.Join(o.SideEffects, "; "))
		}
		r.Scored++
		if o.SpecMatch {
			r.AsSpecified++
		}
		decided := o.Predicted == "problem" || o.Predicted == "refused"
		clean := o.Predicted == "no-problem" || o.Predicted == "not-applicable"
		switch o.Scenario.Situation {
		case result.SituationProblem:
			r.Problems++
			switch {
			case decided:
				r.Detected++
			case o.Predicted == "unknown" || o.Predicted == "manual-check":
				r.UnknownOnProblem++
			default:
				r.Missed++
			}
		case result.SituationNoProblem, result.SituationNotApplicable:
			r.Clean++
			switch {
			case decided:
				r.FalseFindings++
			case o.Predicted == "unknown":
				r.UnknownOnClean++
			}
		case result.SituationUnknown:
			r.InsufficientData++
			if o.Predicted == "unknown" {
				r.CorrectUnknown++
			} else if decided || clean {
				r.Guessed++
			}
		}
	}

	var names []string
	for name := range byRule {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		r := byRule[name]
		var covered []string
		for _, s := range []result.Situation{result.SituationProblem, result.SituationNoProblem, result.SituationUnknown} {
			if situations[name][s] {
				covered = append(covered, string(s))
			}
		}
		r.Situations = strings.Join(covered, ",")
		rep.Rules = append(rep.Rules, *r)
		rep.Total = add(rep.Total, *r)
	}
	rep.Total.Rule = "all"
	return rep
}

func add(a, b RuleScore) RuleScore {
	a.Scenarios += b.Scenarios
	a.Scored += b.Scored
	a.Problems += b.Problems
	a.Detected += b.Detected
	a.Missed += b.Missed
	a.UnknownOnProblem += b.UnknownOnProblem
	a.Clean += b.Clean
	a.FalseFindings += b.FalseFindings
	a.UnknownOnClean += b.UnknownOnClean
	a.InsufficientData += b.InsufficientData
	a.CorrectUnknown += b.CorrectUnknown
	a.Guessed += b.Guessed
	a.Unknown += b.Unknown
	a.AsSpecified += b.AsSpecified
	return a
}

// ─────────────────────────────────────────────────────────── comparison and gate

// Change is how one scenario moved between two runs.
type Change struct {
	Scenario string `json:"scenario"`
	Before   string `json:"before"`
	After    string `json:"after"`
	Kind     string `json:"kind"` // regression, fixed, changed, new, removed
}

// Compare lines two runs up scenario by scenario.
func Compare(baseline, current *result.Run) []Change {
	before := map[string]result.Outcome{}
	for _, o := range baseline.Results {
		before[o.Scenario.ID] = o
	}
	seen := map[string]bool{}
	var out []Change
	for _, o := range current.Results {
		seen[o.Scenario.ID] = true
		b, ok := before[o.Scenario.ID]
		switch {
		case !ok:
			out = append(out, Change{Scenario: o.Scenario.ID, After: o.Predicted, Kind: "new"})
		case passed(b) && !passed(o):
			out = append(out, Change{Scenario: o.Scenario.ID, Before: b.Predicted, After: o.Predicted, Kind: "regression"})
		case !passed(b) && passed(o):
			out = append(out, Change{Scenario: o.Scenario.ID, Before: b.Predicted, After: o.Predicted, Kind: "fixed"})
		case b.Predicted != o.Predicted:
			out = append(out, Change{Scenario: o.Scenario.ID, Before: b.Predicted, After: o.Predicted, Kind: "changed"})
		}
	}
	for _, b := range baseline.Results {
		if !seen[b.Scenario.ID] {
			out = append(out, Change{Scenario: b.Scenario.ID, Before: b.Predicted, Kind: "removed"})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Scenario < out[j].Scenario
	})
	return out
}

// passed: the scenario proves the CLI right — as specified, ground truth held.
func passed(o result.Outcome) bool {
	return o.BenchError == "" && o.SpecMatch && (o.DockerMatch == nil || *o.DockerMatch) && len(o.SideEffects) == 0
}

// Gate decides whether the run may be released. Every reason it returns blocks.
//
// A release is blocked by: a bench error, an audit side effect, a scenario whose
// Docker behaviour contradicts it (no ground truth), a critical scenario that fails
// (a known critical miss), a scenario marked as a regression test that fails (a fixed
// defect come back), a scenario that passed in the baseline and fails now, and a
// baseline scenario missing from this run.
func Gate(current *result.Run, baseline *result.Run) []string {
	var reasons []string
	for _, o := range current.Results {
		id := o.Scenario.ID
		switch {
		case o.BenchError != "":
			reasons = append(reasons, "bench error in "+id+": the run cannot certify anything until it is fixed")
		case o.DockerMatch != nil && !*o.DockerMatch:
			reasons = append(reasons, "Docker did not behave as "+id+" says: its ground truth is broken")
		case len(o.SideEffects) > 0:
			reasons = append(reasons, "the audit changed something in "+id+": "+strings.Join(o.SideEffects, "; "))
		case !o.SpecMatch && o.Scenario.Critical:
			reasons = append(reasons, fmt.Sprintf("critical scenario %s fails: expected %s, predicted %s", id,
				o.Scenario.Expect.Outcome, o.Predicted))
		case !o.SpecMatch && o.Scenario.Regression != "":
			reasons = append(reasons, fmt.Sprintf("regression test %s (%s) fails again: expected %s, predicted %s", id,
				o.Scenario.Regression, o.Scenario.Expect.Outcome, o.Predicted))
		}
	}
	if baseline != nil {
		for _, c := range Compare(baseline, current) {
			switch c.Kind {
			case "regression":
				reasons = append(reasons, fmt.Sprintf("%s passed in the baseline and fails now (%s → %s)", c.Scenario,
					c.Before, c.After))
			case "removed":
				reasons = append(reasons, c.Scenario+" is in the baseline and missing from this run: a removed test "+
					"is never an improvement")
			}
		}
	}
	return reasons
}

// Render prints the report as a fixed-width table.
func Render(rep Report, changes []Change, reasons []string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s on %s\n\n", rep.CLIVersion, rep.Environment)
	fmt.Fprintf(&b, "%-34s %5s %5s | %8s %6s %6s %7s | %5s %6s %7s | %7s %7s | %s\n",
		"rule", "scen", "scored", "problems", "found", "missed", "unknown", "clean", "false", "unknown",
		"no-data", "guessed", "situations")
	for _, r := range append(rep.Rules, rep.Total) {
		fmt.Fprintf(&b, "%-34s %5d %5d | %8d %6d %6d %7d | %5d %6d %7d | %7d %7d | %s\n",
			strings.TrimPrefix(r.Rule, "witness."), r.Scenarios, r.Scored, r.Problems, r.Detected, r.Missed,
			r.UnknownOnProblem, r.Clean, r.FalseFindings, r.UnknownOnClean, r.InsufficientData, r.Guessed, r.Situations)
	}
	t := rep.Total
	fmt.Fprintf(&b, "\ndetection %.0f%% (unknown is not a detection), false findings %.0f%%, unknown predictions %d of %d, "+
		"as specified %d of %d scored\n", 100*t.DetectionRate(), 100*t.FalseFindingRate(), t.Unknown, t.Scenarios,
		t.AsSpecified, t.Scored)
	for _, list := range []struct {
		name  string
		items []string
	}{{"bench errors", rep.BenchErrors}, {"audit side effects", rep.SideEffects}, {"Docker disagreements", rep.DockerDisagreements}} {
		if len(list.items) > 0 {
			fmt.Fprintf(&b, "%s: %s\n", list.name, strings.Join(list.items, "; "))
		}
	}
	if changes != nil {
		fmt.Fprintf(&b, "\nagainst the baseline:")
		if len(changes) == 0 {
			fmt.Fprintf(&b, " no scenario changed")
		}
		fmt.Fprintln(&b)
		for _, c := range changes {
			fmt.Fprintf(&b, "  %-10s %-55s %s → %s\n", c.Kind, c.Scenario, orDash(c.Before), orDash(c.After))
		}
	}
	if reasons != nil {
		if len(reasons) == 0 {
			fmt.Fprintf(&b, "\nrelease gate: PASS\n")
		} else {
			fmt.Fprintf(&b, "\nrelease gate: BLOCKED\n")
			for _, r := range reasons {
				fmt.Fprintf(&b, "  - %s\n", r)
			}
		}
	}
	return b.String()
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
