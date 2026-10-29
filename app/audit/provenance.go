package audit

import (
	"fmt"
	"strings"
	"time"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/witness"
)

// DefaultMaxAge is how long a preflight report confirms its plan. Past it the host
// may have changed — a port taken, a volume removed — and the report says to check
// again before deploying (`--recheck`, or a new audit).
const DefaultMaxAge = time.Hour

// Time-consistency thresholds. A skew of a few seconds between the engine and this
// host is measurement noise; more means one of the two clocks is wrong and the
// evidence times cannot be compared across them. A collection that spans more than
// ten minutes saw the host at moments far enough apart for it to have changed.
const (
	maxEngineSkew      = 5 * time.Second
	maxObservationSpan = 10 * time.Minute
	timeSlack          = time.Second
)

// provenance assembles what every conclusion of the report rests on, and checks
// that the timeline holds together. It is computed last, from what the run did.
func (a *Auditor) provenance(report *model.Report, finished time.Time) *model.Provenance {
	p := &model.Provenance{
		Tool:              report.Tool,
		ToolVersion:       report.Version,
		RulesVersion:      witness.RulesVersion,
		Host:              report.Hostname,
		ServerFingerprint: model.MachineFingerprint(),
		StartedAt:         stamp(report.GeneratedAt),
		FinishedAt:        stamp(finished),
		ClockSynchronized: clockSynchronized(report.System),
		RecheckAfter:      stamp(finished.Add(DefaultMaxAge)),
	}
	if !a.comparedAt.IsZero() {
		p.ComparedAt = stamp(a.comparedAt)
	}
	if plan := report.Plan; plan != nil {
		p.PlanSource, p.PlanDigest, p.PlanResolvedAt = plan.Resolver, plan.Digest, plan.ResolvedAt
		if plan.ResolverVersion != "" {
			p.PlanSource += " " + plan.ResolverVersion
		}
	}

	// Every source the run read: what each section read (DW-82) and, in a
	// preflight, the host sources the witness section compared.
	observations := allObservations(a.observations, report.Capabilities)
	p.Observations = observations
	if caps := report.Capabilities; caps != nil {
		if rt := caps.Runtime; rt != nil {
			p.Engine = strings.TrimSpace(rt.Kind + " " + rt.Version)
			p.EngineID, p.EngineClockSkew = rt.EngineID, rt.ClockSkew
			p.EngineFingerprint = model.EngineFingerprint(rt.EngineID)
			if rt.ComposeKind != "" {
				p.Compose = strings.TrimSpace(rt.ComposeKind + " " + rt.ComposeVersion)
			}
		}
	}
	// The observed span is that of the sources a conclusion was drawn from: in a
	// preflight, the host sources the rules compared (a slow --online
	// vulnerability section before them does not stretch it, as it did not before
	// DW-82); in a host audit, everything the sections read.
	spanned := observations
	if caps := report.Capabilities; caps != nil && len(caps.Observations) > 0 {
		spanned = caps.Observations
	}
	p.ObservedFrom, p.ObservedUntil = observationSpan(spanned)
	p.Completeness = completeness(observations)
	p.TimeChecks = timeChecks(report, p, observations, finished)
	return p
}

func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339) }

// clockSynchronized reads timedatectl's answer from the system section.
func clockSynchronized(facts []model.Fact) string {
	for _, f := range facts {
		if f.Category == "time" && f.Key == "ntpsynchronized" {
			return f.Value
		}
	}
	return "unknown"
}

func observationSpan(observations []model.Observation) (from, until string) {
	for _, o := range observations {
		if o.ObservedAt == "" {
			continue
		}
		if from == "" || o.ObservedAt < from {
			from = o.ObservedAt
		}
		if o.ObservedAt > until {
			until = o.ObservedAt
		}
	}
	return from, until
}

// completeness summarises how fully the sources were read.
func completeness(observations []model.Observation) string {
	if len(observations) == 0 {
		return "no source was observed"
	}
	complete := 0
	byState := map[model.ObservationState][]string{}
	for _, o := range observations {
		if o.State == model.ObservedComplete {
			complete++
			continue
		}
		byState[o.State] = append(byState[o.State], o.Source)
	}
	out := fmt.Sprintf("%d of %d sources read in full", complete, len(observations))
	for _, state := range []model.ObservationState{model.ObservedPartial, model.ObservedFailed, model.ObservedNotCollected} {
		if sources := byState[state]; len(sources) > 0 {
			out += fmt.Sprintf("; %s: %s", state, strings.Join(sources, ", "))
		}
	}
	return out
}

// timeChecks lists every way the run's timeline does not hold together. Evidence
// times are this host's clock; when that clock is unsynchronised, jumped during the
// run, or disagrees with the engine's, the reader is told rather than left to
// compare times that do not mean what they say.
func timeChecks(report *model.Report, p *model.Provenance, observations []model.Observation, finished time.Time) []string {
	var out []string
	started := report.GeneratedAt.UTC()
	if finished.Before(started) {
		out = append(out, fmt.Sprintf("the clock went backwards during the run: it finished at %s, before it "+
			"started at %s", stamp(finished), stamp(started)))
	}

	outside := func(what, at string) {
		t, err := time.Parse(time.RFC3339, at)
		if err != nil {
			return
		}
		if t.Before(started.Add(-timeSlack)) || t.After(finished.Add(timeSlack)) {
			out = append(out, fmt.Sprintf("%s is timed %s, outside the run (%s – %s)", what, at, stamp(started),
				stamp(finished)))
		}
	}
	for _, o := range observations {
		outside("the observation of "+o.Source, o.ObservedAt)
	}
	if report.Plan != nil {
		outside("the plan resolution", report.Plan.ResolvedAt)
	}
	seen := map[string]bool{}
	for _, f := range report.Findings {
		for _, e := range f.Evidence {
			if !seen[e.CapturedAt] {
				seen[e.CapturedAt] = true
				outside("evidence of "+f.Code, e.CapturedAt)
			}
		}
	}

	if p.ClockSynchronized == "no" {
		out = append(out, "the host clock is not NTP-synchronised (timedatectl NTPSynchronized=no): every time "+
			"in this report is this host's clock and may be off")
	}
	if skew, err := time.ParseDuration(strings.TrimPrefix(p.EngineClockSkew, "+")); err == nil &&
		(skew > maxEngineSkew || skew < -maxEngineSkew) {
		out = append(out, fmt.Sprintf("the container engine's clock differs from this host's by %s; times the "+
			"engine reports and times this host reports cannot be compared directly", p.EngineClockSkew))
	}
	if p.ObservedFrom != "" && p.ObservedUntil != "" {
		from, errFrom := time.Parse(time.RFC3339, p.ObservedFrom)
		until, errUntil := time.Parse(time.RFC3339, p.ObservedUntil)
		if errFrom == nil && errUntil == nil && until.Sub(from) > maxObservationSpan {
			out = append(out, fmt.Sprintf("the host was observed over %s (%s – %s); the sources describe "+
				"moments far enough apart for the host to have changed in between", until.Sub(from).Round(time.Second),
				p.ObservedFrom, p.ObservedUntil))
		}
	}
	return out
}

// ProvenanceSummary is the one line the witness notes give the provenance. Since
// DW-94 it is no longer the upload's only carrier: the contract has a Provenance
// message of its own (report.Contract fills it), and this line stays because it
// is what a person reading summary.csv or the collector note sees. The raw engine
// ID it names is replaced by its fingerprint before the upload leaves the host.
func ProvenanceSummary(p *model.Provenance) string {
	parts := []string{fmt.Sprintf("provenance: %s %s, rules %s", p.Tool, orDash(p.ToolVersion), p.RulesVersion)}
	if p.Engine != "" {
		parts = append(parts, fmt.Sprintf("engine %s (id %s)", p.Engine, orDash(p.EngineID)))
	}
	if p.Compose != "" {
		parts = append(parts, "compose "+p.Compose)
	}
	if p.PlanDigest != "" {
		parts = append(parts, fmt.Sprintf("plan %s by %s", p.PlanDigest, p.PlanSource))
	}
	parts = append(parts, fmt.Sprintf("observed %s – %s", orDash(p.ObservedFrom), orDash(p.ObservedUntil)),
		p.Completeness, "recheck after "+p.RecheckAfter)
	consistency := "timeline consistent"
	if len(p.TimeChecks) > 0 {
		consistency = fmt.Sprintf("%d time inconsistency(ies), see provenance.csv", len(p.TimeChecks))
	}
	parts = append(parts, consistency)
	return strings.Join(parts, "; ")
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}
