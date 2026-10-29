package report

import (
	"fmt"
	"strings"
	"time"

	"google.golang.org/protobuf/reflect/protoreflect"

	auditv1 "github.com/BloodHeavenDevelop/deploy-witness-cli/app/contract/auditv1"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
)

// This file is the one place deploy-witness speaks the platform's audit contract.
//
// The contract lives in the `contracts` repository and is shared with
// deploy-witness, which produces levels 0 and 1 of the same product. Restating the
// shape here by hand would mean the divergence is discovered in production, on the
// first upload — so the *generated* types are used as generated, copied in whole
// under app/contract/auditv1 (see the note there: this binary must build without
// access to a private repository), and the conversion is confined to this file.
// Nothing else in the tool knows protobuf exists.

// SchemaVersion is what this build produces and what a receiver checks first. An
// agent built months ago and run today must be told its report is not understood,
// rather than having it half-read.
const SchemaVersion = "1.0"

// levelServer is the level of every report this tool makes: 2, the on-server
// witness. Levels 0 and 1 are the domain-side checks, and they are not this
// binary's business.
const levelServer = 2

// Contract converts a finished report into the shared audit contract.
//
// Only the witness section maps — its findings and their outcomes, one result per
// rule, the launch plan and the provenance — plus the collector statuses, change
// list, rollback plan and command journal: the contract is a *findings* document, and
// deploy-witness's package inventory, pending updates and CVE list have no place in
// it. They stay in the CSV, which is where a person reads them. Sending them would
// be volunteering a full software inventory of somebody's production host to a
// remote service that did not ask for one.
func Contract(r *model.Report) *auditv1.Report {
	out := &auditv1.Report{
		SchemaVersion:     SchemaVersion,
		Level:             levelServer,
		ServerFingerprint: fingerprint(),
		ServerHostname:    r.Hostname,
		GeneratedAt:       r.GeneratedAt.UTC().Format(time.RFC3339),
		StaleAfter:        r.GeneratedAt.UTC().Add(staleAfter).Format(time.RFC3339),
		Producer:          fmt.Sprintf("%s/%s", r.Tool, r.Version),
	}

	for _, finding := range r.Findings {
		out.Findings = append(out.Findings, contractFinding(finding))
	}
	for _, section := range r.Sections {
		// A section outside the run's scope is not a collector of this run. The
		// contract has no status for it — every CollectorStatus other than OK counts
		// against the run's completeness on the receiving side — so it is left out
		// rather than sent as SKIPPED. A host audit therefore arrives with no witness
		// collector, which is also how the receiver tells it from a preflight (a
		// preflight always carries one, whatever its status).
		if section.Status == model.StatusNotApplicable {
			continue
		}
		out.Collectors = append(out.Collectors, contractCollector(section))
	}
	for _, change := range r.Changes {
		out.Changes = append(out.Changes, &auditv1.ChangeItem{
			Kind: change.Kind, Target: change.Target, Detail: change.Detail,
		})
	}
	// The contract's rollback item has a boolean only. An item that could not be
	// verified goes out as available=false — the contract cannot say more — and its
	// detail opens with "unable to verify:", so the receiver can still tell it from
	// one that is known to be missing.
	for _, item := range r.Rollback {
		out.Rollback = append(out.Rollback, &auditv1.RollbackItem{
			Kind: item.Kind, Available: item.Available, Detail: item.Detail,
		})
	}
	// The whole journal, including any refusal. A client who ran an unfamiliar
	// binary on their production host is owed the full list of what it did.
	for _, command := range r.Commands {
		out.CommandJournal = append(out.CommandJournal,
			fmt.Sprintf("%s — %s (%s)", command.Command, command.Outcome, command.Duration))
	}

	// What the run concluded, from what plan, resting on what (DW-94). Until then
	// these went out only as text in the witness collector's note; the note lines
	// stay for a person reading it, but the fields are what a receiver reads.
	for _, rule := range r.Rules {
		out.RuleResults = append(out.RuleResults, &auditv1.RuleResult{
			Code: rule.Code, Rule: rule.Rule, Outcome: contractOutcome(rule.Outcome),
			Findings: int32(rule.Findings), Reason: rule.Reason, Requires: rule.Requires,
		})
	}
	out.Plan = contractPlan(r.Plan)
	out.Provenance = contractProvenance(r.Provenance)

	// The engine's own ID is not ours to publish, any more than /etc/machine-id is:
	// the upload names the engine by its fingerprint alone. The rules write the raw
	// ID into evidence (to tell two engines' answers apart) and the provenance note
	// names it, so every string of the document is swept rather than only the
	// fields known to carry it today.
	if p := r.Provenance; p != nil {
		hideEngineID(out.ProtoReflect(), p.EngineID, model.EngineFingerprint(p.EngineID))
	}

	return out
}

// contractPlan maps the launch plan. Two things are deliberately left out: the
// engine's endpoint (engine_context names it for the person who ran the audit, and
// an address is not the receiver's business) and the per-service configuration
// hashes, which the contract does not carry. No variable value is in the plan to
// begin with — Environment holds names.
func contractPlan(plan *model.LaunchPlan) *auditv1.LaunchPlan {
	if plan == nil {
		return nil
	}
	out := &auditv1.LaunchPlan{
		Files:             plan.Files,
		ProjectDirectory:  plan.ProjectDirectory,
		ProjectName:       plan.ProjectName,
		ProjectNameSource: plan.ProjectNameSource,
		EnvFiles:          plan.EnvFiles,
		Profiles:          plan.Profiles,
		Services:          plan.Services,
		Started:           plan.Started,
		Resolver:          plan.Resolver,
		ResolverVersion:   plan.ResolverVersion,
		Environment:       plan.Environment,
		EngineContext:     plan.Engine.Context,
		EngineLocal:       plan.Engine.Local,
		Digest:            plan.Digest,
		ResolvedAt:        plan.ResolvedAt,
		RemoveOrphans:     plan.RemoveOrphans,
		ForceRecreate:     plan.ForceRecreate,
		NoRecreate:        plan.NoRecreate,
		Notes:             plan.Notes,
	}
	for _, digest := range plan.FileDigests {
		out.FileDigests = append(out.FileDigests, &auditv1.FileDigest{Path: digest.Path, Sha256: digest.SHA256})
	}
	return out
}

// contractProvenance maps the provenance and the observations it rests on — every
// section's (`<section>` / `<section>:<detail>`, DW-82) and, in a preflight, the
// witness section's host sources. A host audit therefore arrives with observations
// too, and a host check that found nothing carries what proves it. The engine goes
// out as its fingerprint, never as the ID `docker info` reports; the host name and
// the server fingerprint already have fields of their own on Report.
func contractProvenance(p *model.Provenance) *auditv1.Provenance {
	if p == nil {
		return nil
	}
	out := &auditv1.Provenance{
		Tool:              p.Tool,
		ToolVersion:       p.ToolVersion,
		RulesVersion:      p.RulesVersion,
		Engine:            p.Engine,
		EngineFingerprint: model.EngineFingerprint(p.EngineID),
		Compose:           p.Compose,
		PlanSource:        p.PlanSource,
		PlanDigest:        p.PlanDigest,
		StartedAt:         p.StartedAt,
		PlanResolvedAt:    p.PlanResolvedAt,
		ObservedFrom:      p.ObservedFrom,
		ObservedUntil:     p.ObservedUntil,
		ComparedAt:        p.ComparedAt,
		FinishedAt:        p.FinishedAt,
		ClockSynchronized: p.ClockSynchronized,
		EngineClockSkew:   p.EngineClockSkew,
		TimeChecks:        p.TimeChecks,
		Completeness:      p.Completeness,
		RecheckAfter:      p.RecheckAfter,
	}
	for _, o := range p.Observations {
		out.Observations = append(out.Observations, &auditv1.Observation{
			Source: o.Source, State: contractObservationState(o.State), Note: o.Note, ObservedAt: o.ObservedAt,
		})
	}
	return out
}

// minEngineIDLength keeps the sweep from rewriting ordinary words: `docker info`
// IDs are UUIDs or twelve colon-separated groups, never a handful of characters.
const minEngineIDLength = 8

// hideEngineID replaces every occurrence of the engine's raw ID in the message's
// strings — nested messages and lists included — with its fingerprint.
func hideEngineID(m protoreflect.Message, raw, fingerprint string) {
	raw = strings.TrimSpace(raw)
	if len(raw) < minEngineIDLength {
		return
	}
	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		switch {
		case fd.IsList() && fd.Kind() == protoreflect.StringKind:
			list := v.List()
			for i := 0; i < list.Len(); i++ {
				list.Set(i, protoreflect.ValueOfString(strings.ReplaceAll(list.Get(i).String(), raw, fingerprint)))
			}
		case fd.IsList() && fd.Kind() == protoreflect.MessageKind:
			list := v.List()
			for i := 0; i < list.Len(); i++ {
				hideEngineID(list.Get(i).Message(), raw, fingerprint)
			}
		case fd.IsMap():
			// The contract has no map fields; were one added, it is not swept
			// silently — the test that checks the raw ID is absent will say so.
		case fd.Kind() == protoreflect.StringKind:
			m.Set(fd, protoreflect.ValueOfString(strings.ReplaceAll(v.String(), raw, fingerprint)))
		case fd.Kind() == protoreflect.MessageKind:
			hideEngineID(v.Message(), raw, fingerprint)
		}
		return true
	})
}

// staleAfter is how long a level 2 report is presented as current. Server state
// drifts; a week later the picture may not hold, and the reader is told so rather
// than left to guess.
const staleAfter = 7 * 24 * time.Hour

func contractFinding(f model.Finding) *auditv1.Finding {
	out := &auditv1.Finding{
		Code:         f.Code,
		Collector:    f.Collector,
		Category:     contractCategory(f.Category),
		Severity:     contractSeverity(f.Severity),
		Subject:      f.Subject,
		Title:        f.Title,
		Description:  f.Description,
		WhyItMatters: f.WhyItMatters,
		WhatToDo:     f.WhatToDo,
		Confidence:   contractConfidence(f.Confidence),
		SortOrder:    int32(f.SortOrder),
		Outcome:      contractOutcome(f.Outcome),
	}
	for _, e := range f.Evidence {
		out.Evidence = append(out.Evidence, &auditv1.Evidence{
			Command:    e.Command,
			Output:     e.Output,
			Truncated:  e.Truncated,
			CapturedAt: e.CapturedAt,
		})
	}
	return out
}

func contractCollector(section model.SectionResult) *auditv1.CollectorResult {
	duration, _ := time.ParseDuration(section.Duration)
	return &auditv1.CollectorResult{
		Collector:  string(section.Section),
		Status:     contractStatus(section.Status),
		Note:       strings.Join(section.Notes, "; "),
		DurationMs: int32(duration.Milliseconds()),
	}
}

// contractOutcome maps a rule's conclusion. An empty outcome — a finding built by
// a path that states none — goes out as UNSPECIFIED, which the receiver reads by
// severity as it always has; it is never guessed into PROBLEM.
func contractOutcome(o model.Outcome) auditv1.Outcome {
	switch o {
	case model.OutcomeProblem:
		return auditv1.Outcome_OUTCOME_PROBLEM
	case model.OutcomeNoProblem:
		return auditv1.Outcome_OUTCOME_NO_PROBLEM
	case model.OutcomeUnknown:
		return auditv1.Outcome_OUTCOME_UNKNOWN
	case model.OutcomeManualCheck:
		return auditv1.Outcome_OUTCOME_MANUAL_CHECK
	case model.OutcomeNotApplicable:
		return auditv1.Outcome_OUTCOME_NOT_APPLICABLE
	default:
		return auditv1.Outcome_OUTCOME_UNSPECIFIED
	}
}

func contractObservationState(s model.ObservationState) auditv1.ObservationState {
	switch s {
	case model.ObservedComplete:
		return auditv1.ObservationState_OBSERVATION_STATE_COMPLETE
	case model.ObservedPartial:
		return auditv1.ObservationState_OBSERVATION_STATE_PARTIAL
	case model.ObservedFailed:
		return auditv1.ObservationState_OBSERVATION_STATE_FAILED
	case model.ObservedNotCollected:
		return auditv1.ObservationState_OBSERVATION_STATE_NOT_COLLECTED
	default:
		return auditv1.ObservationState_OBSERVATION_STATE_UNSPECIFIED
	}
}

func contractSeverity(s model.FindingSeverity) auditv1.Severity {
	switch s {
	case model.FindingBlocker:
		return auditv1.Severity_SEVERITY_BLOCKER
	case model.FindingWarning:
		return auditv1.Severity_SEVERITY_WARNING
	case model.FindingInfo:
		return auditv1.Severity_SEVERITY_INFO
	default:
		return auditv1.Severity_SEVERITY_UNSPECIFIED
	}
}

func contractCategory(category string) auditv1.Category {
	switch category {
	case model.CategoryConflict:
		return auditv1.Category_CATEGORY_CONFLICT
	case model.CategoryResource:
		return auditv1.Category_CATEGORY_RESOURCE
	case model.CategorySecurity:
		return auditv1.Category_CATEGORY_SECURITY
	case model.CategoryExpiry:
		return auditv1.Category_CATEGORY_EXPIRY
	case model.CategoryMissing:
		return auditv1.Category_CATEGORY_MISSING
	default:
		return auditv1.Category_CATEGORY_UNSPECIFIED
	}
}

func contractConfidence(c model.Confidence) auditv1.Confidence {
	switch c {
	case model.ConfidenceHigh:
		return auditv1.Confidence_CONFIDENCE_HIGH
	case model.ConfidenceMedium:
		return auditv1.Confidence_CONFIDENCE_MEDIUM
	case model.ConfidenceLow:
		return auditv1.Confidence_CONFIDENCE_LOW
	default:
		return auditv1.Confidence_CONFIDENCE_UNSPECIFIED
	}
}

// contractStatus maps a section outcome onto the contract's collector status.
//
// `partial` maps to PARTIAL and not to OK. It first went out as OK, and the receiving
// service duly stored a run that had degraded on an unprivileged host as a complete
// audit of that machine — the note survived on the collector row while the report as
// a whole claimed to be finished. That is precisely the failure this repository's
// second promise exists to prevent, so the contract gained the state rather than the
// mapping gaining a compromise.
func contractStatus(status model.Status) auditv1.CollectorStatus {
	switch status {
	case model.StatusOk:
		return auditv1.CollectorStatus_COLLECTOR_STATUS_OK
	case model.StatusPartial:
		return auditv1.CollectorStatus_COLLECTOR_STATUS_PARTIAL
	case model.StatusFailed:
		return auditv1.CollectorStatus_COLLECTOR_STATUS_FAILED
	case model.StatusSkipped:
		return auditv1.CollectorStatus_COLLECTOR_STATUS_SKIPPED
	default:
		return auditv1.CollectorStatus_COLLECTOR_STATUS_UNSPECIFIED
	}
}

// fingerprint identifies this machine to the receiving service; see
// model.MachineFingerprint. The provenance of the local report carries the same value.
func fingerprint() string { return model.MachineFingerprint() }
