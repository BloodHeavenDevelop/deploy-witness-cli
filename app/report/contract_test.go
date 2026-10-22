package report

import (
	"strings"
	"testing"

	auditv1 "github.com/BloodHeavenDevelop/deploy-witness-cli/app/contract/auditv1"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
	"google.golang.org/protobuf/encoding/protojson"
)

// rawEngineID is shaped like a `docker info` ID and appears nowhere else.
const rawEngineID = "7d1c2b9e-4f3a-4e5b-9c8d-0a1b2c3d4e5f"

// preflightReport is a Compose preflight with everything DW-94 maps: a plan, a
// provenance resting on two observations, one result per rule, and evidence and
// notes that name the engine by its raw ID the way the rules and the provenance
// note do.
func preflightReport() *model.Report {
	r := reportWith(model.ModeComposePreflight, &model.SectionResult{Section: model.SectionWitness,
		Status: model.StatusOk, Notes: []string{"provenance: engine docker 29.0 (id " + rawEngineID + ")"}})
	r.Plan = &model.LaunchPlan{
		Files: []string{"compose.yml", "compose.prod.yml"}, ProjectDirectory: "/srv/app",
		ProjectName: "app", ProjectNameSource: "--project-name", EnvFiles: []string{".env"},
		Profiles: []string{"web"}, Services: []string{"api"}, Started: []string{"api", "db"},
		Resolver: model.ResolverCompose, ResolverVersion: "2.40.0", Environment: []string{"COMPOSE_PROFILES"},
		Engine: model.EngineTarget{Context: "default", Endpoint: "unix:///run/secret-engine.sock", Local: true,
			ID: rawEngineID, Name: "node-1", Version: "29.0"},
		Digest: "sha256:plan", FileDigests: []model.FileDigest{{Path: "compose.yml", SHA256: "abc"}},
		ResolvedAt: "2026-10-10T12:00:01Z", ConfigHashes: map[string]string{"api": "confighash-not-sent"},
		RemoveOrphans: true, ForceRecreate: true, Notes: []string{"a note"},
	}
	r.Capabilities = &model.Capabilities{Observations: []model.Observation{
		{Source: model.SourceContainers, State: model.ObservedComplete, Note: "ok", ObservedAt: "2026-10-10T12:00:02Z"},
		{Source: model.SourceVolumes, State: model.ObservedPartial, Note: "capped", ObservedAt: "2026-10-10T12:00:03Z"},
	}}
	r.Provenance = &model.Provenance{
		Tool: "deploy-witness", ToolVersion: "1.6.0", RulesVersion: "r1", Host: "h", ServerFingerprint: "srv",
		Engine: "docker 29.0", EngineID: rawEngineID, EngineFingerprint: model.EngineFingerprint(rawEngineID),
		Compose: "plugin 2.40.0", PlanSource: "docker compose config 2.40.0", PlanDigest: "sha256:plan",
		StartedAt: "2026-10-10T12:00:00Z", PlanResolvedAt: "2026-10-10T12:00:01Z",
		ObservedFrom: "2026-10-10T12:00:02Z", ObservedUntil: "2026-10-10T12:00:03Z",
		ComparedAt: "2026-10-10T12:00:04Z", FinishedAt: "2026-10-10T12:00:05Z", ClockSynchronized: "yes",
		EngineClockSkew: "+0.2s", TimeChecks: []string{"engine " + rawEngineID + " clock drifted"},
		Completeness: "1 of 2 sources read in full; partial: volumes", RecheckAfter: "2026-10-10T13:00:05Z",
	}
	r.Rules = []model.RuleResult{
		{Code: "witness.port_conflict", Rule: "port-conflict", Outcome: model.OutcomeProblem, Findings: 1,
			Reason: "taken", Requires: "sockets"},
		{Code: "witness.no_healthcheck", Rule: "healthcheck", Outcome: model.OutcomeNoProblem, Reason: "fine"},
	}
	r.Findings = []model.Finding{{Code: "witness.port_conflict", Collector: "port-conflict",
		Severity: model.FindingBlocker, Outcome: model.OutcomeProblem, Evidence: []model.Evidence{{
			Command: "docker ps", Output: "container web (engine " + rawEngineID + ", node-1)"}}}}
	return r
}

func TestContractMapsEveryOutcome(t *testing.T) {
	want := map[model.Outcome]auditv1.Outcome{
		model.OutcomeProblem:       auditv1.Outcome_OUTCOME_PROBLEM,
		model.OutcomeNoProblem:     auditv1.Outcome_OUTCOME_NO_PROBLEM,
		model.OutcomeUnknown:       auditv1.Outcome_OUTCOME_UNKNOWN,
		model.OutcomeManualCheck:   auditv1.Outcome_OUTCOME_MANUAL_CHECK,
		model.OutcomeNotApplicable: auditv1.Outcome_OUTCOME_NOT_APPLICABLE,
		"":                         auditv1.Outcome_OUTCOME_UNSPECIFIED,
	}
	if len(model.Outcomes)+1 != len(want) {
		t.Fatalf("model.Outcomes has %d values; the table covers %d", len(model.Outcomes), len(want)-1)
	}
	for outcome, expected := range want {
		r := reportWith(model.ModeComposePreflight, &model.SectionResult{Section: model.SectionWitness, Status: model.StatusOk})
		r.Findings = []model.Finding{{Code: "witness.x", Outcome: outcome, Evidence: []model.Evidence{{Command: "c"}}}}
		r.Rules = []model.RuleResult{{Code: "witness.x", Rule: "x", Outcome: outcome}}
		c := Contract(r)
		if got := c.Findings[0].Outcome; got != expected {
			t.Errorf("finding outcome %q = %s, want %s", outcome, got, expected)
		}
		if got := c.RuleResults[0].Outcome; got != expected {
			t.Errorf("rule outcome %q = %s, want %s", outcome, got, expected)
		}
	}
}

func TestContractCarriesRulesPlanAndProvenance(t *testing.T) {
	c := Contract(preflightReport())

	if len(c.RuleResults) != 2 {
		t.Fatalf("rule_results = %v, want one per rule", c.RuleResults)
	}
	first := c.RuleResults[0]
	if first.Code != "witness.port_conflict" || first.Rule != "port-conflict" || first.Findings != 1 ||
		first.Reason != "taken" || first.Requires != "sockets" || first.Outcome != auditv1.Outcome_OUTCOME_PROBLEM {
		t.Errorf("rule_results[0] = %+v", first)
	}

	p := c.Plan
	if p == nil {
		t.Fatal("plan is unset in a preflight")
	}
	if strings.Join(p.Files, ",") != "compose.yml,compose.prod.yml" || p.ProjectDirectory != "/srv/app" ||
		p.ProjectName != "app" || p.ProjectNameSource != "--project-name" || p.EnvFiles[0] != ".env" ||
		p.Profiles[0] != "web" || p.Services[0] != "api" || strings.Join(p.Started, ",") != "api,db" ||
		p.Resolver != model.ResolverCompose || p.ResolverVersion != "2.40.0" || p.Environment[0] != "COMPOSE_PROFILES" ||
		p.EngineContext != "default" || !p.EngineLocal || p.Digest != "sha256:plan" ||
		p.ResolvedAt != "2026-10-10T12:00:01Z" || !p.RemoveOrphans || !p.ForceRecreate || p.NoRecreate ||
		len(p.Notes) != 1 {
		t.Errorf("plan = %+v", p)
	}
	if len(p.FileDigests) != 1 || p.FileDigests[0].Path != "compose.yml" || p.FileDigests[0].Sha256 != "abc" {
		t.Errorf("file_digests = %v", p.FileDigests)
	}

	v := c.Provenance
	if v == nil {
		t.Fatal("provenance is unset")
	}
	if v.Tool != "deploy-witness" || v.ToolVersion != "1.6.0" || v.RulesVersion != "r1" || v.Engine != "docker 29.0" ||
		v.Compose != "plugin 2.40.0" || v.PlanSource != "docker compose config 2.40.0" || v.PlanDigest != "sha256:plan" ||
		v.StartedAt == "" || v.PlanResolvedAt == "" || v.ObservedFrom == "" || v.ObservedUntil == "" ||
		v.ComparedAt == "" || v.FinishedAt == "" || v.ClockSynchronized != "yes" || v.EngineClockSkew != "+0.2s" ||
		len(v.TimeChecks) != 1 || v.Completeness == "" || v.RecheckAfter != "2026-10-10T13:00:05Z" {
		t.Errorf("provenance = %+v", v)
	}
	if len(v.Observations) != 2 ||
		v.Observations[0].State != auditv1.ObservationState_OBSERVATION_STATE_COMPLETE ||
		v.Observations[1].State != auditv1.ObservationState_OBSERVATION_STATE_PARTIAL ||
		v.Observations[1].Source != model.SourceVolumes || v.Observations[1].Note != "capped" ||
		v.Observations[1].ObservedAt != "2026-10-10T12:00:03Z" {
		t.Errorf("observations = %v", v.Observations)
	}
}

func TestObservationStatesMap(t *testing.T) {
	for state, want := range map[model.ObservationState]auditv1.ObservationState{
		model.ObservedComplete:     auditv1.ObservationState_OBSERVATION_STATE_COMPLETE,
		model.ObservedPartial:      auditv1.ObservationState_OBSERVATION_STATE_PARTIAL,
		model.ObservedFailed:       auditv1.ObservationState_OBSERVATION_STATE_FAILED,
		model.ObservedNotCollected: auditv1.ObservationState_OBSERVATION_STATE_NOT_COLLECTED,
		"":                         auditv1.ObservationState_OBSERVATION_STATE_UNSPECIFIED,
	} {
		if got := contractObservationState(state); got != want {
			t.Errorf("%q = %s, want %s", state, got, want)
		}
	}
}

// The engine is named by a salted hash, computed the way the server fingerprint is,
// and its raw ID appears nowhere in the bytes that are uploaded — not in the
// provenance, the evidence, the collector notes or the time checks. Neither does the
// engine's endpoint, nor the configuration hashes the contract has no field for.
func TestUploadNamesTheEngineByItsFingerprintOnly(t *testing.T) {
	fp := model.EngineFingerprint(rawEngineID)
	if len(fp) != 64 || fp == rawEngineID || strings.Contains(fp, rawEngineID) {
		t.Fatalf("EngineFingerprint = %q, want a sha256 hex digest", fp)
	}
	if model.EngineFingerprint(" "+rawEngineID+"\n") != fp {
		t.Error("the fingerprint must not depend on surrounding whitespace")
	}
	if model.EngineFingerprint("") != "" {
		t.Error("an unknown engine must have an empty fingerprint, not a hash of nothing")
	}

	_, payload, err := Build(preflightReport())
	if err != nil {
		t.Fatal(err)
	}
	text := string(payload)
	for _, leaked := range []string{rawEngineID, "secret-engine.sock", "confighash-not-sent"} {
		if strings.Contains(text, leaked) {
			t.Errorf("the upload carries %q:\n%s", leaked, text)
		}
	}
	var decoded auditv1.Report
	if err := protojson.Unmarshal(payload, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Provenance.GetEngineFingerprint() != fp {
		t.Errorf("engine_fingerprint = %q, want %q", decoded.Provenance.GetEngineFingerprint(), fp)
	}
	if !strings.Contains(decoded.Findings[0].Evidence[0].Output, fp) {
		t.Errorf("evidence should name the engine by its fingerprint: %q", decoded.Findings[0].Evidence[0].Output)
	}
	for _, field := range []string{`"outcome": "OUTCOME_PROBLEM"`, `"rule_results"`, `"plan"`, `"provenance"`,
		`"state": "OBSERVATION_STATE_PARTIAL"`} {
		if !strings.Contains(text, field) {
			t.Errorf("the upload lacks %s", field)
		}
	}
	if decoded.SchemaVersion != "1.0" {
		t.Errorf("schema_version = %q; additive fields do not change it", decoded.SchemaVersion)
	}
}

// A host audit checked no plan: the upload leaves plan unset, and its provenance has
// no plan source or digest and no observations.
func TestHostAuditUploadHasNoPlan(t *testing.T) {
	r := reportWith(model.ModeHostAudit, &model.SectionResult{Section: model.SectionWitness,
		Status: model.StatusNotApplicable})
	r.Provenance = &model.Provenance{Tool: "deploy-witness", ToolVersion: "1.6.0", RulesVersion: "r1",
		Completeness: "no host source was compared (host audit)"}
	c := Contract(r)
	if c.Plan != nil {
		t.Errorf("plan = %+v, want unset in a host audit", c.Plan)
	}
	if c.Provenance == nil || c.Provenance.PlanDigest != "" || c.Provenance.PlanSource != "" ||
		len(c.Provenance.Observations) != 0 || c.Provenance.EngineFingerprint != "" {
		t.Errorf("provenance = %+v", c.Provenance)
	}
	if len(c.RuleResults) != 0 {
		t.Errorf("rule_results = %v, want none", c.RuleResults)
	}
	_, payload, err := Build(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(payload), `"plan"`) {
		t.Errorf("a host audit upload must not carry a plan:\n%s", payload)
	}
}
