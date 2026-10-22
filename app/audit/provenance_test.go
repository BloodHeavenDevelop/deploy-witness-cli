package audit

import (
	"strings"
	"testing"
	"time"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
)

func TestTimeChecks(t *testing.T) {
	started := time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC)
	finished := started.Add(30 * time.Second)
	report := &model.Report{GeneratedAt: started, Findings: []model.Finding{{Code: "witness.x",
		Evidence: []model.Evidence{{CapturedAt: "2026-10-19T12:00:10Z"}, {CapturedAt: "2026-10-19T11:00:00Z"}}}}}
	p := &model.Provenance{ClockSynchronized: "yes", EngineClockSkew: "+0.2s"}
	observations := []model.Observation{{Source: "containers", ObservedAt: "2026-10-19T12:00:05Z"}}

	if got := timeChecks(report, p, observations, finished); len(got) != 1 || !strings.Contains(got[0], "evidence of witness.x") {
		t.Errorf("one piece of evidence lies before the run: %v", got)
	}

	report.Findings = nil
	p.ClockSynchronized, p.EngineClockSkew = "no", "-42.0s"
	p.ObservedFrom, p.ObservedUntil = "2026-10-19T12:00:00Z", "2026-10-19T12:15:00Z"
	got := strings.Join(timeChecks(report, p, observations, finished), "\n")
	for _, want := range []string{"not NTP-synchronised", "differs from this host's by -42.0s", "observed over 15m0s"} {
		if !strings.Contains(got, want) {
			t.Errorf("missing %q in %s", want, got)
		}
	}

	if got := timeChecks(report, &model.Provenance{}, nil, started.Add(-time.Minute)); len(got) != 1 ||
		!strings.Contains(got[0], "went backwards") {
		t.Errorf("clock jump: %v", got)
	}
}

func TestCompleteness(t *testing.T) {
	got := completeness([]model.Observation{
		{Source: "containers", State: model.ObservedComplete}, {Source: "volumes", State: model.ObservedFailed},
		{Source: "sockets", State: model.ObservedPartial},
	})
	if got != "1 of 3 sources read in full; partial: sockets; failed: volumes" {
		t.Errorf("completeness = %q", got)
	}
}

func TestPlanDigestFollowsTheRunNotThePath(t *testing.T) {
	plan := &model.LaunchPlan{ProjectName: "shop", Started: []string{"web"}}
	m := &model.Manifest{Path: "/a/compose.yml", Services: []model.ManifestService{{Name: "web",
		Ports: []model.PortMapping{{HostPort: 8080, ContainerPort: 80}}}}}
	base := PlanDigest(plan, m)

	moved := *m
	moved.Path, moved.Warnings = "/b/compose.yml", []string{"a parser remark"}
	if PlanDigest(plan, &moved) != base {
		t.Error("moving the file or a parser remark must not change the plan")
	}
	changed := *m
	changed.Services = []model.ManifestService{{Name: "web", Ports: []model.PortMapping{{HostPort: 8081, ContainerPort: 80}}}}
	if PlanDigest(plan, &changed) == base {
		t.Error("another published port is another plan")
	}
	if PlanDigest(&model.LaunchPlan{ProjectName: "other", Started: []string{"web"}}, m) == base {
		t.Error("another project name is another plan")
	}
	if !strings.HasPrefix(base, "sha256:") {
		t.Errorf("digest = %q", base)
	}
}
