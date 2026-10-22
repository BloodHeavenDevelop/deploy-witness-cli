package score

import (
	"strings"
	"testing"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/bench/result"
)

func outcome(id, rule string, situation result.Situation, expected, predicted string) result.Outcome {
	var s result.Scenario
	s.ID, s.Rule, s.Situation = id, rule, situation
	s.Expect.Outcome = expected
	yes := true
	return result.Outcome{Scenario: s, Predicted: predicted, SpecMatch: expected == predicted, DockerMatch: &yes}
}

// Unknown is never a detection: a version that answers "unknown" more often does
// not look better for it.
func TestUnknownIsNotADetection(t *testing.T) {
	run := &result.Run{Results: []result.Outcome{
		outcome("p/1", "witness.x", result.SituationProblem, "problem", "problem"),
		outcome("p/2", "witness.x", result.SituationProblem, "problem", "unknown"),
		outcome("p/3", "witness.x", result.SituationProblem, "problem", "no-problem"),
		outcome("c/1", "witness.x", result.SituationNoProblem, "no-problem", "problem"),
		outcome("c/2", "witness.x", result.SituationNoProblem, "no-problem", "unknown"),
		outcome("u/1", "witness.x", result.SituationUnknown, "unknown", "no-problem"),
	}}
	r := Score(run).Rules[0]
	if r.Detected != 1 || r.UnknownOnProblem != 1 || r.Missed != 1 || r.FalseFindings != 1 || r.UnknownOnClean != 1 ||
		r.Guessed != 1 || r.Unknown != 2 {
		t.Errorf("score = %+v", r)
	}
	if got := r.DetectionRate(); got < 0.33 || got > 0.34 {
		t.Errorf("detection rate %.2f, want 1/3 — the unknown counts against it", got)
	}
	if r.Situations != "problem,no-problem,unknown" {
		t.Errorf("situations = %q", r.Situations)
	}
}

// A scenario whose ground truth Docker contradicted is not scored, and blocks.
func TestBrokenGroundTruthIsNotScored(t *testing.T) {
	o := outcome("p/1", "witness.x", result.SituationProblem, "problem", "no-problem")
	no := false
	o.DockerMatch = &no
	run := &result.Run{Results: []result.Outcome{o}}
	if r := Score(run).Rules[0]; r.Scored != 0 || r.Missed != 0 {
		t.Errorf("score = %+v", r)
	}
	if reasons := Gate(run, nil); len(reasons) != 1 || !strings.Contains(reasons[0], "ground truth") {
		t.Errorf("gate = %v", reasons)
	}
}

func TestGateBlocks(t *testing.T) {
	critical := outcome("crit", "witness.x", result.SituationProblem, "problem", "no-problem")
	critical.Scenario.Critical = true
	regression := outcome("reg", "witness.x", result.SituationProblem, "problem", "unknown")
	regression.Scenario.Regression = "DW-52"
	effect := outcome("eff", "witness.x", result.SituationNoProblem, "no-problem", "no-problem")
	effect.SideEffects = []string{"appeared: x"}
	bench := outcome("bench", "witness.x", result.SituationNoProblem, "no-problem", "")
	bench.BenchError = "setup failed"
	ok := outcome("ok", "witness.x", result.SituationNoProblem, "no-problem", "no-problem")
	worse := outcome("worse", "witness.x", result.SituationNoProblem, "no-problem", "unknown")

	baseline := &result.Run{Results: []result.Outcome{ok, outcome("worse", "witness.x", result.SituationNoProblem,
		"no-problem", "no-problem"), outcome("gone", "witness.x", result.SituationProblem, "problem", "problem")}}
	current := &result.Run{Results: []result.Outcome{critical, regression, effect, bench, ok, worse}}

	reasons := strings.Join(Gate(current, baseline), "\n")
	for _, want := range []string{"critical scenario crit", "regression test reg (DW-52)", "changed something in eff",
		"bench error in bench", "worse passed in the baseline", "gone is in the baseline and missing"} {
		if !strings.Contains(reasons, want) {
			t.Errorf("the gate does not block on %q:\n%s", want, reasons)
		}
	}
	if len(Gate(&result.Run{Results: []result.Outcome{ok}}, &result.Run{Results: []result.Outcome{ok}})) != 0 {
		t.Error("an unchanged passing run must pass")
	}
}

func TestCompare(t *testing.T) {
	before := &result.Run{Results: []result.Outcome{
		outcome("a", "witness.x", result.SituationProblem, "problem", "unknown"),
		outcome("b", "witness.x", result.SituationProblem, "problem", "problem"),
	}}
	after := &result.Run{Results: []result.Outcome{
		outcome("a", "witness.x", result.SituationProblem, "problem", "problem"),
		outcome("c", "witness.x", result.SituationProblem, "problem", "problem"),
	}}
	var kinds []string
	for _, c := range Compare(before, after) {
		kinds = append(kinds, c.Kind+":"+c.Scenario)
	}
	if strings.Join(kinds, " ") != "fixed:a new:c removed:b" {
		t.Errorf("changes = %v", kinds)
	}
}
