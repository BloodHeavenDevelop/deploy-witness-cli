// Package result is the shape of a bench run: the scenarios it executed, what the
// CLI predicted for each, what Docker then did, and how the two compare. The bench
// (bench/dwbench) writes it; the quality report and the release gate
// (bench/dwscore) read it. Nothing here touches a host or a container.
package result

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Situation is what a scenario stages for its rule: the three situations every
// rule is defined by, plus the two outcomes that are neither.
type Situation string

const (
	SituationProblem       Situation = "problem"
	SituationNoProblem     Situation = "no-problem"
	SituationUnknown       Situation = "unknown"
	SituationManualCheck   Situation = "manual-check"
	SituationNotApplicable Situation = "not-applicable"
)

// DockerExpectation is what the planned change is expected to do when it runs.
type DockerExpectation string

const (
	// DockerFails: `docker compose up` must fail — the rule predicts a broken start.
	DockerFails DockerExpectation = "fails"
	// DockerSucceeds: `up` must succeed — a similar situation without the problem.
	DockerSucceeds DockerExpectation = "succeeds"
	// DockerAdvisory: Docker does not decide this rule (a missing healthcheck, a
	// floating tag, a risk that does not stop the start); its result is recorded,
	// not scored against the prediction.
	DockerAdvisory DockerExpectation = "advisory"
)

// Scenario is one staged situation, as bench/scenarios/<rule>/<case>/scenario.yaml
// describes it.
type Scenario struct {
	ID          string    `yaml:"id" json:"id"`
	Rule        string    `yaml:"rule" json:"rule"`
	Situation   Situation `yaml:"situation" json:"situation"`
	Description string    `yaml:"description" json:"description"`
	// Critical marks a scenario whose miss blocks a release (DW-84).
	Critical bool `yaml:"critical" json:"critical"`
	// Regression names the defect a scenario reproduces (DW-90): once it passes, it
	// must keep passing.
	Regression string `yaml:"regression" json:"regression,omitempty"`
	Audit      struct {
		// User is "root" or "unprivileged" (not in the docker group, so the engine
		// does not answer).
		User string   `yaml:"user" json:"user"`
		Args []string `yaml:"args" json:"args"`
	} `yaml:"audit" json:"audit"`
	// Project is the Compose project name the scenario deploys under.
	Project string `yaml:"project" json:"project"`
	Expect  struct {
		Outcome string `yaml:"outcome" json:"outcome"`
		// Also lists other outcomes that are equally correct, each with the reason in
		// the scenario's description — "refused" where an older Compose rejects the
		// plan outright instead of letting the rule find the problem.
		Also []string `yaml:"also" json:"also,omitempty"`
	} `yaml:"expect" json:"expect"`
	Docker struct {
		Up      []string          `yaml:"up" json:"up"`
		Outcome DockerExpectation `yaml:"outcome" json:"outcome"`
		// Pattern is a fragment of Docker's error a failure must contain to count
		// as the failure the rule predicted, rather than any failure.
		Pattern string `yaml:"pattern" json:"pattern,omitempty"`
	} `yaml:"docker" json:"docker"`
	// Dir is the scenario's directory, filled in by Load.
	Dir string `yaml:"-" json:"-"`
}

// Accepts reports whether an outcome satisfies the scenario's expectation.
func (s Scenario) Accepts(outcome string) bool {
	if outcome == s.Expect.Outcome {
		return true
	}
	for _, also := range s.Expect.Also {
		if outcome == also {
			return true
		}
	}
	return false
}

// Load reads every scenario.yaml under root, sorted by id.
func Load(root string) ([]Scenario, error) {
	var out []Scenario
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || d.Name() != "scenario.yaml" {
			return err
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var s Scenario
		if err := yaml.Unmarshal(raw, &s); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		s.Dir = filepath.Dir(path)
		if err := s.validate(); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		out = append(out, s)
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, err
}

func (s Scenario) validate() error {
	switch {
	case s.ID == "" || s.Rule == "" || s.Description == "":
		return fmt.Errorf("id, rule and description are required")
	case !strings.HasPrefix(s.Rule, "witness."):
		return fmt.Errorf("rule %q is not a witness code", s.Rule)
	case s.Expect.Outcome == "":
		return fmt.Errorf("expect.outcome is required")
	case s.Docker.Outcome != DockerFails && s.Docker.Outcome != DockerSucceeds && s.Docker.Outcome != DockerAdvisory:
		return fmt.Errorf("docker.outcome must be fails, succeeds or advisory")
	case s.Audit.User != "" && s.Audit.User != "root" && s.Audit.User != "unprivileged":
		return fmt.Errorf("audit.user must be root or unprivileged")
	}
	switch s.Situation {
	case SituationProblem, SituationNoProblem, SituationUnknown, SituationManualCheck, SituationNotApplicable:
	default:
		return fmt.Errorf("situation %q is not one of problem, no-problem, unknown, manual-check, not-applicable", s.Situation)
	}
	return nil
}

// Run is one execution of the bench.
type Run struct {
	BenchVersion string `json:"benchVersion"`
	// The CLI under test.
	CLIVersion string `json:"cliVersion"`
	CLICommit  string `json:"cliCommit"`
	// The disposable environment: image and the engine and Compose inside it.
	Environment    string `json:"environment"`
	DockerVersion  string `json:"dockerVersion"`
	ComposeVersion string `json:"composeVersion"`
	StartedAt      string `json:"startedAt"`
	FinishedAt     string `json:"finishedAt"`
	Results        []Outcome `json:"results"`
}

// Outcome is one scenario's record: input, expectation, prediction, Docker's actual
// behaviour, and the verdicts.
type Outcome struct {
	Scenario Scenario `json:"scenario"`
	// Predicted is the rule's outcome in the CLI's rules.csv; Findings its
	// findings on that rule.
	Predicted string    `json:"predicted"`
	Findings  []Finding `json:"findings"`
	// AuditExit is the CLI's exit code; PreflightStatus the summary's preflight row.
	AuditExit       int    `json:"auditExit"`
	PreflightStatus string `json:"preflightStatus"`
	// Docker is what the planned change did.
	Docker DockerRun `json:"docker"`
	// SideEffects lists every difference between the engine and the scenario
	// directory before and after the audit. Anything here is a defect: the audit
	// must change nothing.
	SideEffects []string `json:"sideEffects"`
	// BenchError is set when the bench itself failed (a setup that did not run, an
	// audit that produced no report): the scenario then proves nothing about the
	// CLI and is counted apart.
	BenchError string `json:"benchError,omitempty"`
	// SpecMatch: the prediction equals the scenario's expected outcome.
	SpecMatch bool `json:"specMatch"`
	// DockerMatch: Docker behaved as the scenario expects (nil when advisory or
	// when the bench failed).
	DockerMatch *bool `json:"dockerMatch"`
	DurationMs  int64 `json:"durationMs"`
}

// Finding is the part of a CLI finding the bench keeps.
type Finding struct {
	Severity string `json:"severity"`
	Outcome  string `json:"outcome"`
	Subject  string `json:"subject"`
	Title    string `json:"title"`
}

// DockerRun is the planned change as it ran.
type DockerRun struct {
	Command string `json:"command"`
	Exit    int    `json:"exit"`
	Failed  bool   `json:"failed"`
	// PatternSeen: the expected failure message appeared.
	PatternSeen bool   `json:"patternSeen"`
	Output      string `json:"output"`
	// Exited lists the containers that were not running a few seconds after an
	// `up` that reported success: a container that starts and dies at once (an exec
	// format error, a missing file) is a failed deployment, whatever the exit code.
	Exited []string `json:"exited,omitempty"`
}

// Read loads a results.json.
func Read(path string) (*Run, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var run Run
	if err := json.Unmarshal(raw, &run); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return &run, nil
}

// Write stores a run as indented JSON.
func (r *Run) Write(path string) error {
	raw, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(raw, '\n'), 0o644)
}
