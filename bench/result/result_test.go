package result

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The committed scenarios must all load: a malformed one would silently drop out
// of every run, which is exactly how a bench loses its hard cases.
func TestCommittedScenariosLoad(t *testing.T) {
	scenarios, err := Load(filepath.Join("..", "scenarios"))
	if err != nil {
		t.Fatal(err)
	}
	if len(scenarios) < 40 {
		t.Fatalf("only %d scenarios loaded", len(scenarios))
	}
	ids := map[string]bool{}
	for _, s := range scenarios {
		if ids[s.ID] {
			t.Errorf("duplicate id %s", s.ID)
		}
		ids[s.ID] = true
		if !strings.HasPrefix(s.ID, strings.TrimPrefix(s.Rule, "witness.")+"/") {
			t.Errorf("%s: the id must start with the rule's code (%s)", s.ID, s.Rule)
		}
		if _, err := os.Stat(filepath.Join(s.Dir, "compose.yml")); err != nil {
			t.Errorf("%s: no compose.yml", s.ID)
		}
		if !s.Accepts(s.Expect.Outcome) {
			t.Errorf("%s: does not accept its own expectation", s.ID)
		}
	}
}

func TestScenarioValidation(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "scenario.yaml"), []byte("id: x\nrule: port\nsituation: problem\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(dir); err == nil {
		t.Error("a scenario without a witness code, description and expectation must be refused")
	}
}
