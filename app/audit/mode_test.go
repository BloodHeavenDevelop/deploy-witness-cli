package audit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
)

func composeFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "docker-compose.yml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// DW-70: a Compose file that does not parse stops the preflight before any section
// runs, instead of producing a report whose witness row merely failed.
func TestPrepareRefusesAnUnparseableComposeFile(t *testing.T) {
	for name, content := range map[string]string{
		"not yaml":       "services: [unclosed\n",
		"not a mapping":  "- just\n- a list\n",
		"declares empty": "# nothing here\n",
	} {
		a := New(load(t, "--compose", composeFile(t, content)), nil, "test")
		err := a.Prepare()
		if err == nil || !strings.Contains(err.Error(), "the Compose preflight cannot start") {
			t.Errorf("%s: error = %v, want the preflight refused", name, err)
		}
	}
}

func TestPrepareParsesTheComposeFileOnce(t *testing.T) {
	a := New(load(t, "--compose", composeFile(t, "services:\n  app:\n    image: nginx:1.27\n")), nil, "test")
	if err := a.Prepare(); err != nil {
		t.Fatal(err)
	}
	if a.manifest == nil || len(a.manifest.Services) != 1 {
		t.Fatalf("manifest = %+v, want one service", a.manifest)
	}
}

func TestPrepareHasNothingToDoInAHostAudit(t *testing.T) {
	a := New(load(t), nil, "test")
	if err := a.Prepare(); err != nil {
		t.Fatal(err)
	}
	if a.manifest != nil {
		t.Error("a host audit must not read a Compose file")
	}
}

// The witness row of a host audit is not applicable — outside the run's scope, not
// skipped — and says it is a host audit.
func TestHostAuditWitnessRow(t *testing.T) {
	row := HostAuditWitness()
	if row.Section != model.SectionWitness || row.Status != model.StatusNotApplicable {
		t.Errorf("row = %+v, want a not-applicable witness row", row)
	}
	if len(row.Notes) != 1 || !strings.HasPrefix(row.Notes[0], "host-audit: not applicable") ||
		!strings.Contains(row.Notes[0], "not a gap") ||
		!strings.Contains(row.Notes[0], "not a Compose preflight result") {
		t.Errorf("notes = %v", row.Notes)
	}
}
