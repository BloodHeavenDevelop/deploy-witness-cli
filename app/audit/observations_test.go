package audit

import (
	"strings"
	"testing"
	"time"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/config"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/run"
)

// A section that found nothing still says what it read: the summary observation
// carries the count that proves "none", the section's state and the moment.
func TestObserveSectionProvesAnEmptyResult(t *testing.T) {
	a := &Auditor{cfg: &config.Config{}, runner: run.New(time.Second)}
	at := time.Date(2026, 10, 29, 12, 0, 3, 0, time.UTC)
	report := &model.Report{}
	result := &model.SectionResult{Section: model.SectionPorts, Status: model.StatusOk}
	a.observeSection(report, result, 0, at)

	if len(a.observations) != 1 {
		t.Fatalf("observations = %+v", a.observations)
	}
	o := a.observations[0]
	if o.Source != "ports" || o.State != model.ObservedComplete || o.ObservedAt != "2026-10-29T12:00:03Z" ||
		!strings.Contains(o.Note, "0 listening socket(s)") {
		t.Errorf("observation = %+v", o)
	}

	a.observations = nil
	failed := &model.SectionResult{Section: model.SectionUpdates, Status: model.StatusFailed,
		Notes: []string{"no supported package manager was detected"}}
	a.observeSection(report, failed, 0, at)
	if o := a.observations[0]; o.Source != "updates" || o.State != model.ObservedFailed ||
		!strings.Contains(o.Note, "no supported package manager was detected") {
		t.Errorf("a failed section is a failed observation with its reason: %+v", o)
	}
}

func TestCommandObservations(t *testing.T) {
	t0 := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	entries := []run.JournalEntry{
		{Command: "/usr/bin/apt-get -s dist-upgrade", StartedAt: t0, Outcome: run.OutcomeOK, Duration: "1s"},
		{Command: "apt-get -s upgrade", StartedAt: t0.Add(2 * time.Second), Outcome: run.OutcomeFailed, ExitCode: 100},
		{Command: "nft list ruleset", StartedAt: t0, Outcome: run.OutcomeMissing, ExitCode: -1},
		{Command: "sshd -T", StartedAt: t0, Outcome: run.OutcomeTimeout},
		{Command: "ss -lntupH", StartedAt: t0.Add(time.Second), Outcome: run.OutcomeOK},
	}
	got := map[string]model.Observation{}
	for _, o := range commandObservations("updates", entries) {
		got[o.Source] = o
	}
	want := map[string]model.ObservationState{
		"updates:apt-get": model.ObservedPartial,
		"updates:nft":     model.ObservedNotCollected,
		"updates:sshd":    model.ObservedFailed,
		"updates:ss":      model.ObservedComplete,
	}
	if len(got) != len(want) {
		t.Fatalf("observations = %+v", got)
	}
	for source, state := range want {
		if got[source].State != state {
			t.Errorf("%s state = %s, want %s", source, got[source].State, state)
		}
	}
	if o := got["updates:apt-get"]; o.ObservedAt != "2026-10-29T12:00:02Z" || !strings.Contains(o.Note, "2 run(s)") ||
		!strings.Contains(o.Note, "exit 100") {
		t.Errorf("apt-get = %+v; timed at the latest launch, every run listed", o)
	}
}

// Posture is quoted; inventory is named and counted, never quoted.
func TestFactObservationsQuotePostureNotInventory(t *testing.T) {
	facts := []model.Fact{
		{Category: "os", Key: "id", Value: "debian", Source: "/etc/os-release"},
		{Category: "host", Key: "machine-id", Value: "0123456789abcdef0123456789abcdef", Source: "/etc/machine-id"},
		{Category: "network", Key: "eth0", Value: "10.0.0.5/24 (mac aa:bb:cc:dd:ee:ff)", Source: "net.Interfaces"},
		{Category: "accounts", Key: "total", Value: "23", Source: "/etc/passwd"},
		{Category: "accounts", Key: "uid-0", Value: "root, toor", Source: "/etc/passwd"},
	}
	got := map[string]string{}
	for _, o := range factObservations(facts, time.Now()) {
		if o.State != model.ObservedComplete {
			t.Errorf("%s state = %s", o.Source, o.State)
		}
		got[o.Source] = o.Note
	}
	if !strings.Contains(got["system:os"], "id=debian") {
		t.Errorf("os = %q", got["system:os"])
	}
	for _, leaked := range []string{"0123456789abcdef", "10.0.0.5", "aa:bb", "toor"} {
		for source, note := range got {
			if strings.Contains(note, leaked) {
				t.Errorf("%s quotes %q: %q", source, leaked, note)
			}
		}
	}
	if !strings.Contains(got["system:accounts"], "total=23") || !strings.Contains(got["system:accounts"], "uid-0: 2 entr") {
		t.Errorf("accounts = %q; counts are the values that go out", got["system:accounts"])
	}
}

func TestAllObservationsMergesInReadOrder(t *testing.T) {
	sections := []model.Observation{{Source: "ports", ObservedAt: "2026-10-29T12:00:01Z"},
		{Source: "witness", ObservedAt: "2026-10-29T12:00:09Z"}}
	caps := &model.Capabilities{Observations: []model.Observation{{Source: "containers",
		ObservedAt: "2026-10-29T12:00:05Z"}}}
	got := allObservations(sections, caps)
	if len(got) != 3 || got[0].Source != "ports" || got[1].Source != "containers" || got[2].Source != "witness" {
		t.Errorf("order = %+v", got)
	}
}

func TestClipSaysItCut(t *testing.T) {
	long := strings.Repeat("я", maxObservationNote)
	got := clip(long)
	if !strings.Contains(got, "cut at") || !strings.HasPrefix(got, "я") {
		t.Errorf("clip = %q", got[len(got)-80:])
	}
	if strings.ContainsRune(got, '�') {
		t.Error("a cut split a UTF-8 sequence")
	}
}
