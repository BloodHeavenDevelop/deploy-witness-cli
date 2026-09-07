package config

import (
	"io"
	"strings"
	"testing"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
)

func load(t *testing.T, args ...string) (*Config, error) {
	t.Helper()
	return Load(args, "test", io.Discard)
}

func TestDefaults(t *testing.T) {
	cfg, err := load(t)
	if err != nil {
		t.Fatal(err)
	}

	if len(cfg.Sections) != len(model.AllSections) {
		t.Errorf("sections = %v, want all", cfg.Sections)
	}
	if cfg.Online {
		t.Error("the tool must be offline unless --online is passed")
	}
	if cfg.OutDir == "" || !strings.Contains(cfg.OutDir, "audit-") {
		t.Errorf("out dir = %q, want a generated audit-<host>-<timestamp> path", cfg.OutDir)
	}
	if cfg.MinSeverity != model.SeverityLow {
		t.Errorf("min severity = %q, want low", cfg.MinSeverity)
	}
}

func TestSectionsAreReorderedCanonically(t *testing.T) {
	// The vulnerability collector consumes the package inventory the earlier
	// sections build, so flag order must not decide run order.
	cfg, err := load(t, "--sections", "services,system")
	if err != nil {
		t.Fatal(err)
	}

	want := []model.Section{model.SectionSystem, model.SectionServices}
	if len(cfg.Sections) != len(want) {
		t.Fatalf("sections = %v, want %v", cfg.Sections, want)
	}
	for i := range want {
		if cfg.Sections[i] != want[i] {
			t.Fatalf("sections = %v, want %v", cfg.Sections, want)
		}
	}
}

func TestSectionsDeduplicate(t *testing.T) {
	cfg, err := load(t, "--sections", "ports,ports,ports")
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Sections) != 1 {
		t.Errorf("sections = %v, want one entry", cfg.Sections)
	}
}

func TestWants(t *testing.T) {
	cfg, err := load(t, "--sections", "ports")
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Wants(model.SectionPorts) {
		t.Error("ports should be selected")
	}
	if cfg.Wants(model.SectionServices) {
		t.Error("services should not be selected")
	}
}

func TestRejectsBadInput(t *testing.T) {
	cases := [][]string{
		{"--sections", "nonsense"},
		{"--timeout", "banana"},
		{"--timeout", "0s"},
		{"--min-severity", "catastrophic"},
		{"--vuln-db", "/definitely/not/here.json"},
	}

	for _, args := range cases {
		if _, err := load(t, args...); err == nil {
			t.Errorf("%v should have been rejected", args)
		}
	}
}

func TestQuietBeatsVerbose(t *testing.T) {
	cfg, err := load(t, "--quiet", "--verbose")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LogLevel != 0 { // logging.LevelError
		t.Errorf("log level = %v, want error-only", cfg.LogLevel)
	}
}
