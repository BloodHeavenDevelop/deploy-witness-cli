package config

import (
	"io"
	"os"
	"path/filepath"
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

	// Without --compose the run is a host audit: every section but witness.
	if cfg.Mode != model.ModeHostAudit {
		t.Errorf("mode = %q, want host-audit", cfg.Mode)
	}
	if len(cfg.Sections) != len(model.AllSections)-1 || cfg.Wants(model.SectionWitness) {
		t.Errorf("sections = %v, want all but witness", cfg.Sections)
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

// A network path is enabled by a typed flag and nothing else (DW-56): an
// environment variable baked into an image or a profile must not open a
// connection or choose where a report goes.
func TestNetworkEnvironmentIsIgnored(t *testing.T) {
	t.Setenv("AUDIT_ONLINE", "1")
	t.Setenv("AUDIT_EGRESS", "true")
	t.Setenv("AUDIT_UPLOAD", "https://collector.example.com")
	t.Setenv("AUDIT_UPLOAD_TOKEN", "token-from-env")
	t.Setenv("AUDIT_OSV_URL", "https://osv.example.com")

	cfg, err := load(t)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Online || cfg.Egress || cfg.WantsUpload() || cfg.UploadURL != "" || cfg.UploadToken != "" {
		t.Fatalf("network enabled from the environment: online=%v egress=%v upload=%q token set=%v",
			cfg.Online, cfg.Egress, cfg.UploadURL, cfg.UploadToken != "")
	}
	if cfg.OSVEndpoint != defaultOSVEndpoint {
		t.Errorf("osv endpoint = %q, want the default: AUDIT_OSV_URL must not choose a recipient", cfg.OSVEndpoint)
	}
	want := []string{"AUDIT_ONLINE", "AUDIT_EGRESS", "AUDIT_UPLOAD", "AUDIT_OSV_URL"}
	if strings.Join(cfg.IgnoredEnv, ",") != strings.Join(want, ",") {
		t.Errorf("ignored env = %v, want %v", cfg.IgnoredEnv, want)
	}
}

// The token is the one value read from the environment, because that keeps it out
// of the process list — but only together with a typed --upload.
func TestUploadTokenFromEnvironmentNeedsTypedUpload(t *testing.T) {
	t.Setenv("AUDIT_UPLOAD_TOKEN", "token-from-env")

	cfg, err := load(t, "--upload", "https://deploy-witness.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.WantsUpload() || cfg.UploadToken != "token-from-env" {
		t.Fatalf("upload = %v, token = %q; want the environment token used", cfg.WantsUpload(), cfg.UploadToken)
	}

	cfg, err = load(t, "--upload", "https://deploy-witness.example.com", "--upload-token", "typed")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.UploadToken != "typed" {
		t.Errorf("token = %q, want the typed flag to win", cfg.UploadToken)
	}
}

func TestUploadAddressRules(t *testing.T) {
	cases := []struct {
		args []string
		ok   bool
	}{
		{[]string{"--upload", "https://deploy-witness.example.com", "--upload-token", "t"}, true},
		{[]string{"--upload", "http://127.0.0.1:8080", "--upload-token", "t"}, true},
		{[]string{"--upload", "http://deploy-witness.example.com", "--upload-token", "t"}, false},
		{[]string{"--upload", "https://u:p@deploy-witness.example.com", "--upload-token", "t"}, false},
		{[]string{"--upload", "https://deploy-witness.example.com"}, false},
		{[]string{"--upload-token", "t"}, false},
		{[]string{"--upload", "", "--upload-token", "t"}, false},
		{[]string{"--online", "--osv-url", "http://osv.example.com"}, false},
		{[]string{"--online", "--osv-url", "https://osv.example.com"}, true},
	}
	for _, tc := range cases {
		_, err := load(t, tc.args...)
		if (err == nil) != tc.ok {
			t.Errorf("%v: error = %v, want ok=%v", tc.args, err, tc.ok)
		}
	}
}

func writeCompose(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "docker-compose.yml")
	if err := os.WriteFile(path, []byte("services:\n  app:\n    image: nginx:1.27\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// DW-70: --compose makes the run a Compose preflight, which always includes the
// witness section and always has its file.
func TestComposeMakesAPreflight(t *testing.T) {
	compose := writeCompose(t)

	cfg, err := load(t, "--compose", compose)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != model.ModeComposePreflight || !cfg.Wants(model.SectionWitness) {
		t.Errorf("mode = %q, sections = %v; want compose-preflight with witness", cfg.Mode, cfg.Sections)
	}

	for _, args := range [][]string{
		{"--mode", "compose-preflight", "--compose", compose},
		{"--mode", "preflight", "--compose", compose, "--sections", "ports,witness"},
	} {
		cfg, err := load(t, args...)
		if err != nil {
			t.Errorf("%v: %v", args, err)
			continue
		}
		if cfg.Mode != model.ModeComposePreflight {
			t.Errorf("%v: mode = %q", args, cfg.Mode)
		}
	}

	for _, args := range [][]string{{"--mode", "host-audit"}, {"--mode", "host", "--sections", "ports"}} {
		cfg, err := load(t, args...)
		if err != nil {
			t.Errorf("%v: %v", args, err)
			continue
		}
		if cfg.Mode != model.ModeHostAudit || cfg.Wants(model.SectionWitness) {
			t.Errorf("%v: mode = %q, sections = %v", args, cfg.Mode, cfg.Sections)
		}
	}
}

// DW-70: every combination that would let a host audit pass for a preflight, or a
// preflight run without its input, is refused before the audit starts.
func TestModeConflictsAreRefused(t *testing.T) {
	compose := writeCompose(t)
	dir := t.TempDir()

	cases := []struct {
		args []string
		want string
	}{
		{[]string{"--sections", "witness"}, "needs --compose"},
		{[]string{"--sections", "ports,witness"}, "needs --compose"},
		{[]string{"--mode", "compose-preflight"}, "needs --compose"},
		{[]string{"--mode", "host-audit", "--compose", compose}, "does not read a Compose file"},
		{[]string{"--compose", compose, "--sections", "ports"}, "leaves witness out"},
		{[]string{"--mode", "everything"}, "invalid --mode"},
		{[]string{"--compose", filepath.Join(dir, "missing.yml")}, "needs a readable Compose file"},
		{[]string{"--compose", dir}, "not a regular file"},
	}
	for _, tc := range cases {
		_, err := load(t, tc.args...)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v: error = %v, want one containing %q", tc.args, err, tc.want)
		}
	}
}

// AUDIT_MODE asserts a preflight from the environment: a job whose AUDIT_COMPOSE
// went missing must stop, not quietly become a host audit.
func TestModeFromEnvironment(t *testing.T) {
	t.Setenv("AUDIT_MODE", "compose-preflight")
	if _, err := load(t); err == nil {
		t.Fatal("AUDIT_MODE=compose-preflight without a Compose file should be refused")
	}
	t.Setenv("AUDIT_COMPOSE", writeCompose(t))
	cfg, err := load(t)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != model.ModeComposePreflight {
		t.Errorf("mode = %q, want compose-preflight", cfg.Mode)
	}
}

// DW-79: --format csv,json writes both outputs from one run; it cannot share one
// stdout stream.
func TestFormatBoth(t *testing.T) {
	for _, value := range []string{"csv,json", "json,csv", "CSV, JSON"} {
		cfg, err := load(t, "--format", value)
		if err != nil {
			t.Errorf("%q: %v", value, err)
			continue
		}
		if !cfg.WantsCSV() || !cfg.WantsJSON() {
			t.Errorf("%q: csv=%v json=%v, want both", value, cfg.WantsCSV(), cfg.WantsJSON())
		}
	}
	if _, err := load(t, "--format", "csv,json", "--stdout"); err == nil || !strings.Contains(err.Error(), "one stream") {
		t.Errorf("csv,json with --stdout: %v", err)
	}
	cfg, _ := load(t, "--format", "json")
	if cfg.WantsCSV() {
		t.Error("--format json must not write CSV")
	}
}

// DW-81: the planned run is reproduced flag for flag: several files in order, env
// files, profiles, project name and directory, services — paths made absolute.
func TestPlannedRunFlags(t *testing.T) {
	dir := t.TempDir()
	first, second := writeComposeAt(t, dir, "compose.yml"), writeComposeAt(t, dir, "compose.prod.yml")
	envFile := writeComposeAt(t, dir, ".env.prod")
	cfg, err := Load([]string{"--compose", first, "--compose", second, "--env-file", envFile,
		"--profile", "web", "--profile", "jobs", "--project-name", "shop", "--project-directory", dir,
		"--compose-service", "web"}, "test", io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(cfg.ComposeFiles, ",") != first+","+second || cfg.Compose != first ||
		strings.Join(cfg.EnvFiles, ",") != envFile || strings.Join(cfg.Profiles, ",") != "web,jobs" ||
		cfg.ProjectName != "shop" || cfg.ProjectDirectory != dir || strings.Join(cfg.ComposeServices, ",") != "web" {
		t.Errorf("cfg = %+v", cfg)
	}

	t.Setenv("AUDIT_COMPOSE", first+string(os.PathListSeparator)+second)
	cfg, err = Load(nil, "test", io.Discard)
	if err != nil || len(cfg.ComposeFiles) != 2 {
		t.Errorf("AUDIT_COMPOSE list: %v %v", cfg, err)
	}
	cfg, err = Load([]string{"--compose", second}, "test", io.Discard)
	if err != nil || strings.Join(cfg.ComposeFiles, ",") != second {
		t.Errorf("a typed --compose replaces AUDIT_COMPOSE: %v %v", cfg.ComposeFiles, err)
	}

	if _, err := Load([]string{"--compose", first, "--env-file", filepath.Join(dir, "missing")}, "test", io.Discard); err == nil {
		t.Error("a missing --env-file must be refused before the audit")
	}
}

func writeComposeAt(t *testing.T, dir, name string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("services:\n  web:\n    image: nginx:1.27\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}
