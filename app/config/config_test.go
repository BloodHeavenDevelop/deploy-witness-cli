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
