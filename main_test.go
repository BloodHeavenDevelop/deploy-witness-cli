package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// cli runs the program the way a user does and returns its exit code and log.
func cli(t *testing.T, args ...string) (int, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := runCLI(args, &stdout, &stderr)
	return code, stderr.String()
}

func writeFile(t *testing.T, dir, name, content string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	return path
}

// noReport fails the test when anything was written to the output directory: a
// refused preflight must leave nothing behind that could be read as a result.
func noReport(t *testing.T, out string) {
	t.Helper()
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		entries, _ := os.ReadDir(out)
		t.Errorf("%s exists (%d entries); a refused preflight must write no report", out, len(entries))
	}
}

// DW-70: an explicitly requested Compose preflight whose file is missing stops
// before anything is collected — exit 2, the reason, and no report.
func TestExplicitPreflightMissingFile(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "report")
	code, log := cli(t, "--mode", "compose-preflight", "--compose", filepath.Join(dir, "missing.yml"), "--out", out)

	if code != exitUsage {
		t.Errorf("exit = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(log, "the Compose preflight needs a readable Compose file") ||
		!strings.Contains(log, "no such file or directory") {
		t.Errorf("log = %q", log)
	}
	noReport(t, out)
}

// A directory is not a Compose file, and is refused the same way.
func TestExplicitPreflightDirectory(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "report")
	code, log := cli(t, "--mode", "compose-preflight", "--compose", dir, "--out", out)

	if code != exitUsage || !strings.Contains(log, "this is not a regular file") {
		t.Errorf("exit = %d, log = %q", code, log)
	}
	noReport(t, out)
}

// DW-70: a file that exists but cannot be read stops the preflight too.
func TestExplicitPreflightUnreadableFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a mode-0000 file; the case cannot be produced")
	}
	dir := t.TempDir()
	out := filepath.Join(dir, "report")
	compose := writeFile(t, dir, "docker-compose.yml", "services:\n  app:\n    image: nginx:1.27\n", 0o000)
	code, log := cli(t, "--mode", "compose-preflight", "--compose", compose, "--out", out)

	if code != exitUsage {
		t.Errorf("exit = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(log, "the Compose preflight needs a readable Compose file") ||
		!strings.Contains(log, "permission denied") {
		t.Errorf("log = %q", log)
	}
	noReport(t, out)
}

// DW-70: a file that reads but does not parse is refused after the network
// statement and before the first section, with "no report was written".
func TestExplicitPreflightUnparseableFile(t *testing.T) {
	cases := map[string]struct{ content, reason string }{
		"broken yaml":   {"services: [unclosed\n", "did not find expected"},
		"not a mapping": {"- just\n- a list\n", "expected a compose file at the top level"},
		"empty":         {"# nothing here\n", "the file declares nothing"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			out := filepath.Join(dir, "report")
			compose := writeFile(t, dir, "docker-compose.yml", tc.content, 0o600)
			code, log := cli(t, "--mode", "compose-preflight", "--compose", compose, "--out", out)

			if code != exitUsage {
				t.Errorf("exit = %d, want %d", code, exitUsage)
			}
			for _, want := range []string{"the Compose preflight cannot start, the Compose file could not be parsed",
				tc.reason, "no report was written"} {
				if !strings.Contains(log, want) {
					t.Errorf("log lacks %q:\n%s", want, log)
				}
			}
			if strings.Contains(log, "section ") {
				t.Errorf("a section ran before the refusal:\n%s", log)
			}
			noReport(t, out)
		})
	}
}

// DW-70: in a host audit the witness section is not applicable — stated in the
// summary and report.json, absent from the upload, and never counted as a gap.
func TestHostAuditWitnessIsNotApplicable(t *testing.T) {
	out := filepath.Join(t.TempDir(), "report")
	code, log := cli(t, "--sections", "ports", "--format", "json", "--out", out)
	if code != exitOK {
		t.Fatalf("exit = %d\n%s", code, log)
	}
	if !strings.Contains(log, "witness not applicable") {
		t.Errorf("log does not state the scope:\n%s", log)
	}

	raw, err := os.ReadFile(filepath.Join(out, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Upload struct {
			Collectors []struct {
				Collector string `json:"collector"`
				Status    string `json:"status"`
			} `json:"collectors"`
		} `json:"upload"`
		Audit struct {
			Mode     string `json:"mode"`
			Sections []struct {
				Section string   `json:"section"`
				Status  string   `json:"status"`
				Notes   []string `json:"notes"`
			} `json:"sections"`
		} `json:"audit"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Audit.Mode != "host-audit" {
		t.Errorf("audit.mode = %q", doc.Audit.Mode)
	}
	found := false
	for _, s := range doc.Audit.Sections {
		if s.Section == "witness" {
			found = true
			if s.Status != "not-applicable" || len(s.Notes) != 1 || !strings.HasPrefix(s.Notes[0], "host-audit: not applicable") {
				t.Errorf("audit witness row = %+v", s)
			}
		}
	}
	if !found {
		t.Error("audit.sections has no witness row stating the scope")
	}
	for _, c := range doc.Upload.Collectors {
		if c.Collector == "witness" {
			t.Errorf("upload carries a witness collector %+v; it is out of scope in a host audit", c)
		}
		if c.Status == "COLLECTOR_STATUS_SKIPPED" {
			t.Errorf("upload collector %q is SKIPPED", c.Collector)
		}
	}
}

// DW-79: --format csv,json writes the CSV tables and report.json from the same
// audit, so the two cannot disagree on when it ran.
func TestFormatBothWritesOneRun(t *testing.T) {
	out := filepath.Join(t.TempDir(), "report")
	code, log := cli(t, "--sections", "ports", "--format", "csv,json", "--out", out)
	if code != exitOK {
		t.Fatalf("exit = %d\n%s", code, log)
	}
	if !strings.Contains(log, "CSV files to") || !strings.Contains(log, "report.json") {
		t.Errorf("log = %s", log)
	}
	summary, err := os.ReadFile(filepath.Join(out, "summary.csv"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(out, "report.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Audit struct {
			GeneratedAt string `json:"generatedAt"`
		} `json:"audit"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	stamp := strings.Replace(strings.TrimSuffix(doc.Audit.GeneratedAt, "Z"), "T", " ", 1)
	if len(stamp) < 19 || !strings.Contains(string(summary), "at "+stamp[:19]+" UTC") {
		t.Errorf("summary.csv does not carry report.json's generatedAt %q:\n%s", doc.Audit.GeneratedAt, summary)
	}
}

// DW-81: a plan Compose would reject stops the preflight — exit 2, Compose's own
// reason, no report. A failed preparation must never yield a preflight result.
func TestPreflightOfAPlanComposeRejects(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil || exec.Command("docker", "compose", "version").Run() != nil {
		t.Skip("docker compose is not installed; the plan is resolved by the built-in parser here")
	}
	dir := t.TempDir()
	out := filepath.Join(dir, "report")
	compose := writeFile(t, dir, "docker-compose.yml",
		"services:\n  app:\n    image: nginx:1.27\n    ports: [\"${DW_TEST_REQUIRED_PORT:?set the port}:80\"]\n", 0o600)
	t.Setenv("DW_TEST_REQUIRED_PORT", "")
	code, log := cli(t, "--compose", compose, "--sections", "witness", "--out", out)

	if code != exitUsage || !strings.Contains(log, "docker compose config rejected the planned run") ||
		!strings.Contains(log, "set the port") {
		t.Errorf("exit = %d, log = %q", code, log)
	}
	noReport(t, out)
}

// DW-81: a plan that includes a remote file is refused rather than resolved,
// because resolving it would fetch it.
func TestPreflightRefusesARemoteInclude(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "report")
	compose := writeFile(t, dir, "docker-compose.yml",
		"include:\n  - https://example.com/base.yml\nservices:\n  app:\n    image: nginx:1.27\n", 0o600)
	code, log := cli(t, "--compose", compose, "--sections", "witness", "--out", out)

	if code != exitUsage || !strings.Contains(log, "from a remote source") {
		t.Errorf("exit = %d, log = %q", code, log)
	}
	noReport(t, out)
}

// DW-81: a plan aimed at a remote engine is a plan for another machine; checking it
// against this one would answer the wrong question.
func TestPreflightRefusesARemoteEngine(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "report")
	compose := writeFile(t, dir, "docker-compose.yml", "services:\n  app:\n    image: nginx:1.27\n", 0o600)
	t.Setenv("DOCKER_HOST", "ssh://deploy@192.0.2.10")
	code, log := cli(t, "--compose", compose, "--sections", "witness", "--out", out)

	if code != exitUsage || !strings.Contains(log, "cannot speak for that engine") {
		t.Errorf("exit = %d, log = %q", code, log)
	}
	noReport(t, out)
}

// DW-81: the plan's flags describe a Compose run and are refused without one.
func TestPlanFlagsNeedACompose(t *testing.T) {
	dir := t.TempDir()
	code, log := cli(t, "--profile", "web", "--out", filepath.Join(dir, "r"))
	if code != exitUsage || !strings.Contains(log, "need --compose") {
		t.Errorf("exit = %d, log = %q", code, log)
	}
}

// DW-82: a report confirms only the plan it checked, on the engine it inspected,
// while it is fresh. The same plan rechecks as confirmed (exit 0); a changed plan
// does not (exit 4), and neither does a report past --max-age.
func TestRecheckConfirmsOnlyTheSamePlan(t *testing.T) {
	if exec.Command("docker", "info").Run() != nil {
		t.Skip("no container engine answers here; a report without an engine identity never rechecks as confirmed")
	}
	dir := t.TempDir()
	out := filepath.Join(dir, "report")
	compose := writeFile(t, dir, "docker-compose.yml", "services:\n  app:\n    image: nginx:1.27\n    ports: [\"18080:80\"]\n", 0o600)
	if code, log := cli(t, "--compose", compose, "--sections", "witness", "--format", "json", "--out", out); code != exitOK {
		t.Fatalf("audit exit %d: %s", code, log)
	}
	saved := filepath.Join(out, "report.json")

	if code, log := cli(t, "--recheck", saved, "--compose", compose); code != exitOK {
		t.Errorf("same plan: exit %d, log %s", code, log)
	}
	if code, _ := cli(t, "--recheck", saved, "--compose", compose, "--max-age", "1ns"); code != exitRecheck {
		t.Errorf("stale report: exit %d, want %d", code, exitRecheck)
	}
	writeFile(t, dir, "docker-compose.yml", "services:\n  app:\n    image: nginx:1.27\n    ports: [\"18081:80\"]\n", 0o600)
	if code, _ := cli(t, "--recheck", saved, "--compose", compose); code != exitRecheck {
		t.Errorf("changed plan: exit %d, want %d", code, exitRecheck)
	}
}
