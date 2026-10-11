package main

import (
	"bytes"
	"encoding/json"
	"os"
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
