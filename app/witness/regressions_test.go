package witness

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/redact"
)

// Every confirmed defect — a false alarm, a miss, an unknown the data did not
// justify, on a pilot, on the bench or in review — becomes a case under
// testdata/regressions: the cause, the expected outcome, and an artificial input
// that reproduces it. The cases run with every `make test`, so a fixed defect that
// comes back fails the build before the next release (DW-90).
//
// The archive must not become a store of client data, and this file enforces it:
// a case with a public IP address, a real-looking domain, an engine or machine id,
// an e-mail address or anything the credential sweep would mask is refused.

const regressionsDir = "testdata/regressions"

type regressionCase struct {
	ID             string `yaml:"id"`
	Task           string `yaml:"task"`
	Kind           string `yaml:"kind"`
	Found          string `yaml:"found"`
	Summary        string `yaml:"summary"`
	Cause          string `yaml:"cause"`
	RecheckMinutes *int   `yaml:"recheck_minutes"`
	FixedIn        string `yaml:"fixed_in"`
	Expect         struct {
		Rules          map[string]string `yaml:"rules"`
		NoBlocker      bool              `yaml:"no_blocker"`
		NoBlockerFor   []string          `yaml:"no_blocker_for"`
		ChangesContain []string          `yaml:"changes_contain"`
	} `yaml:"expect"`
}

type regressionInput struct {
	Project         string              `json:"project"`
	Plan            *model.LaunchPlan   `json:"plan"`
	Manifest        *model.Manifest     `json:"manifest"`
	Capabilities    *model.Capabilities `json:"capabilities"`
	EgressChecked   bool                `json:"egressChecked"`
	RegistryResults map[string]string   `json:"registryResults"`
	PortsUnchecked  bool                `json:"portsUnchecked"`
}

func loadRegressions(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(regressionsDir)
	if err != nil {
		t.Fatal(err)
	}
	var dirs []string
	for _, e := range entries {
		if e.IsDir() && !strings.HasPrefix(e.Name(), "_") {
			dirs = append(dirs, filepath.Join(regressionsDir, e.Name()))
		}
	}
	sort.Strings(dirs)
	if len(dirs) == 0 {
		t.Fatal("no regression case")
	}
	return dirs
}

func TestPilotRegressions(t *testing.T) {
	minutes := 0
	for _, dir := range loadRegressions(t) {
		dir := dir
		t.Run(filepath.Base(dir), func(t *testing.T) {
			c, in := readRegression(t, dir)
			if c.RecheckMinutes != nil {
				minutes += *c.RecheckMinutes
			}
			result := Evaluate(in)

			got := map[string]model.Outcome{}
			for _, r := range result.Rules {
				got[r.Code] = r.Outcome
			}
			for code, want := range c.Expect.Rules {
				if string(got[code]) != want {
					t.Errorf("%s (%s, %s): %s ended %q, want %q — the defect is back: %s",
						c.ID, c.Kind, c.Task, code, got[code], want, c.Summary)
				}
			}
			for _, f := range result.Findings {
				if f.Severity != model.FindingBlocker {
					continue
				}
				if c.Expect.NoBlocker || contains(c.Expect.NoBlockerFor, f.Code) {
					t.Errorf("%s: a blocker is back — %s: %s", c.ID, f.Code, f.Title)
				}
			}
			for _, phrase := range c.Expect.ChangesContain {
				found := false
				for _, ch := range result.Changes {
					found = found || strings.Contains(ch.Detail, phrase)
				}
				if !found {
					t.Errorf("%s: no change row says %q", c.ID, phrase)
				}
			}
		})
	}
	t.Logf("regression cases: %d; manual recheck time they recorded on pilots: %d min", len(loadRegressions(t)), minutes)
}

func readRegression(t *testing.T, dir string) (regressionCase, Input) {
	t.Helper()
	var c regressionCase
	raw, err := os.ReadFile(filepath.Join(dir, "case.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(raw, &c); err != nil {
		t.Fatalf("%s/case.yaml: %v", dir, err)
	}
	if err := c.validate(filepath.Base(dir)); err != nil {
		t.Fatalf("%s/case.yaml: %v", dir, err)
	}
	inputRaw, err := os.ReadFile(filepath.Join(dir, "input.json"))
	if err != nil {
		t.Fatal(err)
	}
	var input regressionInput
	if err := json.Unmarshal(inputRaw, &input); err != nil {
		t.Fatalf("%s/input.json: %v", dir, err)
	}
	if input.Manifest == nil || input.Capabilities == nil {
		t.Fatalf("%s/input.json: a manifest and capabilities are required", dir)
	}
	if len(input.Capabilities.Observations) == 0 {
		// A case states the sources that failed; every other one answered in full.
		input.Capabilities.Observations = completeObservations()
	}
	return c, Input{
		Manifest: input.Manifest, Caps: input.Capabilities, Plan: input.Plan,
		Now: time.Date(2026, 10, 19, 12, 0, 0, 0, time.UTC), Project: input.Project,
		EgressChecked: input.EgressChecked, RegistryResults: input.RegistryResults,
		PortsUnchecked: input.PortsUnchecked,
	}
}

func (c regressionCase) validate(dirName string) error {
	switch {
	case c.ID != dirName:
		return fmt.Errorf("id %q must be the directory name %q", c.ID, dirName)
	case !strings.HasPrefix(c.ID, c.Task+"-"):
		return fmt.Errorf("id %q must start with its task %q", c.ID, c.Task)
	case c.Kind != "false-alarm" && c.Kind != "miss" && c.Kind != "unjustified-unknown":
		return fmt.Errorf("kind %q: false-alarm, miss or unjustified-unknown", c.Kind)
	case c.Found != "pilot" && c.Found != "bench" && c.Found != "review":
		return fmt.Errorf("found %q: pilot, bench or review", c.Found)
	case c.Found == "pilot" && (c.RecheckMinutes == nil || *c.RecheckMinutes <= 0):
		return fmt.Errorf("a pilot defect records the minutes its manual recheck took (recheck_minutes)")
	case strings.TrimSpace(c.Summary) == "" || strings.TrimSpace(c.Cause) == "" || c.FixedIn == "":
		return fmt.Errorf("summary, cause and fixed_in are required")
	case len(c.Expect.Rules) == 0:
		return fmt.Errorf("expect.rules: at least one rule outcome")
	}
	known := map[string]bool{}
	for _, r := range rules() {
		known[r.code] = true
	}
	for code, outcome := range c.Expect.Rules {
		if !known[code] {
			return fmt.Errorf("expect.rules: %s is not a rule", code)
		}
		if model.Outcome(outcome).Rank() >= len(model.Outcomes) {
			return fmt.Errorf("expect.rules: %q is not an outcome", outcome)
		}
	}
	return nil
}

// ─────────────────────────────────────────────────── the archive holds no client data

var (
	ipLike     = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b|\b[0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{0,4}){2,7}\b`)
	domainLike = regexp.MustCompile(`\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b`)
	emailLike  = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}`)
	idLike     = regexp.MustCompile(`\b[0-9a-f]{32}\b|\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b|\b[0-9a-f]{64}\b`)
)

// allowedSuffixes are the names reserved for examples (RFC 2606, RFC 6761) and the
// file and image names the cases use.
var allowedSuffixes = []string{".example", ".example.com", ".example.net", ".example.org", ".test", ".invalid",
	".localhost", ".yml", ".yaml", ".json", ".conf", ".env", ".sock", ".pem", ".txt", ".csv", ".service"}

var allowedNames = map[string]bool{"engine.example": true, "docker.io": true}

func TestRegressionArchiveHoldsNoClientData(t *testing.T) {
	for _, dir := range append(loadRegressions(t), filepath.Join(regressionsDir, "_template")) {
		for _, name := range []string{"case.yaml", "input.json"} {
			raw, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				t.Fatal(err)
			}
			text := string(raw)
			where := filepath.Join(filepath.Base(dir), name)
			for _, problem := range clientData(text) {
				t.Errorf("%s: %s", where, problem)
			}
		}
	}
}

func clientData(text string) []string {
	var out []string
	if masked := redact.String(text); masked != text {
		out = append(out, "contains material the credential sweep masks")
	}
	for _, m := range ipLike.FindAllString(text, -1) {
		ip := net.ParseIP(m)
		if ip == nil {
			continue
		}
		if !(ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || documentation(ip)) {
			out = append(out, "a public IP address: "+m)
		}
	}
	for _, m := range domainLike.FindAllString(strings.ToLower(text), -1) {
		if !allowedName(m) {
			out = append(out, "a domain outside the reserved example names: "+m)
		}
	}
	for _, m := range emailLike.FindAllString(text, -1) {
		if !allowedName(strings.SplitN(m, "@", 2)[1]) {
			out = append(out, "an e-mail address: "+m)
		}
	}
	for _, m := range idLike.FindAllString(strings.ToLower(text), -1) {
		if !strings.HasPrefix(m, "00000000") {
			out = append(out, "an engine, machine or image id: "+m+" (use one starting with 00000000)")
		}
	}
	return out
}

func allowedName(name string) bool {
	if allowedNames[name] {
		return true
	}
	for _, suffix := range allowedSuffixes {
		if strings.HasSuffix(name, suffix) || name == strings.TrimPrefix(suffix, ".") {
			return true
		}
	}
	// Image references and versions read like names (nginx.1.27 does not, but
	// "postgres.internal" would): anything with a digit-only label is a version.
	for _, label := range strings.Split(name, ".") {
		if label != "" && strings.Trim(label, "0123456789") == "" {
			return true
		}
	}
	return false
}

func documentation(ip net.IP) bool {
	for _, cidr := range []string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"} {
		_, n, _ := net.ParseCIDR(cidr)
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// The lint itself is tested: it must catch what it promises to.
func TestClientDataLint(t *testing.T) {
	for _, bad := range []string{
		`"address": "8.8.4.4"`, `"host": "shop.acme-corp.ru"`, `owner: ops@acme-corp.com`,
		`"engineId": "d2da8027-bed0-4bc1-947e-0f0dd80a6c0f"`, `DB_PASSWORD=hunter2hunter2`,
	} {
		if len(clientData(bad)) == 0 {
			t.Errorf("the lint let through %s", bad)
		}
	}
	for _, good := range []string{
		`"address": "192.0.2.10"`, `"address": "10.1.2.3"`, `"name": "shop.example.com"`, `"image": "nginx:1.27"`,
		`"engineId": "00000000-0000-4000-8000-000000000001"`, `"path": "/srv/app/docker-compose.yml"`,
	} {
		if problems := clientData(good); len(problems) > 0 {
			t.Errorf("the lint refused %s: %v", good, problems)
		}
	}
}
