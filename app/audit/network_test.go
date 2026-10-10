package audit

import (
	"io"
	"strings"
	"testing"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/config"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/netpath"
)

func load(t *testing.T, args ...string) *config.Config {
	t.Helper()
	cfg, err := config.Load(args, "test", io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func byPath(plan []model.NetworkUse) map[string]model.NetworkUse {
	out := map[string]model.NetworkUse{}
	for _, use := range plan {
		out[use.Path] = use
	}
	return out
}

// A default run — even with every network variable set — plans no network use,
// and the runner it builds refuses network-reaching commands.
func TestDefaultRunIsOffline(t *testing.T) {
	t.Setenv("AUDIT_ONLINE", "1")
	t.Setenv("AUDIT_UPLOAD", "https://collector.example.com")
	t.Setenv("AUDIT_UPLOAD_TOKEN", "t")
	cfg := load(t)

	plan := NetworkPlan(cfg)
	if len(plan) != 4 {
		t.Fatalf("plan has %d rows, want one per path (4)", len(plan))
	}
	for _, use := range plan {
		if use.Enabled || use.Recipient != "" {
			t.Errorf("%s enabled on a default run: %+v", use.Path, use)
		}
	}
	if !strings.Contains(byPath(plan)[netpath.PathOSV].Note, "AUDIT_ONLINE is set in the environment and was ignored") {
		t.Errorf("the ignored variable should be named: %q", byPath(plan)[netpath.PathOSV].Note)
	}
	summary := PlanSummary(plan)
	if len(summary) != 1 || !strings.HasPrefix(summary[0], "network: none") {
		t.Errorf("summary = %v, want a single 'network: none' line", summary)
	}

	if New(cfg, nil, "test").runner.NetworkAllowed() {
		t.Error("a default run must build a runner that refuses network commands")
	}
}

func TestPlanNamesRecipients(t *testing.T) {
	cfg := load(t, "--online", "--egress",
		"--upload", "https://deploy-witness.example.com", "--upload-token", "t")
	plan := byPath(NetworkPlan(cfg))

	if osv := plan[netpath.PathOSV]; !osv.Enabled || !strings.HasPrefix(osv.Recipient, "https://api.osv.dev") {
		t.Errorf("osv = %+v", osv)
	}
	if feeds := plan[netpath.PathDistroFeeds]; !feeds.Enabled || !strings.Contains(feeds.Recipient, "security.archlinux.org") {
		t.Errorf("distro feeds = %+v", feeds)
	}
	if up := plan[netpath.PathUpload]; !up.Enabled ||
		!strings.HasPrefix(up.Recipient, "https://deploy-witness.example.com/api/public/audit/upload") {
		t.Errorf("upload = %+v", up)
	}
	if !New(cfg, nil, "test").runner.NetworkAllowed() {
		t.Error("--online must allow the distribution feeds")
	}
	if len(PlanSummary(NetworkPlan(cfg))) != 4 {
		t.Error("every enabled path gets its own line")
	}
}

func TestNetworkRecordCountsFeedRuns(t *testing.T) {
	a := New(load(t, "--online"), nil, "test")
	a.osvRequests = 3
	record := byPath(a.networkRecord([]model.CommandRun{
		{Command: "debsecan --format summary --suite bookworm", Outcome: "ok", Network: "--online"},
		{Command: "dpkg-query -W", Outcome: "ok"},
	}))
	if record[netpath.PathOSV].Contacts != 3 {
		t.Errorf("osv contacts = %d, want 3", record[netpath.PathOSV].Contacts)
	}
	if feeds := record[netpath.PathDistroFeeds]; feeds.Contacts != 1 || !strings.Contains(feeds.Note, "debsecan") {
		t.Errorf("feeds = %+v, want one debsecan run", feeds)
	}
}
