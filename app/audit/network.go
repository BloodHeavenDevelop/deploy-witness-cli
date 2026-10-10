package audit

import (
	"fmt"
	"net/url"
	"sort"
	"strings"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/config"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/netpath"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/report"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/run"
)

// NetworkPlan is every network path this tool has, with what this configuration
// will do on each: enabled or not, who receives the traffic, and what is sent.
// main prints it before the audit starts, and the finished report carries it with
// the contacts counted (network.csv), so the recipients are known before anything
// is sent and checkable after.
func NetworkPlan(cfg *config.Config) []model.NetworkUse {
	ignored := map[string]bool{}
	for _, name := range cfg.IgnoredEnv {
		ignored[name] = true
	}
	off := func(flag string, envs ...string) string {
		note := "not enabled: " + flag + " was not given"
		for _, env := range envs {
			if ignored[env] {
				note += "; " + env + " is set in the environment and was ignored (network paths are enabled by a typed flag only)"
			}
		}
		return note
	}

	osv := model.NetworkUse{
		Path: netpath.PathOSV, Flag: netpath.FlagOnline, Enabled: cfg.Online,
		Sends: "the name, version and ecosystem of every installed package (POST /v1/querybatch), " +
			"then one GET /v1/vulns/<id> per advisory found; the host name is resolved by the system resolver",
	}
	feeds := model.NetworkUse{
		Path: netpath.PathDistroFeeds, Flag: netpath.FlagOnline, Enabled: cfg.Online,
		Recipient: "chosen by the distribution tool: security-tracker.debian.org (debsecan), " +
			"security.archlinux.org (arch-audit)",
		Sends: "the tool's own HTTPS download of its advisory data (debsecan's request names the release " +
			"codename); the package list is compared on this host",
	}
	egress := model.NetworkUse{
		Path: netpath.PathEgress, Flag: netpath.FlagEgress, Enabled: cfg.Egress,
		Sends: "a DNS lookup of each registry by the system resolver, then one TCP connect, closed at once; " +
			"no TLS, no HTTP, no bytes sent",
	}
	upload := model.NetworkUse{
		Path: netpath.PathUpload, Flag: netpath.FlagUpload, Enabled: cfg.WantsUpload(),
		Sends: "one POST of the `upload` half of report.json with the one-time token in X-Upload-Token; no retry",
	}

	if cfg.Online {
		if target, err := url.Parse(cfg.OSVEndpoint); err == nil {
			osv.Recipient = netpath.Describe(target)
		}
		osv.Note = "requests are counted in contacts"
		feeds.Note = "runs only the tools installed here; each run is counted in contacts and listed in commands.csv"
	} else {
		osv.Note = off(netpath.FlagOnline, "AUDIT_ONLINE", "AUDIT_OSV_URL")
		feeds.Recipient = ""
		feeds.Note = off(netpath.FlagOnline, "AUDIT_ONLINE") + "; debsecan and arch-audit are not run"
	}

	if cfg.Egress {
		egress.Recipient = "the registries named by the images in --compose"
		if cfg.Compose == "" || !cfg.Wants(model.SectionWitness) {
			egress.Note = "enabled, but no registry is contacted without --compose and the witness section"
		}
	} else {
		egress.Note = off(netpath.FlagEgress, "AUDIT_EGRESS")
	}

	if cfg.WantsUpload() {
		if endpoint, err := report.UploadEndpoint(cfg.UploadURL); err == nil {
			upload.Recipient = netpath.Describe(endpoint)
		}
		upload.Note = "sent after this report is written; the outcome is on stdout and in the exit code"
	} else {
		upload.Note = off(netpath.FlagUpload, "AUDIT_UPLOAD")
	}

	return []model.NetworkUse{osv, feeds, egress, upload}
}

// PlanSummary renders the plan as log lines, one per path, enabled ones first.
func PlanSummary(plan []model.NetworkUse) []string {
	var enabled []string
	for _, use := range plan {
		if use.Enabled {
			enabled = append(enabled, fmt.Sprintf("network: %s (%s) → %s: sends %s",
				use.Flag, use.Path, use.Recipient, use.Sends))
		}
	}
	if len(enabled) == 0 {
		return []string{"network: none — --online, --egress and --upload were not given: deploy-witness " +
			"opens no network connection and runs none of the commands that fetch data over the network"}
	}
	return enabled
}

// networkRecord is the plan with what actually happened filled in.
func (a *Auditor) networkRecord(commands []model.CommandRun) []model.NetworkUse {
	plan := NetworkPlan(a.cfg)
	for i := range plan {
		switch plan[i].Path {
		case netpath.PathOSV:
			plan[i].Contacts = a.osvRequests
		case netpath.PathDistroFeeds:
			var tools []string
			for _, c := range commands {
				if c.Network == "" || c.Outcome == run.OutcomeRefused || c.Outcome == run.OutcomeMissing {
					continue
				}
				plan[i].Contacts++
				tools = append(tools, strings.Fields(c.Command)[0])
			}
			if len(tools) > 0 {
				plan[i].Note = "ran: " + strings.Join(dedupe(tools), ", ") + "; see commands.csv"
			}
		case netpath.PathEgress:
			plan[i].Contacts = len(a.egressTargets)
			if len(a.egressTargets) > 0 {
				targets := append([]string(nil), a.egressTargets...)
				sort.Strings(targets)
				plan[i].Recipient = strings.Join(targets, ", ")
			}
		}
	}
	return plan
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
