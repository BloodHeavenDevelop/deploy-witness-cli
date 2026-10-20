package witness

import (
	"strings"
	"testing"
	"time"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
)

// cleanInput is a plan that every rule can check and none objects to: one pinned
// service with a healthcheck, publishing one port nobody holds, on a host where
// every source answered.
func cleanInput() Input {
	in := baseInput()
	in.Manifest.Services = []model.ManifestService{{
		Name:           "web",
		Image:          model.ImageRef{Raw: "nginx@sha256:abc", Repository: "nginx", Digest: "sha256:abc"},
		HasHealthcheck: true,
		Ports:          []model.PortMapping{{HostPort: 8080, ContainerPort: 80, Protocol: "tcp"}},
	}}
	in.Caps.Images = []model.ContainerImage{{Reference: "nginx@sha256:abc", Architecture: "amd64", OS: "linux"}}
	in.EgressChecked = true
	in.RegistryResults = map[string]string{"docker.io": ""}
	return in
}

func ruleResult(t *testing.T, in Input, code string) model.RuleResult {
	t.Helper()
	for _, r := range Evaluate(in).Rules {
		if r.Code == code {
			return r
		}
	}
	t.Fatalf("no rule result for %s", code)
	return model.RuleResult{}
}

func unreachableEngine(in *Input) {
	in.Caps.Runtime.Reachable = false
	in.Caps.Runtime.Note = "permission denied"
	for i := range in.Caps.Observations {
		switch in.Caps.Observations[i].Source {
		case model.SourceContainers, model.SourceNetworks, model.SourceNetworkSubnets,
			model.SourceVolumes, model.SourceImages:
			in.Caps.Observations[i].State = model.ObservedFailed
			in.Caps.Observations[i].Note = "docker did not answer: permission denied"
		}
	}
}

type situation struct {
	name   string
	mutate func(*Input)
	want   model.Outcome
}

// Every rule is defined by three situations — a problem is proven, no problem is
// proven, the data is insufficient — plus "not applicable" where the plan can give
// it nothing to check and "manual check" where the question cannot be settled from
// inside the host. This table is that definition, executed. A rule added to rules()
// without a row here fails TestEveryRuleHasItsSituations.
var situations = map[string][]situation{
	"witness.port_conflict": {
		{"held by another process", func(in *Input) {
			in.Caps.Ports = []model.Port{{Protocol: "tcp", Address: "0.0.0.0", Port: 8080, State: "LISTEN", Pid: 7, Process: "python3"}}
		}, model.OutcomeProblem},
		{"free", nil, model.OutcomeNoProblem},
		{"held by our own container", func(in *Input) {
			in.Caps.Containers = []model.Container{{Name: "app-web-1", Project: "app", Service: "web", State: "running",
				Ports: []model.PortMapping{{HostIP: "0.0.0.0", HostPort: 8080, ContainerPort: 80, Protocol: "tcp"}}}}
		}, model.OutcomeNoProblem},
		{"sockets not read", func(in *Input) { in.PortsUnchecked = true }, model.OutcomeUnknown},
		{"held, engine did not answer", func(in *Input) {
			unreachableEngine(in)
			in.Caps.Ports = []model.Port{{Protocol: "tcp", Address: "0.0.0.0", Port: 8080, State: "LISTEN", Process: "docker-proxy"}}
		}, model.OutcomeUnknown},
		{"sctp publish", func(in *Input) {
			in.Manifest.Services[0].Ports = []model.PortMapping{{HostPort: 9000, ContainerPort: 9000, Protocol: "sctp"}}
		}, model.OutcomeManualCheck},
		{"no published port", func(in *Input) { in.Manifest.Services[0].Ports = nil }, model.OutcomeNotApplicable},
	},
	"witness.container_name_conflict": {
		{"taken by another project", func(in *Input) {
			in.Manifest.Services[0].ContainerName = "web"
			in.Caps.Containers = []model.Container{{Name: "web", Project: "other", State: "running"}}
		}, model.OutcomeProblem},
		{"free", func(in *Input) { in.Manifest.Services[0].ContainerName = "web" }, model.OutcomeNoProblem},
		{"engine did not answer", func(in *Input) {
			in.Manifest.Services[0].ContainerName = "web"
			unreachableEngine(in)
		}, model.OutcomeUnknown},
		{"no fixed name", nil, model.OutcomeNotApplicable},
	},
	"witness.volume_name_conflict": {
		{"external volume missing", func(in *Input) {
			in.Manifest.Volumes = []model.ManifestVolume{{Name: "shared", External: true}}
		}, model.OutcomeProblem},
		{"external volume present", func(in *Input) {
			in.Manifest.Volumes = []model.ManifestVolume{{Name: "shared", External: true}}
			in.Caps.ContainerVolumes = []model.ContainerVolume{{Name: "shared", Project: "app"}}
		}, model.OutcomeNoProblem},
		{"engine did not answer", func(in *Input) {
			in.Manifest.Volumes = []model.ManifestVolume{{Name: "shared", External: true}}
			unreachableEngine(in)
		}, model.OutcomeUnknown},
		{"no external volume", nil, model.OutcomeNotApplicable},
	},
	"witness.bind_path_conflict": {
		{"binds /etc", func(in *Input) {
			in.Manifest.Services[0].Volumes = []model.VolumeMount{{Kind: model.MountBind, Source: "/etc", Target: "/x"}}
		}, model.OutcomeProblem},
		{"binds a data directory", func(in *Input) {
			in.Manifest.Services[0].Volumes = []model.VolumeMount{{Kind: model.MountBind, Source: "/srv/app/data", Target: "/x"}}
		}, model.OutcomeNoProblem},
		{"no bind mount", nil, model.OutcomeNotApplicable},
	},
	"witness.network_name_conflict": {
		{"external network missing", func(in *Input) {
			in.Manifest.Networks = []model.ManifestNetwork{{Name: "edge", External: true}}
		}, model.OutcomeProblem},
		{"external network present", func(in *Input) {
			in.Manifest.Networks = []model.ManifestNetwork{{Name: "edge", External: true}}
			in.Caps.ContainerNetworks = []model.ContainerNetwork{{Name: "edge", Project: "app"}}
		}, model.OutcomeNoProblem},
		{"engine did not answer", func(in *Input) {
			in.Manifest.Networks = []model.ManifestNetwork{{Name: "edge", External: true}}
			unreachableEngine(in)
		}, model.OutcomeUnknown},
		{"shared with another stack", func(in *Input) {
			in.Manifest.Networks = []model.ManifestNetwork{{Name: "edge", External: true}}
			in.Caps.ContainerNetworks = []model.ContainerNetwork{{Name: "edge", Project: "proxy"}}
		}, model.OutcomeManualCheck},
		{"no external network", nil, model.OutcomeNotApplicable},
	},
	"witness.subnet_overlap": {
		{"overlaps", func(in *Input) {
			in.Manifest.Networks = []model.ManifestNetwork{{Name: "back", Subnets: []string{"10.10.0.0/16"}}}
			in.Caps.ContainerNetworks = []model.ContainerNetwork{{Name: "x", Project: "other", Subnets: []string{"10.10.5.0/24"}}}
		}, model.OutcomeProblem},
		{"disjoint", func(in *Input) {
			in.Manifest.Networks = []model.ManifestNetwork{{Name: "back", Subnets: []string{"10.10.0.0/16"}}}
			in.Caps.ContainerNetworks = []model.ContainerNetwork{{Name: "x", Project: "other", Subnets: []string{"10.20.0.0/16"}}}
		}, model.OutcomeNoProblem},
		{"subnets of some networks unknown", func(in *Input) {
			in.Manifest.Networks = []model.ManifestNetwork{{Name: "back", Subnets: []string{"10.10.0.0/16"}}}
			in.Caps.Observe(model.SourceNetworkSubnets, model.ObservedPartial, "1 of 3 networks could not be inspected")
		}, model.OutcomeUnknown},
		{"no explicit subnet", nil, model.OutcomeNotApplicable},
	},
	"witness.insufficient_memory": {
		{"asks for more than is available", func(in *Input) {
			in.Manifest.Services[0].MemReservationBytes = 7 << 30
		}, model.OutcomeProblem},
		{"fits", func(in *Input) { in.Manifest.Services[0].MemReservationBytes = 1 << 30 }, model.OutcomeNoProblem},
		{"memory unreadable", func(in *Input) {
			in.Manifest.Services[0].MemReservationBytes = 1 << 30
			in.Caps.MemTotalBytes, in.Caps.MemAvailableBytes = 0, 0
		}, model.OutcomeUnknown},
		{"no requirement declared", nil, model.OutcomeNotApplicable},
	},
	"witness.insufficient_disk": {
		{"no headroom for a pull", func(in *Input) {
			in.Caps.Images = nil
			in.Caps.Filesystems[0].AvailableBytes = 1 << 29
		}, model.OutcomeProblem},
		{"headroom", func(in *Input) { in.Caps.Images = nil }, model.OutcomeNoProblem},
		{"nothing to pull", nil, model.OutcomeNoProblem},
		{"no filesystem measured", func(in *Input) { in.Caps.Filesystems = nil }, model.OutcomeUnknown},
		{"images not listed", func(in *Input) { unreachableEngine(in) }, model.OutcomeUnknown},
	},
	"witness.insufficient_inodes": {
		{"inodes nearly gone", func(in *Input) { in.Caps.Filesystems[0].InodesFree = 1000 }, model.OutcomeProblem},
		{"inodes to spare", nil, model.OutcomeNoProblem},
		{"no filesystem measured", func(in *Input) { in.Caps.Filesystems = nil }, model.OutcomeUnknown},
		{"no fixed inode count", func(in *Input) {
			in.Caps.Filesystems[0].InodesTotal, in.Caps.Filesystems[0].InodesFree = 0, 0
		}, model.OutcomeNotApplicable},
	},
	"witness.architecture_mismatch": {
		{"image built for another architecture", func(in *Input) {
			in.Caps.Images[0].Architecture = "arm64"
		}, model.OutcomeProblem},
		{"matches", nil, model.OutcomeNoProblem},
		{"image not on the host yet", func(in *Input) { in.Caps.Images = nil }, model.OutcomeUnknown},
		{"host architecture unknown", func(in *Input) { in.Caps.Arch = "" }, model.OutcomeUnknown},
	},
	"witness.runtime_missing_or_old": {
		{"no engine", func(in *Input) { in.Caps.Runtime = nil }, model.OutcomeProblem},
		{"engine and compose present", nil, model.OutcomeNoProblem},
		{"engine did not answer", func(in *Input) { unreachableEngine(in) }, model.OutcomeUnknown},
	},
	"witness.registry_unreachable": {
		{"unreachable", func(in *Input) { in.RegistryResults = map[string]string{"docker.io": "i/o timeout"} }, model.OutcomeProblem},
		{"reachable", nil, model.OutcomeNoProblem},
		{"not checked (no --egress)", func(in *Input) { in.EgressChecked = false }, model.OutcomeUnknown},
		{"everything built locally", func(in *Input) {
			in.Manifest.Services[0].Image = model.ImageRef{}
			in.Manifest.Services[0].Build = "."
		}, model.OutcomeNotApplicable},
	},
	"witness.proxy_conflict": {
		{"nginx listens on 443", func(in *Input) {
			in.Manifest.Services[0].Ports = []model.PortMapping{{HostPort: 443, ContainerPort: 443, Protocol: "tcp"}}
			in.Caps.Proxy = &model.Proxy{Kind: "nginx", ListenPorts: []int{80, 443}}
		}, model.OutcomeProblem},
		{"no web server", func(in *Input) {
			in.Manifest.Services[0].Ports = []model.PortMapping{{HostPort: 443, ContainerPort: 443, Protocol: "tcp"}}
		}, model.OutcomeNoProblem},
		{"QUIC on 443/udp against nginx", func(in *Input) {
			in.Manifest.Services[0].Ports = []model.PortMapping{{HostPort: 443, ContainerPort: 443, Protocol: "udp"}}
			in.Caps.Proxy = &model.Proxy{Kind: "nginx", ListenPorts: []int{443}}
		}, model.OutcomeUnknown},
		{"configuration unreadable", func(in *Input) {
			in.Manifest.Services[0].Ports = []model.PortMapping{{HostPort: 443, ContainerPort: 443, Protocol: "tcp"}}
			in.Caps.Proxy = &model.Proxy{Kind: "nginx"}
			in.Caps.Observe(model.SourceProxy, model.ObservedFailed, "no configuration file could be read")
		}, model.OutcomeUnknown},
		{"neither 80 nor 443", nil, model.OutcomeNotApplicable},
	},
	"witness.domain_conflict": {
		{"vhost exists", func(in *Input) {
			in.Manifest.Services[0].Labels = map[string]string{"traefik.http.routers.w.rule": "Host(`a.example.com`)"}
			in.Caps.Proxy = &model.Proxy{Kind: "nginx", ServerNames: []model.ProxyServerName{{Name: "a.example.com", File: "/etc/nginx/a", Line: 2}}}
		}, model.OutcomeProblem},
		{"no vhost for it", func(in *Input) {
			in.Manifest.Services[0].Labels = map[string]string{"traefik.http.routers.w.rule": "Host(`a.example.com`)"}
			in.Caps.Proxy = &model.Proxy{Kind: "nginx", ServerNames: []model.ProxyServerName{{Name: "b.example.com", File: "/etc/nginx/b", Line: 2}}}
		}, model.OutcomeNoProblem},
		{"configuration unreadable", func(in *Input) {
			in.Manifest.Services[0].Labels = map[string]string{"traefik.http.routers.w.rule": "Host(`a.example.com`)"}
			in.Caps.Proxy = &model.Proxy{Kind: "nginx"}
			in.Caps.Observe(model.SourceProxy, model.ObservedFailed, "no configuration file could be read")
		}, model.OutcomeUnknown},
		{"catch-all would answer", func(in *Input) {
			in.Manifest.Services[0].Labels = map[string]string{"traefik.http.routers.w.rule": "Host(`a.example.com`)"}
			in.Caps.Proxy = &model.Proxy{Kind: "nginx", ServerNames: []model.ProxyServerName{{Name: "_", File: "/etc/nginx/default", Line: 3}}}
		}, model.OutcomeManualCheck},
		{"no domain in labels", nil, model.OutcomeNotApplicable},
	},
	"witness.database_version_mismatch": {
		{"postgres 16 on 15 data", func(in *Input) {
			in.Manifest.Services[0].Image = model.ImageRef{Raw: "postgres:16", Repository: "postgres", Tag: "16"}
			in.Caps.Databases = []model.Database{{Kind: "postgres", Version: "15", DataDir: "/var/lib/postgresql/15/main"}}
		}, model.OutcomeProblem},
		{"same major", func(in *Input) {
			in.Manifest.Services[0].Image = model.ImageRef{Raw: "postgres:15", Repository: "postgres", Tag: "15"}
			in.Caps.Databases = []model.Database{{Kind: "postgres", Version: "15"}}
		}, model.OutcomeNoProblem},
		{"tag names no version", func(in *Input) {
			in.Manifest.Services[0].Image = model.ImageRef{Raw: "postgres:latest", Repository: "postgres", Tag: "latest"}
			in.Caps.Databases = []model.Database{{Kind: "postgres", Version: "15"}}
		}, model.OutcomeUnknown},
		{"no database image", nil, model.OutcomeNotApplicable},
	},
	"witness.env_file_missing": {
		{"missing", func(in *Input) {
			in.Manifest.Services[0].EnvFiles = []model.EnvFileRef{{Path: "/srv/app/.env"}}
		}, model.OutcomeProblem},
		{"present", func(in *Input) {
			in.Manifest.Services[0].EnvFiles = []model.EnvFileRef{{Path: "/srv/app/.env", Exists: true}}
		}, model.OutcomeNoProblem},
		{"no env_file", nil, model.OutcomeNotApplicable},
	},
	"witness.no_healthcheck": {
		{"none", func(in *Input) { in.Manifest.Services[0].HasHealthcheck = false }, model.OutcomeProblem},
		{"defined", nil, model.OutcomeNoProblem},
	},
	"witness.floating_image_tag": {
		{"latest", func(in *Input) {
			in.Manifest.Services[0].Image = model.ImageRef{Raw: "nginx:latest", Repository: "nginx", Tag: "latest"}
		}, model.OutcomeProblem},
		{"digest", nil, model.OutcomeNoProblem},
		{"built locally", func(in *Input) {
			in.Manifest.Services[0].Image = model.ImageRef{}
			in.Manifest.Services[0].Build = "."
		}, model.OutcomeNotApplicable},
	},
	"witness.privileged_container": {
		{"privileged", func(in *Input) { in.Manifest.Services[0].Privileged = true }, model.OutcomeProblem},
		{"plain", nil, model.OutcomeNoProblem},
	},
	"witness.backup_gap": {
		{"data and no backup", func(in *Input) {
			in.Manifest.Services[0].Volumes = []model.VolumeMount{{Kind: model.MountVolume, Source: "data", Target: "/d"}}
		}, model.OutcomeProblem},
		{"fresh backup", func(in *Input) {
			in.Manifest.Services[0].Volumes = []model.VolumeMount{{Kind: model.MountVolume, Source: "data", Target: "/d"}}
			in.Caps.Backup = model.BackupPosture{Tools: []string{"restic"}, Locations: []model.BackupLocation{
				{Path: "/backup", NewestFileAt: fixedNow.Format(time.RFC3339), AgeDays: 1}}}
		}, model.OutcomeNoProblem},
		{"a tool, and nowhere local it writes to", func(in *Input) {
			in.Manifest.Services[0].Volumes = []model.VolumeMount{{Kind: model.MountVolume, Source: "data", Target: "/d"}}
			in.Caps.Backup = model.BackupPosture{Tools: []string{"restic"}}
		}, model.OutcomeManualCheck},
		{"no persistent data", nil, model.OutcomeNotApplicable},
	},
	"witness.no_rollback_plan": {
		{"running image has no digest", func(in *Input) {
			in.Caps.Containers = []model.Container{{Name: "app-web-1", Project: "app", Service: "web", Image: "nginx:old", State: "running"}}
		}, model.OutcomeProblem},
		{"only the snapshot is unverifiable", nil, model.OutcomeManualCheck},
	},
	"witness.certificate_expiring": {
		{"expires in 3 days", func(in *Input) {
			in.Caps.Certificates = []model.Certificate{{Path: "/etc/ssl/a.pem", NotAfter: "2026-08-20T00:00:00Z", DaysLeft: 3}}
		}, model.OutcomeProblem},
		{"valid for months", func(in *Input) {
			in.Caps.Certificates = []model.Certificate{{Path: "/etc/ssl/a.pem", NotAfter: "2027-01-01T00:00:00Z", DaysLeft: 137}}
		}, model.OutcomeNoProblem},
		{"unparseable", func(in *Input) {
			in.Caps.Certificates = []model.Certificate{{Path: "/etc/ssl/a.pem"}}
		}, model.OutcomeUnknown},
	},
	"witness.reboot_required": {
		{"pending", func(in *Input) { in.Caps.RebootRequired = "yes" }, model.OutcomeProblem},
		{"not pending", nil, model.OutcomeNoProblem},
		{"unknown", func(in *Input) { in.Caps.RebootRequired = "unknown" }, model.OutcomeUnknown},
	},
	"witness.disk_at_limit": {
		{"98% full", func(in *Input) { in.Caps.Filesystems[0].UsedBytes = 98 << 30 }, model.OutcomeProblem},
		{"40% full", nil, model.OutcomeNoProblem},
		{"nothing measured", func(in *Input) { in.Caps.Filesystems = nil }, model.OutcomeUnknown},
	},
}

// noCleanResult names the rules that cannot end in no-problem by design, and why.
var noCleanResult = map[string]string{
	"witness.no_rollback_plan": "a provider snapshot is never visible from inside the host, so the best this " +
		"rule can conclude is manual-check",
}

func TestEveryRuleHasItsSituations(t *testing.T) {
	for _, r := range rules() {
		cases, ok := situations[r.code]
		if !ok {
			t.Errorf("%s has no situations: define at least a problem, a no-problem and, where the data can be "+
				"missing, an unknown case", r.code)
			continue
		}
		seen := map[model.Outcome]bool{}
		for _, c := range cases {
			seen[c.want] = true
		}
		if _, exempt := noCleanResult[r.code]; exempt && !seen[model.OutcomeNoProblem] {
			seen[model.OutcomeNoProblem] = true
		}
		if !seen[model.OutcomeProblem] || !(seen[model.OutcomeNoProblem]) {
			t.Errorf("%s: the situations must include a problem and a no-problem case", r.code)
		}
	}
	if len(situations) != len(rules()) {
		t.Errorf("situations cover %d codes, rules() has %d", len(situations), len(rules()))
	}
}

func TestRuleOutcomesInEachSituation(t *testing.T) {
	for code, cases := range situations {
		for _, c := range cases {
			t.Run(code+"/"+c.name, func(t *testing.T) {
				in := cleanInput()
				if c.mutate != nil {
					c.mutate(&in)
				}
				got := ruleResult(t, in, code)
				if got.Outcome != c.want {
					t.Errorf("outcome %s, want %s (reason: %s)", got.Outcome, c.want, got.Reason)
				}
				if got.Reason == "" || got.Requires == "" {
					t.Errorf("a rule result must say why and what it needs: %+v", got)
				}
			})
		}
	}
}

// What a rule could not decide must reach witness.csv and the upload, not only
// rules.csv: an unknown or a manual check always has a finding stating it.
func TestUndecidedRulesAlwaysPublishAFinding(t *testing.T) {
	for code, cases := range situations {
		for _, c := range cases {
			if c.want != model.OutcomeUnknown && c.want != model.OutcomeManualCheck {
				continue
			}
			in := cleanInput()
			if c.mutate != nil {
				c.mutate(&in)
			}
			found := false
			for _, f := range Evaluate(in).Findings {
				if f.Code == code && f.Outcome == c.want {
					found = true
					if len(f.Evidence) == 0 || f.Description == "" || f.WhatToDo == "" {
						t.Errorf("%s/%s: incomplete finding %+v", code, c.name, f)
					}
				}
			}
			if !found {
				t.Errorf("%s/%s: outcome %s is stated in rules.csv only", code, c.name, c.want)
			}
		}
	}
}

// Severity and outcome are separate axes, tied by two invariants: only a proven
// problem can block, and "no problem" is never more than info.
func TestOnlyAProvenProblemCanBlock(t *testing.T) {
	for code, cases := range situations {
		for _, c := range cases {
			in := cleanInput()
			if c.mutate != nil {
				c.mutate(&in)
			}
			result := Evaluate(in)
			for _, note := range result.Notes {
				if strings.Contains(note, "downgraded") || strings.Contains(note, "discarded") {
					t.Errorf("%s/%s: %s", code, c.name, note)
				}
			}
			for _, f := range result.Findings {
				if f.Outcome == "" {
					t.Errorf("%s: a finding without an outcome", f.Code)
				}
				if f.Severity == model.FindingBlocker && f.Outcome != model.OutcomeProblem {
					t.Errorf("%s: a %s blocker", f.Code, f.Outcome)
				}
				if (f.Outcome == model.OutcomeNoProblem || f.Outcome == model.OutcomeNotApplicable) &&
					f.Severity != model.FindingInfo {
					t.Errorf("%s: a %s finding at %s", f.Code, f.Outcome, f.Severity)
				}
			}
		}
	}
}

func TestFixOutcomeEnforcesTheInvariants(t *testing.T) {
	f := model.Finding{Severity: model.FindingBlocker, Outcome: model.OutcomeUnknown}
	if !fixOutcome(&f) || f.Severity != model.FindingWarning {
		t.Errorf("an unknown blocker must be downgraded to a warning: %+v", f)
	}
	f = model.Finding{Severity: model.FindingWarning, Outcome: model.OutcomeNoProblem}
	if !fixOutcome(&f) || f.Severity != model.FindingInfo {
		t.Errorf("a no-problem warning must be downgraded to info: %+v", f)
	}
	f = model.Finding{Severity: model.FindingBlocker}
	if fixOutcome(&f) || f.Outcome != model.OutcomeProblem {
		t.Errorf("a blocker without an outcome reads as a problem: %+v", f)
	}
}

func TestEveryRuleEndsInExactlyOneOutcome(t *testing.T) {
	result := Evaluate(busyHost())
	if len(result.Rules) != len(rules()) {
		t.Fatalf("%d rule results for %d rules", len(result.Rules), len(rules()))
	}
	seen := map[string]bool{}
	for _, r := range result.Rules {
		if seen[r.Code] {
			t.Errorf("%s reported twice", r.Code)
		}
		seen[r.Code] = true
		if r.Outcome.Rank() >= len(model.Outcomes) {
			t.Errorf("%s: outcome %q is not in the vocabulary", r.Code, r.Outcome)
		}
	}
	summary := OutcomeSummary(result.Rules)
	if !strings.HasPrefix(summary, "rule outcomes: 24 rules") || !strings.Contains(summary, "problem (") {
		t.Errorf("summary: %s", summary)
	}
}
