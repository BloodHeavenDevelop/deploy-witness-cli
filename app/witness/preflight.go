// Package witness compares what a deployment asks for against what the host
// offers, and states every disagreement it finds.
//
// The split from `app/collect` is strict and deliberate: nothing in here observes
// the host. Every rule is a pure function of the manifest and the capabilities
// already collected, which is what makes each finding explainable — and testable
// without a machine in a particular state.
//
// Three properties are enforced rather than encouraged:
//
//   - Every finding carries evidence. Evaluate drops one that does not and says so,
//     because a claim about somebody's production server that cannot be checked is
//     worse than silence.
//   - A blocker is rare. It means "this will not work" or "this is already
//     exploitable", not "this worries me". A false blocker is the most expensive
//     mistake this product can make: it stops a deployment that would have been
//     fine, and the next one goes out with the checks switched off.
//   - "Not checked" is never rendered as "fine". A rule whose input was not
//     observed says so, in its own finding, rather than staying quiet.
package witness

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
)

// Input is everything the rules may look at.
type Input struct {
	Manifest *model.Manifest
	Caps     *model.Capabilities
	// Now anchors every date comparison. Passed in rather than read, so a
	// certificate-expiry test is not a different test tomorrow.
	Now time.Time
	// Project is the compose project name the deployment will use. It is what
	// separates "port 8080 is taken by something else" from "port 8080 is taken by
	// the previous version of this very deployment", and getting it wrong turns
	// every redeployment into a wall of false conflicts.
	Project string
	// EgressChecked records whether registry reachability was actually tested. It
	// is false unless --egress was passed, and the corresponding rule then reports
	// "not checked" instead of concluding anything.
	EgressChecked bool
	// RegistryResults maps a registry host to the error from reaching it, or "" for
	// success. Only populated when EgressChecked is true.
	RegistryResults map[string]string
	// PortsUnchecked records that the listening sockets were not collected (the
	// ports section was not selected), so an empty Caps.Ports means "not looked
	// at", not "nothing listening".
	PortsUnchecked bool
	// PlanResolvedAt is when the plan was resolved: the time of every piece of
	// evidence quoting the manifest. Zero means Now.
	PlanResolvedAt time.Time
	// Plan is the planned run — its directory, configuration hashes and `up`
	// options decide what happens to the containers already there. Nil in tests
	// that do not need it: every container of the project then counts as this
	// deployment's previous version.
	Plan *model.LaunchPlan
}

// RulesVersion identifies the rule set a report was produced with. It changes
// whenever any rule's logic, threshold or outcome changes — independently of the
// tool version, so a report states which judgement it rests on and --recheck can
// tell that an older one was made under rules that have since changed.
//
//	1  the rule set up to 1.4.0
//	2  one outcome per rule; the exact planned run; evidence provenance
const RulesVersion = "2"

// rule is one check. Rules never observe and never mutate their input.
//
// eval states what the rule found; assess states what the rule could conclude when
// eval found nothing to say — that the plan gives it nothing to check, that the data
// it needs was not there, or that it checked and everything is in order. The two are
// separate because "no finding" means three different things, and a report that lets
// a reader guess which one is the dishonest half of the second promise.
type rule struct {
	name string
	// code is the finding code the rule publishes under; it is also the key of the
	// rule's RuleResult.
	code string
	// title names the check in a sentence: "Port conflicts", "External volumes".
	title string
	// requires names the data the rule cannot decide without, for rules.csv.
	requires string
	eval     func(Input) []model.Finding
	// assess is optional; a rule without it reports no-problem when it published
	// nothing.
	assess func(Input) verdict
}

// rules is the full set. The order here is the order the codes are documented in,
// which is also the order a reader meets them in the report before severity sorting
// takes over.
func rules() []rule {
	return []rule{
		{"port-conflict", "witness.port_conflict", "Port conflicts",
			"the published ports; the listening sockets (ports section); the containers' publications",
			portConflicts, assessPorts},
		{"container-name-conflict", "witness.container_name_conflict", "Fixed container names",
			"container_name of each service; the engine's container list",
			containerNameConflicts, assessContainerNames},
		{"project-ownership", "witness.project_ownership", "Ownership of the existing containers",
			"the engine's containers with their Compose labels; the plan's project, directory and services",
			projectOwnership, assessProjectOwnership},
		{"volume-name-conflict", "witness.volume_name_conflict", "External volumes",
			"the external volumes of the plan; the engine's volume list",
			volumeNameConflicts, assessExternalVolumes},
		{"bind-path-conflict", "witness.bind_path_conflict", "Bind mount sources",
			"the bind mounts of the plan",
			bindPathConflicts, assessBindPaths},
		{"network-name-conflict", "witness.network_name_conflict", "External networks",
			"the external networks of the plan; the engine's network list",
			networkNameConflicts, assessExternalNetworks},
		{"subnet-overlap", "witness.subnet_overlap", "Subnet overlaps",
			"the explicit IPAM subnets of the plan; every engine network's subnets",
			subnetOverlaps, assessSubnets},
		{"memory", "witness.insufficient_memory", "Memory",
			"the memory reservations and limits of the plan; /proc/meminfo",
			memoryShortfall, assessMemory},
		{"disk", "witness.insufficient_disk", "Disk space for image pulls",
			"the images of the plan; the engine's image list; the filesystem of the container store",
			diskShortfall, assessDisk},
		{"inodes", "witness.insufficient_inodes", "Inodes",
			"the filesystem of the container store, with a fixed inode count",
			inodeShortfall, assessInodes},
		{"architecture", "witness.architecture_mismatch", "CPU architecture",
			"uname -m; platform: of each service; the architecture of each image already on the host",
			architectureMismatch, assessArchitecture},
		{"runtime-version", "witness.runtime_missing_or_old", "Container engine and Compose",
			"the engine binary and whether it answers; the Compose implementation",
			runtimeVersion, nil},
		{"registry", "witness.registry_unreachable", "Registry reachability",
			"the registries the plan pulls from; a TCP connect to each (--egress)",
			registryReachability, assessRegistries},
		{"proxy-port", "witness.proxy_conflict", "Web server ports 80/443",
			"ports 80/443 of the plan; the web server's and the control panels' listen ports",
			proxyPortConflict, assessProxyPorts},
		{"domain", "witness.domain_conflict", "Domains",
			"the domains in the services' labels; the web server's server names",
			domainConflict, assessDomains},
		{"database-version", "witness.database_version_mismatch", "Database major versions",
			"the database images and their tags; the databases already on the host",
			databaseVersionMismatch, assessDatabases},
		{"env-file", "witness.env_file_missing", "env_file presence",
			"env_file of each service; whether each file exists",
			missingEnvFiles, assessEnvFiles},
		{"healthcheck", "witness.no_healthcheck", "Healthchecks",
			"healthcheck of each service",
			missingHealthchecks, assessServices},
		{"floating-tag", "witness.floating_image_tag", "Image pinning",
			"the image reference of each pulled service",
			floatingTags, assessPulledImages},
		{"security-flags", "witness.privileged_container", "Host authority",
			"privileged, cap_add, devices, network_mode and socket mounts of each service",
			securityFlags, assessServices},
		{"backup", "witness.backup_gap", "Backups",
			"the persistent data of the plan; backup tools, jobs and directories on the host",
			backupGap, assessBackup},
		{"rollback", "witness.no_rollback_plan", "Rollback plan",
			"the rollback section of this report",
			rollbackGap, nil},
		{"certificate", "witness.certificate_expiring", "Certificate expiry",
			"the TLS certificates found on the host, parsed",
			certificateExpiry, assessCertificates},
		{"reboot", "witness.reboot_required", "Pending reboot",
			"needs-restarting -r or /var/run/reboot-required (system section)",
			rebootPending, assessReboot},
		{"disk-pressure", "witness.disk_at_limit", "Filesystem fill level",
			"capacity of every writable filesystem",
			diskPressure, assessFilesystems},
	}
}

// Result is everything Evaluate concludes.
type Result struct {
	Findings []model.Finding
	Rules    []model.RuleResult
	Changes  []model.ChangeItem
	Rollback []model.RollbackItem
	Notes    []string
}

// Evaluate runs every rule and returns the findings, one outcome per rule, the
// change list and the rollback plan.
//
// It never returns an error. A rule that cannot reach a conclusion produces a
// finding that says so, which is the whole point: the caller has no way to render
// "the engine gave up" usefully, and a report that omits a check silently is the
// one outcome this package exists to prevent.
func Evaluate(in Input) Result {
	if in.Manifest == nil || in.Caps == nil {
		return Result{Notes: []string{
			"witness: nothing to compare — a manifest and the host capabilities are both required",
		}}
	}
	if in.Now.IsZero() {
		in.Now = time.Now().UTC()
	}

	var out Result
	dropped, corrected := 0, 0
	for _, r := range rules() {
		var published []model.Finding
		for _, finding := range r.eval(in) {
			// The one invariant worth spending code on. A finding with no evidence
			// is a defect in a rule, and the honest response is to lose the finding
			// and admit it rather than publish an unbacked claim.
			if len(finding.Evidence) == 0 {
				dropped++
				continue
			}
			if finding.Collector == "" {
				finding.Collector = r.name
			}
			if fixOutcome(&finding) {
				corrected++
			}
			published = append(published, finding)
		}

		result, synthesized := conclude(in, r, published)
		if synthesized != nil {
			published = append(published, *synthesized)
		}
		out.Findings = append(out.Findings, published...)
		out.Rules = append(out.Rules, result)
	}
	if dropped > 0 {
		out.Notes = append(out.Notes, fmt.Sprintf(
			"%d finding(s) were discarded because no evidence was attached to them; this is a bug in deploy-witness, "+
				"not a property of the host", dropped))
	}
	if corrected > 0 {
		out.Notes = append(out.Notes, fmt.Sprintf(
			"%d finding(s) carried a severity their outcome does not allow (a blocker that is not a proven "+
				"problem, or a warning that is not a problem at all) and were downgraded; this is a bug in "+
				"deploy-witness, not a property of the host", corrected))
	}

	sortFindings(out.Findings)
	out.Changes = Changes(in)
	out.Rollback = Rollback(in)
	return out
}

// sortFindings puts the report in the order somebody reads it: worst first, then by
// rule, then by the rule's own ordering, then by subject so two runs of the same
// audit produce the same file.
func sortFindings(findings []model.Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.Severity.Rank() != b.Severity.Rank() {
			return a.Severity.Rank() < b.Severity.Rank()
		}
		if a.Collector != b.Collector {
			return a.Collector < b.Collector
		}
		if a.SortOrder != b.SortOrder {
			return a.SortOrder < b.SortOrder
		}
		return a.Subject < b.Subject
	})
}

// ─────────────────────────────────────────────────────────────── evidence

// maxEvidenceOutput bounds one captured fragment. Long enough to hold the lines
// that matter, short enough that a report stays readable.
const maxEvidenceOutput = 1500

// evidence builds one piece of evidence, truncating honestly.
//
// command is what a reader would run to see the same thing for themselves; it is
// always a command from the published allowlist or a path on disk, never a
// paraphrase. output is what was observed, rendered compactly from the values that
// were parsed.
//
// The evidence is an observation, and it carries the time of that observation: the
// moment its source was read on the host (Capabilities.Observations), not the
// moment the rules compared. A source with no recorded time falls back to the
// comparison time, which is never earlier than the observation.
func evidence(in Input, command, output string) model.Evidence {
	truncated := false
	if len(output) > maxEvidenceOutput {
		output = output[:maxEvidenceOutput]
		truncated = true
	}
	e := model.Evidence{
		Command:    command,
		Output:     output,
		Truncated:  truncated,
		CapturedAt: in.Now.UTC().Format(time.RFC3339),
		Origin:     model.OriginHost,
		Source:     sourceOf(command),
	}
	if strings.HasPrefix(command, "deploy-witness rule ") || strings.HasPrefix(command, "the rollback section") {
		e.Origin = model.OriginRule
	}
	if e.Source != "" && in.Caps != nil {
		if o := in.Caps.Observed(e.Source); o.ObservedAt != "" {
			e.CapturedAt = o.ObservedAt
		}
	}
	return e
}

// sourceOf names the observation source a piece of evidence was read from, from the
// command a reader would run to see the same thing.
func sourceOf(command string) string {
	c := " " + command + " "
	switch {
	case strings.Contains(c, " ps -a ") || strings.Contains(c, " info "):
		return model.SourceContainers
	case strings.Contains(c, " volume "):
		return model.SourceVolumes
	case strings.Contains(c, " network inspect "):
		return model.SourceNetworkSubnets
	case strings.Contains(c, " network "):
		return model.SourceNetworks
	case strings.Contains(c, " image "):
		return model.SourceImages
	case strings.HasPrefix(command, "ss ") || strings.Contains(c, "/proc/net"):
		return model.SourceSockets
	case strings.Contains(c, "/proc/meminfo"):
		return model.SourceMemory
	case strings.Contains(c, "/proc/mounts"):
		return model.SourceFilesystems
	case strings.HasPrefix(command, "uname"):
		return model.SourceArch
	case strings.HasPrefix(command, "nginx") || strings.HasPrefix(command, "apache") || strings.HasPrefix(command, "httpd"):
		return model.SourceProxy
	}
	return ""
}

// manifestEvidence points at the requirement side of a comparison. The manifest is
// the reader's own file, so quoting the path and the service is enough for them to
// find the line.
func manifestEvidence(in Input, service, detail string) model.Evidence {
	path := "docker-compose.yml"
	if in.Manifest != nil && in.Manifest.Path != "" {
		path = in.Manifest.Path
	}
	command := path
	if service != "" {
		command = path + " (service " + service + ")"
	}
	e := evidence(in, command, detail)
	e.Origin, e.Source = model.OriginPlan, ""
	if !in.PlanResolvedAt.IsZero() {
		e.CapturedAt = in.PlanResolvedAt.UTC().Format(time.RFC3339)
	}
	return e
}

// ─────────────────────────────────────────────────────────────── helpers

// sameProject reports whether an existing container, network or volume belongs to
// the deployment being checked. Compose reuses its own resources on purpose, so a
// collision with itself is information, not a conflict.
func sameProject(in Input, project string) bool {
	if in.Project == "" || project == "" {
		return false
	}
	return strings.EqualFold(normaliseProject(in.Project), normaliseProject(project))
}

// normaliseProject applies compose's own name normalisation: lowercase, and
// everything outside [a-z0-9_-] dropped. Without it, a directory called `My App`
// never matches the project label `myapp` and every redeployment reads as a
// conflict.
func normaliseProject(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(name) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_', r == '-':
			b.WriteRune(r)
		}
	}
	return b.String()
}

// humanBytes renders a byte count the way an operator reads one.
func humanBytes(b int64) string {
	if b < 0 {
		return "unknown"
	}
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	value, exp := float64(b), 0
	for value >= unit && exp < 4 {
		value /= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", value, "KMGTP"[exp-1])
}
