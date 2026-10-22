package witness

import (
	"fmt"
	"sort"
	"strings"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
)

// Every rule ends in exactly one outcome, and the outcome is a separate axis from
// the severity:
//
//   - the section Status says whether the comparison ran to completion;
//   - the Outcome says what a rule concluded — problem, no-problem, unknown,
//     manual-check, not-applicable;
//   - the Severity says how much attention a finding deserves.
//
// Two invariants tie them together and are enforced here rather than trusted to
// each rule: only a proven problem can be a blocker, and a finding that concludes
// there is no problem cannot be more than info. A rule that breaks either is
// corrected and the correction is counted as a bug in this tool.

// verdict is what a rule concludes on its own, before its findings are counted.
type verdict struct {
	outcome model.Outcome
	reason  string
	// evidence and todo are used only when the verdict has to be published as a
	// finding of its own — an unknown or a manual check that no finding states.
	evidence []model.Evidence
	todo     string
}

func checked(reason string) verdict { return verdict{outcome: model.OutcomeNoProblem, reason: reason} }

func notApplicable(reason string) verdict {
	return verdict{outcome: model.OutcomeNotApplicable, reason: reason}
}

// undecided is the verdict for a rule whose input was not there. command and output
// are the evidence: where the data should have come from, and what happened.
func undecided(in Input, reason, command, output, todo string) verdict {
	return verdict{
		outcome:  model.OutcomeUnknown,
		reason:   reason,
		evidence: []model.Evidence{evidence(in, command, output)},
		todo:     todo,
	}
}

// fixOutcome fills an empty outcome and enforces the two invariants. It reports
// whether it had to correct a severity, which is a defect in the rule.
func fixOutcome(f *model.Finding) bool {
	if f.Outcome == "" {
		// A rule that forgot to say is read the way the finding has always been
		// read; the tests require every rule to say explicitly.
		f.Outcome = model.OutcomeProblem
		if f.Severity == model.FindingInfo {
			f.Outcome = model.OutcomeNoProblem
		}
	}
	switch {
	case f.Severity == model.FindingBlocker && f.Outcome != model.OutcomeProblem:
		f.Severity = model.FindingWarning
		return true
	case (f.Outcome == model.OutcomeNoProblem || f.Outcome == model.OutcomeNotApplicable) &&
		f.Severity != model.FindingInfo:
		f.Severity = model.FindingInfo
		return true
	}
	return false
}

// conclude derives a rule's result from its findings and its verdict, and builds the
// finding that states an unknown or a manual check nobody else stated — so that what
// a rule could not decide reaches witness.csv and the upload, not only rules.csv.
func conclude(in Input, r rule, findings []model.Finding) (model.RuleResult, *model.Finding) {
	v := checked("checked; nothing in the plan collides with what was observed")
	if r.assess != nil {
		v = r.assess(in)
	}

	outcome := v.outcome
	counts := map[model.Outcome]int{}
	for _, f := range findings {
		counts[f.Outcome]++
		if f.Outcome.Rank() < outcome.Rank() {
			outcome = f.Outcome
		}
	}

	var synthesized *model.Finding
	if (v.outcome == model.OutcomeUnknown || v.outcome == model.OutcomeManualCheck) && counts[v.outcome] == 0 {
		f := verdictFinding(in, r, v)
		synthesized = &f
		counts[v.outcome]++
	}

	result := model.RuleResult{
		Code:     r.code,
		Rule:     r.name,
		Outcome:  outcome,
		Findings: len(findings),
		Requires: r.requires,
		Reason:   v.reason,
	}
	if synthesized != nil {
		result.Findings++
	}
	if len(findings) > 0 {
		summary := fmt.Sprintf("%d finding(s): %s", len(findings), countOutcomes(counts))
		if v.outcome != model.OutcomeNoProblem {
			summary += "; " + v.reason
		}
		result.Reason = summary
	}
	return result, synthesized
}

func countOutcomes(counts map[model.Outcome]int) string {
	var parts []string
	for _, o := range model.Outcomes {
		if counts[o] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[o], o))
		}
	}
	return strings.Join(parts, ", ")
}

func verdictFinding(in Input, r rule, v verdict) model.Finding {
	title := r.title + " could not be decided"
	why := "A check that could not be decided is not a passed check: nothing in this report says the deployment " +
		"is clear on this point, and nothing says it is not."
	todo := v.todo
	if todo == "" {
		todo = "Re-run the audit where the missing data can be read, or settle the question by hand before deploying."
	}
	if v.outcome == model.OutcomeManualCheck {
		title = r.title + " needs a manual check"
		why = "This cannot be established from inside the host, by design. It is listed so that it is checked, " +
			"not so that it is assumed."
	}
	ev := v.evidence
	if len(ev) == 0 {
		ev = []model.Evidence{evidence(in, "deploy-witness rule "+r.code, v.reason)}
	}
	return model.Finding{
		Code:         r.code,
		Collector:    r.name,
		Category:     model.CategoryMissing,
		Severity:     model.FindingInfo,
		Confidence:   model.ConfidenceHigh,
		SortOrder:    1000,
		Title:        title,
		Description:  upperFirst(v.reason) + ".",
		WhyItMatters: why,
		WhatToDo:     todo,
		Evidence:     ev,
		Outcome:      v.outcome,
	}
}

func upperFirst(text string) string {
	text = strings.TrimSuffix(strings.TrimSpace(text), ".")
	if text == "" {
		return text
	}
	return strings.ToUpper(text[:1]) + text[1:]
}

// OutcomeSummary is the one-line account of every rule's outcome that the witness
// row of summary.csv and the upload's witness collector carry: counts first, then
// the codes of everything that is not settled in the deployment's favour. Since
// DW-94 the upload also states each outcome in a field of its own (Finding.outcome
// and one RuleResult per rule), so this line is for the reader, no longer the only
// carrier.
func OutcomeSummary(results []model.RuleResult) string {
	byOutcome := map[model.Outcome][]string{}
	for _, r := range results {
		byOutcome[r.Outcome] = append(byOutcome[r.Outcome], strings.TrimPrefix(r.Code, "witness."))
	}
	var parts []string
	for _, o := range model.Outcomes {
		codes := byOutcome[o]
		if len(codes) == 0 {
			continue
		}
		sort.Strings(codes)
		part := fmt.Sprintf("%d %s", len(codes), o)
		if o != model.OutcomeNoProblem && o != model.OutcomeNotApplicable {
			part += " (" + strings.Join(codes, ", ") + ")"
		}
		parts = append(parts, part)
	}
	return fmt.Sprintf("rule outcomes: %d rules — %s", len(results), strings.Join(parts, "; "))
}

// ─────────────────────────────────────────────────────────── data requirements

// engineList says whether one of the engine's lists can prove that something is
// absent. It can when it was read in full, and when there is no engine at all —
// nothing can exist in an engine that is not installed. A list that was not read,
// or read in part, proves presence and never absence.
func engineList(in Input, source string) (bool, string) {
	if in.Caps.Runtime == nil {
		return true, "no container engine is installed"
	}
	o := in.Caps.Observed(source)
	if o.State == model.ObservedComplete {
		return true, o.Note
	}
	why := o.Note
	if why == "" {
		why = "the engine's " + source + " were not listed"
	}
	return false, why
}

func engineCommand(in Input, args string) string {
	kind := "docker"
	if in.Caps.Runtime != nil && in.Caps.Runtime.Kind != "" {
		kind = in.Caps.Runtime.Kind
	}
	return kind + " " + args
}

const engineTodo = "Re-run the audit as a user who can reach the container engine (root, or a member of the " +
	"docker group), or check by hand before deploying."

// ─────────────────────────────────────────────────────────── the verdicts

func publishedPorts(in Input) int {
	n := 0
	for _, svc := range in.Manifest.Services {
		for _, mapping := range svc.Ports {
			n += len(mapping.HostPorts())
		}
	}
	return n
}

func assessPorts(in Input) verdict {
	if publishedPorts(in) == 0 {
		return notApplicable("the plan publishes no host port")
	}
	if in.PortsUnchecked {
		return undecided(in, "the ports section was not selected, so the listening sockets were not read and "+
			"no published port could be checked against them",
			"/proc/net/tcp, /proc/net/tcp6, /proc/net/udp, /proc/net/udp6", "not read on this run",
			"Re-run with the ports section selected (it is by default).")
	}
	if o := in.Caps.Observed(model.SourceSockets); o.State == model.ObservedFailed {
		return undecided(in, "the listening sockets could not be read: "+o.Note,
			"/proc/net/tcp, /proc/net/tcp6, /proc/net/udp, /proc/net/udp6", o.Note,
			"Re-run on the host itself, as root, so the socket tables are readable.")
	}
	return checked(fmt.Sprintf("%d published binding(s) were compared with the listening sockets and the "+
		"containers' publications", publishedPorts(in)))
}

func assessContainerNames(in Input) verdict {
	var fixed []string
	for _, svc := range in.Manifest.Services {
		if svc.ContainerName != "" {
			fixed = append(fixed, svc.ContainerName)
		}
	}
	if len(fixed) == 0 {
		return notApplicable("no service sets container_name; Compose names the containers after the project")
	}
	if ok, why := engineList(in, model.SourceContainers); !ok {
		return undecided(in, "the existing containers could not be listed ("+why+"), so whether "+
			strings.Join(fixed, ", ")+" is taken is unknown",
			engineCommand(in, "ps -a --format {{json .}}"), why, engineTodo)
	}
	return checked("no existing container is named " + strings.Join(fixed, ", "))
}

func assessExternalVolumes(in Input) verdict {
	used := mountedVolumes(in)
	var external, created []string
	for _, v := range in.Manifest.Volumes {
		if !used[v.Name] {
			continue
		}
		name := engineNameOf(v.EngineName, v.Name)
		if v.External {
			external = append(external, name)
		} else {
			created = append(created, name)
		}
	}
	if len(external)+len(created) == 0 {
		return notApplicable("the plan mounts no named volume")
	}
	if len(external) == 0 {
		if listed, why := engineList(in, model.SourceVolumes); !listed {
			return undecided(in, "the engine's volumes could not be listed ("+why+"), so whether "+
				strings.Join(created, ", ")+" already exist — created by someone else — is unknown",
				engineCommand(in, "volume ls --format {{json .}}"), why, engineTodo)
		}
	}
	reason := "every external volume (" + strings.Join(external, ", ") + ") exists"
	if len(created) > 0 {
		reason = strings.Join(created, ", ") + " are created by Compose or already this project's"
		if len(external) > 0 {
			reason += "; every external volume (" + strings.Join(external, ", ") + ") exists"
		}
	}
	return checked(reason)
}

func assessBindPaths(in Input) verdict {
	binds := 0
	for _, svc := range in.Manifest.Services {
		for _, mount := range svc.Volumes {
			if mount.Kind == model.MountBind {
				binds++
			}
		}
	}
	if binds == 0 {
		return notApplicable("the plan declares no bind mount")
	}
	if o := in.Caps.Observed(model.SourceBindSources); o.State == model.ObservedNotCollected || o.State == model.ObservedFailed {
		return undecided(in, "the bind mount sources were not examined on this host", "stat <source>",
			orUnknown(o.Note), "Re-run the audit on the host itself.")
	}
	return checked(fmt.Sprintf("%d bind mount(s): no source is a sensitive host path, every source exists or is "+
		"created by the engine, and none is denied to the container user by its mode bits — access itself is not "+
		"proven: ACLs, user namespaces and SELinux are not read", binds))
}

func assessExternalNetworks(in Input) verdict {
	var external, created []string
	for _, n := range in.Manifest.Networks {
		name := engineNameOf(n.EngineName, n.Name)
		if n.External {
			external = append(external, name)
		} else {
			created = append(created, name)
		}
	}
	if len(external)+len(created) == 0 {
		return notApplicable("the plan declares no network")
	}
	if len(external) == 0 {
		if listed, why := engineList(in, model.SourceNetworks); !listed {
			return undecided(in, "the engine's networks could not be listed ("+why+"), so whether "+
				strings.Join(created, ", ")+" already exist — created by someone else — is unknown",
				engineCommand(in, "network ls --format {{json .}}"), why, engineTodo)
		}
	}
	reason := "every external network (" + strings.Join(external, ", ") + ") exists and can be joined"
	if len(created) > 0 {
		reason = strings.Join(created, ", ") + " are created by Compose or already this project's"
		if len(external) > 0 {
			reason += "; every external network (" + strings.Join(external, ", ") + ") exists and can be joined"
		}
	}
	return checked(reason)
}

func assessSubnets(in Input) verdict {
	var subnets []string
	for _, n := range in.Manifest.Networks {
		subnets = append(subnets, n.Subnets...)
	}
	if len(subnets) == 0 {
		return notApplicable("the plan sets no explicit subnet; the engine allocates a free range itself")
	}
	if ok, why := engineList(in, model.SourceNetworks); !ok {
		return undecided(in, "the engine's networks could not be listed ("+why+"), so whether "+
			strings.Join(subnets, ", ")+" overlaps one is unknown",
			engineCommand(in, "network ls --format {{json .}}"), why, engineTodo)
	}
	if in.Caps.Runtime != nil {
		if o := in.Caps.Observed(model.SourceNetworkSubnets); o.State != model.ObservedComplete {
			return undecided(in, "the subnets of some engine networks are unknown ("+o.Note+"), so an overlap "+
				"with "+strings.Join(subnets, ", ")+" cannot be ruled out",
				engineCommand(in, "network inspect <network>"), o.Note, engineTodo)
		}
	}
	return checked(strings.Join(subnets, ", ") + " overlaps no subnet of an existing network")
}

func assessMemory(in Input) verdict {
	for _, svc := range in.Manifest.Services {
		if svc.MemReservationBytes > 0 || svc.MemLimitBytes > 0 {
			return checked("the declared reservations and limits fit in the available memory")
		}
	}
	return notApplicable("no service declares a memory reservation or limit")
}

func assessDisk(in Input) verdict {
	if _, ok := deploymentFilesystem(in); !ok {
		return verdict{outcome: model.OutcomeUnknown, reason: "no filesystem capacity was collected"}
	}
	if ok, why := engineList(in, model.SourceImages); !ok {
		return undecided(in, "the images already on the host could not be listed ("+why+"), so which images "+
			"still have to be pulled is unknown", engineCommand(in, "image ls"), why, engineTodo)
	}
	return checked("the filesystem of the container store has at least the minimum pull headroom, or nothing " +
		"has to be pulled")
}

func assessInodes(in Input) verdict {
	target, ok := deploymentFilesystem(in)
	if !ok {
		return undecided(in, "no filesystem capacity was collected, so the inodes of the container store are "+
			"unknown", "/proc/mounts + statfs", "no filesystem could be measured",
			"Re-run the audit on the host itself.")
	}
	if target.InodesTotal == 0 {
		return notApplicable(target.Mount + " (" + target.FSType + ") has no fixed inode count, so it cannot run " +
			"out of inodes")
	}
	return checked(target.Mount + " has inodes to spare")
}

func assessFilesystems(in Input) verdict {
	if len(in.Caps.Filesystems) == 0 {
		return undecided(in, "no filesystem capacity was collected", "/proc/mounts + statfs",
			"no filesystem could be measured", "Re-run the audit on the host itself.")
	}
	return checked(fmt.Sprintf("%d filesystem(s) measured, none above %.0f%%", len(in.Caps.Filesystems),
		diskPressureWarn))
}

func assessArchitecture(in Input) verdict {
	if normaliseArch(in.Caps.Arch) == "" {
		return undecided(in, "the host's CPU architecture could not be read", "uname -m", "no answer",
			"Re-run the audit on the host itself.")
	}
	present := map[string]bool{}
	for _, image := range in.Caps.Images {
		present[image.Reference] = image.Architecture != ""
	}
	listed, why := engineList(in, model.SourceImages)
	var pending []string
	for _, svc := range in.Manifest.Services {
		if svc.Build != "" || svc.Platform != "" || svc.Image.Raw == "" {
			continue
		}
		if !present[svc.Image.Raw] {
			pending = append(pending, svc.Image.Raw)
		}
	}
	if len(pending) > 0 {
		reason := fmt.Sprintf("the architecture of %s is not known on this host yet — the image is not here "+
			"(or not inspected), and which platforms a registry offers cannot be seen offline; the engine "+
			"decides at pull time", strings.Join(pending, ", "))
		if !listed {
			reason = fmt.Sprintf("the images already on the host could not be listed (%s), so the architecture "+
				"of %s is unknown", why, strings.Join(pending, ", "))
		}
		return undecided(in, reason, engineCommand(in, "image inspect <image>"),
			"not present or not inspected: "+strings.Join(pending, ", "),
			"Pull the images before deploying (`docker compose pull`) and re-run, or confirm each one publishes "+
				"a variant for "+normaliseArch(in.Caps.Arch)+".")
	}
	return checked("every pinned platform and every image present matches " + normaliseArch(in.Caps.Arch))
}

func pulledImages(in Input) []string {
	var out []string
	for _, svc := range in.Manifest.Services {
		if svc.Build == "" && svc.Image.Raw != "" {
			out = append(out, svc.Image.Raw)
		}
	}
	return out
}

func assessRegistries(in Input) verdict {
	if len(pulledImages(in)) == 0 {
		return notApplicable("every service is built locally; nothing is pulled")
	}
	return checked("every registry the plan pulls from answered a TCP connect (--egress)")
}

func assessProxyPorts(in Input) verdict {
	web := false
	for _, svc := range in.Manifest.Services {
		for _, mapping := range svc.Ports {
			for _, port := range mapping.HostPorts() {
				if port == 80 || port == 443 {
					web = true
				}
			}
		}
	}
	if !web {
		return notApplicable("the plan publishes neither 80 nor 443")
	}
	if o := in.Caps.Observed(model.SourceProxy); o.State == model.ObservedFailed {
		return undecided(in, "the web server's configuration could not be read ("+o.Note+"), so its listen "+
			"ports are unknown", "nginx -T / apachectl -S", o.Note,
			"Re-run the audit as root, which can read the web server's configuration.")
	}
	return checked("no web server or control panel on this host listens on the published 80/443")
}

func assessDomains(in Input) verdict {
	var domains []string
	for _, svc := range in.Manifest.Services {
		domains = append(domains, serviceDomains(svc)...)
	}
	if len(domains) == 0 {
		return notApplicable("no service names a domain in its labels (Traefik Host() rules, VIRTUAL_HOST)")
	}
	if in.Caps.Proxy == nil {
		return checked("no web server is installed, so no existing vhost can claim " + strings.Join(domains, ", "))
	}
	if o := in.Caps.Observed(model.SourceProxy); o.State == model.ObservedFailed {
		return undecided(in, "the web server's configuration could not be read ("+o.Note+"), so whether it "+
			"already serves "+strings.Join(domains, ", ")+" is unknown", "nginx -T / apachectl -S", o.Note,
			"Re-run the audit as root, which can read the web server's configuration.")
	}
	return checked("no existing vhost serves " + strings.Join(domains, ", "))
}

func assessDatabases(in Input) verdict {
	var unversioned []string
	databases := 0
	for _, svc := range in.Manifest.Services {
		kind := databaseKindOfImage(svc.Image)
		if kind == "" {
			continue
		}
		databases++
		if majorVersion(svc.Image.Tag) != "" {
			continue
		}
		for _, db := range in.Caps.Databases {
			if db.Kind == kind {
				unversioned = append(unversioned, svc.Name)
				break
			}
		}
	}
	if databases == 0 {
		return notApplicable("the plan runs no recognised database image")
	}
	if len(unversioned) > 0 {
		return undecided(in, "the image tag of "+strings.Join(unversioned, ", ")+" names no major version, so "+
			"it cannot be compared with the database already on this host",
			"the image tag", "no numeric major version in the tag",
			"Pin the database image to a major version (postgres:16, not postgres:latest).")
	}
	return checked("no database image disagrees with the major version of a database already on this host")
}

func assessEnvFiles(in Input) verdict {
	for _, svc := range in.Manifest.Services {
		if len(svc.EnvFiles) > 0 {
			return checked("every env_file exists")
		}
	}
	return notApplicable("no service reads an env_file")
}

func assessServices(in Input) verdict {
	if len(in.Manifest.Services) == 0 {
		return notApplicable("the plan declares no service")
	}
	return checked(fmt.Sprintf("all %d service(s) checked", len(in.Manifest.Services)))
}

func assessPulledImages(in Input) verdict {
	if len(pulledImages(in)) == 0 {
		return notApplicable("every service is built locally; no image reference is pulled")
	}
	return checked("every pulled image is pinned by digest")
}

func assessBackup(in Input) verdict {
	if !hasPersistentData(in.Manifest) {
		return notApplicable("the plan declares no persistent data")
	}
	backup := in.Caps.Backup
	if len(backup.Locations) == 0 && len(backup.Tools) > 0 {
		// A tool and no local directory: it may well write to a remote repository,
		// which is invisible from here. Neither "covered" nor "not covered" is shown.
		return verdict{
			outcome: model.OutcomeManualCheck,
			reason: "backup tooling is installed (" + strings.Join(backup.Tools, ", ") + ") but no backup " +
				"directory exists on this host; a job writing to a remote repository is not visible from here, so " +
				"whether it covers " + strings.Join(persistentData(in.Manifest), ", ") + " is unknown",
			evidence: []model.Evidence{evidence(in, "PATH lookup of restic, borg, duplicity, rsnapshot; stat /backup /var/backups",
				"tools: "+strings.Join(backup.Tools, ", ")+"; no backup directory found"+noteSuffix(backup.Note))},
			todo: "Confirm a backup job includes the deployment's volumes and bind mounts, and when it last succeeded.",
		}
	}
	return checked("a backup location written to within the last " + fmt.Sprint(backupStaleDays) + " days exists")
}

func assessCertificates(in Input) verdict {
	var unreadable []string
	for _, cert := range in.Caps.Certificates {
		if cert.NotAfter == "" {
			unreadable = append(unreadable, cert.Path)
		}
	}
	if len(unreadable) > 0 {
		return undecided(in, fmt.Sprintf("%d certificate file(s) could not be parsed, so their expiry is "+
			"unknown: %s", len(unreadable), strings.Join(unreadable, ", ")),
			"x509 parse of each certificate", strings.Join(unreadable, "\n"),
			"Check those files by hand: `openssl x509 -noout -enddate -in <file>`.")
	}
	if len(in.Caps.Certificates) == 0 {
		return checked("no TLS certificate was found on this host")
	}
	return checked(fmt.Sprintf("%d certificate(s), none expiring within %d days", len(in.Caps.Certificates),
		certificateExpiryWarnDays))
}

func assessReboot(in Input) verdict {
	switch in.Caps.RebootRequired {
	case "yes":
		return checked("a reboot is pending")
	case "no":
		return checked("no reboot is pending")
	}
	return undecided(in, "whether a reboot is pending could not be established (no needs-restarting, no "+
		"/var/run/reboot-required on this distribution, or the system section was not selected)",
		"needs-restarting -r / /var/run/reboot-required", "no answer",
		"Compare the running kernel (`uname -r`) with the newest installed one by hand.")
}
