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
}

// rule is one check. Rules never observe and never mutate their input.
type rule struct {
	name string
	eval func(Input) []model.Finding
}

// rules is the full set. The order here is the order the codes are documented in,
// which is also the order a reader meets them in the report before severity sorting
// takes over.
func rules() []rule {
	return []rule{
		{"port-conflict", portConflicts},
		{"container-name-conflict", containerNameConflicts},
		{"volume-name-conflict", volumeNameConflicts},
		{"bind-path-conflict", bindPathConflicts},
		{"network-name-conflict", networkNameConflicts},
		{"subnet-overlap", subnetOverlaps},
		{"memory", memoryShortfall},
		{"disk", diskShortfall},
		{"inodes", inodeShortfall},
		{"architecture", architectureMismatch},
		{"runtime-version", runtimeVersion},
		{"registry", registryReachability},
		{"proxy-port", proxyPortConflict},
		{"domain", domainConflict},
		{"database-version", databaseVersionMismatch},
		{"env-file", missingEnvFiles},
		{"healthcheck", missingHealthchecks},
		{"floating-tag", floatingTags},
		{"security-flags", securityFlags},
		{"backup", backupGap},
		{"rollback", rollbackGap},
		{"certificate", certificateExpiry},
		{"reboot", rebootPending},
		{"disk-pressure", diskPressure},
	}
}

// Evaluate runs every rule and returns the findings, the change list and the
// rollback plan.
//
// It never returns an error. A rule that cannot reach a conclusion produces a
// finding that says so, which is the whole point: the caller has no way to render
// "the engine gave up" usefully, and a report that omits a check silently is the
// one outcome this package exists to prevent.
func Evaluate(in Input) (findings []model.Finding, changes []model.ChangeItem, rollback []model.RollbackItem, notes []string) {
	if in.Manifest == nil || in.Caps == nil {
		return nil, nil, nil, []string{
			"witness: nothing to compare — a manifest and the host capabilities are both required",
		}
	}
	if in.Now.IsZero() {
		in.Now = time.Now().UTC()
	}

	dropped := 0
	for _, r := range rules() {
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
			findings = append(findings, finding)
		}
	}
	if dropped > 0 {
		notes = append(notes, fmt.Sprintf(
			"%d finding(s) were discarded because no evidence was attached to them; this is a bug in deploy-witness, "+
				"not a property of the host", dropped))
	}

	sortFindings(findings)
	changes = Changes(in)
	rollback = Rollback(in)
	return findings, changes, rollback, notes
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
func evidence(in Input, command, output string) model.Evidence {
	truncated := false
	if len(output) > maxEvidenceOutput {
		output = output[:maxEvidenceOutput]
		truncated = true
	}
	return model.Evidence{
		Command:    command,
		Output:     output,
		Truncated:  truncated,
		CapturedAt: in.Now.UTC().Format(time.RFC3339),
	}
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
	return evidence(in, command, detail)
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
