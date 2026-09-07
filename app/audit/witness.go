package audit

import (
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"time"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/collect/backup"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/collect/certs"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/collect/docker"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/collect/host"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/collect/manifest"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/collect/panels"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/collect/proxy"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/collect/scheduler"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/witness"
)

// witnessSection compares the deployment manifest against this host.
//
// It is the only section that needs an input, and the only one that reads what the
// sections before it collected: the listening sockets and the service units are
// already in the report, and gathering them a second time would be both slower and
// capable of disagreeing with itself.
func (a *Auditor) witnessSection(report *model.Report, result *model.SectionResult) {
	if a.cfg.Compose == "" {
		result.Status = model.StatusSkipped
		result.Note("no --compose was given, so there was no deployment to compare this host against; " +
			"everything else in this report still applies")
		return
	}

	parsed, err := manifest.Parse(a.cfg.Compose, result)
	if err != nil {
		result.Fail(fmt.Sprintf("could not read %s: %v", a.cfg.Compose, err))
		return
	}
	report.Manifest = parsed

	caps := &model.Capabilities{
		Ports:          report.Ports,
		Services:       report.Services,
		RebootRequired: rebootRequired(report),
	}

	// A witness run that was given no ports section is missing the single most
	// useful input it has, and the report says so rather than producing a conflict
	// list that looks reassuringly short.
	if !a.cfg.Wants(model.SectionPorts) {
		result.Degrade("the ports section was not selected, so port conflicts could not be checked")
	}

	// The order is a dependency order, not a preference. panels reads the service
	// units, scheduler fills the job inventory that certs needs to tell an installed
	// renewal tool from a renewal that actually runs, and Databases reads the ports.
	// Each of these degrades honestly on an empty input, but the report is worth more
	// when they are given one.
	host.Collect(a.runner, caps, result)
	docker.Collect(a.runner, caps, result)
	proxy.Collect(a.runner, caps, result)
	panels.Collect(a.runner, caps, result)
	scheduler.Collect(a.runner, caps, result)
	certs.Collect(a.runner, caps, result)
	backup.Collect(a.runner, caps, result)
	caps.Databases = host.Databases(caps, result)

	report.Capabilities = caps

	in := witness.Input{
		Manifest: parsed,
		Caps:     caps,
		Now:      time.Now().UTC(),
		Project:  projectName(a.cfg.Compose),
	}
	if a.cfg.Egress {
		in.EgressChecked = true
		in.RegistryResults = a.checkRegistries(parsed, result)
	}

	findings, changes, rollback, notes := witness.Evaluate(in)
	report.Findings = findings
	report.Changes = changes
	report.Rollback = rollback
	for _, note := range notes {
		result.Degrade(note)
	}
}

// projectName is the Compose project the deployment will use: the name of the
// directory holding the manifest, which is Compose's own default. Getting this
// wrong turns every redeployment into a wall of false conflicts with itself, so it
// is derived rather than guessed.
func projectName(composePath string) string {
	return filepath.Base(filepath.Dir(composePath))
}

// rebootRequired reads the answer the system section already established, rather
// than probing again. "unknown" is a real answer and is carried through as one.
//
// The value is normalised to its first word. On Debian and Ubuntu the system
// collector writes `yes (linux-image-generic, libssl3)` — the packages that asked
// for the reboot, which is useful in that table and fatal here: the rule downstream
// compares against "yes", so the finding silently never fired on the whole apt
// family while working fine wherever the answer came from `needs-restarting -r`.
// Comparing prefixes rather than requiring an exact match is what keeps that from
// happening again the next time somebody enriches the fact.
func rebootRequired(report *model.Report) string {
	for _, fact := range report.System {
		if fact.Category == "updates" && fact.Key == "reboot-required" {
			if word, _, found := strings.Cut(fact.Value, " "); found {
				return word
			}
			return fact.Value
		}
	}
	return "unknown"
}

// registryProbeTimeout bounds the one outbound check this tool performs.
const registryProbeTimeout = 5 * time.Second

// checkRegistries tests whether the registries the manifest pulls from can be
// reached. It runs only behind --egress.
//
// A TCP connect to port 443 and nothing more: no TLS handshake, no HTTP request, no
// authentication, no image manifest fetched. The question is whether this host's
// egress reaches the registry at all, and a connect answers it without sending
// anybody a single byte about what is being deployed here.
func (a *Auditor) checkRegistries(parsed *model.Manifest, result *model.SectionResult) map[string]string {
	out := map[string]string{}

	for _, svc := range parsed.Services {
		if svc.Build != "" || svc.Image.Raw == "" {
			continue
		}
		registry := svc.Image.Registry
		if registry == "" {
			registry = "docker.io"
		}
		if _, done := out[registry]; done {
			continue
		}

		address := registry
		if _, _, err := net.SplitHostPort(registry); err != nil {
			address = net.JoinHostPort(registry, "443")
		}

		a.log.Info("--egress: testing reachability of ", address)
		conn, err := net.DialTimeout("tcp", address, registryProbeTimeout)
		if err != nil {
			out[registry] = err.Error()
			continue
		}
		_ = conn.Close()
		out[registry] = ""
	}

	if len(out) > 0 {
		result.Note(fmt.Sprintf("--egress was given, so %d registry host(s) were contacted with a TCP connect "+
			"on port 443; nothing was sent and no image was fetched", len(out)))
	}
	return out
}

// findingCounts maps the witness severities onto the summary's two counters, so
// that a reader scanning summary.csv sees the blockers without opening the section.
func findingCounts(findings []model.Finding) (blockers, warnings int) {
	for _, f := range findings {
		switch f.Severity {
		case model.FindingBlocker:
			blockers++
		case model.FindingWarning:
			warnings++
		}
	}
	return blockers, warnings
}
