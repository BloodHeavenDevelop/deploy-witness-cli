// Package audit orchestrates the collectors and assembles the report.
package audit

import (
	"fmt"
	"os"
	"time"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/collect/manifest"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/collect/ports"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/collect/services"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/collect/system"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/config"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/logging"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/pkgmgr"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/run"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/vuln"
)

// Auditor holds everything the sections share.
type Auditor struct {
	cfg     *config.Config
	log     *logging.Logger
	version string
	runner  *run.Runner

	os      model.OSRelease
	manager pkgmgr.Manager

	// packages is the installed inventory, read once. The updates and
	// vulnerability sections both need it, and on a host with 3000 packages
	// reading it twice is the single most expensive thing the tool would do.
	packages     []pkgmgr.Package
	packagesRead bool

	// manifest is the Compose file of a preflight, parsed by Prepare before any
	// section runs; parseNotes holds what the parser degraded on, for the witness
	// section to carry.
	manifest   *model.Manifest
	parseNotes model.SectionResult

	// What the network paths actually did, for network.csv: requests sent to the
	// OSV API, and the host:port of every registry --egress dialled.
	osvRequests   int
	egressTargets []string
}

// New prepares an audit.
func New(cfg *config.Config, log *logging.Logger, version string) *Auditor {
	runner := run.New(cfg.Timeout)
	// The child programs that fetch advisory data themselves (debsecan,
	// arch-audit) are part of the --online path, and only of it.
	runner.AllowNetwork(cfg.Online)
	return &Auditor{
		cfg:     cfg,
		log:     log,
		version: version,
		runner:  runner,
	}
}

// Prepare checks the input of a Compose preflight before anything is collected.
//
// A Compose file that cannot be read or parsed is a usage error, returned here so
// the run stops before the first section: an audit that ran for minutes and then
// reported a failed comparison would be a report with no preflight in it, and that
// is the one shape a missing preflight must never take. A host audit has no input,
// and Prepare does nothing.
func (a *Auditor) Prepare() error {
	if a.cfg.Mode != model.ModeComposePreflight {
		return nil
	}
	a.parseNotes = model.SectionResult{Section: model.SectionWitness, Status: model.StatusOk}
	parsed, err := manifest.Parse(a.cfg.Compose, &a.parseNotes)
	if err != nil {
		return fmt.Errorf("the Compose preflight cannot start, the Compose file could not be parsed: %w", err)
	}
	a.manifest = parsed
	return nil
}

// Run executes every selected section. It returns a report even when sections
// fail — a partial audit is still worth reading, and summary.csv says exactly
// which parts are missing.
func (a *Auditor) Run() *model.Report {
	hostname, _ := os.Hostname()

	report := &model.Report{
		GeneratedAt: time.Now().UTC(),
		Hostname:    hostname,
		Tool:        "deploy-witness",
		Version:     a.version,
		Mode:        a.cfg.Mode,
	}

	switch a.cfg.Mode {
	case model.ModeComposePreflight:
		a.log.Info(fmt.Sprintf("mode: %s of %s", a.cfg.Mode.Label(), a.cfg.Compose))
	default:
		a.log.Info(fmt.Sprintf("mode: %s — no --compose was given, so no planned deployment is compared "+
			"with this host and the witness section is not run", a.cfg.Mode.Label()))
	}

	osrel, err := model.ReadOSRelease()
	if err != nil {
		a.log.Warn("could not read os-release: ", err)
	}
	a.os = osrel

	manager, err := pkgmgr.Detect(osrel, a.runner)
	if err != nil {
		a.log.Warn("package manager detection failed: ", err)
	} else {
		a.manager = manager
		a.log.Info("package manager: ", manager.Name())
	}

	for _, section := range a.cfg.Sections {
		result := model.SectionResult{Section: section, Status: model.StatusOk}
		started := time.Now()

		switch section {
		case model.SectionSystem:
			report.System = system.Collect(a.runner, a.os, a.manager, &result)
			result.Records = len(report.System)
		case model.SectionUpdates:
			report.Updates = a.updates(&result)
			result.Records = len(report.Updates)
		case model.SectionVulnerabilities:
			report.Vulnerabilities = a.vulnerabilities(&result)
			result.Records = len(report.Vulnerabilities)
			result.Critical, result.High = gradeCounts(report.Vulnerabilities)
		case model.SectionPorts:
			report.Ports = ports.Collect(a.runner, &result)
			result.Records = len(report.Ports)
			a.noteExposure(report.Ports, &result)
		case model.SectionServices:
			report.Services = services.Collect(a.runner, a.cfg.ServicesAll, &result)
			result.Records = len(report.Services)
		case model.SectionWitness:
			a.witnessSection(report, &result)
			result.Records = len(report.Findings)
			result.Critical, result.High = findingCounts(report.Findings)
		}

		result.Duration = time.Since(started).Round(time.Millisecond).String()
		report.Sections = append(report.Sections, result)
		a.log.Info(fmt.Sprintf("section %s: %s, %d rows in %s",
			section, result.Status, result.Records, result.Duration))
	}

	// A host audit still carries a witness row, marked skipped and labelled as a host
	// audit, in summary.csv, report.json and the upload alike. Leaving the row out
	// would make the upload a collector list with nothing missing and no findings —
	// which a receiver cannot tell from a preflight that found nothing wrong.
	if a.cfg.Mode == model.ModeHostAudit {
		report.Sections = append(report.Sections, HostAuditWitness())
		a.log.Info("host audit finished: no Compose preflight was run, so nothing in this report says " +
			"whether a deployment fits this host")
	}

	report.Commands = journal(a.runner)
	report.Network = a.networkRecord(report.Commands)
	if refused := refusedCommands(report.Commands); refused > 0 {
		// A refusal means a collector asked for something the published allowlist
		// does not cover: a defect in this tool. It is stated at error level and in
		// the report, because a client comparing the journal against the published
		// list must not be the first to notice.
		a.log.Error(fmt.Sprintf(
			"%d command(s) were refused by the allowlist; see commands.csv — this is a bug in deploy-witness", refused))
	}

	return report
}

// journal converts the runner's record into report rows.
func journal(runner *run.Runner) []model.CommandRun {
	entries := runner.Journal()
	out := make([]model.CommandRun, 0, len(entries))
	for _, e := range entries {
		out = append(out, model.CommandRun{
			Command:   e.Command,
			StartedAt: e.StartedAt.Format("2006-01-02 15:04:05"),
			Duration:  e.Duration,
			ExitCode:  e.ExitCode,
			Outcome:   e.Outcome,
			Network:   e.Network,
		})
	}
	return out
}

func refusedCommands(list []model.CommandRun) int {
	refused := 0
	for _, c := range list {
		if c.Outcome == run.OutcomeRefused {
			refused++
		}
	}
	return refused
}

func (a *Auditor) updates(result *model.SectionResult) []model.Update {
	if a.manager == nil {
		result.Fail("no supported package manager was detected")
		return nil
	}

	updates, err := a.manager.Updates()
	if err != nil {
		result.Degrade(fmt.Sprintf("%s: %v", a.manager.Name(), err))
	}

	security := 0
	for _, u := range updates {
		if u.Security {
			security++
		}
	}
	if security > 0 {
		result.Note(fmt.Sprintf("%d of %d pending updates come from a security channel", security, len(updates)))
	}
	result.Note("read from metadata already on disk; no repository refresh was performed")
	return updates
}

func (a *Auditor) vulnerabilities(result *model.SectionResult) []model.Vulnerability {
	if a.manager == nil {
		result.Fail("no supported package manager was detected")
		return nil
	}

	packages, err := a.installed()
	if err != nil {
		result.Fail(fmt.Sprintf("could not list installed packages: %v", err))
		return nil
	}

	return vuln.Collect(a.manager, packages, vuln.Options{
		Ecosystem:   a.cfg.Ecosystem,
		VulnDB:      a.cfg.VulnDB,
		Online:      a.cfg.Online,
		OSVEndpoint: a.cfg.OSVEndpoint,
		MaxLookups:  a.cfg.MaxOSVQuery,
		MinSeverity: a.cfg.MinSeverity,
		Timeout:     a.cfg.Timeout,
		UserAgent:   "deploy-witness/" + a.version,
		Requests:    &a.osvRequests,
	}, result)
}

func (a *Auditor) installed() ([]pkgmgr.Package, error) {
	if a.packagesRead {
		return a.packages, nil
	}
	packages, err := a.manager.Installed()
	if err != nil {
		return nil, err
	}
	a.packages, a.packagesRead = packages, true
	return packages, nil
}

// noteExposure surfaces the one thing a reader wants from the ports table before
// reading it: how much of it faces the network.
func (a *Auditor) noteExposure(list []model.Port, result *model.SectionResult) {
	exposed := 0
	for _, p := range list {
		if p.Exposure == model.ExposureAll {
			exposed++
		}
	}
	if exposed > 0 {
		result.Note(fmt.Sprintf("%d of %d listening sockets are bound to all interfaces", exposed, len(list)))
	}
}

func gradeCounts(list []model.Vulnerability) (critical, high int) {
	for _, v := range list {
		switch v.Severity {
		case model.SeverityCritical:
			critical++
		case model.SeverityHigh:
			high++
		}
	}
	return critical, high
}
