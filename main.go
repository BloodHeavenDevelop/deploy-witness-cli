// Command deploy-witness audits the machine it runs on and writes a CSV report.
//
// It is offline by default: everything it reads comes from the kernel, /etc and
// package metadata already on disk. Three network paths exist, each enabled only by
// a flag typed on the command line: --online (the OSV API, plus debsecan or
// arch-audit, which download their own advisory data), --egress (one TCP connect per
// registry in --compose) and --upload (one POST of the report). Their recipients
// are printed before the audit starts and recorded in network.csv; see
// app/netpath and docs/<lang>/04-cli-reference.md.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/audit"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/config"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/logging"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/netpath"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/redact"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/report"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/run"
)

// version is stamped at build time by the Makefile, which reads the newest heading
// in CHANGELOG.md: go build -ldflags "-X main.version=x.y.z".
//
// The default is "dev" rather than a version number. A hardcoded number here goes
// stale the moment a release is cut, and it does not go stale quietly: it is printed
// by --version and --commands and it is what an uploaded report names as its
// producer, so a `go run .` build would attribute its findings to a release it is
// not.
var version = "dev"

// Exit codes. They are part of the interface — a scheduled run is read by its
// exit status before anyone opens the CSV.
const (
	exitOK          = 0 // the report was written; sections may still carry notes
	exitSectionFail = 1 // the report was written but at least one section failed
	exitUsage       = 2 // bad arguments, or the report could not be written
	exitUploadFail  = 3 // the report was written but --upload could not deliver it
	exitRecheck     = 4 // --recheck: the report does not confirm this plan on this engine now
)

func main() {
	os.Exit(mainWithCode())
}

func mainWithCode() int {
	return runCLI(os.Args[1:], os.Stdout, os.Stderr)
}

// runCLI is the whole program with its arguments and streams passed in, so the
// tests can drive it end to end — exit code, log and files written — as a user would.
func runCLI(args []string, stdout, stderr io.Writer) int {
	cfg, err := config.Load(args, version, stderr)
	switch {
	case errors.Is(err, flag.ErrHelp):
		return exitOK
	case err != nil:
		fmt.Fprintln(stderr, "deploy-witness:", err)
		return exitUsage
	}

	if cfg.ShowVersion {
		fmt.Fprintln(stdout, "deploy-witness", version)
		return exitOK
	}

	if cfg.ShowCommands {
		printCommands(stdout)
		return exitOK
	}

	// Every diagnostic goes to stderr, so --stdout yields a CSV stream a pipe can
	// consume unmodified.
	log := logging.New(stderr, cfg.LogLevel)

	for _, name := range cfg.IgnoredEnv {
		log.Warn(name + " is set in the environment and ignored: network paths are enabled only by a flag " +
			"typed on the command line")
	}
	for _, name := range run.RemoteEngineEnv(os.Environ()) {
		log.Warn(name + " points at a remote container engine and is removed from the environment of every " +
			"command this audit runs: docker/podman are asked about this host's local engine only")
	}
	// Who will receive what is stated before anything is collected, let alone sent.
	for _, line := range audit.PlanSummary(audit.NetworkPlan(cfg)) {
		log.Info(line)
	}

	auditor := audit.New(cfg, log, version)
	if cfg.Recheck != "" {
		return recheck(auditor, cfg, log, stdout)
	}
	// A Compose preflight whose input cannot be parsed stops here, before anything
	// is collected and with no report written: there is no preflight to report, and
	// a report without one must not be mistaken for a clean preflight.
	if err := auditor.Prepare(); err != nil {
		log.Error(err, "; no report was written")
		return exitUsage
	}
	result := auditor.Run()

	// The last thing before anything is written: sweep the free-form text for
	// credentials. No collector reads a secret on purpose, but a cron line or a
	// process command line can carry one, and this report may be uploaded.
	if masked := redact.Report(result); masked > 0 {
		log.Infof("masked credential-looking material in %d field(s) before writing the report", masked)
	}

	payload, err := writeReport(cfg, log, result, stdout)
	if err != nil {
		log.Error("could not write the report: ", err)
		return exitUsage
	}

	if cfg.WantsUpload() {
		if endpoint, err := report.UploadEndpoint(cfg.UploadURL); err == nil {
			log.Infof("uploading %d bytes (the `upload` half of the report) and the one-time token to %s",
				len(payload), netpath.Describe(endpoint))
		}
		url, err := report.Upload(context.Background(), cfg.UploadURL, cfg.UploadToken, payload,
			"deploy-witness/"+version)
		if err != nil {
			// A failed upload is not a footnote. The operator ran a command whose
			// point was to deliver this report, and it did not arrive.
			log.Error("the upload failed: ", err)
			return exitUploadFail
		}
		log.Infof("uploaded %d bytes to %s; anyone holding the report link in the answer below can read it",
			len(payload), cfg.UploadURL)
		if trimmed := strings.TrimSpace(url); trimmed != "" {
			fmt.Fprintln(stdout, trimmed)
		}
	}

	return statusCode(result)
}

// writeReport renders the report in the requested format(s) and returns the
// contract payload — the exact bytes --upload would send, taken from the same
// document that was written to disk rather than built a second time. With
// --format csv,json both outputs are rendered from this one result, so the CSV
// tables and report.json carry the same timestamps, PIDs and findings.
func writeReport(cfg *config.Config, log *logging.Logger, result *model.Report, stdout io.Writer) ([]byte, error) {
	if cfg.ToStdout {
		if cfg.WantsJSON() {
			return report.WriteJSON(stdout, result)
		}
		if err := report.WriteCombined(stdout, result); err != nil {
			return nil, err
		}
		return contractPayload(cfg, result)
	}

	if cfg.WantsCSV() {
		paths, err := report.WriteDir(cfg.OutDir, result)
		if err != nil {
			return nil, err
		}
		log.Infof("wrote %d CSV files to %s", len(paths), cfg.OutDir)
	}
	if cfg.WantsJSON() {
		path, payload, err := report.WriteJSONFile(cfg.OutDir, result)
		if err != nil {
			return nil, err
		}
		log.Infof("wrote %s", path)
		return payload, nil
	}
	return contractPayload(cfg, result)
}

// contractPayload builds the upload bytes for a CSV run, and only when an upload was
// actually asked for: rendering a contract document nobody requested would be work
// done for no reason.
func contractPayload(cfg *config.Config, result *model.Report) ([]byte, error) {
	if !cfg.WantsUpload() {
		return nil, nil
	}
	_, payload, err := report.Build(result)
	return payload, err
}

// printCommands renders the allowlist. It prints the enforced list itself rather
// than a description of it, so there is nothing here that could be out of date.
func printCommands(w io.Writer) {
	specs := run.Commands()
	fmt.Fprintf(w, "deploy-witness %s can run exactly these %d commands and nothing else.\n", version, len(specs))
	fmt.Fprintf(w, "Anything outside this list is refused before the binary is even looked up, and the\n")
	fmt.Fprintf(w, "refusal is recorded in commands.csv. An argument shown as <kind> is filled in at\n")
	fmt.Fprintf(w, "run time and constrained to a character class that admits no shell metacharacters.\n")
	if networked := run.NetworkCommands(); len(networked) > 0 {
		fmt.Fprintf(w, "%d of them reach the network themselves and are marked \"network\": the run refuses\n", len(networked))
		fmt.Fprintf(w, "them unless the flag named next to them was typed. Every other command reads data on this host.\n")
	}

	section := ""
	for _, spec := range specs {
		if spec.Section != section {
			section = spec.Section
			fmt.Fprintf(w, "\n[%s]\n", section)
		}
		fmt.Fprintf(w, "  %s\n      %s\n", spec, spec.Purpose)
		if spec.Network != "" {
			fmt.Fprintf(w, "      network: yes — runs only with %s\n", spec.Network)
		}
	}
}

// recheck confirms a report against the plan and engine of right now, writing
// nothing. The verdict lines go to stdout, so a deployment script can keep them.
func recheck(auditor *audit.Auditor, cfg *config.Config, log *logging.Logger, stdout io.Writer) int {
	result, err := auditor.Recheck(cfg.Recheck, cfg.MaxAge, time.Now().UTC())
	if err != nil {
		log.Error(err)
		return exitUsage
	}
	for _, line := range result.Lines {
		fmt.Fprintln(stdout, line)
	}
	if !result.Confirmed {
		log.Error("the report does not confirm this deployment: run the preflight again before deploying")
		return exitRecheck
	}
	log.Info("the report confirms this plan on this engine")
	return exitOK
}

func statusCode(result *model.Report) int {
	for _, section := range result.Sections {
		if section.Status == model.StatusFailed {
			return exitSectionFail
		}
	}
	return exitOK
}
