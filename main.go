// Command deploy-witness audits the machine it runs on and writes a CSV report.
//
// It is offline by default: everything it reads comes from the kernel, /etc and
// package metadata already on disk. The only code path that touches the network
// is the OSV API lookup behind --online.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/audit"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/config"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/logging"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
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
)

func main() {
	os.Exit(mainWithCode())
}

func mainWithCode() int {
	cfg, err := config.Load(os.Args[1:], version, os.Stderr)
	switch {
	case errors.Is(err, flag.ErrHelp):
		return exitOK
	case err != nil:
		fmt.Fprintln(os.Stderr, "deploy-witness:", err)
		return exitUsage
	}

	if cfg.ShowVersion {
		fmt.Println("deploy-witness", version)
		return exitOK
	}

	if cfg.ShowCommands {
		printCommands(os.Stdout)
		return exitOK
	}

	// Every diagnostic goes to stderr, so --stdout yields a CSV stream a pipe can
	// consume unmodified.
	log := logging.New(os.Stderr, cfg.LogLevel)

	result := audit.New(cfg, log, version).Run()

	// The last thing before anything is written: sweep the free-form text for
	// credentials. No collector reads a secret on purpose, but a cron line or a
	// process command line can carry one, and this report may be uploaded.
	if masked := redact.Report(result); masked > 0 {
		log.Infof("masked credential-looking material in %d field(s) before writing the report", masked)
	}

	payload, err := writeReport(cfg, log, result)
	if err != nil {
		log.Error("could not write the report: ", err)
		return exitUsage
	}

	if cfg.WantsUpload() {
		url, err := report.Upload(context.Background(), cfg.UploadURL, cfg.UploadToken, payload,
			"deploy-witness/"+version)
		if err != nil {
			// A failed upload is not a footnote. The operator ran a command whose
			// point was to deliver this report, and it did not arrive.
			log.Error("the upload failed: ", err)
			return exitUploadFail
		}
		log.Infof("uploaded %d bytes to %s", len(payload), cfg.UploadURL)
		if trimmed := strings.TrimSpace(url); trimmed != "" {
			fmt.Println(trimmed)
		}
	}

	return statusCode(result)
}

// writeReport renders the report in the requested format and returns the contract
// payload — the exact bytes --upload would send, taken from the same document that
// was written to disk rather than built a second time.
func writeReport(cfg *config.Config, log *logging.Logger, result *model.Report) ([]byte, error) {
	switch {
	case cfg.WantsJSON() && cfg.ToStdout:
		return report.WriteJSON(os.Stdout, result)

	case cfg.WantsJSON():
		path, payload, err := report.WriteJSONFile(cfg.OutDir, result)
		if err != nil {
			return nil, err
		}
		log.Infof("wrote %s", path)
		return payload, nil

	case cfg.ToStdout:
		if err := report.WriteCombined(os.Stdout, result); err != nil {
			return nil, err
		}
		return contractPayload(cfg, result)

	default:
		paths, err := report.WriteDir(cfg.OutDir, result)
		if err != nil {
			return nil, err
		}
		log.Infof("wrote %d CSV files to %s", len(paths), cfg.OutDir)
		return contractPayload(cfg, result)
	}
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

	section := ""
	for _, spec := range specs {
		if spec.Section != section {
			section = spec.Section
			fmt.Fprintf(w, "\n[%s]\n", section)
		}
		fmt.Fprintf(w, "  %s\n      %s\n", spec, spec.Purpose)
	}
}

func statusCode(result *model.Report) int {
	for _, section := range result.Sections {
		if section.Status == model.StatusFailed {
			return exitSectionFail
		}
	}
	return exitOK
}
