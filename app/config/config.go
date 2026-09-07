// Package config turns the command line and the environment into the one struct
// the audit reads. Flags win over environment; environment wins over defaults.
package config

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/logging"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
)

// Config is the resolved run configuration.
type Config struct {
	OutDir      string
	ToStdout    bool
	Sections    []model.Section
	VulnDB      string
	Online      bool
	OSVEndpoint string
	Ecosystem   string
	MinSeverity model.Severity
	Timeout     time.Duration
	ServicesAll bool
	MaxOSVQuery int
	LogLevel    logging.Level
	ShowVersion bool
	// Compose is the deployment manifest the witness section compares the host
	// against. Without it that section has no requirements side and reports itself
	// as skipped rather than running empty.
	Compose string
	// Egress permits the one outbound check in the witness section: whether the
	// registries the manifest pulls from are reachable. Off by default, like every
	// other network path in this tool.
	Egress bool
	// Format is "csv" or "json". CSV is a directory of tables for a person; JSON is
	// one document for a machine, and it is what --upload sends.
	Format string
	// UploadURL and UploadToken send the report to a witness service. Both are
	// required together, and neither has a default: nothing is ever uploaded
	// unless the operator asked for it in the command line they typed.
	UploadURL   string
	UploadToken string
	// ShowCommands prints the allowlist and exits. It is meant to be the first
	// thing somebody runs: the answer to "what will this do to my server?" should
	// be available without running the audit itself.
	ShowCommands bool
}

// Output formats.
const (
	formatCSV  = "csv"
	formatJSON = "json"
)

// Defaults not worth a named constant elsewhere.
const (
	defaultOSVEndpoint = "https://api.osv.dev"
	defaultTimeout     = 60 * time.Second
	// defaultMaxOSVQuery bounds how many advisory detail requests the --online
	// path will make. It exists so an unattended run on a host with thousands of
	// packages cannot turn into an unbounded crawl; when it bites, the run says
	// so in summary.csv rather than silently truncating.
	defaultMaxOSVQuery = 1500
)

// ErrHelp signals that usage was printed and the process should exit cleanly.
var ErrHelp = flag.ErrHelp

// Load parses arguments into a Config.
func Load(args []string, version string, out io.Writer) (*Config, error) {
	fs := flag.NewFlagSet("deploy-witness", flag.ContinueOnError)
	fs.SetOutput(out)

	cfg := &Config{}
	var sections, minSeverity, timeout string
	var verbose, quiet bool

	fs.StringVar(&cfg.OutDir, "out", env("AUDIT_OUT", ""),
		"directory to write the CSV report into (default: ./audit-<host>-<UTC timestamp>)")
	fs.BoolVar(&cfg.ToStdout, "stdout", envBool("AUDIT_STDOUT", false),
		"write one combined CSV to stdout instead of a directory of files")
	fs.StringVar(&sections, "sections", env("AUDIT_SECTIONS", ""),
		"comma-separated subset of: system,updates,vulnerabilities,ports,services,witness (default: all)")
	fs.StringVar(&cfg.VulnDB, "vuln-db", env("AUDIT_VULN_DB", ""),
		"path to an offline OSV dataset: a .json/.jsonl file, a .zip export, or a directory of OSV records")
	fs.BoolVar(&cfg.Online, "online", envBool("AUDIT_ONLINE", false),
		"additionally query the OSV API over the network (off by default: the tool is offline-only unless asked)")
	fs.StringVar(&cfg.OSVEndpoint, "osv-url", env("AUDIT_OSV_URL", defaultOSVEndpoint),
		"OSV API base URL, used only with --online")
	fs.StringVar(&cfg.Ecosystem, "ecosystem", env("AUDIT_ECOSYSTEM", ""),
		`override the OSV ecosystem, e.g. "Debian:12" (needed on distributions OSV does not publish, such as Arch)`)
	fs.StringVar(&minSeverity, "min-severity", env("AUDIT_MIN_SEVERITY", string(model.SeverityLow)),
		"drop vulnerabilities below this severity: low|medium|high|critical (unknown is never dropped)")
	fs.StringVar(&timeout, "timeout", env("AUDIT_TIMEOUT", defaultTimeout.String()),
		"per-command timeout, e.g. 30s or 2m")
	fs.BoolVar(&cfg.ServicesAll, "services-all", envBool("AUDIT_SERVICES_ALL", false),
		"include inactive service units, not only running ones")
	fs.IntVar(&cfg.MaxOSVQuery, "max-osv-lookups", envInt("AUDIT_MAX_OSV_LOOKUPS", defaultMaxOSVQuery),
		"cap on advisory detail lookups per run, used only with --online")
	fs.BoolVar(&verbose, "verbose", envBool("AUDIT_VERBOSE", false),
		"log every probe, including the ones that found nothing")
	fs.BoolVar(&quiet, "quiet", envBool("AUDIT_QUIET", false),
		"log errors only")
	fs.StringVar(&cfg.Compose, "compose", env("AUDIT_COMPOSE", ""),
		"path to the docker-compose.yml the `witness` section checks this host against")
	fs.BoolVar(&cfg.Egress, "egress", envBool("AUDIT_EGRESS", false),
		"allow the witness section to test whether the manifest's registries are reachable (off by default)")
	fs.StringVar(&cfg.Format, "format", env("AUDIT_FORMAT", formatCSV),
		"output format: csv (a directory of tables) or json (one document)")
	fs.StringVar(&cfg.UploadURL, "upload", env("AUDIT_UPLOAD", ""),
		"base URL of a witness service to send the report to (off unless given; requires --upload-token)")
	fs.StringVar(&cfg.UploadToken, "upload-token", env("AUDIT_UPLOAD_TOKEN", ""),
		"one-time token authorising the upload")
	fs.BoolVar(&cfg.ShowVersion, "version", false, "print the version and exit")
	fs.BoolVar(&cfg.ShowCommands, "commands", false,
		"print every command this binary is able to run, and exit — the tool cannot execute anything outside that list")

	fs.Usage = func() {
		fmt.Fprintf(out, "deploy-witness %s — local server audit, CSV report.\n\n", version)
		fmt.Fprintf(out, "Usage:\n  deploy-witness [flags]\n\nFlags:\n")
		fs.PrintDefaults()
		fmt.Fprintf(out, "\nEvery flag also reads an AUDIT_-prefixed environment variable.\n")
	}

	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if cfg.ShowVersion || cfg.ShowCommands {
		return cfg, nil
	}

	// --quiet wins over --verbose: asking for silence and then being given debug
	// output is the more surprising outcome of the two.
	cfg.LogLevel = logging.LevelInfo
	switch {
	case quiet:
		cfg.LogLevel = logging.LevelError
	case verbose:
		cfg.LogLevel = logging.LevelDebug
	}

	parsed, err := time.ParseDuration(timeout)
	if err != nil {
		return nil, fmt.Errorf("invalid --timeout %q: %w", timeout, err)
	}
	if parsed <= 0 {
		return nil, fmt.Errorf("invalid --timeout %q: must be positive", timeout)
	}
	cfg.Timeout = parsed

	cfg.Sections, err = parseSections(sections)
	if err != nil {
		return nil, err
	}

	cfg.MinSeverity = model.ParseSeverity(minSeverity)
	if cfg.MinSeverity == model.SeverityUnknown {
		return nil, fmt.Errorf("invalid --min-severity %q: expected low, medium, high or critical", minSeverity)
	}

	if cfg.VulnDB != "" {
		if _, err := os.Stat(cfg.VulnDB); err != nil {
			return nil, fmt.Errorf("--vuln-db %q: %w", cfg.VulnDB, err)
		}
	}

	cfg.Format = strings.ToLower(strings.TrimSpace(cfg.Format))
	if cfg.Format != formatCSV && cfg.Format != formatJSON {
		return nil, fmt.Errorf("invalid --format %q: expected csv or json", cfg.Format)
	}

	if cfg.Compose != "" {
		if _, err := os.Stat(cfg.Compose); err != nil {
			return nil, fmt.Errorf("--compose %q: %w", cfg.Compose, err)
		}
		cfg.Compose, err = filepath.Abs(cfg.Compose)
		if err != nil {
			return nil, err
		}
	}

	// The two upload flags are useless apart, and a partially configured upload that
	// silently does nothing is worse than a refusal to start.
	switch {
	case cfg.UploadURL != "" && cfg.UploadToken == "":
		return nil, fmt.Errorf("--upload needs --upload-token")
	case cfg.UploadToken != "" && cfg.UploadURL == "":
		return nil, fmt.Errorf("--upload-token needs --upload")
	}

	if cfg.OutDir == "" {
		cfg.OutDir = defaultOutDir()
	}
	cfg.OutDir, err = filepath.Abs(cfg.OutDir)
	if err != nil {
		return nil, err
	}

	return cfg, nil
}

// WantsJSON reports whether the report should be rendered as one JSON document.
func (c *Config) WantsJSON() bool { return c.Format == formatJSON }

// WantsUpload reports whether the report should be sent to a witness service.
func (c *Config) WantsUpload() bool { return c.UploadURL != "" && c.UploadToken != "" }

// Wants reports whether a section was selected for this run.
func (c *Config) Wants(section model.Section) bool {
	for _, s := range c.Sections {
		if s == section {
			return true
		}
	}
	return false
}

func parseSections(raw string) ([]model.Section, error) {
	if strings.TrimSpace(raw) == "" {
		return model.AllSections, nil
	}

	var selected []model.Section
	seen := map[model.Section]bool{}
	for _, part := range strings.Split(raw, ",") {
		name := model.Section(strings.ToLower(strings.TrimSpace(part)))
		if name == "" {
			continue
		}
		known := false
		for _, s := range model.AllSections {
			if s == name {
				known = true
				break
			}
		}
		if !known {
			return nil, fmt.Errorf("unknown section %q", name)
		}
		if !seen[name] {
			seen[name] = true
			selected = append(selected, name)
		}
	}
	if len(selected) == 0 {
		return nil, fmt.Errorf("--sections selected nothing")
	}

	// Keep the canonical order regardless of how the flag was written: the
	// vulnerability collector consumes the package list the updates collector
	// builds, so running them out of order would silently lose findings.
	var ordered []model.Section
	for _, s := range model.AllSections {
		if seen[s] {
			ordered = append(ordered, s)
		}
	}
	return ordered, nil
}

func defaultOutDir() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "host"
	}
	host = strings.NewReplacer("/", "-", " ", "-", string(os.PathSeparator), "-").Replace(host)
	return fmt.Sprintf("audit-%s-%s", host, time.Now().UTC().Format("20060102-150405"))
}

func env(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return fallback
}

func envBool(key string, fallback bool) bool {
	v, ok := os.LookupEnv(key)
	if !ok {
		return fallback
	}
	parsed, err := strconv.ParseBool(strings.TrimSpace(v))
	if err != nil {
		return fallback
	}
	return parsed
}

func envInt(key string, fallback int) int {
	v, ok := os.LookupEnv(key)
	if !ok {
		return fallback
	}
	parsed, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return fallback
	}
	return parsed
}
