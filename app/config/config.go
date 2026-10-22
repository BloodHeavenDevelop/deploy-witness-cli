// Package config turns the command line and the environment into the one struct
// the audit reads. Flags win over environment; environment wins over defaults.
//
// The exception is the network. --online, --egress, --upload and --osv-url have no
// environment fallback: a variable baked into an image, a CI runner or a login
// profile must not be able to make an offline audit open a connection, or choose
// where a report goes. Those paths are enabled by a flag typed on the command line
// and nothing else; a matching AUDIT_* variable is ignored and the run says so.
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
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/netpath"
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
	// Mode is host-audit or compose-preflight, resolved from --mode and --compose.
	// A Compose preflight always has a Compose file and always runs the witness
	// section; a host audit has neither. See resolveMode.
	Mode model.Mode
	// Compose is the deployment manifest the witness section compares the host
	// against. It is set exactly when Mode is compose-preflight, and it is the first
	// of ComposeFiles.
	Compose string
	// The planned run, as `docker compose` would be invoked: the files in order
	// (`-f`), the env files, the profiles, the project name, the project directory
	// and the services named on the command line. All paths are absolute. A
	// preflight compares the run the engineer is about to make, and a different
	// file order or a missing profile is a different run.
	ComposeFiles     []string
	EnvFiles         []string
	Profiles         []string
	ProjectName      string
	ProjectDirectory string
	ComposeServices  []string
	// The `docker compose up` options of the planned run that decide what happens
	// to the containers already there.
	RemoveOrphans bool
	ForceRecreate bool
	NoRecreate    bool
	// Egress permits the one outbound check in the witness section: whether the
	// registries the manifest pulls from are reachable. Off by default, like every
	// other network path in this tool.
	Egress bool
	// Format is "csv", "json" or "csv,json". CSV is a directory of tables for a
	// person; JSON is one document for a machine, and it is what --upload sends.
	// "csv,json" writes both from the one audit, so the two describe the same run.
	Format string
	// UploadURL and UploadToken send the report to a witness service. Both are
	// required together, and neither has a default: nothing is ever uploaded
	// unless the operator typed --upload. The token may come from
	// AUDIT_UPLOAD_TOKEN; the URL never comes from the environment.
	UploadURL   string
	UploadToken string
	// IgnoredEnv names the network-enabling AUDIT_* variables that were set in the
	// environment and ignored, so the run can say so instead of silently doing
	// something other than what the operator may expect.
	IgnoredEnv []string
	// Recheck is a report.json to confirm against the current plan and engine
	// instead of running an audit; MaxAge is how old it may be. See audit.Recheck.
	Recheck string
	MaxAge  time.Duration
	// ShowCommands prints the allowlist and exits. It is meant to be the first
	// thing somebody runs: the answer to "what will this do to my server?" should
	// be available without running the audit itself.
	ShowCommands bool
}

// Output formats.
const (
	formatCSV  = "csv"
	formatJSON = "json"
	formatBoth = "csv,json"
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
	var sections, minSeverity, timeout, mode string
	var verbose, quiet bool

	fs.StringVar(&cfg.OutDir, "out", env("AUDIT_OUT", ""),
		"directory to write the CSV report into (default: ./audit-<host>-<UTC timestamp>)")
	fs.BoolVar(&cfg.ToStdout, "stdout", envBool("AUDIT_STDOUT", false),
		"write one combined CSV to stdout instead of a directory of files")
	fs.StringVar(&sections, "sections", env("AUDIT_SECTIONS", ""),
		"comma-separated subset of: system,updates,vulnerabilities,ports,services,witness (default: all)")
	fs.StringVar(&cfg.VulnDB, "vuln-db", env("AUDIT_VULN_DB", ""),
		"path to an offline OSV dataset: a .json/.jsonl file, a .zip export, or a directory of OSV records")
	fs.BoolVar(&cfg.Online, "online", false,
		"additionally query the OSV API, and run debsecan/arch-audit, over the network (off by default; flag only, no AUDIT_ONLINE)")
	fs.StringVar(&cfg.OSVEndpoint, "osv-url", defaultOSVEndpoint,
		"OSV API base URL, used only with --online; https:// (http:// only for a loopback host)")
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
	composeFiles := listFlag(splitPathList(env("AUDIT_COMPOSE", "")))
	envFiles := listFlag(splitPathList(env("AUDIT_ENV_FILE", "")))
	profiles := listFlag(splitComma(env("AUDIT_PROFILE", "")))
	services := listFlag(splitComma(env("AUDIT_COMPOSE_SERVICES", "")))
	fs.Var(&composeFiles, "compose",
		"a Compose file to check this host against, as docker compose -f; repeat it for several, in the order you deploy with; makes the run a Compose preflight")
	fs.Var(&envFiles, "env-file",
		"an env file the planned run uses, as docker compose --env-file; repeatable")
	fs.Var(&profiles, "profile",
		"a profile the planned run activates, as docker compose --profile; repeatable")
	fs.StringVar(&cfg.ProjectName, "project-name", env("AUDIT_PROJECT_NAME", ""),
		"the project name the planned run uses, as docker compose -p (default: what Compose derives)")
	fs.StringVar(&cfg.ProjectDirectory, "project-directory", env("AUDIT_PROJECT_DIRECTORY", ""),
		"the project directory of the planned run, as docker compose --project-directory (default: the first file's directory)")
	fs.BoolVar(&cfg.RemoveOrphans, "remove-orphans", envBool("AUDIT_REMOVE_ORPHANS", false),
		"the planned run uses docker compose up --remove-orphans")
	fs.BoolVar(&cfg.ForceRecreate, "force-recreate", envBool("AUDIT_FORCE_RECREATE", false),
		"the planned run uses docker compose up --force-recreate")
	fs.BoolVar(&cfg.NoRecreate, "no-recreate", envBool("AUDIT_NO_RECREATE", false),
		"the planned run uses docker compose up --no-recreate")
	fs.Var(&services, "compose-service",
		"a service the planned run starts, as in docker compose up <service>; repeatable (default: every service)")
	fs.StringVar(&mode, "mode", env("AUDIT_MODE", ""),
		"host-audit (the host on its own) or compose-preflight (needs --compose); default: compose-preflight when --compose is given, host-audit otherwise")
	fs.BoolVar(&cfg.Egress, "egress", false,
		"allow the witness section to test whether the manifest's registries are reachable (off by default; flag only, no AUDIT_EGRESS)")
	fs.StringVar(&cfg.Format, "format", env("AUDIT_FORMAT", formatCSV),
		"output format: csv (a directory of tables), json (one document) or csv,json (both, from the same run)")
	fs.StringVar(&cfg.UploadURL, "upload", "",
		"https:// base URL of a witness service to send the report to (off unless given; flag only, no AUDIT_UPLOAD; needs a token)")
	fs.StringVar(&cfg.UploadToken, "upload-token", "",
		"one-time token authorising the upload; prefer AUDIT_UPLOAD_TOKEN, which keeps it out of the process list")
	var maxAge string
	fs.StringVar(&cfg.Recheck, "recheck", "",
		"confirm that a report.json still describes this plan on this engine, instead of auditing; needs the same --compose flags (exit 0 confirmed, 4 re-run the audit)")
	fs.StringVar(&maxAge, "max-age", env("AUDIT_MAX_AGE", "1h"),
		"with --recheck: how old a report may be and still confirm the plan")
	fs.BoolVar(&cfg.ShowVersion, "version", false, "print the version and exit")
	fs.BoolVar(&cfg.ShowCommands, "commands", false,
		"print every command this binary is able to run, and exit — the tool cannot execute anything outside that list")

	fs.Usage = func() {
		fmt.Fprintf(out, "deploy-witness %s — local server audit, CSV report.\n\n", version)
		fmt.Fprintf(out, "Usage:\n  deploy-witness [flags]\n\nFlags:\n")
		fs.PrintDefaults()
		fmt.Fprintf(out, "\nEvery flag also reads an AUDIT_-prefixed environment variable, except the ones that\n"+
			"open the network: --online, --egress, --upload and --osv-url are read from the command\n"+
			"line only. AUDIT_UPLOAD_TOKEN is read, and only takes effect together with --upload.\n")
	}

	if err := fs.Parse(args); err != nil {
		return nil, err
	}

	typed := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { typed[f.Name] = true })
	cfg.ComposeFiles, cfg.EnvFiles = composeFiles.values(), envFiles.values()
	cfg.Profiles, cfg.ComposeServices = profiles.values(), services.values()
	if len(cfg.ComposeFiles) > 0 {
		cfg.Compose = cfg.ComposeFiles[0]
	}

	// Network-enabling variables are ignored, and named, rather than honoured.
	for _, name := range []string{"AUDIT_ONLINE", "AUDIT_EGRESS", "AUDIT_UPLOAD", "AUDIT_OSV_URL"} {
		if v, ok := os.LookupEnv(name); ok && strings.TrimSpace(v) != "" {
			cfg.IgnoredEnv = append(cfg.IgnoredEnv, name)
		}
	}

	// The token is a secret, not a switch: reading it from the environment keeps
	// it out of `ps` and /proc/<pid>/cmdline, and on its own it enables nothing —
	// without --upload typed it is simply unused.
	if !typed["upload-token"] {
		cfg.UploadToken = ""
		if typed["upload"] {
			cfg.UploadToken = strings.TrimSpace(os.Getenv("AUDIT_UPLOAD_TOKEN"))
		}
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

	if cfg.MaxAge, err = time.ParseDuration(maxAge); err != nil || cfg.MaxAge <= 0 {
		return nil, fmt.Errorf("invalid --max-age %q: expected a positive duration such as 30m or 2h", maxAge)
	}
	if cfg.Recheck != "" {
		if err := checkPlanFile("--recheck", cfg.Recheck); err != nil {
			return nil, err
		}
		if cfg.Compose == "" {
			return nil, fmt.Errorf("--recheck confirms a report against the planned run, and needs the same " +
				"--compose (and --env-file, --profile, … ) flags the report was made with")
		}
	}

	cfg.Sections, err = parseSections(sections)
	if err != nil {
		return nil, err
	}

	cfg.Mode, err = resolveMode(mode, cfg.Compose, strings.TrimSpace(sections) != "", cfg.Sections)
	if err != nil {
		return nil, err
	}
	if cfg.Mode == model.ModeHostAudit {
		cfg.Sections = withoutSection(cfg.Sections, model.SectionWitness)
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

	cfg.Format = strings.ToLower(strings.ReplaceAll(cfg.Format, " ", ""))
	switch cfg.Format {
	case formatCSV, formatJSON, formatBoth:
	case "json,csv":
		cfg.Format = formatBoth
	default:
		return nil, fmt.Errorf("invalid --format %q: expected csv, json or csv,json", cfg.Format)
	}
	if cfg.Format == formatBoth && cfg.ToStdout {
		return nil, fmt.Errorf("--format csv,json writes two outputs and --stdout is one stream; " +
			"choose csv or json with --stdout, or drop --stdout")
	}

	if cfg.Compose != "" {
		for i, file := range cfg.ComposeFiles {
			if err := checkComposeFile(file); err != nil {
				return nil, err
			}
			if cfg.ComposeFiles[i], err = filepath.Abs(file); err != nil {
				return nil, err
			}
		}
		cfg.Compose = cfg.ComposeFiles[0]
		for i, file := range cfg.EnvFiles {
			if err := checkPlanFile("--env-file", file); err != nil {
				return nil, err
			}
			if cfg.EnvFiles[i], err = filepath.Abs(file); err != nil {
				return nil, err
			}
		}
		if cfg.ProjectDirectory != "" {
			info, statErr := os.Stat(cfg.ProjectDirectory)
			if statErr != nil || !info.IsDir() {
				return nil, fmt.Errorf("--project-directory %q: the planned run needs an existing directory", cfg.ProjectDirectory)
			}
			if cfg.ProjectDirectory, err = filepath.Abs(cfg.ProjectDirectory); err != nil {
				return nil, err
			}
		}
	} else if len(cfg.EnvFiles) > 0 || len(cfg.Profiles) > 0 || cfg.ProjectName != "" ||
		cfg.ProjectDirectory != "" || len(cfg.ComposeServices) > 0 || cfg.RemoveOrphans || cfg.ForceRecreate ||
		cfg.NoRecreate {
		return nil, fmt.Errorf("--env-file, --profile, --project-name, --project-directory, --compose-service, " +
			"--remove-orphans, --force-recreate and --no-recreate describe a planned Compose run and need --compose; " +
			"a host audit has none")
	}
	if cfg.ForceRecreate && cfg.NoRecreate {
		return nil, fmt.Errorf("--force-recreate and --no-recreate are incompatible, as they are for docker compose up")
	}

	// The two upload flags are useless apart, and a partially configured upload that
	// silently does nothing is worse than a refusal to start.
	switch {
	case typed["upload"] && strings.TrimSpace(cfg.UploadURL) == "":
		return nil, fmt.Errorf("--upload needs a URL")
	case cfg.UploadURL != "" && cfg.UploadToken == "":
		return nil, fmt.Errorf("--upload needs --upload-token or AUDIT_UPLOAD_TOKEN")
	case cfg.UploadToken != "" && cfg.UploadURL == "":
		return nil, fmt.Errorf("--upload-token needs --upload")
	}

	// Addresses are checked before the audit runs, so a refused address costs the
	// operator a second, not a whole audit followed by a failed upload.
	if cfg.UploadURL != "" {
		if _, err := netpath.CheckEndpoint("--upload", cfg.UploadURL); err != nil {
			return nil, err
		}
	}
	if cfg.Online {
		if _, err := netpath.CheckEndpoint("--osv-url", cfg.OSVEndpoint); err != nil {
			return nil, err
		}
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

// WantsJSON reports whether report.json (or a JSON stream) should be written.
func (c *Config) WantsJSON() bool { return c.Format == formatJSON || c.Format == formatBoth }

// WantsCSV reports whether the CSV tables should be written.
func (c *Config) WantsCSV() bool { return c.Format == formatCSV || c.Format == formatBoth }

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

// resolveMode decides between a host audit and a Compose preflight, and refuses
// every combination that would let one pass for the other.
//
// Without --mode the presence of --compose decides. With it, the two must agree:
// --mode compose-preflight is how a scheduled job asserts that it is a preflight,
// so a Compose file that went missing from its environment stops the run instead
// of quietly turning it into a host audit. A typed `witness` in --sections without
// a Compose file is refused for the same reason: the section is the comparison,
// and there is nothing to compare.
func resolveMode(raw, compose string, sectionsTyped bool, sections []model.Section) (model.Mode, error) {
	var mode model.Mode
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "":
		mode = model.ModeHostAudit
		if compose != "" {
			mode = model.ModeComposePreflight
		}
	case string(model.ModeHostAudit), "host":
		mode = model.ModeHostAudit
	case string(model.ModeComposePreflight), "preflight":
		mode = model.ModeComposePreflight
	default:
		return "", fmt.Errorf("invalid --mode %q: expected host-audit or compose-preflight", raw)
	}

	witness := false
	for _, s := range sections {
		if s == model.SectionWitness {
			witness = true
		}
	}

	switch {
	case mode == model.ModeComposePreflight && compose == "":
		return "", fmt.Errorf("--mode compose-preflight needs --compose <docker-compose.yml>: " +
			"a preflight compares a planned deployment with this host, and without the file there is none")
	case mode == model.ModeHostAudit && compose != "":
		return "", fmt.Errorf("--mode host-audit does not read a Compose file, but --compose (or AUDIT_COMPOSE) " +
			"names one; drop it, or use --mode compose-preflight")
	case mode == model.ModeHostAudit && sectionsTyped && witness:
		return "", fmt.Errorf("the witness section is the Compose preflight and needs --compose <docker-compose.yml>; " +
			"without one, leave witness out of --sections to run a host audit")
	case mode == model.ModeComposePreflight && sectionsTyped && !witness:
		return "", fmt.Errorf("--compose makes this run a Compose preflight, which is the witness section, " +
			"but --sections leaves witness out; add it, or drop --compose to run a host audit")
	}
	return mode, nil
}

// checkComposeFile refuses, before anything is collected, a --compose path that
// cannot be the input of a preflight: missing, a directory, or unreadable. Whether
// its content parses is checked by the audit before the first section runs.
func checkComposeFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("--compose %q: the Compose preflight needs a readable Compose file: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("--compose %q: the Compose preflight needs a Compose file, and this is not a regular file", path)
	}
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("--compose %q: the Compose preflight needs a readable Compose file: %w", path, err)
	}
	return file.Close()
}

// checkPlanFile refuses a file of the planned run that does not exist or cannot be
// read, before anything is collected.
func checkPlanFile(flagName, path string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("%s %q: the planned run names a file that cannot be read: %w", flagName, path, err)
	}
	return file.Close()
}

// listFlag is a repeatable string flag. Values given on the command line replace
// the environment default rather than adding to it.
type listFlag []string

func (l *listFlag) String() string { return strings.Join(*l, ",") }

func (l *listFlag) Set(value string) error {
	// The first typed value replaces whatever the environment supplied.
	if len(*l) > 0 && (*l)[0] == envMarker {
		*l = nil
	}
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("empty value")
	}
	*l = append(*l, value)
	return nil
}

func (l listFlag) values() []string {
	out := make([]string, 0, len(l))
	for _, v := range l {
		if v != envMarker {
			out = append(out, v)
		}
	}
	return out
}

// envMarker leads a list that came from the environment, so a typed flag knows to
// replace it rather than add to it.
const envMarker = "\x00env"

func splitPathList(raw string) []string {
	return markEnv(strings.Split(raw, string(os.PathListSeparator)))
}

func splitComma(raw string) []string {
	return markEnv(strings.Split(raw, ","))
}

func markEnv(parts []string) []string {
	var out []string
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return append([]string{envMarker}, out...)
}

func withoutSection(sections []model.Section, drop model.Section) []model.Section {
	out := make([]model.Section, 0, len(sections))
	for _, s := range sections {
		if s != drop {
			out = append(out, s)
		}
	}
	return out
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
