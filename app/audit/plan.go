package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/collect/manifest"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/redact"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/run"
	"gopkg.in/yaml.v3"
)

// A Compose preflight checks one exact run: these files in this order, these env
// files and profiles, this project name and directory, these services, on this
// engine. The plan is resolved before anything is collected, by Compose itself
// whenever Compose is installed here, and a plan that cannot be resolved stops the
// run: a preflight of a configuration Compose would reject, or of a run on another
// machine, is not a preflight result at all.

// errPlan marks an error in preparing the plan, as opposed to a failure of this
// tool; the caller prints it and exits 2.
var errPlan = errors.New("the Compose preflight cannot start")

func planError(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errPlan, fmt.Sprintf(format, args...))
}

// preparePlan resolves the planned run into a manifest. It is Prepare's work for a
// Compose preflight.
func (a *Auditor) preparePlan() error {
	cfg := a.cfg
	plan := &model.LaunchPlan{
		Files:            cfg.ComposeFiles,
		ProjectDirectory: cfg.ProjectDirectory,
		EnvFiles:         cfg.EnvFiles,
		Profiles:         cfg.Profiles,
		Services:         cfg.ComposeServices,
		ProjectName:      cfg.ProjectName,
		Environment:      composeEnvironment(os.Environ()),
	}
	if plan.ProjectDirectory == "" {
		plan.ProjectDirectory = filepath.Dir(cfg.Compose)
	}

	if err := a.planEngine(plan); err != nil {
		return err
	}

	// Every file must parse on its own first: a file that is not a Compose file is a
	// usage error with the parser's own explanation, whatever Compose would add.
	for _, file := range plan.Files {
		if _, err := manifest.Parse(file, nil); err != nil {
			return fmt.Errorf("the Compose preflight cannot start, the Compose file could not be parsed: %w", err)
		}
	}
	for _, file := range plan.Files {
		remote, err := manifest.RemoteIncludes(file)
		if err != nil {
			return fmt.Errorf("the Compose preflight cannot start, the Compose file could not be parsed: %w", err)
		}
		if len(remote) > 0 {
			return planError("%s includes %s from a remote source; resolving the plan would fetch it, and this "+
				"audit does not open connections — vendor the included file next to the plan and include it by path",
				file, strings.Join(remote, ", "))
		}
	}

	parsed, err := a.resolve(plan)
	if err != nil {
		return err
	}

	plan.ProjectName, plan.ProjectNameSource = planProjectName(cfg.ProjectName, plan, parsed)
	if err := selectServices(plan, parsed); err != nil {
		return err
	}
	plan.Digest = PlanDigest(plan, parsed)
	plan.FileDigests = fileDigests(plan.Files)
	plan.ResolvedAt = time.Now().UTC().Format(time.RFC3339)

	a.manifest = parsed
	a.plan = plan
	return nil
}

// resolve obtains the final model: from `docker compose config` when Compose is
// here and the plan's paths can be passed to it, from the built-in parser otherwise
// — and then only for a plan the built-in parser can read faithfully.
func (a *Auditor) resolve(plan *model.LaunchPlan) (*model.Manifest, error) {
	version, available := a.composeVersion()
	args := composeConfigArgs(plan, true)
	_, allowed := run.Allowed("docker", args)

	if available && allowed {
		raw, err := a.runner.Output("docker", args...)
		if err != nil && strings.Contains(err.Error(), "no-env-resolution") {
			// A Compose older than the flag: the same model, with env_file contents
			// merged into it in memory. They are dropped by the decoder all the same.
			raw, err = a.runner.Output("docker", composeConfigArgs(plan, false)...)
		}
		if err != nil {
			return nil, planError("docker compose config rejected the planned run, so Compose would reject it "+
				"too: %s", redact.String(strings.TrimSpace(err.Error())))
		}
		parsed, err := manifest.FromComposeConfig([]byte(raw), plan.Files[0], &a.parseNotes)
		if err != nil {
			return nil, planError("%v", err)
		}
		plan.Resolver, plan.ResolverVersion = model.ResolverCompose, version
		return parsed, nil
	}

	reason := "docker compose is not installed on this host"
	if available {
		reason = "a path of the planned run contains characters this tool will not pass to a command " +
			"(the allowlist admits [A-Za-z0-9@:+,%._/-] in a path)"
	}
	if len(plan.Files) > 1 || len(plan.EnvFiles) > 0 || len(plan.Profiles) > 0 {
		return nil, planError("%s, and the built-in parser cannot reproduce this plan: merging several Compose "+
			"files, --env-file and --profile are resolved by Compose alone", reason)
	}

	parsed, err := manifest.Parse(plan.Files[0], &a.parseNotes)
	if err != nil {
		return nil, fmt.Errorf("the Compose preflight cannot start, the Compose file could not be parsed: %w", err)
	}
	plan.Resolver = model.ResolverBuiltin
	note := reason + ", so the plan was read by the built-in parser — an approximation of what Compose " +
		"resolves; this preflight is partial"
	plan.Notes = append(plan.Notes, note)
	a.parseNotes.Degrade(note)
	return parsed, nil
}

func (a *Auditor) composeVersion() (string, bool) {
	if !run.Available("docker") {
		return "", false
	}
	out, err := a.runner.Output("docker", "compose", "version", "--short")
	if err != nil {
		return "", false
	}
	return strings.TrimPrefix(strings.TrimSpace(out), "v"), true
}

// composeConfigArgs is the `docker compose` invocation that resolves the plan,
// with the plan's own flags in the order the engineer gives them.
func composeConfigArgs(plan *model.LaunchPlan, noEnvResolution bool) []string {
	args := []string{"compose", "--project-directory", plan.ProjectDirectory}
	for _, file := range plan.Files {
		args = append(args, "--file", file)
	}
	for _, file := range plan.EnvFiles {
		args = append(args, "--env-file", file)
	}
	for _, profile := range plan.Profiles {
		args = append(args, "--profile", profile)
	}
	if plan.ProjectName != "" {
		args = append(args, "--project-name", plan.ProjectName)
	}
	args = append(args, "config", "--format", "json")
	if noEnvResolution {
		args = append(args, "--no-env-resolution")
	}
	return args
}

// planEngine establishes which engine the planned run would reach. This audit
// inspects the host it runs on; a plan aimed at another engine — a remote docker
// context, a DOCKER_HOST over TCP or SSH — is a plan for another machine, and
// checking it against this one would answer the wrong question with confidence.
func (a *Auditor) planEngine(plan *model.LaunchPlan) error {
	if host := strings.TrimSpace(os.Getenv("DOCKER_HOST")); host != "" {
		plan.Engine.Endpoint, plan.Engine.Context = host, "DOCKER_HOST"
		plan.Engine.Local = strings.HasPrefix(host, "unix://")
		if !plan.Engine.Local {
			return planError("DOCKER_HOST points the planned run at the engine at %s; this audit inspects the host "+
				"it runs on and cannot speak for that engine — run deploy-witness on that server", host)
		}
		return nil
	}
	if !run.Available("docker") {
		plan.Engine.Local = true
		return nil
	}
	name, endpoint := a.activeContext()
	plan.Engine.Context, plan.Engine.Endpoint = name, endpoint
	switch {
	case endpoint == "":
		plan.Engine.Local = true
		plan.Notes = append(plan.Notes, "the active docker context could not be read; the local engine was inspected")
	case strings.HasPrefix(endpoint, "unix://"):
		plan.Engine.Local = true
	default:
		return planError("the active docker context %q sends the planned run to the engine at %s; this audit "+
			"inspects the host it runs on and cannot speak for that engine — run deploy-witness on that server, or "+
			"select a local context (docker context use default)", name, endpoint)
	}
	return nil
}

// activeContext reads the name and engine endpoint of the docker CLI's active
// context, from its local context store.
func (a *Auditor) activeContext() (name, endpoint string) {
	if out, err := a.runner.Output("docker", "context", "show"); err == nil {
		name = strings.TrimSpace(out)
	}
	out, err := a.runner.Output("docker", "context", "inspect", "--format", "{{json .Endpoints.docker.Host}}")
	if err != nil {
		return name, ""
	}
	if json.Unmarshal([]byte(strings.TrimSpace(out)), &endpoint) != nil {
		endpoint = strings.Trim(strings.TrimSpace(out), `"`)
	}
	return name, endpoint
}

// pinLocalEngine keeps a host audit offline when the docker CLI's active context
// points at a remote engine: every docker command it runs is pinned to the local
// default context. DOCKER_HOST is already handled by the Runner.
func (a *Auditor) pinLocalEngine() {
	if !run.Available("docker") || strings.TrimSpace(os.Getenv("DOCKER_HOST")) != "" {
		return
	}
	name, endpoint := a.activeContext()
	if endpoint == "" || strings.HasPrefix(endpoint, "unix://") {
		return
	}
	a.runner.SetEnv("DOCKER_CONTEXT", "default")
	a.log.Warn(fmt.Sprintf("the active docker context %q points at a remote engine (%s); every docker command of "+
		"this audit is pinned to the local default context instead", name, endpoint))
}

// projectName is the name the planned run will use, and where it comes from, in
// Compose's own order of precedence.
func planProjectName(requested string, plan *model.LaunchPlan, parsed *model.Manifest) (string, string) {
	switch {
	case requested != "":
		if plan.Resolver == model.ResolverCompose && parsed.Name != "" {
			return parsed.Name, "--project-name"
		}
		return normaliseName(requested), "--project-name"
	case strings.TrimSpace(os.Getenv("COMPOSE_PROJECT_NAME")) != "":
		if plan.Resolver == model.ResolverCompose && parsed.Name != "" {
			return parsed.Name, "COMPOSE_PROJECT_NAME"
		}
		return normaliseName(os.Getenv("COMPOSE_PROJECT_NAME")), "COMPOSE_PROJECT_NAME"
	}
	if declared := declaredName(plan.Files); declared != "" {
		if plan.Resolver == model.ResolverCompose && parsed.Name != "" {
			return parsed.Name, "name: in the Compose file"
		}
		return normaliseName(declared), "name: in the Compose file"
	}
	if plan.Resolver == model.ResolverCompose && parsed.Name != "" {
		return parsed.Name, "the project directory"
	}
	return normaliseName(filepath.Base(plan.ProjectDirectory)), "the project directory"
}

// declaredName is the last top-level `name:` among the plan's files, which is the
// one a merge keeps.
func declaredName(files []string) string {
	name := ""
	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		var doc struct {
			Name string `yaml:"name"`
		}
		if yaml.Unmarshal(raw, &doc) == nil && strings.TrimSpace(doc.Name) != "" {
			name = strings.TrimSpace(doc.Name)
		}
	}
	return name
}

// normaliseName applies Compose's project name normalisation: lowercase, and
// everything outside [a-z0-9_-] dropped.
func normaliseName(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(name)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_', r == '-':
			b.WriteRune(r)
		}
	}
	return b.String()
}

// selectServices narrows the manifest to what `docker compose up <service>…` starts:
// the named services and everything they depend on. A name that is not in the
// resolved plan stops the run — Compose would refuse it, or it sits in a profile
// this plan does not activate.
func selectServices(plan *model.LaunchPlan, parsed *model.Manifest) error {
	byName := map[string]model.ManifestService{}
	for _, svc := range parsed.Services {
		byName[svc.Name] = svc
	}
	if len(plan.Services) == 0 {
		for _, svc := range parsed.Services {
			plan.Started = append(plan.Started, svc.Name)
		}
		sort.Strings(plan.Started)
		return nil
	}

	wanted := map[string]bool{}
	queue := append([]string(nil), plan.Services...)
	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]
		if wanted[name] {
			continue
		}
		svc, ok := byName[name]
		if !ok {
			return planError("service %q is not in the resolved plan (no such service, or it belongs to a profile "+
				"this plan does not activate — add --profile)", name)
		}
		wanted[name] = true
		queue = append(queue, svc.DependsOn...)
	}

	kept := parsed.Services[:0]
	for _, svc := range parsed.Services {
		if wanted[svc.Name] {
			kept = append(kept, svc)
			plan.Started = append(plan.Started, svc.Name)
		}
	}
	parsed.Services = kept
	sort.Strings(plan.Started)
	return nil
}

// composeEnvironment names the variables of this run's environment that change
// what Compose resolves or where it sends the run. Names only.
func composeEnvironment(environ []string) []string {
	var out []string
	for _, kv := range environ {
		name, value, _ := strings.Cut(kv, "=")
		if strings.TrimSpace(value) == "" {
			continue
		}
		if strings.HasPrefix(name, "COMPOSE_") || name == "DOCKER_HOST" || name == "DOCKER_CONTEXT" {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// PlanDigest identifies a resolved plan by what the rules compare: the resolved
// manifest (without its path and parser warnings, which do not change the run), the
// project name, the profiles and what the plan starts. Two plans with the same
// digest are the same run as far as this audit is concerned; a report never
// confirms a plan with another one.
func PlanDigest(plan *model.LaunchPlan, parsed *model.Manifest) string {
	requirements := *parsed
	requirements.Path, requirements.Warnings = "", nil
	canonical := struct {
		Manifest model.Manifest `json:"manifest"`
		Project  string         `json:"project"`
		Profiles []string       `json:"profiles"`
		Started  []string       `json:"started"`
	}{requirements, plan.ProjectName, plan.Profiles, plan.Started}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// fileDigests hashes the Compose files of the plan. The env files are not hashed:
// their contents are values this tool does not read, and what they change in the
// plan is already in the resolved model the digest covers.
func fileDigests(files []string) []model.FileDigest {
	var out []model.FileDigest
	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		sum := sha256.Sum256(raw)
		out = append(out, model.FileDigest{Path: file, SHA256: hex.EncodeToString(sum[:])})
	}
	return out
}
