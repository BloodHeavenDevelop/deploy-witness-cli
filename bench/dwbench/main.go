// Command dwbench is the reproducible test bench of the deploy-witness CLI (DW-83).
//
// It starts one disposable Docker-in-Docker container from a pinned image, loads
// the images the scenarios need into it from this machine (nothing is pulled), and
// for every scenario under bench/scenarios:
//
//  1. resets the engine inside the container to empty;
//  2. stages the situation (the scenario's setup.sh, run inside the container);
//  3. runs the audit — the prediction — and snapshots the engine and the scenario
//     directory before and after it, so anything the audit itself changed is
//     reported as a side effect;
//  4. runs the planned change (`docker compose … up`) — the actual behaviour;
//  5. compares: the prediction against the scenario's expected outcome, and Docker's
//     behaviour against what the scenario says Docker will do.
//
// Bench failures (a setup that did not run, an audit that wrote no report) are
// recorded apart from CLI failures. The disposable container is removed at the end.
//
//	make bench                         # every scenario
//	make bench BENCH_ARGS="-only port" # a subset, by id prefix
package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/bench/result"
)

// BenchVersion changes whenever the harness changes how it stages, runs or
// compares, so two result files from different harnesses are not compared blindly.
const BenchVersion = "1"

type options struct {
	bin, scenarios, out, image, images, only, commit string
	keep                                              bool
	timeout                                           time.Duration
}

func main() {
	var o options
	flag.StringVar(&o.bin, "bin", "./deploy-witness", "the deploy-witness binary under test (linux, static: make build)")
	flag.StringVar(&o.scenarios, "scenarios", "bench/scenarios", "directory of scenarios")
	flag.StringVar(&o.out, "out", "", "directory to write results.json and results.csv into (default bench/out/<UTC timestamp>)")
	flag.StringVar(&o.image, "image", "docker:27.5.1-dind", "the pinned Docker-in-Docker image of the disposable environment")
	flag.StringVar(&o.images, "images", "alpine:3.21", "comma-separated images to load into the environment from this machine")
	flag.StringVar(&o.only, "only", "", "run only the scenarios whose id starts with this")
	flag.StringVar(&o.commit, "commit", "", "the commit of the CLI under test, for the record")
	flag.BoolVar(&o.keep, "keep", false, "keep the disposable container after the run, for debugging")
	flag.DurationVar(&o.timeout, "timeout", 3*time.Minute, "timeout per command")
	flag.Parse()

	if err := run(o); err != nil {
		fmt.Fprintln(os.Stderr, "dwbench:", err)
		os.Exit(2)
	}
}

func run(o options) error {
	scenarios, err := result.Load(o.scenarios)
	if err != nil {
		return err
	}
	if o.only != "" {
		var kept []result.Scenario
		for _, s := range scenarios {
			if strings.HasPrefix(s.ID, o.only) {
				kept = append(kept, s)
			}
		}
		scenarios = kept
	}
	if len(scenarios) == 0 {
		return fmt.Errorf("no scenario to run under %s", o.scenarios)
	}
	if o.out == "" {
		o.out = filepath.Join("bench", "out", time.Now().UTC().Format("20060102-150405"))
	}
	if err := os.MkdirAll(o.out, 0o755); err != nil {
		return err
	}
	bin, err := filepath.Abs(o.bin)
	if err != nil {
		return err
	}
	cliVersion, err := host(o, bin, "--version")
	if err != nil {
		return fmt.Errorf("the binary under test does not run (%v) — make build first", err)
	}

	env, err := startEnvironment(o, bin)
	if err != nil {
		return err
	}
	if !o.keep {
		defer env.remove()
	}

	r := &result.Run{
		BenchVersion:   BenchVersion,
		CLIVersion:     strings.TrimSpace(cliVersion),
		CLICommit:      o.commit,
		Environment:    o.image,
		DockerVersion:  env.mustExec("docker", "version", "--format", "{{.Server.Version}}"),
		ComposeVersion: env.mustExec("docker", "compose", "version", "--short"),
		StartedAt:      time.Now().UTC().Format(time.RFC3339),
	}
	for _, s := range scenarios {
		fmt.Printf("%-55s ", s.ID)
		outcome := env.scenario(s)
		r.Results = append(r.Results, outcome)
		fmt.Println(verdictLine(outcome))
	}
	r.FinishedAt = time.Now().UTC().Format(time.RFC3339)

	if err := r.Write(filepath.Join(o.out, "results.json")); err != nil {
		return err
	}
	if err := writeCSV(filepath.Join(o.out, "results.csv"), r); err != nil {
		return err
	}
	fmt.Printf("\n%s\nresults: %s\n", summary(r), o.out)
	return nil
}

func verdictLine(o result.Outcome) string {
	if o.BenchError != "" {
		return "BENCH ERROR: " + o.BenchError
	}
	spec := "ok"
	if !o.SpecMatch {
		spec = fmt.Sprintf("MISMATCH (expected %s, predicted %s)", o.Scenario.Expect.Outcome, o.Predicted)
	}
	docker := "advisory"
	if o.DockerMatch != nil {
		docker = map[bool]string{true: "docker ok", false: "DOCKER DISAGREES"}[*o.DockerMatch]
	}
	extra := ""
	if len(o.SideEffects) > 0 {
		extra = fmt.Sprintf(" — %d SIDE EFFECT(S) OF THE AUDIT", len(o.SideEffects))
	}
	return fmt.Sprintf("%s · %s%s", spec, docker, extra)
}

func summary(r *result.Run) string {
	var spec, docker, dockerScored, bench, effects int
	for _, o := range r.Results {
		switch {
		case o.BenchError != "":
			bench++
			continue
		case o.SpecMatch:
			spec++
		}
		if o.DockerMatch != nil {
			dockerScored++
			if *o.DockerMatch {
				docker++
			}
		}
		if len(o.SideEffects) > 0 {
			effects++
		}
	}
	return fmt.Sprintf("%d scenarios: prediction as specified %d/%d, Docker as expected %d/%d, bench errors %d, "+
		"audits with side effects %d", len(r.Results), spec, len(r.Results)-bench, docker, dockerScored, bench, effects)
}

// ───────────────────────────────────────────────────────── the environment

type environment struct {
	o    options
	name string
}

func startEnvironment(o options, bin string) (*environment, error) {
	env := &environment{o: o, name: fmt.Sprintf("dwbench-%d", os.Getpid())}
	// --network none: the environment reaches nothing outside itself. Whatever a
	// scenario needs is loaded into it from this machine, and a pull — by Compose
	// for a missing image or a foreign platform — fails instead of fetching.
	if _, err := host(o, "docker", "run", "-d", "--privileged", "--network", "none", "--name", env.name, o.image); err != nil {
		return nil, fmt.Errorf("could not start the disposable environment %s: %w", o.image, err)
	}
	deadline := time.Now().Add(90 * time.Second)
	for {
		if _, err := env.exec("docker", "info"); err == nil {
			break
		}
		if time.Now().After(deadline) {
			env.remove()
			return nil, fmt.Errorf("the engine inside %s did not come up", env.name)
		}
		time.Sleep(time.Second)
	}
	for _, image := range strings.Split(o.images, ",") {
		if image = strings.TrimSpace(image); image == "" {
			continue
		}
		if err := env.loadImage(image); err != nil {
			env.remove()
			return nil, err
		}
	}
	if _, err := host(o, "docker", "cp", bin, env.name+":/usr/local/bin/deploy-witness"); err != nil {
		env.remove()
		return nil, err
	}
	if _, err := env.exec("sh", "-c", "adduser -D bench && mkdir -p /out && chmod 1777 /out"); err != nil {
		env.remove()
		return nil, err
	}
	return env, nil
}

// loadImage copies an image from this machine's engine into the environment's, so
// the bench pulls nothing and every run uses the same bytes.
func (e *environment) loadImage(image string) error {
	if _, err := host(e.o, "docker", "image", "inspect", image); err != nil {
		return fmt.Errorf("image %s is not on this machine; docker pull it once, then re-run", image)
	}
	ctx, cancel := context.WithTimeout(context.Background(), e.o.timeout)
	defer cancel()
	save := exec.CommandContext(ctx, "docker", "save", image)
	load := exec.CommandContext(ctx, "docker", "exec", "-i", e.name, "docker", "load")
	pipe, err := save.StdoutPipe()
	if err != nil {
		return err
	}
	load.Stdin = pipe
	var out bytes.Buffer
	load.Stdout, load.Stderr = &out, &out
	if err := save.Start(); err != nil {
		return err
	}
	if err := load.Run(); err != nil {
		return fmt.Errorf("loading %s into the environment: %v: %s", image, err, out.String())
	}
	return save.Wait()
}

func (e *environment) remove() { _, _ = host(e.o, "docker", "rm", "-f", "-v", e.name) }

func (e *environment) exec(args ...string) (string, error) {
	return host(e.o, append([]string{"docker", "exec", e.name}, args...)...)
}

func (e *environment) execIn(dir string, args ...string) (string, error) {
	return host(e.o, append([]string{"docker", "exec", "-w", dir, e.name}, args...)...)
}

func (e *environment) mustExec(args ...string) string {
	out, err := e.exec(args...)
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(out)
}

// host runs a command on this machine. The returned output is stdout and stderr
// together, which is what a scenario's verdict is read from.
func host(o options, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), o.timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	err := cmd.Run()
	return out.String(), err
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	if exit, ok := err.(*exec.ExitError); ok {
		return exit.ExitCode()
	}
	return -1
}

// ───────────────────────────────────────────────────────── one scenario

const resetScript = `docker rm -f $(docker ps -aq) >/dev/null 2>&1
docker volume rm -f $(docker volume ls -q) >/dev/null 2>&1
docker network prune -f >/dev/null 2>&1
rm -rf /bench /out/* /root/dwbench-* 2>/dev/null
mkdir -p /bench
true`

const snapshotScript = `docker ps -a --format '{{.Names}}|{{.State}}|{{.Image}}' | sort
echo ---
docker volume ls -q | sort
echo ---
docker network ls --format '{{.Name}}|{{.Driver}}' | sort
echo ---
ls -laR "$1" 2>&1 | grep -v ' \.$' | grep -v ' \.\.$' | sed 's/ [A-Z][a-z][a-z] [ 0-9][0-9] [0-9:]\{4,5\} / /'`

func (e *environment) scenario(s result.Scenario) result.Outcome {
	started := time.Now()
	o := result.Outcome{Scenario: s}
	defer func() { o.DurationMs = time.Since(started).Milliseconds() }()

	dir := "/bench/" + strings.ReplaceAll(s.ID, "/", "--")
	project := s.Project
	if project == "" {
		project = "bench"
	}
	if _, err := e.exec("sh", "-c", resetScript); err != nil {
		o.BenchError = "the engine could not be reset: " + err.Error()
		return o
	}
	if _, err := host(e.o, "docker", "cp", s.Dir, e.name+":"+dir); err != nil {
		o.BenchError = "the scenario could not be copied in: " + err.Error()
		return o
	}
	if _, err := e.exec("chmod", "-R", "a+rX", dir); err != nil {
		o.BenchError = err.Error()
		return o
	}
	if _, err := os.Stat(filepath.Join(s.Dir, "setup.sh")); err == nil {
		if out, err := e.execIn(dir, "sh", "-e", "setup.sh"); err != nil {
			o.BenchError = "setup.sh failed: " + tail(out, 600)
			return o
		}
	}

	before, _ := e.exec("sh", "-c", snapshotScript, "snapshot", dir)

	outDir := "/out/" + strings.ReplaceAll(s.ID, "/", "--")
	audit := append([]string{"deploy-witness", "--compose", dir + "/compose.yml", "--project-name", project,
		"--format", "json", "--out", outDir}, s.Audit.Args...)
	var auditOut string
	var auditErr error
	if s.Audit.User == "unprivileged" {
		auditOut, auditErr = e.execIn(dir, "su", "bench", "-s", "/bin/sh", "-c", shellJoin(audit))
	} else {
		auditOut, auditErr = e.execIn(dir, audit...)
	}
	o.AuditExit = exitCode(auditErr)

	after, _ := e.exec("sh", "-c", snapshotScript, "snapshot", dir)
	o.SideEffects = diffLines(before, after)

	switch o.AuditExit {
	case 0, 1:
		if err := e.readPrediction(&o, outDir+"/report.json"); err != nil {
			o.BenchError = "the audit wrote no readable report: " + err.Error() + ": " + tail(auditOut, 400)
			return o
		}
	case 2:
		// The plan was refused before any section ran: that is itself a prediction
		// ("this run cannot be prepared"), and scenarios may expect it.
		o.Predicted = "refused"
	default:
		o.BenchError = fmt.Sprintf("the audit exited %d: %s", o.AuditExit, tail(auditOut, 400))
		return o
	}
	o.SpecMatch = s.Accepts(o.Predicted)

	up := s.Docker.Up
	if len(up) == 0 {
		up = []string{"up", "-d"}
	}
	compose := append([]string{"docker", "compose", "-f", "compose.yml", "-p", project}, up...)
	upOut, upErr := e.execIn(dir, compose...)
	o.Docker = result.DockerRun{
		Command: strings.Join(compose, " "),
		Exit:    exitCode(upErr),
		Failed:  upErr != nil,
		Output:  tail(upOut, 1500),
	}
	if s.Docker.Pattern != "" {
		o.Docker.PatternSeen = strings.Contains(upOut, s.Docker.Pattern)
	}
	if !o.Docker.Failed {
		// `up -d` returns once the containers have started; one that dies right
		// after is a failed deployment all the same.
		time.Sleep(3 * time.Second)
		ps, _ := e.execIn(dir, "docker", "compose", "-f", "compose.yml", "-p", project, "ps", "-a",
			"--format", "{{.Name}} {{.State}} {{.ExitCode}}")
		for _, line := range strings.Split(strings.TrimSpace(ps), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && fields[1] != "running" {
				o.Docker.Exited = append(o.Docker.Exited, line)
			}
		}
		if len(o.Docker.Exited) > 0 {
			o.Docker.Failed = true
		}
	}
	switch s.Docker.Outcome {
	case result.DockerFails:
		match := o.Docker.Failed && (s.Docker.Pattern == "" || o.Docker.PatternSeen)
		o.DockerMatch = &match
	case result.DockerSucceeds:
		match := !o.Docker.Failed && (s.Docker.Pattern == "" || o.Docker.PatternSeen)
		o.DockerMatch = &match
	}
	return o
}

// readPrediction takes the rule's outcome and findings out of the report.
func (e *environment) readPrediction(o *result.Outcome, path string) error {
	raw, err := e.exec("cat", path)
	if err != nil {
		return err
	}
	var doc struct {
		Audit struct {
			Rules []struct {
				Code    string `json:"code"`
				Outcome string `json:"outcome"`
			} `json:"rules"`
			Findings []struct {
				Code     string `json:"code"`
				Severity string `json:"severity"`
				Outcome  string `json:"outcome"`
				Subject  string `json:"subject"`
				Title    string `json:"title"`
			} `json:"findings"`
			Sections []struct {
				Section string `json:"section"`
				Status  string `json:"status"`
			} `json:"sections"`
		} `json:"audit"`
	}
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return err
	}
	o.Predicted = "absent"
	for _, r := range doc.Audit.Rules {
		if r.Code == o.Scenario.Rule {
			o.Predicted = r.Outcome
		}
	}
	for _, f := range doc.Audit.Findings {
		if f.Code == o.Scenario.Rule {
			o.Findings = append(o.Findings, result.Finding{Severity: f.Severity, Outcome: f.Outcome, Subject: f.Subject, Title: f.Title})
		}
	}
	for _, s := range doc.Audit.Sections {
		if s.Section == "witness" {
			o.PreflightStatus = s.Status
		}
	}
	return nil
}

func diffLines(before, after string) []string {
	seen := map[string]int{}
	for _, l := range strings.Split(before, "\n") {
		seen[l]++
	}
	var out []string
	for _, l := range strings.Split(after, "\n") {
		if seen[l] > 0 {
			seen[l]--
			continue
		}
		out = append(out, "appeared: "+l)
	}
	for l, n := range seen {
		for ; n > 0; n-- {
			out = append(out, "disappeared: "+l)
		}
	}
	return out
}

func shellJoin(args []string) string {
	quoted := make([]string, len(args))
	for i, a := range args {
		quoted[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
	}
	return strings.Join(quoted, " ")
}

func tail(text string, n int) string {
	text = strings.TrimSpace(text)
	if len(text) > n {
		return "…" + text[len(text)-n:]
	}
	return text
}

func writeCSV(path string, r *result.Run) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	_ = w.Write([]string{"Scenario", "Rule", "Situation", "Expected", "Predicted", "Spec match", "Docker expected",
		"Docker exit", "Docker match", "Side effects", "Bench error", "Critical", "Regression"})
	for _, o := range r.Results {
		dockerMatch := ""
		if o.DockerMatch != nil {
			dockerMatch = fmt.Sprint(*o.DockerMatch)
		}
		_ = w.Write([]string{o.Scenario.ID, o.Scenario.Rule, string(o.Scenario.Situation), o.Scenario.Expect.Outcome,
			o.Predicted, fmt.Sprint(o.SpecMatch), string(o.Scenario.Docker.Outcome), fmt.Sprint(o.Docker.Exit),
			dockerMatch, fmt.Sprint(len(o.SideEffects)), o.BenchError, fmt.Sprint(o.Scenario.Critical),
			o.Scenario.Regression})
	}
	w.Flush()
	return w.Error()
}
