// Package run wraps external command execution. Every collector shells out to
// distribution tooling at some point; centralising it keeps the timeout, the
// non-zero-exit policy and the "command is missing" answer identical everywhere.
package run

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// ErrNotFound is returned when the binary is not installed. Collectors treat this
// as "this host does not use that tool", never as a failure.
var ErrNotFound = errors.New("command not found")

// Runner executes commands with a shared timeout.
//
// Every execution passes the allowlist in allowlist.go and lands in the journal.
// Both are properties of the Runner rather than of its callers, so a collector
// cannot opt out of either by forgetting to ask.
type Runner struct {
	Timeout time.Duration

	mu      sync.Mutex
	journal []JournalEntry
}

// JournalEntry is one command this run executed, or tried to.
//
// A refused command is recorded too. A client who ran an unfamiliar binary on
// their production host is owed the full list of what it did, and "it tried
// something it was not allowed to do" is the single most important line that list
// could ever contain.
type JournalEntry struct {
	// Command is the full argv, joined for reading. Nothing here goes through a
	// shell, so this is a description rather than something to paste back.
	Command string `json:"command"`
	// StartedAt is when the command was launched, UTC.
	StartedAt time.Time `json:"startedAt"`
	// Duration is how long it took, rounded to the millisecond.
	Duration string `json:"duration"`
	// ExitCode is the process exit code, or -1 when nothing was launched.
	ExitCode int `json:"exitCode"`
	// Outcome is "ok", "failed", "timeout", "missing" or "refused".
	Outcome string `json:"outcome"`
}

// Journal outcomes.
const (
	OutcomeOK      = "ok"
	OutcomeFailed  = "failed"
	OutcomeTimeout = "timeout"
	OutcomeMissing = "missing"
	OutcomeRefused = "refused"
)

// New builds a Runner.
func New(timeout time.Duration) *Runner {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &Runner{Timeout: timeout}
}

// Journal returns every command this Runner executed, in order.
func (r *Runner) Journal() []JournalEntry {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]JournalEntry, len(r.journal))
	copy(out, r.journal)
	return out
}

func (r *Runner) record(entry JournalEntry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.journal = append(r.journal, entry)
}

// Available reports whether a binary is on PATH.
func Available(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// Path resolves a binary on PATH, or "" if it is missing.
func Path(name string) string {
	p, err := exec.LookPath(name)
	if err != nil {
		return ""
	}
	return p
}

// Output runs a command and returns its stdout. A non-zero exit is an error.
func (r *Runner) Output(name string, args ...string) (string, error) {
	out, _, err := r.OutputAllowExit(nil, name, args...)
	return out, err
}

// OutputAllowExit runs a command, treating the listed exit codes as success, and
// returns stdout plus the exit code.
//
// The allowlist is not a convenience: `dnf check-update` exits 100 when updates
// exist, `pacman -Qu` exits 1 when there are none, and `apk version -l` exits 1
// on an empty result. Treating those as failures would report "updates
// unavailable" on a host whose updates were collected perfectly well.
func (r *Runner) OutputAllowExit(allowed []int, name string, args ...string) (string, int, error) {
	started := time.Now().UTC()
	entry := JournalEntry{
		Command:   strings.TrimSpace(name + " " + strings.Join(args, " ")),
		StartedAt: started,
		ExitCode:  -1,
	}
	finish := func(outcome string, code int) {
		entry.Outcome = outcome
		entry.ExitCode = code
		entry.Duration = time.Since(started).Round(time.Millisecond).String()
		r.record(entry)
	}

	// The allowlist is checked before the binary is even looked up: whether the
	// command exists on this host is none of our business until we have
	// established that we are permitted to run it.
	if _, ok := Allowed(name, args); !ok {
		finish(OutcomeRefused, -1)
		return "", -1, notAllowedError(name, args)
	}

	if !Available(name) {
		finish(OutcomeMissing, -1)
		return "", -1, fmt.Errorf("%s: %w", name, ErrNotFound)
	}

	ctx, cancel := context.WithTimeout(context.Background(), r.Timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	// Deterministic, parseable output regardless of the operator's locale: a
	// Russian or German LC_MESSAGES rewrites every table header these parsers
	// depend on.
	cmd.Env = append(cmd.Environ(), "LC_ALL=C", "LANG=C", "LANGUAGE=C")

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	code := cmd.ProcessState.ExitCode()

	if ctx.Err() == context.DeadlineExceeded {
		finish(OutcomeTimeout, code)
		return stdout.String(), code, fmt.Errorf("%s: timed out after %s", name, r.Timeout)
	}
	if err != nil {
		for _, ok := range allowed {
			if code == ok {
				finish(OutcomeOK, code)
				return stdout.String(), code, nil
			}
		}
		finish(OutcomeFailed, code)
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		if len(msg) > 300 {
			msg = msg[:300] + "…"
		}
		return stdout.String(), code, fmt.Errorf("%s exited %d: %s", name, code, msg)
	}
	finish(OutcomeOK, code)
	return stdout.String(), code, nil
}

// Lines splits command output into trimmed, non-empty lines.
func Lines(out string) []string {
	var lines []string
	for _, l := range strings.Split(out, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			lines = append(lines, l)
		}
	}
	return lines
}
