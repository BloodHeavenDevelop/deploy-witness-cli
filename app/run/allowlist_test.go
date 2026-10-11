package run

import (
	"errors"
	"strings"
	"testing"
)

func TestAllowedMatchesExactArgv(t *testing.T) {
	cases := []struct {
		name   string
		binary string
		args   []string
		want   bool
	}{
		{name: "a listed command with no arguments", binary: "systemd-detect-virt", want: true},
		{name: "a listed command with its exact arguments", binary: "pacman", args: []string{"-Q"}, want: true},
		{name: "a placeholder argument", binary: "systemctl", args: []string{"is-active", "nftables"}, want: true},
		{name: "a repeated placeholder", binary: "systemctl", args: []string{
			"show", "--property=Id", "--property=MainPID", "--property=User",
			"--property=ActiveEnterTimestamp", "sshd.service", "getty@tty1.service",
		}, want: true},

		// Everything below is what the allowlist exists to stop.
		{name: "an unlisted binary", binary: "curl", args: []string{"https://example.com"}},
		{name: "a shell", binary: "sh", args: []string{"-c", "id"}},
		{name: "a listed binary with unlisted arguments", binary: "pacman", args: []string{"-Syu"}},
		{name: "a listed binary with no arguments at all", binary: "pacman"},
		{name: "extra arguments appended to a listed form", binary: "pacman", args: []string{"-Q", "--root", "/"}},
		{name: "apt-get without the simulation flag", binary: "apt-get", args: []string{"dist-upgrade"}},
		{name: "dnf without the cache-only flag", binary: "dnf", args: []string{"-q", "check-update"}},
		{name: "a repeated placeholder with nothing in it", binary: "systemctl", args: []string{
			"show", "--property=Id", "--property=MainPID", "--property=User",
			"--property=ActiveEnterTimestamp",
		}},
		{name: "a placeholder carrying a shell metacharacter", binary: "systemctl",
			args: []string{"is-active", "nftables; rm -rf /"}},
		{name: "a placeholder carrying a substitution", binary: "systemctl",
			args: []string{"is-active", "$(id)"}},
		{name: "a placeholder carrying a newline", binary: "systemctl",
			args: []string{"is-active", "nftables\nreboot"}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := Allowed(tc.binary, tc.args); ok != tc.want {
				t.Fatalf("Allowed(%q, %q) = %v, want %v", tc.binary, tc.args, ok, tc.want)
			}
		})
	}
}

// The refusal has to happen in the Runner, not merely be available to callers who
// remember to ask — and it has to happen before the binary is even looked up, so
// that "not allowed" cannot be mistaken for "not installed".
func TestRunnerRefusesUnlistedCommand(t *testing.T) {
	r := New(0)

	out, code, err := r.OutputAllowExit(nil, "sh", "-c", "echo hello")
	if !errors.Is(err, ErrNotAllowed) {
		t.Fatalf("err = %v, want ErrNotAllowed", err)
	}
	if out != "" || code != -1 {
		t.Fatalf("a refused command must produce nothing: out = %q, code = %d", out, code)
	}

	journal := r.Journal()
	if len(journal) != 1 {
		t.Fatalf("journal has %d entries, want 1 — a refusal must be recorded, not swallowed", len(journal))
	}
	if journal[0].Outcome != OutcomeRefused {
		t.Fatalf("outcome = %q, want %q", journal[0].Outcome, OutcomeRefused)
	}
	if !strings.Contains(journal[0].Command, "sh -c echo hello") {
		t.Fatalf("journal does not name the command: %q", journal[0].Command)
	}
}

// A malformed entry would be a wildcard or a dead rule, and both are worse than a
// missing command: one grants too much, the other silently collects nothing.
func TestPublishedListIsWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, spec := range Commands() {
		if spec.Binary == "" {
			t.Errorf("a spec has no binary: %+v", spec)
		}
		if spec.Purpose == "" {
			t.Errorf("%s has no purpose — the published list is read by people deciding whether to trust it", spec)
		}
		if spec.Section == "" {
			t.Errorf("%s has no section", spec)
		}
		if seen[spec.String()] {
			t.Errorf("%s is listed twice", spec)
		}
		seen[spec.String()] = true

		for i, arg := range spec.Args {
			kind, repeat, ok := placeholder(arg)
			if !ok {
				// A bare "<" is `apk version -l <`, apk's own "older than"
				// selector, and a real literal. Anything longer that opens with
				// "<" is a mistyped placeholder, which would otherwise be
				// enforced as a literal nobody ever passes — a dead rule.
				if strings.HasPrefix(arg, "<") && arg != "<" {
					t.Errorf("%s: argument %d looks like a placeholder but does not parse: %q", spec, i, arg)
				}
				continue
			}
			if _, known := argPatterns[kind]; !known {
				t.Errorf("%s: argument %d uses unknown kind %q", spec, i, kind)
			}
			if repeat && i != len(spec.Args)-1 {
				t.Errorf("%s: a repeated placeholder must be last, but %q is at %d", spec, arg, i)
			}
		}
	}
}

// No pattern may admit anything that could turn one argument into two commands if
// the argument ever reached a shell — even though nothing here uses one.
func TestArgumentPatternsRejectMetacharacters(t *testing.T) {
	hostile := []string{
		"a b", "a;b", "a|b", "a&b", "a`b`", "a$(b)", "a${b}", "a\nb", "a\tb",
		"a>b", "a<b", "a'b", "a\"b", "a\\b", "a*b", "a?b", "a(b)", "a#b", "a!b",
	}
	// The one admitted exception, with its reason recorded next to the pattern:
	// systemd escapes device paths into service unit names with `\x2d`, so a real
	// unit on a real host carries a backslash. It is inert to execve.
	allowsBackslash := map[ArgKind]bool{ArgUnit: true}

	for kind, pattern := range argPatterns {
		for _, value := range hostile {
			if allowsBackslash[kind] && strings.Contains(value, `\`) {
				continue
			}
			// A leading slash makes the value plausible for the path kind, whose
			// pattern must reject it on the metacharacter alone.
			candidates := []string{value}
			if kind == ArgPath {
				candidates = []string{"/" + value}
			}
			for _, candidate := range candidates {
				if pattern.MatchString(candidate) {
					t.Errorf("kind %q accepts %q", kind, candidate)
				}
			}
		}
	}
}

// debsecan and arch-audit download their advisory data on every call (DW-53). The
// Runner refuses them on a run without --online, before looking the binary up, so
// the offline promise holds for child processes even if a collector forgets to
// check.
func TestRunnerRefusesNetworkCommandsOffline(t *testing.T) {
	r := New(0)
	if r.NetworkAllowed() {
		t.Fatal("a new Runner must not allow the network")
	}

	for _, argv := range [][]string{{"debsecan", "--format", "summary"}, {"arch-audit", "--json"}} {
		_, _, err := r.OutputAllowExit(nil, argv[0], argv[1:]...)
		if !errors.Is(err, ErrNetworkNotAllowed) {
			t.Errorf("%v: error = %v, want ErrNetworkNotAllowed", argv, err)
		}
	}
	for _, entry := range r.Journal() {
		if entry.Outcome != OutcomeRefused || entry.Network != "--online" {
			t.Errorf("journal entry = %+v, want refused and marked --online", entry)
		}
	}

	r.AllowNetwork(true)
	if _, _, err := r.OutputAllowExit(nil, "arch-audit", "--json"); errors.Is(err, ErrNetworkNotAllowed) {
		t.Error("with the network allowed, arch-audit must not be refused")
	}
}

// Every command that reaches the network says which flag permits it, and the only
// flag that may is --online: --egress and --upload are done by the binary itself.
func TestNetworkCommandsNameOnline(t *testing.T) {
	networked := NetworkCommands()
	if len(networked) == 0 {
		t.Fatal("debsecan and arch-audit must be marked as reaching the network")
	}
	for _, spec := range networked {
		if spec.Network != "--online" {
			t.Errorf("%s: network flag = %q, want --online", spec, spec.Network)
		}
	}
	for _, spec := range Commands() {
		if (spec.Binary == "debsecan" || spec.Binary == "arch-audit") && spec.Network == "" {
			t.Errorf("%s fetches advisories over the network and is not marked", spec)
		}
		if spec.Binary == "zypper" && !strings.Contains(strings.Join(spec.Args, " "), "--no-refresh") {
			t.Errorf("%s may refresh repositories: it needs --no-refresh", spec)
		}
	}
}

func TestChildEnvDropsRemoteEngines(t *testing.T) {
	environ := []string{
		"PATH=/usr/bin",
		"DOCKER_HOST=tcp://10.0.0.5:2375",
		"CONTAINER_HOST=ssh://core@10.0.0.6/run/podman/podman.sock",
	}
	got := strings.Join(childEnv(environ), " ")
	if strings.Contains(got, "DOCKER_HOST") || strings.Contains(got, "CONTAINER_HOST") || !strings.Contains(got, "PATH=") {
		t.Errorf("childEnv = %q, want the remote engine variables dropped", got)
	}

	local := []string{"DOCKER_HOST=unix:///run/user/1000/docker.sock"}
	if len(childEnv(local)) != 1 || len(RemoteEngineEnv(local)) != 0 {
		t.Error("a local unix socket must be kept")
	}
}
