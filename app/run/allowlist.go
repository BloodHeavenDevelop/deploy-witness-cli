package run

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// This file is the enforcement half of the promise that this binary only ever
// reads. Its companion, commands.go, is the list itself.
//
// The design is deliberately restrictive rather than merely conventional:
//
//   - A command that is not in the list cannot be executed. Not "should not" —
//     Runner refuses it, and the refusal is recorded in the journal so it shows up
//     in the report rather than only in a log nobody kept.
//   - Arguments are matched too, not just the binary. `apt-get dist-upgrade` is
//     only permitted with `-s`; being allowed to run apt-get is not the same as
//     being allowed to install packages.
//   - Free-form arguments exist (a unit name, a container id, a path) but every
//     one of them is constrained by a character class. Combined with the fact that
//     nothing here goes through a shell, that leaves no room for an argument to
//     become a second command.
//
// The same list is what `--commands` prints, so what the tool says it can run and
// what it can actually run cannot drift apart: there is one source for both.

// ErrNotAllowed is returned when something asks Runner to execute a command that
// is not on the published list. It is a defect in this tool, never a property of
// the audited host, so it is reported loudly rather than swallowed.
var ErrNotAllowed = errors.New("command is not on the published allowlist")

// ArgKind is the character class of one free-form argument. Kinds are deliberately
// coarse — they are a bound on what an argument may look like, not a validator of
// what it means.
type ArgKind string

const (
	// ArgUnit is a service unit or timer name: web.service, getty@tty1.service.
	ArgUnit ArgKind = "unit"
	// ArgSuite is a distribution suite or release codename: bookworm, 42.
	ArgSuite ArgKind = "suite"
	// ArgPath is an absolute filesystem path. Relative paths are rejected: every
	// path this tool passes to a command comes from a directory it walked itself.
	ArgPath ArgKind = "path"
	// ArgContainer is a container or volume or network name, or a short id.
	ArgContainer ArgKind = "container"
	// ArgImage is a container image reference, tag and digest included.
	ArgImage ArgKind = "image"
	// ArgUser is a local account name.
	ArgUser ArgKind = "user"
	// ArgName is the fallback for a plain identifier — a package, a profile, a
	// zone. No slashes, no spaces, no shell metacharacters.
	ArgName ArgKind = "name"
)

// argPatterns bounds each kind. Anchored, and none of them admits a space, a
// quote, a semicolon, a backtick or a dollar sign.
var argPatterns = map[ArgKind]*regexp.Regexp{
	// The backslash is here on evidence, not on principle. A real host in this
	// family runs
	//
	//     systemd-fsck@dev-disk-by\x2duuid-F9EA\x2dEBDF.service
	//
	// — systemd's own escaping of a device path, and an ordinary `--type=service`
	// unit. Excluding it cost a whole batch of `systemctl show` output on the first
	// machine the allowlist was tried on. It is admitted because nothing here goes
	// through a shell: to execve, a backslash is an ordinary byte in an argument.
	ArgUnit:  regexp.MustCompile(`^[A-Za-z0-9@:._\\-]{1,255}$`),
	ArgSuite: regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`),
	// 1000 is the ceiling Go's regexp allows on a repeat count, and it is well
	// past PATH_MAX for anything this tool passes to a command.
	ArgPath:      regexp.MustCompile(`^/[A-Za-z0-9@:+,%._/-]{0,1000}$`),
	ArgContainer: regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`),
	ArgImage:     regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,255}$`),
	ArgUser:      regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`),
	ArgName:      regexp.MustCompile(`^[A-Za-z0-9@+._-]{1,128}$`),
}

// Spec is one command the tool is permitted to run.
//
// Args is the exact argument vector, except that an element written as `<kind>`
// stands for one free-form argument of that kind and `<kind>...` for one or more
// of them at the end. Anything else must match literally.
type Spec struct {
	Binary string
	Args   []string
	// Purpose is what the command is read for, in the reader's terms. It is
	// printed by --commands and copied into the documentation, so it answers
	// "why is this tool allowed to run that?" without reference to the code.
	Purpose string
	// Section is the audit section that needs it, or "core" for the ones the run
	// itself depends on.
	Section string
	// MaxRepeat bounds a trailing `<kind>...` argument. Zero means the default.
	MaxRepeat int
}

// defaultMaxRepeat bounds a repeated argument when a Spec does not say. It is the
// systemd chunk size with room to spare; an argv longer than this is a bug in the
// caller, not a host with many units.
const defaultMaxRepeat = 256

// String renders the spec the way --commands and the docs print it.
//
// Control characters are escaped rather than emitted. Two entries carry a literal
// tab and a trailing newline inside a `--qf` format string, and printing those raw
// broke the published list into stray blank lines — in the one output whose whole
// job is to be read carefully before the binary is trusted.
func (s Spec) String() string {
	if len(s.Args) == 0 {
		return s.Binary
	}
	args := make([]string, len(s.Args))
	for i, arg := range s.Args {
		args[i] = escapeControl(arg)
	}
	return s.Binary + " " + strings.Join(args, " ")
}

// escapeControl makes a whitespace-carrying argument printable without changing
// what is matched: only the rendering passes through here.
func escapeControl(arg string) string {
	if !strings.ContainsAny(arg, "\t\n\r") {
		return arg
	}
	return strings.NewReplacer("\t", `\t`, "\n", `\n`, "\r", `\r`).Replace(arg)
}

// matches reports whether argv is permitted by this spec.
func (s Spec) matches(argv []string) bool {
	maxRepeat := s.MaxRepeat
	if maxRepeat <= 0 {
		maxRepeat = defaultMaxRepeat
	}

	for i, want := range s.Args {
		kind, repeat, isPlaceholder := placeholder(want)
		if !isPlaceholder {
			if i >= len(argv) || argv[i] != want {
				return false
			}
			continue
		}

		pattern, known := argPatterns[kind]
		if !known {
			// An unknown kind is a typo in commands.go. Refusing is the only safe
			// reading: a placeholder nobody can match must not become a wildcard.
			return false
		}

		if !repeat {
			if i >= len(argv) || !pattern.MatchString(argv[i]) {
				return false
			}
			continue
		}

		// A repeated placeholder is only ever the last element, and it must
		// consume at least one argument.
		rest := argv[i:]
		if len(rest) == 0 || len(rest) > maxRepeat {
			return false
		}
		for _, got := range rest {
			if !pattern.MatchString(got) {
				return false
			}
		}
		return true
	}

	// No repeat consumed the tail, so the lengths have to agree exactly.
	return len(argv) == len(s.Args)
}

// placeholder decodes `<kind>` and `<kind>...`.
func placeholder(token string) (kind ArgKind, repeat bool, ok bool) {
	repeat = strings.HasSuffix(token, "...")
	trimmed := strings.TrimSuffix(token, "...")
	if !strings.HasPrefix(trimmed, "<") || !strings.HasSuffix(trimmed, ">") {
		return "", false, false
	}
	return ArgKind(trimmed[1 : len(trimmed)-1]), repeat, true
}

// Allowed reports whether the command may be executed, and returns the spec that
// permits it.
func Allowed(binary string, args []string) (Spec, bool) {
	for _, spec := range commands {
		if spec.Binary != binary {
			continue
		}
		if spec.matches(args) {
			return spec, true
		}
	}
	return Spec{}, false
}

// Commands returns the published list, sorted for stable output. This is the one
// place --commands and the documentation read, so neither can describe a set of
// commands other than the one that is enforced.
func Commands() []Spec {
	out := make([]Spec, len(commands))
	copy(out, commands)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Section != out[j].Section {
			return out[i].Section < out[j].Section
		}
		if out[i].Binary != out[j].Binary {
			return out[i].Binary < out[j].Binary
		}
		return strings.Join(out[i].Args, " ") < strings.Join(out[j].Args, " ")
	})
	return out
}

// notAllowedError names the refused command without interpolating the arguments
// into a message that might later be logged somewhere less careful.
func notAllowedError(binary string, args []string) error {
	return fmt.Errorf("%s (%d argument(s)): %w", binary, len(args), ErrNotAllowed)
}
