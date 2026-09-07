// Package scheduler enumerates the scheduled work already installed on the host.
//
// It exists because a deployment almost always adds some: a nightly dump, a
// certificate renewal, a log rotation. Adding one blind is how two jobs end up
// writing the same file at 03:00, or how a hand-written renewal hook quietly
// duplicates the one the panel already installed. So the audit has to be able to
// say what is scheduled now — and cron hides in more places than anybody
// remembers:
//
//	/etc/crontab                 system crontab, with a user field
//	/etc/cron.d/*                drop-ins, also with a user field
//	/etc/cron.{hourly,daily,…}   scripts, run by run-parts, not crontab lines
//	/var/spool/cron/*            per-user crontabs (RHEL layout)
//	/var/spool/cron/crontabs/*   per-user crontabs (Debian/SUSE layout)
//	/var/spool/at*               one-shot at jobs
//	systemd timers               where scheduled work lives on a modern host
//
// Two properties of this package are not negotiable:
//
//   - The per-user spool directories are root-only. Running unprivileged, this
//     package finds *no* per-user jobs, and it says so with Degrade rather than
//     returning a short list that reads like a complete one. "There are no cron
//     jobs" and "we were not allowed to look" are different answers.
//   - Every reported command goes through maskSecrets first. See mask.go.
package scheduler

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/run"
)

// Job kinds, from the vocabulary model.ScheduledJob documents.
const (
	kindCrontab = "crontab"
	kindCronD   = "cron.d"
	kindAt      = "at"
	kindTimer   = "timer"
)

// Bounds. A crontab is a text file a person wrote, so these are generous enough
// never to bite on a sane host — and they exist for the one that is not sane.
// Every one of them reports itself when it bites; none of them truncates quietly.
const (
	// maxCrontabBytes caps one crontab read. 256 KiB is several thousand lines.
	maxCrontabBytes = 256 << 10
	// maxFilesPerDir caps how many entries one cron directory contributes.
	maxFilesPerDir = 512
	// maxJobs caps the whole result set.
	maxJobs = 2000
	// showChunk bounds one `systemctl show` argument vector, as in the services
	// collector. It stays under the allowlist's MaxRepeat for that command.
	showChunk = 100
)

// Where to look. They are joined onto a root so the scanners can be pointed at a
// fixture tree in a test; in production the root is "".
const (
	pathEtcCrontab = "/etc/crontab"
	pathEtcCronD   = "/etc/cron.d"
	pathCronSpool  = "/var/spool/cron"
	pathAtSpool    = "/var/spool/at"
)

// cronCadences are the run-parts directories, in the order a reader expects.
var cronCadences = []string{"hourly", "daily", "weekly", "monthly"}

// Collect fills caps.Jobs.
func Collect(runner *run.Runner, caps *model.Capabilities, result *model.SectionResult) {
	caps.Jobs = Scan(runner, result)
}

// Scan is Collect's body, exported for one caller: the backup collector needs the
// same cron and timer inventory to decide whether anything on this host actually
// runs a backup.
//
// Sharing it rather than re-implementing it is a correctness decision, not a
// tidiness one. A second cron parser would be a second place for the secret
// masking to be forgotten, and a second set of answers to "did we manage to read
// the spool directory" — which is exactly the disagreement an audit must not
// contain.
func Scan(runner *run.Runner, result *model.SectionResult) []model.ScheduledJob {
	return scan(runner, "", result)
}

func scan(runner *run.Runner, root string, result *model.SectionResult) []model.ScheduledJob {
	var jobs []model.ScheduledJob
	var problems []string

	collect := func(found []model.ScheduledJob, issues []string) {
		jobs = append(jobs, found...)
		problems = append(problems, issues...)
	}

	collect(scanEtcCrontab(root))
	collect(scanCronD(root))
	collect(scanCronDirs(root))
	collect(scanUserSpools(root))

	atJobs, atProblems := scanAtSpool(root)
	problems = append(problems, atProblems...)
	if len(atJobs) > 0 {
		jobs = append(jobs, atJobs...)
		// An at spool file is a shell script with the submitting shell's entire
		// environment pasted at the top. That is precisely where its secrets are,
		// so the file is never opened: the job is reported as present, with its
		// owner and its path, and with no command.
		result.Note(fmt.Sprintf("scheduled jobs: %d one-shot at job(s) found; their command is not reported because an at spool file embeds the submitting shell's whole environment", len(atJobs)))
	}

	// The per-user spools are mode 0700 (RHEL) or a 1730 root:crontab directory
	// (Debian). Unprivileged, the walk above found nothing there and cannot.
	if os.Geteuid() != 0 {
		own, name := ownCrontab(runner, result)
		jobs = append(jobs, own...)

		reported := "no account's"
		if name != "" {
			reported = name + "'s"
		}
		if spoolExists(root) {
			result.Degrade("scheduled jobs: not running as root, so the per-user crontabs under " +
				filepath.Join(root, pathCronSpool) + " are unreadable; only " + reported +
				" own crontab was collected. Jobs owned by other accounts exist on most hosts and are not in this report")
		} else {
			// A missing spool directory is a complete answer rather than a gap:
			// there is nothing there to be denied. It is still stated, because the
			// claim only covers the two standard paths — another cron
			// implementation keeps its spool somewhere else entirely.
			result.Note("scheduled jobs: no per-user cron spool directory exists at " +
				filepath.Join(root, pathCronSpool) + " or " + filepath.Join(root, pathCronSpool, "crontabs") +
				", so this host has no per-user crontabs in the standard locations; " + reported +
				" own crontab was read directly")
		}
	}

	jobs = append(jobs, collectTimers(runner, result)...)

	if len(problems) > 0 {
		result.Degrade("scheduled jobs: " + strings.Join(problems, "; "))
	}

	sort.SliceStable(jobs, func(i, j int) bool {
		a, b := jobs[i], jobs[j]
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		if a.Schedule != b.Schedule {
			return a.Schedule < b.Schedule
		}
		return a.Command < b.Command
	})

	if len(jobs) > maxJobs {
		result.Note(fmt.Sprintf("scheduled jobs: %d entries found, only the first %d are reported", len(jobs), maxJobs))
		jobs = jobs[:maxJobs]
	}
	return jobs
}

// ─────────────────────────────────────────────────────── crontab line parsing

// envAssignment matches a crontab environment line: SHELL=, PATH=, MAILTO=,
// CRON_TZ=, PGPASSWORD=. Such a line is not a job, and its *value* is never
// stored — the whole line is dropped here rather than parsed and masked, because
// the safest handling of a value we have no use for is not to touch it.
//
// It cannot collide with a real job line: a schedule field starts with a digit,
// an asterisk or an @, never with a letter or an underscore.
var envAssignment = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*\s*=`)

// cronNicknames are vixie cron's shorthand schedules. @reboot is the one that
// matters most for a witness: it is the schedule that fires during the reboot
// the deployment is about to perform.
var cronNicknames = map[string]bool{
	"@reboot": true, "@yearly": true, "@annually": true, "@monthly": true,
	"@weekly": true, "@daily": true, "@midnight": true, "@hourly": true,
}

// userField matches a plausible account name in the sixth field of a system
// crontab. It is a heuristic and it has a known failure: a malformed /etc/cron.d
// line that omits the user field entirely and starts its command with a bare word
// (`cd /srv && …`) will have that word read as the owner. Guessing the other way
// — treating every sixth field as part of the command — misreads every correct
// file instead, which is worse.
var userField = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,31}\$?$`)

// unitName mirrors run.ArgUnit and accountName mirrors run.ArgUser. Anything
// outside them would be refused by the allowlist, and a refusal is recorded as a
// defect in this tool, so a name that cannot pass is dropped before it is ever
// submitted.
var (
	unitName    = regexp.MustCompile(`^[A-Za-z0-9@:._\\-]{1,255}$`)
	accountName = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
)

// parseCrontab turns crontab-syntax text into jobs.
//
// withUser selects the six-field system form (/etc/crontab, /etc/cron.d), where
// the field after the schedule is the account the job runs as. A per-user
// crontab has no such field and its owner comes from the file's name instead.
func parseCrontab(content, source, kind, defaultOwner string, withUser bool) []model.ScheduledJob {
	var jobs []model.ScheduledJob
	for _, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if envAssignment.MatchString(line) {
			continue
		}
		schedule, owner, command, ok := splitCronLine(line, withUser)
		if !ok {
			continue
		}
		if owner == "" {
			owner = defaultOwner
		}
		jobs = append(jobs, model.ScheduledJob{
			Kind:     kind,
			Owner:    owner,
			Schedule: schedule,
			Command:  maskSecrets(command),
			Source:   source,
		})
	}
	return jobs
}

// splitCronLine splits one job line into schedule, owner and command. owner is
// empty when the line carries no user field.
func splitCronLine(line string, withUser bool) (schedule, owner, command string, ok bool) {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return "", "", "", false
	}

	var rest []string
	if nick := strings.ToLower(fields[0]); cronNicknames[nick] {
		schedule = nick
		rest = fields[1:]
	} else {
		// Five schedule fields plus at least one word of command.
		if len(fields) < 6 {
			return "", "", "", false
		}
		schedule = strings.Join(fields[:5], " ")
		rest = fields[5:]
	}
	if len(rest) == 0 {
		return "", "", "", false
	}

	if withUser && len(rest) > 1 && userField.MatchString(rest[0]) {
		owner = rest[0]
		rest = rest[1:]
	}

	command = cutAtPercent(strings.Join(rest, " "))
	if command == "" {
		return "", "", "", false
	}
	return schedule, owner, command, true
}

// cutAtPercent ends the command at the first unescaped percent sign.
//
// That is what cron itself does — crontab(5): the command runs up to the first
// unescaped %, and everything after it is handed to the job on standard input.
// Cutting there is therefore accurate rather than lossy, and it has a second
// benefit: an interactive password typed into that stdin block never reaches the
// report.
func cutAtPercent(command string) string {
	for i := 0; i < len(command); i++ {
		if command[i] == '%' && (i == 0 || command[i-1] != '\\') {
			return strings.TrimSpace(command[:i])
		}
	}
	return command
}

// ──────────────────────────────────────────────────────────── the file scanners
//
// Each scanner takes the filesystem root to read from — "" on a real host, a
// fixture directory in a test — and returns the jobs it found plus a list of
// things it could not read. The second return value is the honesty channel: it is
// what stops a permission error from being rendered as an empty result.

// scanEtcCrontab reads /etc/crontab, the six-field system crontab.
func scanEtcCrontab(root string) ([]model.ScheduledJob, []string) {
	path := filepath.Join(root, pathEtcCrontab)
	content, truncated, err := readLimited(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, []string{path + ": " + err.Error()}
	}
	var problems []string
	if truncated {
		problems = append(problems, fmt.Sprintf("%s: only the first %d bytes were read", path, maxCrontabBytes))
	}
	return parseCrontab(content, path, kindCrontab, "root", true), problems
}

// scanCronD reads /etc/cron.d. Its files use the same six-field form as
// /etc/crontab, user field included — which is the field most often mistaken for
// the first word of the command.
func scanCronD(root string) ([]model.ScheduledJob, []string) {
	dir := filepath.Join(root, pathEtcCronD)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, []string{dir + ": " + err.Error()}
	}

	var jobs []model.ScheduledJob
	var problems []string
	seen := 0
	for _, entry := range entries {
		if entry.IsDir() || ignoredName(entry.Name()) {
			continue
		}
		seen++
		if seen > maxFilesPerDir {
			problems = append(problems, fmt.Sprintf("%s: more than %d files, the rest were not read", dir, maxFilesPerDir))
			break
		}
		path := filepath.Join(dir, entry.Name())
		content, truncated, err := readLimited(path)
		if err != nil {
			problems = append(problems, path+": "+err.Error())
			continue
		}
		if truncated {
			problems = append(problems, fmt.Sprintf("%s: only the first %d bytes were read", path, maxCrontabBytes))
		}
		jobs = append(jobs, parseCrontab(content, path, kindCronD, "root", true)...)
	}
	return jobs, problems
}

// scanCronDirs lists /etc/cron.hourly, .daily, .weekly and .monthly.
//
// These hold executables, not crontab lines: run-parts executes each file, and
// the schedule is the directory's own cadence rather than anything inside the
// file. Nothing here reads a file's contents.
func scanCronDirs(root string) ([]model.ScheduledJob, []string) {
	var jobs []model.ScheduledJob
	var problems []string

	for _, cadence := range cronCadences {
		dir := filepath.Join(root, "/etc/cron."+cadence)
		entries, err := os.ReadDir(dir)
		if err != nil {
			if !os.IsNotExist(err) {
				problems = append(problems, dir+": "+err.Error())
			}
			continue
		}
		seen := 0
		for _, entry := range entries {
			if entry.IsDir() || ignoredName(entry.Name()) {
				continue
			}
			seen++
			if seen > maxFilesPerDir {
				problems = append(problems, fmt.Sprintf("%s: more than %d files, the rest were not listed", dir, maxFilesPerDir))
				break
			}
			jobs = append(jobs, model.ScheduledJob{
				Kind: "cron." + cadence,
				// run-parts is invoked by root, from /etc/crontab or from
				// anacron. A script in here always runs as root.
				Owner:    "root",
				Schedule: cadence,
				Command:  maskSecrets(filepath.Join(dir, entry.Name())),
				Source:   dir,
			})
		}
	}
	return jobs, problems
}

// scanUserSpools reads the per-user crontabs, in both layouts the distributions
// use: /var/spool/cron/<user> on RHEL and SUSE, /var/spool/cron/crontabs/<user>
// on Debian. The owner is the file's name — these files have no user field.
//
// This is the scanner that returns nothing when the audit runs unprivileged, and
// the reason scan() degrades the section in that case.
func scanUserSpools(root string) ([]model.ScheduledJob, []string) {
	var jobs []model.ScheduledJob
	var problems []string

	for _, base := range []string{pathCronSpool, filepath.Join(pathCronSpool, "crontabs")} {
		dir := filepath.Join(root, base)
		entries, err := os.ReadDir(dir)
		if err != nil {
			if !os.IsNotExist(err) {
				problems = append(problems, dir+": "+err.Error())
			}
			continue
		}
		seen := 0
		for _, entry := range entries {
			// "crontabs" and "atjobs" are the sibling directories, not crontabs.
			if entry.IsDir() || ignoredName(entry.Name()) {
				continue
			}
			seen++
			if seen > maxFilesPerDir {
				problems = append(problems, fmt.Sprintf("%s: more than %d files, the rest were not read", dir, maxFilesPerDir))
				break
			}
			path := filepath.Join(dir, entry.Name())
			content, truncated, err := readLimited(path)
			if err != nil {
				problems = append(problems, path+": "+err.Error())
				continue
			}
			if truncated {
				problems = append(problems, fmt.Sprintf("%s: only the first %d bytes were read", path, maxCrontabBytes))
			}
			jobs = append(jobs, parseCrontab(content, path, kindCrontab, entry.Name(), false)...)
		}
	}
	return jobs, problems
}

// atJobName matches an at spool file: a queue letter followed by hex digits.
var atJobName = regexp.MustCompile(`^[a-zA-Z][0-9A-Fa-f]{5,}$`)

// scanAtSpool lists one-shot at jobs. They are easy to forget and they are the
// ones nobody expects to fire during a deployment window.
//
// The Command is left empty on purpose: an at job file is the submitting shell's
// environment followed by the command, so reading it would mean reading exported
// variable values. scan() attaches a note saying so, because an empty Command
// that nobody explains is the sort of blank a reader fills in optimistically.
func scanAtSpool(root string) ([]model.ScheduledJob, []string) {
	var jobs []model.ScheduledJob
	var problems []string

	dirs, err := filepath.Glob(filepath.Join(root, pathAtSpool+"*"))
	if err != nil {
		problems = append(problems, filepath.Join(root, pathAtSpool)+"*: "+err.Error())
	}
	// Debian keeps at's queue beside cron's.
	dirs = append(dirs, filepath.Join(root, pathCronSpool, "atjobs"))

	for _, dir := range dirs {
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			continue
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			problems = append(problems, dir+": "+err.Error())
			continue
		}
		seen := 0
		for _, entry := range entries {
			if entry.IsDir() || !atJobName.MatchString(entry.Name()) {
				continue
			}
			seen++
			if seen > maxFilesPerDir {
				problems = append(problems, fmt.Sprintf("%s: more than %d files, the rest were not listed", dir, maxFilesPerDir))
				break
			}
			path := filepath.Join(dir, entry.Name())
			jobs = append(jobs, model.ScheduledJob{
				Kind:     kindAt,
				Owner:    fileOwner(path),
				Schedule: "one-shot",
				Source:   path,
			})
		}
	}
	return jobs, problems
}

// ─────────────────────────────────────────────────────────────── systemd timers

// collectTimers reads the timer list from systemd.
func collectTimers(runner *run.Runner, result *model.SectionResult) []model.ScheduledJob {
	if runner == nil {
		return nil
	}
	if !run.Available("systemctl") {
		// No systemd. That is a complete answer on an OpenRC or SysV host, not a
		// gap, so it is a note rather than a degrade.
		result.Note("scheduled jobs: systemctl is not installed, so there are no systemd timers to enumerate")
		return nil
	}

	out, _, err := runner.OutputAllowExit([]int{1}, "systemctl", "list-timers",
		"--all", "--no-pager", "--plain", "--no-legend")
	if err != nil {
		if errors.Is(err, run.ErrNotFound) {
			result.Note("scheduled jobs: systemctl is not installed, so there are no systemd timers to enumerate")
			return nil
		}
		result.Degrade("scheduled jobs: systemctl list-timers failed (" + err.Error() + "); systemd timers are not in this report")
		return nil
	}

	jobs := parseTimers(out)
	resolveTimerOwners(runner, jobs, result)
	return jobs
}

// parseTimers reads `systemctl list-timers --all --no-pager --plain --no-legend`.
//
// The columns are NEXT, LEFT, LAST, PASSED, UNIT, ACTIVATES, and the first four
// are made of a variable number of whitespace-separated words ("n/a",
// "1 week 2 days left", "Mon 2026-08-17 03:00:00 UTC"). Rather than counting
// words, the parser anchors on the one token that is unambiguous: the unit name
// ends in ".timer". Everything before it is the timing, everything after it is
// what the timer starts.
func parseTimers(out string) []model.ScheduledJob {
	var jobs []model.ScheduledJob
	for _, line := range run.Lines(out) {
		// --no-legend should suppress it, but older systemd prints the footer
		// anyway.
		if strings.Contains(line, "timers listed") {
			continue
		}
		fields := strings.Fields(line)
		unitAt := -1
		for i, field := range fields {
			if strings.HasSuffix(field, ".timer") {
				unitAt = i
				break
			}
		}
		if unitAt < 0 {
			continue
		}

		unit := fields[unitAt]
		var activates []string
		for _, field := range fields[unitAt+1:] {
			field = strings.Trim(field, ",")
			if field == "" || field == "-" || field == "n/a" {
				continue
			}
			activates = append(activates, field)
		}
		if len(activates) == 0 {
			// systemd's own default: foo.timer starts foo.service unless Unit=
			// says otherwise.
			activates = []string{strings.TrimSuffix(unit, ".timer") + ".service"}
		}

		jobs = append(jobs, model.ScheduledJob{
			Kind: kindTimer,
			// Filled in by resolveTimerOwners; "unknown" is what survives when
			// that query is not possible, and it is the honest value.
			Owner:    "unknown",
			Schedule: timerSchedule(fields[:unitAt]),
			Command:  maskSecrets(strings.Join(activates, ", ")),
			Source:   unit,
		})
	}
	return jobs
}

// timerSchedule renders the timing columns.
//
// list-timers reports when the timer will next fire, not the OnCalendar
// expression behind it; recovering the expression would mean a query per unit.
// The label says "next" so the reader is not left thinking they are looking at a
// recurrence rule.
func timerSchedule(timing []string) string {
	if len(timing) == 0 {
		return "unknown"
	}
	if timing[0] == "n/a" || timing[0] == "-" {
		return "next n/a"
	}
	// "Mon 2026-08-17 03:00:00 UTC" — four words.
	return "next " + normaliseTimestamp(strings.Join(timing[:min(4, len(timing))], " "))
}

// normaliseTimestamp converts systemd's local-time stamp to the UTC form the rest
// of the report uses, because this tool stores UTC and lets the reader convert.
//
// An unrecognised stamp is passed through untouched rather than reinterpreted.
// That matters more than it looks: Go resolves a zone abbreviation it does not
// know to offset zero, so "rendering" such a stamp as UTC would invent a time
// that is hours away from the one systemd printed. A stamp we cannot convert is
// still evidence; a converted one that is wrong is not.
func normaliseTimestamp(raw string) string {
	parsed, err := time.Parse("Mon 2006-01-02 15:04:05 MST", raw)
	if err != nil {
		return raw
	}
	// A zero offset is only believable when the abbreviation actually says so —
	// systemd prints the host's own zone, and the host is what we are running on,
	// so a known abbreviation resolves correctly here.
	if _, offset := parsed.Zone(); offset == 0 &&
		!strings.HasSuffix(raw, "UTC") && !strings.HasSuffix(raw, "GMT") {
		return raw
	}
	return parsed.UTC().Format("2006-01-02 15:04:05") + " UTC"
}

// resolveTimerOwners fills in the account each timer's unit runs as.
//
// list-timers does not carry it, so it comes from one batched `systemctl show`
// over the activated units — the same query the services collector already
// makes, reused rather than duplicated. A timer whose unit cannot be queried
// keeps Owner "unknown"; guessing root would be wrong on exactly the units where
// it matters.
func resolveTimerOwners(runner *run.Runner, jobs []model.ScheduledJob, result *model.SectionResult) {
	positions := map[string][]int{}
	var units []string
	for i := range jobs {
		unit, _, _ := strings.Cut(jobs[i].Command, ",")
		unit = strings.TrimSpace(unit)
		if !unitName.MatchString(unit) {
			continue
		}
		if _, seen := positions[unit]; !seen {
			units = append(units, unit)
		}
		positions[unit] = append(positions[unit], i)
	}
	if len(units) == 0 {
		return
	}

	for start := 0; start < len(units); start += showChunk {
		end := min(start+showChunk, len(units))
		args := append([]string{"show",
			"--property=Id",
			"--property=MainPID",
			"--property=User",
			"--property=ActiveEnterTimestamp",
		}, units[start:end]...)

		out, _, err := runner.OutputAllowExit([]int{1}, "systemctl", args...)
		if err != nil {
			result.Degrade("scheduled jobs: could not resolve which account each systemd timer runs as (systemctl show: " +
				err.Error() + "); their Owner stays \"unknown\"")
			return
		}

		for _, block := range strings.Split(out, "\n\n") {
			properties := map[string]string{}
			for _, line := range run.Lines(block) {
				if key, value, ok := strings.Cut(line, "="); ok {
					properties[key] = value
				}
			}
			id := properties["Id"]
			if id == "" {
				continue
			}
			owner := properties["User"]
			if owner == "" {
				// systemd reports an empty User for units running as root.
				owner = "root"
			}
			for _, i := range positions[id] {
				jobs[i].Owner = owner
			}
		}
	}
}

// ─────────────────────────────────────────────────────────── the user's own crontab

// ownCrontab reads the crontab of the account the audit is running as.
//
// This is the one place `crontab -l -u <user>` can do any good: only root may ask
// for somebody else's crontab, so on an unprivileged run the single account whose
// spool file is reachable is our own. Asking for every account in /etc/passwd
// would be one refused subprocess per user and would still report nothing.
func ownCrontab(runner *run.Runner, result *model.SectionResult) ([]model.ScheduledJob, string) {
	if runner == nil {
		return nil, ""
	}
	current, err := user.Current()
	if err != nil {
		result.Degrade("scheduled jobs: could not determine the current account (" + err.Error() + "), so its own crontab was not read")
		return nil, ""
	}
	name := current.Username
	// The allowlist bounds this argument; a name outside it would be refused and
	// recorded as a defect in this tool, so it is dropped here instead.
	if !accountName.MatchString(name) {
		result.Degrade("scheduled jobs: the current account name is not in a form this tool will pass to a command, so its own crontab was not read")
		return nil, ""
	}

	// crontab exits 1 with "no crontab for <user>" when the account has none,
	// which is an answer rather than a failure.
	out, _, err := runner.OutputAllowExit([]int{1}, "crontab", "-l", "-u", name)
	if err != nil {
		if !errors.Is(err, run.ErrNotFound) {
			result.Degrade("scheduled jobs: crontab -l -u " + name + " failed (" + err.Error() + ")")
		}
		return nil, name
	}
	return parseCrontab(out, "crontab -l -u "+name, kindCrontab, name, false), name
}

// ─────────────────────────────────────────────────────────────────────── helpers

// readLimited reads at most maxCrontabBytes of a file and says whether it hit
// the ceiling. A crontab is a hand-written text file; anything larger than this
// is either not a crontab or is not going to be read by a person either.
func readLimited(path string) (content string, truncated bool, err error) {
	file, err := os.Open(path)
	if err != nil {
		return "", false, err
	}
	defer file.Close()

	buf, err := io.ReadAll(io.LimitReader(file, maxCrontabBytes+1))
	if err != nil {
		return "", false, err
	}
	if len(buf) > maxCrontabBytes {
		return string(buf[:maxCrontabBytes]), true, nil
	}
	return string(buf), false, nil
}

// spoolExists reports whether a per-user cron spool directory is there at all.
//
// It is what separates the two unprivileged answers: "there is a spool directory
// and we were refused" is a gap in the audit, while "there is no spool directory"
// is a complete finding. Stat succeeds on a mode 0700 directory, so this question
// is answerable without being allowed to read it.
func spoolExists(root string) bool {
	for _, base := range []string{pathCronSpool, filepath.Join(pathCronSpool, "crontabs")} {
		if info, err := os.Stat(filepath.Join(root, base)); err == nil && info.IsDir() {
			return true
		}
	}
	return false
}

// ignoredName filters the files a cron directory accumulates and cron itself
// skips: editor backups, package-manager leftovers, dotfiles.
func ignoredName(name string) bool {
	if name == "" || strings.HasPrefix(name, ".") || strings.HasSuffix(name, "~") {
		return true
	}
	for _, suffix := range []string{
		".bak", ".old", ".orig", ".disabled", ".swp",
		".dpkg-dist", ".dpkg-old", ".dpkg-new", ".dpkg-tmp",
		".rpmsave", ".rpmnew", ".rpmorig", ".ucf-dist", ".ucf-old", ".ucf-new",
	} {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
}

// fileOwner resolves a file's owning account name, falling back to the numeric
// uid and then to "unknown". It is used for at jobs, whose owner is recorded
// nowhere but in the file's ownership.
func fileOwner(path string) string {
	info, err := os.Stat(path)
	if err != nil {
		return "unknown"
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "unknown"
	}
	uid := fmt.Sprintf("%d", stat.Uid)
	if account, err := user.LookupId(uid); err == nil {
		return account.Username
	}
	return "uid:" + uid
}
