// Package backup establishes what the host does about backups, and — the part
// that actually decides the answer — when it last did it.
//
// The three fields it fills are deliberately different kinds of evidence, and the
// report is worth reading only if they are kept apart:
//
//	Tools      something that can take a backup is installed. Weak on its own:
//	           an installed restic that nothing ever invokes is not a backup.
//	Jobs       something scheduled appears to run one. Stronger — this is intent.
//	Locations  something has been written, and here is the date. This is the one
//	           that can contradict the other two, and it usually does: a /backup
//	           directory whose newest file is fourteen months old is the finding,
//	           and the reason "there is a /backup directory" is not reassurance.
//
// Nothing here opens a backup file. Sizes and modification times come from stat;
// contents are never read, never parsed and never reported.
//
// When none of the three finds anything, that is a real, reportable state of the
// host — "this machine has no backups" — and it goes in Note as a statement, not
// as an error.
package backup

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/collect/scheduler"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/run"
)

// conventionalRoots are where a backup ends up when nobody chose deliberately.
// They are checked whether or not any backup tool is installed: a nightly
// `tar | ssh` writes into /backup just as happily as restic does.
var conventionalRoots = []string{
	"/backup", "/backups", "/var/backups", "/srv/backup", "/mnt/backup",
}

// maxJobPaths bounds how many repository paths are taken from the scheduled jobs.
// It is a bound on trust as much as on work: these paths come from a text file a
// person wrote.
const maxJobPaths = 8

// maxJobLine truncates one reported job. A cron line can be a whole shell script.
const maxJobLine = 300

// Collect fills caps.Backup.
func Collect(runner *run.Runner, caps *model.Capabilities, result *model.SectionResult) {
	caps.Backup = collect(runner, caps, "", time.Now().UTC(), defaultLimits, result)
}

func collect(runner *run.Runner, caps *model.Capabilities, root string, now time.Time,
	lim limits, result *model.SectionResult) model.BackupPosture {

	posture := model.BackupPosture{}
	var notes []string

	posture.Tools = detectTools(runner)

	// The scheduled work is taken from the scheduler collector's output when it has
	// already run. When it has not — the order the audit calls its collectors in is
	// not this package's business — the same scan is repeated through the helper
	// that collector exports. Either way there is one cron parser and one secret
	// mask on this host, which is why this package does not carry its own.
	jobs := caps.Jobs
	if len(jobs) == 0 && runner != nil {
		jobs = scheduler.Scan(runner, result)
	}
	posture.Jobs = backupJobs(jobs)

	locations, locationNotes, degradations := scanLocations(root, jobs, now, lim)
	posture.Locations = locations
	notes = append(notes, locationNotes...)
	notes = append(notes, degradations...)

	// A bound that bit or a directory that holds nothing is a note; a directory we
	// were not allowed to read is a gap, and the section says so.
	for _, note := range degradations {
		result.Degrade("backup: " + note)
	}
	for _, note := range locationNotes {
		result.Note("backup: " + note)
	}

	if os.Geteuid() != 0 {
		// The scheduler collector already establishes exactly which crontabs were
		// readable and degrades the section accordingly; the posture repeats the
		// limitation without restating its details, because BackupPosture.Jobs is
		// read on its own and a short job list has to carry the reason it is short.
		notes = append(notes, "not running as root: a backup job owned by another account may not appear in Jobs, since the per-user crontabs are not readable unprivileged")
	}

	// Each negative is stated on its own, because they are three different facts
	// and a reader acts on them differently. All three at once is the state this
	// collector exists to be able to report out loud.
	if len(posture.Tools) == 0 && len(posture.Jobs) == 0 && len(posture.Locations) == 0 {
		notes = append(notes, "no backup tool is installed, no scheduled job looks like a backup and none of the conventional backup directories ("+
			strings.Join(conventionalRoots, ", ")+") exists: nothing observed on this host takes backups")
	} else {
		if len(posture.Tools) == 0 {
			notes = append(notes, "no backup tool was found on PATH")
		}
		if len(posture.Jobs) == 0 {
			notes = append(notes, "no scheduled job was found that invokes a backup, so nothing observed here runs one on a schedule")
		}
		if len(posture.Locations) == 0 {
			notes = append(notes, "none of the conventional backup directories ("+strings.Join(conventionalRoots, ", ")+
				") exists and no scheduled job named a local repository, so there is no backup date to report")
		}
	}

	posture.Note = strings.Join(notes, "; ")
	return posture
}

// ───────────────────────────────────────────────────────────────────── tooling

// toolProbe is one backup tool and how to establish its presence.
type toolProbe struct {
	binary string
	// versionArgs is the allowlisted version probe, or nil when presence on PATH
	// is all this tool is prepared to claim. Nothing here is invoked with any
	// argument that could write, prune or restore.
	versionArgs []string
	// weak marks a tool that dumps data but does not manage backups. mysqldump
	// being installed says nothing: it ships with the mysql client. It is reported
	// because a cron line calling it is real evidence, and labelled because its
	// mere presence is not.
	weak bool
	// note qualifies a weak tool in the one channel this field has — the string
	// itself, since Tools is a []string.
	note string
}

var probes = []toolProbe{
	{binary: "restic", versionArgs: []string{"version"}},
	{binary: "borg", versionArgs: []string{"--version"}},
	{binary: "borgmatic"},
	{binary: "duplicity", versionArgs: []string{"--version"}},
	{binary: "duplicati-cli"},
	{binary: "rsnapshot", versionArgs: []string{"--version"}},
	{binary: "rclone"},
	{binary: "kopia"},
	{binary: "tarsnap"},
	{binary: "bup"},
	{binary: "bacula-fd"},
	{binary: "bareos-fd"},
	{binary: "amdump"},
	{binary: "veeamconfig"},
	{binary: "veeamagent"},
	{binary: "pgbackrest"},
	{binary: "barman"},
	{binary: "wal-g"},
	{binary: "snapper"},
	{binary: "timeshift"},
	{binary: "mysqldump", weak: true, note: "a dump tool, not a backup system: present on any host with the mysql client"},
	{binary: "mariadb-dump", weak: true, note: "a dump tool, not a backup system: present on any host with the mariadb client"},
	{binary: "pg_dump", weak: true, note: "a dump tool, not a backup system: present on any host with the postgres client"},
	{binary: "pg_dumpall", weak: true, note: "a dump tool, not a backup system: present on any host with the postgres client"},
	{binary: "mongodump", weak: true, note: "a dump tool, not a backup system: present on any host with the mongo client"},
}

// detectTools reports which backup tools the host has, with a version where an
// allowlisted probe exists for it.
func detectTools(runner *run.Runner) []string {
	var tools []string
	for _, probe := range probes {
		if !run.Available(probe.binary) {
			continue
		}

		entry := probe.binary
		if runner != nil && len(probe.versionArgs) > 0 {
			out, err := runner.Output(probe.binary, probe.versionArgs...)
			if err != nil {
				// Installed but it would not answer. That is still a presence.
				entry += " (installed; the version probe failed)"
			} else if version := firstVersion(out); version != "" {
				entry += " " + version
			}
		}
		if probe.weak {
			entry += " (" + probe.note + ")"
		}
		tools = append(tools, entry)
	}
	return tools
}

// versionToken matches the first version-looking word of a --version line:
// "restic 0.16.4 compiled with go1.21.5", "borg 1.2.7", "duplicity 2.1.4".
var versionToken = regexp.MustCompile(`\bv?(\d+(?:\.\d+){1,3}[A-Za-z0-9.+~-]*)`)

func firstVersion(out string) string {
	line, _, _ := strings.Cut(strings.TrimSpace(out), "\n")
	if match := versionToken.FindStringSubmatch(line); match != nil {
		return match[1]
	}
	return ""
}

// ──────────────────────────────────────────────────────────────── scheduled jobs

// backupTool matches a scheduled command that invokes something whose job is
// backing up. The word boundaries matter: `borg` must not match `cyborg`, and a
// bare `dump` is not on the list at all because kdump, vmcore-dmesg and
// tcpdump would all answer to it.
var backupTool = regexp.MustCompile(`(?i)\b(restic|borgmatic|borg|duplicity|duplicati|rsnapshot|rclone|kopia|tarsnap|bup|bacula|bareos|amdump|veeam|pgbackrest|barman|wal-g|mysqldump|mariadb-dump|pg_dump|pg_dumpall|mongodump|snapper|timeshift|zfs\s+send|btrfs\s+send)\b`)

// backupHint matches the naming a hand-rolled backup gives itself. A
// `tar czf /srv/archive/db-$(date +\%F).tgz` job has no tool name in it at all;
// what it has is the word backup, or dump, in a path or a script name.
var backupHint = regexp.MustCompile(`(?i)(backup|backups|bkp|snapshot|dumpall|\.dump\b|db-dump|sql\.gz|sql\.bz2|\.sql\b)`)

// backupJobs picks the scheduled entries that appear to run a backup.
//
// Commands arrive already swept for secrets by the scheduler collector, which is
// the second reason this package reuses that scan instead of reading cron itself.
func backupJobs(jobs []model.ScheduledJob) []string {
	var found []string
	for _, job := range jobs {
		haystack := job.Command + " " + job.Source
		if !backupTool.MatchString(haystack) && !backupHint.MatchString(haystack) {
			continue
		}
		line := fmt.Sprintf("%s %s: %s [%s]", job.Kind, job.Schedule, job.Command, job.Source)
		if len(line) > maxJobLine {
			line = line[:maxJobLine] + "…"
		}
		found = append(found, line)
	}
	return found
}

// repoFlag and repoEnv pull an absolute repository path out of a scheduled
// command: `restic -r /mnt/nas/restic`, `borg create --repo=/backup/borg`,
// `BORG_REPO=/srv/borg`. Only absolute local paths are taken — an sftp: or s3:
// target is somebody else's disk, and this tool does not go looking there.
var (
	repoFlag = regexp.MustCompile(`(?:^|\s)(?:-r|--repo|--repository|--repo-dir)[=\s]"?(/[^\s"';|]+)`)
	repoEnv  = regexp.MustCompile(`(?:BORG_REPO|RESTIC_REPOSITORY)="?(/[^\s"';|]+)`)
)

// jobPaths extracts candidate repository directories from the scheduled jobs.
func jobPaths(root string, jobs []model.ScheduledJob) []string {
	var paths []string
	seen := map[string]bool{}
	for _, job := range jobs {
		for _, pattern := range []*regexp.Regexp{repoFlag, repoEnv} {
			for _, match := range pattern.FindAllStringSubmatch(job.Command, -1) {
				candidate := filepath.Join(root, filepath.Clean(match[1]))
				if seen[candidate] || !isDir(candidate) {
					continue
				}
				seen[candidate] = true
				paths = append(paths, candidate)
				if len(paths) >= maxJobPaths {
					return paths
				}
			}
		}
	}
	return paths
}

// ─────────────────────────────────────────────────────────────────── locations

// scanLocations measures every backup directory worth measuring: the conventional
// roots, any deduplicating repository sitting directly inside one of them, and any
// repository a scheduled job names.
//
// It returns the locations, the notes that belong in BackupPosture.Note, and the
// subset of those notes that are gaps rather than remarks — the ones that must
// degrade the section, because they are the ones that can make a full directory
// look empty.
func scanLocations(root string, jobs []model.ScheduledJob, now time.Time, lim limits) (
	locations []model.BackupLocation, notes []string, degradations []string) {

	deadline := time.Now().Add(totalBudget)
	seen := map[string]bool{}
	var skipped []string

	measure := func(path, kind string) {
		if seen[path] {
			return
		}
		seen[path] = true
		if time.Now().After(deadline) {
			skipped = append(skipped, path)
			return
		}
		location, locationNotes := scanLocation(path, now, lim)
		locations = append(locations, location)
		if kind != "" {
			notes = append(notes, path+" is a "+kind+" repository")
		}
		for _, note := range locationNotes {
			if strings.Contains(note, "unreadable") {
				degradations = append(degradations, note)
				continue
			}
			notes = append(notes, note)
		}
	}

	for _, conventional := range conventionalRoots {
		dir := filepath.Join(root, conventional)
		if !isDir(dir) {
			continue
		}
		measure(dir, repoKind(dir))

		// A repository is usually one level down: /backup/borg, /backups/restic.
		entries, err := os.ReadDir(dir)
		if err != nil {
			degradations = append(degradations, "unreadable: "+dir+": "+errText(err))
			continue
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			child := filepath.Join(dir, entry.Name())
			if kind := repoKind(child); kind != "" {
				measure(child, kind)
			}
		}
	}

	for _, path := range jobPaths(root, jobs) {
		measure(path, repoKind(path))
	}

	if len(skipped) > 0 {
		notes = append(notes, fmt.Sprintf("the %s walking budget for this section ran out, so %s %s not examined",
			totalBudget, strings.Join(skipped, ", "), plural(len(skipped))))
	}
	return locations, notes, degradations
}

func plural(n int) string {
	if n == 1 {
		return "was"
	}
	return "were"
}
