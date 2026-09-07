package scheduler

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/redact"
)

// writeFile creates root/relative with the given contents, making the parents.
func writeFile(t *testing.T, root, relative, contents string) string {
	t.Helper()
	path := filepath.Join(root, relative)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// find returns the one job whose command contains substring.
func find(t *testing.T, jobs []model.ScheduledJob, substring string) model.ScheduledJob {
	t.Helper()
	for _, job := range jobs {
		if strings.Contains(job.Command, substring) {
			return job
		}
	}
	t.Fatalf("no job whose command contains %q in %+v", substring, jobs)
	return model.ScheduledJob{}
}

// ─────────────────────────────────────────────────────────────── /etc/cron.d

func TestScanCronDReadsTheUserField(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "/etc/cron.d/certbot", `# Renew certificates
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/sbin:/usr/bin
17 3 * * * root test -x /usr/bin/certbot && perl -e 'sleep int(rand(43200))' && certbot -q renew
30 4 * * 1 www-data /usr/local/bin/prune-cache --keep 5
@reboot deploy /srv/app/bin/warm-cache
`)

	jobs, problems := scanCronD(root)
	if len(problems) != 0 {
		t.Fatalf("unexpected problems: %v", problems)
	}
	if len(jobs) != 3 {
		t.Fatalf("expected 3 jobs, got %d: %+v", len(jobs), jobs)
	}

	certbot := find(t, jobs, "certbot -q renew")
	if certbot.Kind != "cron.d" {
		t.Errorf("kind = %q, want cron.d", certbot.Kind)
	}
	// The sixth field is the account, not the first word of the command.
	if certbot.Owner != "root" {
		t.Errorf("owner = %q, want root", certbot.Owner)
	}
	if certbot.Schedule != "17 3 * * *" {
		t.Errorf("schedule = %q, want %q", certbot.Schedule, "17 3 * * *")
	}
	if strings.HasPrefix(certbot.Command, "root") {
		t.Errorf("the user field leaked into the command: %q", certbot.Command)
	}
	if certbot.Source != filepath.Join(root, "/etc/cron.d/certbot") {
		t.Errorf("source = %q", certbot.Source)
	}

	prune := find(t, jobs, "prune-cache")
	if prune.Owner != "www-data" {
		t.Errorf("owner = %q, want www-data", prune.Owner)
	}

	// A nickname line in a system crontab still carries the user field.
	warm := find(t, jobs, "warm-cache")
	if warm.Schedule != "@reboot" || warm.Owner != "deploy" {
		t.Errorf("@reboot line = %+v, want schedule @reboot owner deploy", warm)
	}
}

// ──────────────────────────────────────────────────────────── /etc/crontab

func TestScanEtcCrontab(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "/etc/crontab", `SHELL=/bin/sh
MAILTO=ops@example.com
17 *	* * *	root	cd / && run-parts --report /etc/cron.hourly
25 6	* * *	root	test -x /usr/sbin/anacron || run-parts --report /etc/cron.daily
`)

	jobs, problems := scanEtcCrontab(root)
	if len(problems) != 0 {
		t.Fatalf("unexpected problems: %v", problems)
	}
	if len(jobs) != 2 {
		t.Fatalf("expected 2 jobs, got %d: %+v", len(jobs), jobs)
	}
	for _, job := range jobs {
		if job.Kind != "crontab" || job.Owner != "root" {
			t.Errorf("job = %+v, want kind crontab owner root", job)
		}
	}
	// Tabs are field separators like spaces, and the schedule is normalised to
	// single spaces.
	if jobs[0].Schedule != "17 * * * *" {
		t.Errorf("schedule = %q, want %q", jobs[0].Schedule, "17 * * * *")
	}
}

// ─────────────────────────────────────────────────────── per-user crontabs

func TestScanUserSpoolsTakesTheOwnerFromTheFilename(t *testing.T) {
	root := t.TempDir()
	// RHEL layout.
	writeFile(t, root, "/var/spool/cron/deploy", `# deploy's own crontab
MAILTO=""
@daily /srv/app/bin/rotate-sessions
*/15 * * * * /srv/app/bin/queue-worker --once
`)
	// Debian layout, alongside it.
	writeFile(t, root, "/var/spool/cron/crontabs/postgres", "@hourly /usr/local/bin/wal-push\n")

	jobs, problems := scanUserSpools(root)
	if len(problems) != 0 {
		t.Fatalf("unexpected problems: %v", problems)
	}
	if len(jobs) != 3 {
		t.Fatalf("expected 3 jobs, got %d: %+v", len(jobs), jobs)
	}

	rotate := find(t, jobs, "rotate-sessions")
	if rotate.Owner != "deploy" {
		t.Errorf("owner = %q, want deploy", rotate.Owner)
	}
	if rotate.Schedule != "@daily" {
		t.Errorf("schedule = %q, want @daily", rotate.Schedule)
	}
	// A per-user crontab has no user field: the first word after the schedule is
	// already the command.
	worker := find(t, jobs, "queue-worker")
	if worker.Owner != "deploy" {
		t.Errorf("owner = %q, want deploy", worker.Owner)
	}
	if !strings.HasPrefix(worker.Command, "/srv/app/bin/queue-worker") {
		t.Errorf("command = %q, want it to start with the binary path", worker.Command)
	}

	wal := find(t, jobs, "wal-push")
	if wal.Owner != "postgres" {
		t.Errorf("owner = %q, want postgres", wal.Owner)
	}
}

func TestParseCrontabSkipsCommentsAndEnvironmentLines(t *testing.T) {
	// MAILTO and PGPASSWORD are both assignments and neither is a job. The second
	// one is why the value is never even parsed: it would be a credential in the
	// report.
	content := `# a comment
	# an indented comment
MAILTO=ops@example.com
PGPASSWORD=tr0ub4dor3
CRON_TZ=Europe/Warsaw
PATH = /usr/bin:/bin

30 2 * * * /usr/local/bin/nightly
`
	jobs := parseCrontab(content, "/tmp/fixture", "crontab", "root", false)
	if len(jobs) != 1 {
		t.Fatalf("expected 1 job, got %d: %+v", len(jobs), jobs)
	}
	if jobs[0].Command != "/usr/local/bin/nightly" {
		t.Errorf("command = %q", jobs[0].Command)
	}
	for _, job := range jobs {
		for _, leak := range []string{"tr0ub4dor3", "MAILTO", "Europe/Warsaw"} {
			if strings.Contains(job.Command, leak) {
				t.Errorf("environment line leaked %q into %+v", leak, job)
			}
		}
	}
}

func TestSplitCronLineNicknames(t *testing.T) {
	cases := []struct {
		name     string
		line     string
		withUser bool
		schedule string
		owner    string
		command  string
		ok       bool
	}{
		{
			name: "reboot in a user crontab", line: "@reboot /srv/start.sh --quiet",
			schedule: "@reboot", command: "/srv/start.sh --quiet", ok: true,
		},
		{
			name: "daily in cron.d", line: "@daily backupuser /usr/bin/restic backup /srv",
			withUser: true, schedule: "@daily", owner: "backupuser",
			command: "/usr/bin/restic backup /srv", ok: true,
		},
		{
			name: "hourly, uppercase", line: "@HOURLY /usr/bin/sync-clock",
			schedule: "@hourly", command: "/usr/bin/sync-clock", ok: true,
		},
		{
			name: "midnight", line: "@midnight /usr/bin/rotate",
			schedule: "@midnight", command: "/usr/bin/rotate", ok: true,
		},
		{
			name: "five fields", line: "*/5 1-4 * * 1,3 /usr/bin/poll",
			schedule: "*/5 1-4 * * 1,3", command: "/usr/bin/poll", ok: true,
		},
		{
			name: "a schedule with no command is not a job", line: "* * * * *",
		},
		{
			name: "an unknown nickname is not a schedule", line: "@fortnightly /usr/bin/poll",
		},
		{
			name: "stdin data after an unescaped % is not part of the command",
			line: "0 3 * * * /usr/bin/psql -f -%SELECT 1;", schedule: "0 3 * * *",
			command: "/usr/bin/psql -f -", ok: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			schedule, owner, command, ok := splitCronLine(c.line, c.withUser)
			if ok != c.ok {
				t.Fatalf("ok = %v, want %v", ok, c.ok)
			}
			if !ok {
				return
			}
			if schedule != c.schedule {
				t.Errorf("schedule = %q, want %q", schedule, c.schedule)
			}
			if owner != c.owner {
				t.Errorf("owner = %q, want %q", owner, c.owner)
			}
			if command != c.command {
				t.Errorf("command = %q, want %q", command, c.command)
			}
		})
	}
}

// ─────────────────────────────────────────────────── the run-parts directories

func TestScanCronDirsUsesTheDirectoryCadence(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "/etc/cron.daily/logrotate", "#!/bin/sh\n")
	writeFile(t, root, "/etc/cron.daily/apt-compat", "#!/bin/sh\n")
	writeFile(t, root, "/etc/cron.weekly/man-db", "#!/bin/sh\n")
	// Leftovers cron itself ignores.
	writeFile(t, root, "/etc/cron.daily/logrotate.dpkg-old", "#!/bin/sh\n")
	writeFile(t, root, "/etc/cron.daily/.placeholder", "")
	writeFile(t, root, "/etc/cron.daily/backup~", "#!/bin/sh\n")

	jobs, problems := scanCronDirs(root)
	if len(problems) != 0 {
		t.Fatalf("unexpected problems: %v", problems)
	}
	if len(jobs) != 3 {
		t.Fatalf("expected 3 jobs, got %d: %+v", len(jobs), jobs)
	}

	logrotate := find(t, jobs, "cron.daily/logrotate")
	if logrotate.Kind != "cron.daily" {
		t.Errorf("kind = %q, want cron.daily", logrotate.Kind)
	}
	// These are scripts, not crontab lines: the cadence comes from the directory.
	if logrotate.Schedule != "daily" {
		t.Errorf("schedule = %q, want daily", logrotate.Schedule)
	}
	if logrotate.Owner != "root" {
		t.Errorf("owner = %q, want root", logrotate.Owner)
	}
	if logrotate.Source != filepath.Join(root, "/etc/cron.daily") {
		t.Errorf("source = %q", logrotate.Source)
	}

	manDB := find(t, jobs, "cron.weekly/man-db")
	if manDB.Kind != "cron.weekly" || manDB.Schedule != "weekly" {
		t.Errorf("weekly job = %+v", manDB)
	}
}

// ─────────────────────────────────────────────────────────────── systemd timers

// timerFixture is `systemctl list-timers --all --no-pager --plain --no-legend`.
// It carries the two shapes that break a column-counting parser: a variable-width
// LEFT column and an n/a NEXT.
const timerFixture = `Sun 2026-08-16 20:00:00 UTC 3h 12min left Sun 2026-08-16 12:00:00 UTC 4h 48min ago logrotate.timer logrotate.service
Mon 2026-08-17 03:10:00 UTC 10h left      Sun 2026-08-16 03:10:00 UTC 13h ago      certbot.timer certbot.service
Mon 2026-08-17 00:00:00 UTC 7h left       n/a                         n/a          restic-backup.timer restic-backup.service
n/a                         n/a           Sat 2026-08-15 06:00:00 UTC 1 day 10h ago fstrim.timer fstrim.service
Mon 2026-08-17 06:00:00 UTC 18h left      n/a                         n/a          plain.timer -
`

func TestParseTimers(t *testing.T) {
	jobs := parseTimers(timerFixture)
	if len(jobs) != 5 {
		t.Fatalf("expected 5 timers, got %d: %+v", len(jobs), jobs)
	}

	for _, job := range jobs {
		if job.Kind != "timer" {
			t.Errorf("kind = %q, want timer", job.Kind)
		}
		// The account is resolved by a separate query; before it runs the honest
		// value is "unknown", not "root".
		if job.Owner != "unknown" {
			t.Errorf("owner = %q, want unknown", job.Owner)
		}
	}

	if jobs[0].Source != "logrotate.timer" {
		t.Errorf("source = %q, want logrotate.timer", jobs[0].Source)
	}
	if jobs[0].Command != "logrotate.service" {
		t.Errorf("command = %q, want logrotate.service", jobs[0].Command)
	}
	// A variable-width LEFT column must not shift the timestamp, and the stamp is
	// stored in UTC rather than in the host's local zone.
	if jobs[0].Schedule != "next 2026-08-16 20:00:00 UTC" {
		t.Errorf("schedule = %q", jobs[0].Schedule)
	}
	if jobs[1].Schedule != "next 2026-08-17 03:10:00 UTC" {
		t.Errorf("schedule = %q", jobs[1].Schedule)
	}
	// A timer that will not fire again is reported as such, not dropped.
	if jobs[3].Source != "fstrim.timer" || jobs[3].Schedule != "next n/a" {
		t.Errorf("fstrim = %+v", jobs[3])
	}
	// An empty ACTIVATES column means systemd's default: foo.timer → foo.service.
	if jobs[4].Command != "plain.service" {
		t.Errorf("command = %q, want plain.service", jobs[4].Command)
	}
}

func TestNormaliseTimestamp(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Sun 2026-08-16 20:00:00 UTC", "2026-08-16 20:00:00 UTC"},
		{"Sun 2026-08-16 20:00:00 GMT", "2026-08-16 20:00:00 UTC"},
		// An abbreviation Go cannot resolve is passed through untouched: calling it
		// UTC would move the time by however many hours the real offset is.
		{"Sun 2026-08-16 20:00:00 XYZ", "Sun 2026-08-16 20:00:00 XYZ"},
		{"n/a", "n/a"},
		{"not a timestamp at all", "not a timestamp at all"},
	}
	for _, c := range cases {
		if got := normaliseTimestamp(c.in); got != c.want {
			t.Errorf("normaliseTimestamp(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestParseTimersIgnoresTheFooter(t *testing.T) {
	jobs := parseTimers("5 timers listed.\nPass --all to see loaded but inactive timers, too.\n")
	if len(jobs) != 0 {
		t.Fatalf("expected no timers, got %+v", jobs)
	}
}

// ─────────────────────────────────────────────────────────── secret masking

func TestMaskSecrets(t *testing.T) {
	cases := []struct {
		name string
		in   string
		// leak is the credential that must not survive.
		leak string
		// keep is context that must survive, so masking does not swallow the
		// information the report exists to carry.
		keep string
	}{
		{
			name: "mysql glued password",
			in:   `mysqldump -uroot -pS3cr3t-P4ss! --all-databases | gzip > /backup/db.sql.gz`,
			leak: "S3cr3t-P4ss!", keep: "mysqldump",
		},
		{
			name: "bearer token in a curl header",
			in:   `curl -s -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.abcdef" https://api.example.com/ping`,
			leak: "eyJhbGciOiJIUzI1NiJ9.abcdef", keep: "https://api.example.com/ping",
		},
		{
			name: "credentials inside a repository URL",
			in:   `restic -r sftp://backupuser:hunter2@nas.example.com/repo backup /srv`,
			leak: "hunter2", keep: "nas.example.com/repo",
		},
		{
			name: "an environment prefix on the command",
			in:   `PGPASSWORD=tr0ub4dor3 pg_dump -U app app > /var/backups/app.sql`,
			leak: "tr0ub4dor3", keep: "pg_dump",
		},
		{
			name: "a long option with an = value",
			in:   `borgmatic --config /etc/borgmatic.yaml --encryption-passphrase=letmein1234`,
			leak: "letmein1234", keep: "/etc/borgmatic.yaml",
		},
		{
			name: "a long option with a separate value",
			in:   `rclone sync /srv remote:bucket --token 9f8e7d6c5b4a3210`,
			leak: "9f8e7d6c5b4a3210", keep: "remote:bucket",
		},
		{
			name: "basic auth passed to curl",
			in:   `curl -u monitor:s3cretvalue https://health.example.com/`,
			leak: "s3cretvalue", keep: "monitor",
		},
		{
			name: "sshpass",
			in:   `sshpass -p Passw0rd! rsync -a /srv backup@10.0.0.9:/backup`,
			leak: "Passw0rd!", keep: "rsync -a /srv",
		},
		{
			name: "a token in a webhook query string",
			in:   `curl -fsS "https://hooks.example.com/notify?token=abcd1234efgh"`,
			leak: "abcd1234efgh", keep: "hooks.example.com/notify",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := maskSecrets(c.in)
			if strings.Contains(got, c.leak) {
				t.Errorf("the credential survived masking\n in:  %s\n out: %s\n leak: %s", c.in, got, c.leak)
			}
			if !strings.Contains(got, redact.Marker) {
				t.Errorf("nothing was masked\n in:  %s\n out: %s", c.in, got)
			}
			if c.keep != "" && !strings.Contains(got, c.keep) {
				t.Errorf("masking swallowed the context %q\n in:  %s\n out: %s", c.keep, c.in, got)
			}
		})
	}
}

func TestMaskSecretsLeavesOrdinaryCommandsAlone(t *testing.T) {
	// -p means something harmless almost everywhere, and a report that masks
	// `mkdir -p` teaches its reader to ignore the masking.
	for _, in := range []string{
		"/usr/bin/mkdir -p /var/log/app && /usr/bin/logrotate -f /etc/logrotate.conf",
		"tar -cpzf /backup/etc.tgz /etc",
		"ssh -p 2222 deploy@10.0.0.5 /srv/app/bin/health",
		"/usr/bin/restic -r /mnt/backup/restic forget --keep-daily 7 --prune",
	} {
		if got := maskSecrets(in); got != in {
			t.Errorf("masking changed an ordinary command\n in:  %s\n out: %s", in, got)
		}
	}
}

// ─────────────────────────────────────────────────────────────── at jobs

func TestScanAtSpoolReportsPresenceWithoutReadingTheJob(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "/var/spool/at/a0000101a5c2ef", "#!/bin/sh\nexport PGPASSWORD=tr0ub4dor3\n/srv/deploy.sh\n")
	writeFile(t, root, "/var/spool/at/.SEQ", "1\n")
	writeFile(t, root, "/var/spool/cron/atjobs/b00002019bcdef", "#!/bin/sh\n/srv/other.sh\n")

	jobs, problems := scanAtSpool(root)
	if len(problems) != 0 {
		t.Fatalf("unexpected problems: %v", problems)
	}
	if len(jobs) != 2 {
		t.Fatalf("expected 2 at jobs, got %d: %+v", len(jobs), jobs)
	}
	for _, job := range jobs {
		if job.Kind != "at" {
			t.Errorf("kind = %q, want at", job.Kind)
		}
		if job.Schedule != "one-shot" {
			t.Errorf("schedule = %q, want one-shot", job.Schedule)
		}
		// The spool file is never opened, so nothing from inside it can appear.
		if job.Command != "" {
			t.Errorf("command = %q, want it empty: the file is not read", job.Command)
		}
		if job.Source == "" {
			t.Error("source is empty")
		}
	}
}

// ───────────────────────────────────────────────── unreadable is not empty

func TestScannersReportWhatTheyCouldNotRead(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root, which can read a 0000 directory")
	}
	root := t.TempDir()
	writeFile(t, root, "/var/spool/cron/crontabs/deploy", "@daily /srv/backup.sh\n")
	locked := filepath.Join(root, "/var/spool/cron/crontabs")
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })

	jobs, problems := scanUserSpools(root)
	if len(jobs) != 0 {
		t.Fatalf("expected no jobs from an unreadable directory, got %+v", jobs)
	}
	// This is the whole promise: no jobs *and* a stated reason, never one without
	// the other.
	if len(problems) == 0 {
		t.Fatal("an unreadable spool directory produced no problem to report")
	}
	if !strings.Contains(strings.Join(problems, " "), locked) {
		t.Errorf("the problem does not name the directory: %v", problems)
	}
}
