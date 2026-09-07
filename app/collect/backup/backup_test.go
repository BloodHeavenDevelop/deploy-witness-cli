package backup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
)

// reference is the fixed "now" every age in this file is measured against, so a
// test never depends on the day it runs.
var reference = time.Date(2026, 8, 16, 12, 0, 0, 0, time.UTC)

// write creates root/relative with the given size and modification time.
func write(t *testing.T, root, relative string, size int, modTime time.Time) string {
	t.Helper()
	path := filepath.Join(root, relative)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(path), err)
	}
	if err := os.WriteFile(path, make([]byte, size), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	if err := os.Chtimes(path, modTime, modTime); err != nil {
		t.Fatalf("chtimes %s: %v", path, err)
	}
	return path
}

func joined(notes []string) string { return strings.Join(notes, " | ") }

// ─────────────────────────────────────────────────────────── the date is the point

func TestScanLocationMeasuresTheNewestFile(t *testing.T) {
	root := t.TempDir()
	newest := reference.Add(-24 * time.Hour)
	write(t, root, "full-2026-08-13.tar.gz", 100, reference.Add(-72*time.Hour))
	write(t, root, "daily/incremental.tar.gz", 200, newest)
	write(t, root, "daily/backup.log", 50, reference.Add(-240*time.Hour))

	location, notes := scanLocation(root, reference, defaultLimits)

	if location.Path != root {
		t.Errorf("path = %q, want %q", location.Path, root)
	}
	if location.FileCount != 3 {
		t.Errorf("fileCount = %d, want 3", location.FileCount)
	}
	if location.SizeBytes != 350 {
		t.Errorf("sizeBytes = %d, want 350", location.SizeBytes)
	}
	if want := newest.UTC().Format(time.RFC3339); location.NewestFileAt != want {
		t.Errorf("newestFileAt = %q, want %q", location.NewestFileAt, want)
	}
	if location.AgeDays != 1 {
		t.Errorf("ageDays = %d, want 1", location.AgeDays)
	}
	if len(notes) != 0 {
		t.Errorf("unexpected notes: %v", notes)
	}
}

// TestScanLocationAbandonedArchive is the case the whole collector exists for: the
// directory is there, it is full, and nothing has written to it in over a year.
func TestScanLocationAbandonedArchive(t *testing.T) {
	root := t.TempDir()
	stale := reference.Add(-400 * 24 * time.Hour)
	write(t, root, "backup-2025-07-12.sql.gz", 4096, stale)
	write(t, root, "backup-2025-07-11.sql.gz", 4096, stale.Add(-24*time.Hour))

	location, _ := scanLocation(root, reference, defaultLimits)

	if location.FileCount != 2 {
		t.Fatalf("fileCount = %d, want 2", location.FileCount)
	}
	if location.AgeDays != 400 {
		t.Errorf("ageDays = %d, want 400", location.AgeDays)
	}
	if want := stale.UTC().Format(time.RFC3339); location.NewestFileAt != want {
		t.Errorf("newestFileAt = %q, want %q", location.NewestFileAt, want)
	}
}

func TestScanLocationEmptyDirectorySaysSo(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "daily"), 0o755); err != nil {
		t.Fatal(err)
	}

	location, notes := scanLocation(root, reference, defaultLimits)

	// An empty NewestFileAt is the model's signal for "no date". AgeDays has no
	// third state, so 0 must not be left to speak for itself — the note is what
	// stops it reading as "backed up today".
	if location.NewestFileAt != "" {
		t.Errorf("newestFileAt = %q, want it empty", location.NewestFileAt)
	}
	if location.FileCount != 0 || location.SizeBytes != 0 {
		t.Errorf("location = %+v, want an empty count and size", location)
	}
	if !strings.Contains(joined(notes), "no regular files") {
		t.Errorf("notes do not explain the empty result: %v", notes)
	}
}

func TestScanLocationIgnoresSymlinkedFiles(t *testing.T) {
	root := t.TempDir()
	target := write(t, root, "real.tar", 100, reference.Add(-48*time.Hour))
	if err := os.Symlink(target, filepath.Join(root, "latest.tar")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	location, _ := scanLocation(root, reference, defaultLimits)
	// Counting the symlink would double both the file count and the bytes.
	if location.FileCount != 1 || location.SizeBytes != 100 {
		t.Errorf("location = %+v, want one file of 100 bytes", location)
	}
}

// ─────────────────────────────────────────────────────────────────── the bounds

func TestScanLocationFileBoundIsReported(t *testing.T) {
	root := t.TempDir()
	for i := range 10 {
		write(t, root, filepath.Join("many", "file-"+string(rune('a'+i))), 10, reference)
	}

	location, notes := scanLocation(root, reference, limits{maxDepth: 6, maxFiles: 3, budget: time.Minute})

	if location.FileCount != 3 {
		t.Errorf("fileCount = %d, want 3 — the bound", location.FileCount)
	}
	// Never cap a result set silently.
	if !strings.Contains(joined(notes), "lower bounds") {
		t.Errorf("the bound was not reported: %v", notes)
	}
	if !strings.Contains(joined(notes), "3 files") {
		t.Errorf("the note does not name the bound: %v", notes)
	}
}

func TestScanLocationDepthBoundIsReported(t *testing.T) {
	root := t.TempDir()
	write(t, root, "top.tar", 10, reference)
	write(t, root, "a/b/c/deep.tar", 999, reference)

	location, notes := scanLocation(root, reference, limits{maxDepth: 2, maxFiles: 100, budget: time.Minute})

	if location.SizeBytes != 10 {
		t.Errorf("sizeBytes = %d, want 10: the deep file is below the depth limit", location.SizeBytes)
	}
	if !strings.Contains(joined(notes), "levels deep were not examined") {
		t.Errorf("the depth bound was not reported: %v", notes)
	}
}

func TestScanLocationTimeBudgetIsReported(t *testing.T) {
	root := t.TempDir()
	for i := range 200 {
		write(t, root, filepath.Join("many", "file-"+strings.Repeat("x", i%7)+string(rune('a'+i%26))), 1, reference)
	}

	_, notes := scanLocation(root, reference, limits{maxDepth: 6, maxFiles: 100000, budget: time.Nanosecond})

	if !strings.Contains(joined(notes), "time budget") {
		t.Errorf("the time budget was not reported: %v", notes)
	}
}

func TestScanLocationUnreadableSubdirectoryIsReported(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root, which can read a 0000 directory")
	}
	root := t.TempDir()
	write(t, root, "top.tar", 10, reference)
	locked := filepath.Join(root, "locked")
	write(t, root, "locked/inner.tar", 10, reference)
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })

	_, notes := scanLocation(root, reference, defaultLimits)

	if !strings.Contains(joined(notes), "unreadable") {
		t.Errorf("an unreadable subdirectory produced no note: %v", notes)
	}
}

// ───────────────────────────────────────────────────────── repository markers

func TestRepoKind(t *testing.T) {
	root := t.TempDir()

	// borg: a config file beside data/.
	borg := filepath.Join(root, "borgrepo")
	write(t, borg, "config", 40, reference)
	write(t, borg, "data/0/1", 4096, reference)
	write(t, borg, "README", 20, reference)

	// restic: a config file beside snapshots/ — and a data/ too, which is why
	// snapshots/ has to be tested first.
	restic := filepath.Join(root, "resticrepo")
	write(t, restic, "config", 155, reference)
	write(t, restic, "data/ab/abcdef", 4096, reference)
	write(t, restic, "snapshots/0123456789", 300, reference)
	write(t, restic, "keys/aabbcc", 400, reference)

	// An ordinary directory that happens to hold a file called config.
	plain := filepath.Join(root, "plain")
	write(t, plain, "config", 10, reference)

	cases := []struct {
		dir  string
		want string
	}{
		{borg, "borg"},
		{restic, "restic"},
		{plain, ""},
		{filepath.Join(root, "missing"), ""},
	}
	for _, c := range cases {
		if got := repoKind(c.dir); got != c.want {
			t.Errorf("repoKind(%s) = %q, want %q", c.dir, got, c.want)
		}
	}
}

func TestScanLocationsFindsRootsAndTheReposInsideThem(t *testing.T) {
	root := t.TempDir()
	// /backup, with a borg repository one level down.
	write(t, root, "backup/dump.sql.gz", 500, reference.Add(-48*time.Hour))
	write(t, root, "backup/borgrepo/config", 40, reference)
	write(t, root, "backup/borgrepo/data/0/1", 4096, reference.Add(-2*time.Hour))
	// /var/backups, as Debian ships it.
	write(t, root, "var/backups/dpkg.status.0", 900, reference.Add(-96*time.Hour))

	locations, notes, degradations := scanLocations(root, nil, reference, defaultLimits)
	if len(degradations) != 0 {
		t.Fatalf("unexpected degradations: %v", degradations)
	}

	byPath := map[string]model.BackupLocation{}
	for _, location := range locations {
		byPath[location.Path] = location
	}
	for _, want := range []string{"backup", "backup/borgrepo", "var/backups"} {
		if _, ok := byPath[filepath.Join(root, want)]; !ok {
			t.Errorf("%s was not measured; got %v", want, byPath)
		}
	}
	// A directory that does not exist is not a location.
	if _, ok := byPath[filepath.Join(root, "srv/backup")]; ok {
		t.Error("a nonexistent conventional root was reported as a location")
	}
	if !strings.Contains(joined(notes), "is a borg repository") {
		t.Errorf("the repository was not identified: %v", notes)
	}

	// The repository's own newest file is what dates the last run.
	repo := byPath[filepath.Join(root, "backup/borgrepo")]
	if repo.AgeDays != 0 {
		t.Errorf("repo ageDays = %d, want 0", repo.AgeDays)
	}
}

// ───────────────────────────────────────────────────────────── scheduled jobs

func TestBackupJobsPicksTheBackupsOut(t *testing.T) {
	jobs := []model.ScheduledJob{
		{Kind: "cron.d", Owner: "root", Schedule: "30 2 * * *", Source: "/etc/cron.d/restic",
			Command: "/usr/bin/restic -r /mnt/backup/restic backup /srv --quiet"},
		{Kind: "cron.daily", Owner: "root", Schedule: "daily", Source: "/etc/cron.daily",
			Command: "/etc/cron.daily/backup-db"},
		{Kind: "timer", Owner: "root", Schedule: "next n/a", Source: "borgmatic.timer",
			Command: "borgmatic.service"},
		{Kind: "crontab", Owner: "postgres", Schedule: "@daily", Source: "/var/spool/cron/postgres",
			Command: "/usr/bin/pg_dump app | gzip > /srv/dumps/app.sql.gz"},
		// Not backups, and each one is a plausible false positive.
		{Kind: "timer", Owner: "root", Schedule: "next n/a", Source: "logrotate.timer",
			Command: "logrotate.service"},
		{Kind: "crontab", Owner: "root", Schedule: "*/5 * * * *", Source: "/etc/crontab",
			Command: "/usr/sbin/tcpdump -c 10 -w /tmp/capture"},
		{Kind: "crontab", Owner: "root", Schedule: "@hourly", Source: "/etc/crontab",
			Command: "/opt/cyborg-agent/bin/run --once"},
	}

	found := backupJobs(jobs)
	if len(found) != 4 {
		t.Fatalf("expected 4 backup jobs, got %d: %v", len(found), found)
	}
	all := joined(found)
	for _, want := range []string{"restic", "backup-db", "borgmatic", "pg_dump"} {
		if !strings.Contains(all, want) {
			t.Errorf("%q is missing from %v", want, found)
		}
	}
	for _, unwanted := range []string{"logrotate", "tcpdump", "cyborg"} {
		if strings.Contains(all, unwanted) {
			t.Errorf("%q was mistaken for a backup: %v", unwanted, found)
		}
	}
	// The reported line carries the schedule and where it was found, which is what
	// makes it actionable.
	if !strings.Contains(found[0], "30 2 * * *") || !strings.Contains(found[0], "/etc/cron.d/restic") {
		t.Errorf("job line lost its schedule or source: %q", found[0])
	}
}

func TestJobPathsTakesLocalRepositoriesFromTheJobs(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "mnt/nas/restic"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "srv/borg"), 0o755); err != nil {
		t.Fatal(err)
	}

	jobs := []model.ScheduledJob{
		{Command: "/usr/bin/restic -r /mnt/nas/restic backup /srv"},
		{Command: "BORG_REPO=/srv/borg /usr/bin/borg create ::daily /srv"},
		// A remote repository is somebody else's disk; this tool does not follow it.
		{Command: "/usr/bin/restic -r sftp:backup@nas:/repo backup /srv"},
		// A directory that does not exist is not a location either.
		{Command: "/usr/bin/restic --repo /mnt/gone backup /srv"},
	}

	paths := jobPaths(root, jobs)
	if len(paths) != 2 {
		t.Fatalf("expected 2 paths, got %v", paths)
	}
	if paths[0] != filepath.Join(root, "mnt/nas/restic") {
		t.Errorf("paths[0] = %q", paths[0])
	}
	if paths[1] != filepath.Join(root, "srv/borg") {
		t.Errorf("paths[1] = %q", paths[1])
	}
}

func TestFirstVersion(t *testing.T) {
	cases := []struct{ in, want string }{
		{"restic 0.16.4 compiled with go1.21.5 on linux/amd64", "0.16.4"},
		{"borg 1.2.7", "1.2.7"},
		{"duplicity 2.1.4", "2.1.4"},
		{"rsnapshot 1.4.5\n", "1.4.5"},
		{"", ""},
		{"no version here", ""},
	}
	for _, c := range cases {
		if got := firstVersion(c.in); got != c.want {
			t.Errorf("firstVersion(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// ──────────────────────────────────────────────────────────────── the posture

func TestCollectReportsAStaleDirectoryAndItsJobs(t *testing.T) {
	root := t.TempDir()
	write(t, root, "backup/db-2025-07-12.sql.gz", 2048, reference.Add(-400*24*time.Hour))

	caps := &model.Capabilities{Jobs: []model.ScheduledJob{
		{Kind: "cron.d", Owner: "root", Schedule: "30 2 * * *", Source: "/etc/cron.d/backup",
			Command: "/usr/local/bin/backup-db --to /backup"},
	}}
	result := &model.SectionResult{Section: model.SectionWitness, Status: model.StatusOk}

	// A nil runner keeps the test off the host's PATH probes that need a
	// subprocess; nothing here should shell out.
	posture := collect(nil, caps, root, reference, defaultLimits, result)

	if len(posture.Locations) != 1 {
		t.Fatalf("expected 1 location, got %+v", posture.Locations)
	}
	if posture.Locations[0].AgeDays != 400 {
		t.Errorf("ageDays = %d, want 400", posture.Locations[0].AgeDays)
	}
	if len(posture.Jobs) != 1 {
		t.Fatalf("expected 1 backup job, got %v", posture.Jobs)
	}
	if posture.Note == "" {
		t.Error("Note is empty: something is always worth saying about a backup posture")
	}
	// caps.Jobs was already populated, so nothing re-scanned cron behind our back.
	if len(caps.Jobs) != 1 {
		t.Errorf("caps.Jobs was modified: %+v", caps.Jobs)
	}
}
