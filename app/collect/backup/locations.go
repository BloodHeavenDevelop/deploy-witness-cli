package backup

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
)

// This file is the part of the collector that answers the only question that
// matters about a backup directory: when was something last written into it.
//
// A `/backup` directory is not evidence of a backup. Every abandoned backup looks
// exactly like a working one from the outside — same path, same permissions, same
// reassuring name — and the single thing that separates them is the modification
// time of the newest file inside. So that is what is collected, and it is
// collected without ever opening a file: the contents are none of this tool's
// business, and reading them would turn an audit into a data handler.
//
// The walk is bounded three ways, because a backup directory is precisely the
// place where a host keeps two million small files. Every bound that bites is
// reported: an unannounced truncation would turn "we stopped counting" into "this
// is how many there are".

// limits bounds one directory walk.
type limits struct {
	// maxDepth is how far below the root to descend. Backups nest by date, so a
	// few levels is plenty; a deeper tree gets a note rather than a full crawl.
	maxDepth int
	// maxFiles is how many regular files to account for.
	maxFiles int
	// budget is the wall-clock ceiling for this one directory.
	budget time.Duration
}

// defaultLimits are sized so a normal backup directory is walked completely and a
// pathological one still cannot hold the audit up for long. The whole section's
// walking is additionally capped by totalBudget.
var defaultLimits = limits{maxDepth: 6, maxFiles: 20000, budget: 2 * time.Second}

// totalBudget caps the walking across every location together. A host with eight
// backup directories on eight cold NFS mounts must not add a minute to the run.
const totalBudget = 10 * time.Second

// errStopWalk ends a walk that has hit a bound. It never escapes scanLocation.
var errStopWalk = errors.New("walk bound reached")

func (l limits) normalise() limits {
	if l.maxDepth <= 0 {
		l.maxDepth = defaultLimits.maxDepth
	}
	if l.maxFiles <= 0 {
		l.maxFiles = defaultLimits.maxFiles
	}
	if l.budget <= 0 {
		l.budget = defaultLimits.budget
	}
	return l
}

// scanLocation measures one backup directory: the newest modification time in it,
// how old that is, how many regular files it holds and how many bytes.
//
// now is a parameter so the age is deterministic and testable. The returned notes
// are the honesty channel — an unreadable subdirectory, a bound that bit, or a
// directory that holds nothing at all.
func scanLocation(path string, now time.Time, lim limits) (model.BackupLocation, []string) {
	lim = lim.normalise()
	location := model.BackupLocation{Path: path}
	var notes []string

	// A symlinked /backup is common (/backup -> /mnt/data/backup), and
	// filepath.WalkDir does not follow symlinks — pointed at one it would yield a
	// single non-directory entry and report an empty backup. Resolve first.
	walkRoot := path
	if resolved, err := filepath.EvalSymlinks(path); err == nil && resolved != path {
		walkRoot = resolved
		notes = append(notes, path+" resolves to "+resolved)
	}

	started := time.Now()
	var (
		newest     time.Time
		files      int
		bytes      int64
		entries    int
		unreadable int
		// stopped names the bound that ended the walk outright; depthHit records
		// that some subtree was pruned while the rest was still walked. They are
		// separate because they are different claims about the numbers below.
		stopped  string
		depthHit bool
	)

	err := filepath.WalkDir(walkRoot, func(current string, entry fs.DirEntry, err error) error {
		if err != nil {
			// A directory we are not allowed to read is a gap in the answer, and
			// the reason a location can look empty when it is full.
			unreadable++
			if unreadable <= 3 {
				notes = append(notes, "unreadable: "+current+": "+errText(err))
			}
			if entry != nil && entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}

		entries++
		if entries%64 == 0 && time.Since(started) > lim.budget {
			stopped = fmt.Sprintf("the %s time budget", lim.budget)
			return errStopWalk
		}

		if entry.IsDir() {
			if depth(walkRoot, current) >= lim.maxDepth {
				depthHit = true
				return fs.SkipDir
			}
			return nil
		}
		// Symlinks, sockets and device nodes are not backup content and their
		// sizes are meaningless here. Not following them also means no loops.
		if !entry.Type().IsRegular() {
			return nil
		}

		info, err := entry.Info()
		if err != nil {
			unreadable++
			if unreadable <= 3 {
				notes = append(notes, "unreadable: "+current+": "+errText(err))
			}
			return nil
		}

		files++
		bytes += info.Size()
		if info.ModTime().After(newest) {
			newest = info.ModTime()
		}
		if files >= lim.maxFiles {
			stopped = fmt.Sprintf("the limit of %d files", lim.maxFiles)
			return errStopWalk
		}
		return nil
	})
	if err != nil && !errors.Is(err, errStopWalk) {
		notes = append(notes, path+": "+errText(err))
	}

	if unreadable > 3 {
		notes = append(notes, fmt.Sprintf("%s: %d further entries were unreadable", path, unreadable-3))
	}
	if stopped != "" {
		notes = append(notes, fmt.Sprintf("%s: the walk stopped at %s, so its file count and size are lower bounds and its newest file may be newer still", path, stopped))
	}
	if depthHit {
		notes = append(notes, fmt.Sprintf("%s: subdirectories more than %d levels deep were not examined, so its file count and size are lower bounds", path, lim.maxDepth))
	}

	location.FileCount = files
	location.SizeBytes = bytes
	if !newest.IsZero() {
		location.NewestFileAt = newest.UTC().Format(time.RFC3339)
		// Truncated towards zero: a file written 47 hours ago is one day old.
		location.AgeDays = int(now.Sub(newest).Hours() / 24)
	} else if files == 0 {
		// NewestFileAt stays empty, which is the model's documented signal for
		// "nothing to date". AgeDays stays 0 because the type has no third state,
		// so the note is what stops a reader taking 0 for "backed up today".
		notes = append(notes, path+": holds no regular files, so there is no backup date to report")
	}
	return location, notes
}

// depth counts directory levels between root and path. The root itself is 0.
func depth(root, path string) int {
	relative, err := filepath.Rel(root, path)
	if err != nil || relative == "." {
		return 0
	}
	return strings.Count(relative, string(filepath.Separator)) + 1
}

// repoKind names the deduplicating-archive format a directory is a repository of,
// or "" when it is an ordinary directory.
//
// Both formats keep a `config` file at the top of the repository. restic pairs it
// with snapshots/, borg with data/ — and restic also has a data/, so snapshots/ is
// tested first or every restic repository would be reported as a borg one.
//
// This matters beyond labelling: a repository's newest file is written by every
// successful run, so its mtime is the date of the last backup even though nothing
// inside is readable without the passphrase.
func repoKind(dir string) string {
	if !isFile(filepath.Join(dir, "config")) {
		return ""
	}
	switch {
	case isDir(filepath.Join(dir, "snapshots")):
		return "restic"
	case isDir(filepath.Join(dir, "data")):
		return "borg"
	}
	return ""
}

func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func isFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

// errText keeps a filesystem error short. The path is already in the note.
func errText(err error) string {
	var pathErr *fs.PathError
	if errors.As(err, &pathErr) {
		return pathErr.Err.Error()
	}
	return err.Error()
}
