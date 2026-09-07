package services

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type processEntry struct {
	pid     int
	ppid    int
	name    string
	cmdline string
}

// readProcessTable walks /proc. Processes that vanish mid-walk are skipped
// silently: a process table read without a kernel snapshot is always slightly
// stale, and treating the race as an error would fail the section on any busy
// host.
func readProcessTable() ([]processEntry, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}

	var out []processEntry
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || !entry.IsDir() {
			continue
		}

		base := filepath.Join("/proc", entry.Name())
		p := processEntry{pid: pid}

		if raw, err := os.ReadFile(filepath.Join(base, "comm")); err == nil {
			p.name = strings.TrimSpace(string(raw))
		} else {
			continue
		}
		if raw, err := os.ReadFile(filepath.Join(base, "cmdline")); err == nil {
			p.cmdline = strings.TrimSpace(
				strings.Join(strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00"), " "))
		}
		if raw, err := os.ReadFile(filepath.Join(base, "status")); err == nil {
			for _, line := range strings.Split(string(raw), "\n") {
				if value, ok := strings.CutPrefix(line, "PPid:"); ok {
					p.ppid, _ = strconv.Atoi(strings.TrimSpace(value))
					break
				}
			}
		}
		out = append(out, p)
	}
	return out, nil
}
