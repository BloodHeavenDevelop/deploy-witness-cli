//go:build !windows

package scheduler

import (
	"fmt"
	"io/fs"
	"syscall"
)

// ownerUID is the numeric owner of a file, as a string ready for user.LookupId.
func ownerUID(info fs.FileInfo) (string, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", false
	}
	return fmt.Sprintf("%d", stat.Uid), true
}
