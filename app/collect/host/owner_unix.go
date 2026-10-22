//go:build !windows

package host

import (
	"io/fs"
	"syscall"
)

// owner is the numeric owner and group of a stat result, or -1 when the platform
// does not report one.
func owner(info fs.FileInfo) (int, int) {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return int(st.Uid), int(st.Gid)
	}
	return -1, -1
}
