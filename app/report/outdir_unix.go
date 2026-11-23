//go:build !windows

package report

import (
	"fmt"
	"os"
	"strconv"
	"syscall"
)

// checkOutDirOwner accepts a directory only this account (or root) can change. Under
// sudo, the directory of the operator who invoked it is accepted too.
func checkOutDirOwner(dir string, info os.FileInfo) error {
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("report directory %s is writable by group or others; choose a private directory", dir)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("could not read the owner of report directory %s", dir)
	}
	euid := os.Geteuid()
	owner := int(stat.Uid)
	if owner == euid || owner == 0 {
		return nil
	}
	if euid == 0 {
		if sudo, err := strconv.Atoi(os.Getenv("SUDO_UID")); err == nil && sudo == owner {
			return nil
		}
	}
	return fmt.Errorf("report directory %s belongs to another account; choose a private directory", dir)
}
