//go:build windows

package system

import "errors"

// statFilesystem has nothing to measure on Windows: storage is read from
// /proc/mounts, which does not exist there. It exists so the binary builds.
func statFilesystem(string) (blocks, free, available, blockSize uint64, err error) {
	return 0, 0, 0, 0, errors.New("statfs is not available on windows")
}
