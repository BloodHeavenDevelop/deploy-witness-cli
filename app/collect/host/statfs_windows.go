//go:build windows

package host

import "errors"

type filesystemStat struct {
	blocks, free, available, blockSize, files, filesFree uint64
}

// statFilesystem has nothing to measure on Windows: the inventory walks
// /proc/mounts, which does not exist there, so this is never reached with a real
// mount. It exists so the binary builds; a mount it is handed counts as unreadable.
func statFilesystem(string) (filesystemStat, error) {
	return filesystemStat{}, errors.New("statfs is not available on windows")
}
