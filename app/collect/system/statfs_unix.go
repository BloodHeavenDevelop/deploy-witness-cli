//go:build !windows

package system

import "syscall"

// statFilesystem returns statfs(2)'s block counts and the block size, widened to
// uint64 because the field types differ between Linux and macOS.
func statFilesystem(mount string) (blocks, free, available, blockSize uint64, err error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(mount, &stat); err != nil {
		return 0, 0, 0, 0, err
	}
	return uint64(stat.Blocks), uint64(stat.Bfree), uint64(stat.Bavail),
		uint64(stat.Bsize), nil //nolint:gosec // a block size is never negative
}
