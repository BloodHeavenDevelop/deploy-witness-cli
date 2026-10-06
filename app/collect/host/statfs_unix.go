//go:build !windows

package host

import "syscall"

// filesystemStat is the part of statfs(2) the filesystem inventory reads, in one
// unit (bytes per block) so the caller does no per-platform arithmetic.
type filesystemStat struct {
	blocks, free, available, blockSize, files, filesFree uint64
}

func statFilesystem(mount string) (filesystemStat, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(mount, &stat); err != nil {
		return filesystemStat{}, err
	}
	return filesystemStat{
		blocks:    uint64(stat.Blocks),
		free:      uint64(stat.Bfree),
		available: uint64(stat.Bavail),
		blockSize: uint64(stat.Bsize), //nolint:gosec // a block size is never negative
		files:     uint64(stat.Files),
		filesFree: uint64(stat.Ffree),
	}, nil
}
