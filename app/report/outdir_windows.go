//go:build windows

package report

import "os"

// checkOutDirOwner has nothing to check on Windows, where POSIX owner and mode bits
// do not describe who may write to a directory.
func checkOutDirOwner(string, os.FileInfo) error { return nil }
