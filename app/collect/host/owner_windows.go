//go:build windows

package host

import "io/fs"

// owner has no numeric owner to report on Windows.
func owner(fs.FileInfo) (int, int) { return -1, -1 }
