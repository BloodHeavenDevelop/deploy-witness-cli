//go:build windows

package scheduler

import "io/fs"

// ownerUID has no uid to return on Windows; the at-job owner is reported as
// "unknown", which is what it is.
func ownerUID(fs.FileInfo) (string, bool) {
	return "", false
}
