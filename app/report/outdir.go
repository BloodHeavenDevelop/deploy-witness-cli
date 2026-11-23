package report

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// The tool normally runs as root and may be started from a directory other accounts
// can write to, so the report directory is checked before use and every file is
// written relative to the opened directory, never through a path looked up again.

// CreateOutDir creates a generated report directory. The name is predictable, so an
// existing entry of that name is never reused: a new directory with a random suffix
// is created beside it instead. It returns the directory actually created.
func CreateOutDir(dir string) (string, error) {
	if err := os.MkdirAll(filepath.Dir(dir), 0o750); err != nil {
		return "", err
	}
	err := os.Mkdir(dir, 0o750)
	if err == nil {
		return dir, nil
	}
	if !errors.Is(err, os.ErrExist) {
		return "", err
	}
	return os.MkdirTemp(filepath.Dir(dir), filepath.Base(dir)+"-*")
}

// CheckOutDir refuses a report directory that exists and is not safe to write into.
// A directory that does not exist yet passes: it is created at write time.
func CheckOutDir(dir string) error {
	info, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return checkOutDirInfo(dir, info)
}

func checkOutDirInfo(dir string, info os.FileInfo) error {
	if !info.IsDir() {
		return fmt.Errorf("report directory %s is not a real directory", dir)
	}
	return checkOutDirOwner(dir, info)
}

// openOutDir creates the directory if needed, verifies it and opens it. The checks
// apply to the opened directory, so swapping the path afterwards has no effect.
func openOutDir(dir string) (*os.Root, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	before, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if err := checkOutDirInfo(dir, before); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	opened, err := root.Stat(".")
	if err == nil && !os.SameFile(before, opened) {
		err = fmt.Errorf("report directory %s changed while it was being opened", dir)
	}
	if err == nil {
		err = checkOutDirInfo(dir, opened)
	}
	if err != nil {
		root.Close()
		return nil, err
	}
	return root, nil
}

// writeReportFile replaces name inside root with a mode 0600 file holding data. The
// content goes to a new file first, and an existing entry that is not a regular file
// is refused, so a link is neither followed nor replaced.
func writeReportFile(root *os.Root, name string, data []byte) (err error) {
	if info, statErr := root.Lstat(name); statErr == nil {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%s exists in the report directory and is not a regular file", name)
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}

	suffix := make([]byte, 8)
	if _, err := rand.Read(suffix); err != nil {
		return err
	}
	temp := "." + name + "." + hex.EncodeToString(suffix)
	file, err := root.OpenFile(temp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = root.Remove(temp)
		}
	}()
	if _, err = file.Write(data); err != nil {
		file.Close()
		return err
	}
	if err = file.Close(); err != nil {
		return err
	}
	return root.Rename(temp, name)
}
