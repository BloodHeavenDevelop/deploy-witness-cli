package host

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
)

// BindSources looks at every bind mount source of the plan on this host — by stat
// alone. Nothing is created, opened or read: a missing directory stays missing
// (whether the engine would create it is the plan's business, not this
// collector's), and a path this account cannot reach is "unknown", never "missing".
//
// What a stat shows is what this account sees. It is not what the container's user
// will see: user-namespace remapping, rootless engines, ACLs and SELinux labels are
// not read, and the rules say so instead of promising access.
func BindSources(manifest *model.Manifest, caps *model.Capabilities, result *model.SectionResult) {
	seen := map[string]bool{}
	var paths []string
	for _, svc := range manifest.Services {
		for _, m := range svc.Volumes {
			if m.Kind == model.MountBind && m.Source != "" && filepath.IsAbs(m.Source) && !seen[m.Source] {
				seen[m.Source] = true
				paths = append(paths, m.Source)
			}
		}
	}
	sort.Strings(paths)
	if len(paths) == 0 {
		caps.Observe(model.SourceBindSources, model.ObservedComplete, "the plan has no bind mount")
		return
	}

	unknown := 0
	for _, path := range paths {
		info := StatPath(path)
		if fs, ok := FilesystemFor(path, caps.Filesystems); ok {
			info.ReadOnlyFS = fs.ReadOnly
		}
		if info.State == "unknown" {
			unknown++
		}
		caps.BindSources = append(caps.BindSources, info)
	}
	if unknown > 0 {
		note := fmt.Sprintf("%d of %d bind mount source(s) could not be examined by this account, so whether "+
			"they exist is unknown", unknown, len(paths))
		result.Degrade("bind sources: " + note)
		caps.Observe(model.SourceBindSources, model.ObservedPartial, "stat: "+note)
		return
	}
	caps.Observe(model.SourceBindSources, model.ObservedComplete, fmt.Sprintf("stat of %d bind source(s)", len(paths)))
}

// StatPath describes one path without opening it: whether it exists, what it is
// (following a symlink, which is what the engine mounts), its mode and owner.
func StatPath(path string) model.PathInfo {
	info := model.PathInfo{Path: path, UID: -1, GID: -1}
	link, err := os.Lstat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		info.State = "missing"
		return info
	case err != nil:
		info.State, info.Error = "unknown", err.Error()
		return info
	}
	target := link
	if link.Mode()&os.ModeSymlink != 0 {
		info.SymlinkTarget, _ = os.Readlink(path)
		followed, err := os.Stat(path)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			info.State, info.Type, info.Dangling = "exists", "symlink", true
			return info
		case err != nil:
			info.State, info.Error = "unknown", err.Error()
			return info
		}
		target = followed
	}
	info.State = "exists"
	info.Type = fileType(target.Mode())
	info.Mode = fmt.Sprintf("%04o", target.Mode().Perm())
	info.UID, info.GID = owner(target)
	return info
}

func fileType(mode fs.FileMode) string {
	switch {
	case mode.IsDir():
		return "directory"
	case mode.IsRegular():
		return "file"
	case mode&fs.ModeSocket != 0:
		return "socket"
	case mode&fs.ModeDevice != 0:
		return "device"
	case mode&fs.ModeNamedPipe != 0:
		return "fifo"
	}
	return "other"
}
