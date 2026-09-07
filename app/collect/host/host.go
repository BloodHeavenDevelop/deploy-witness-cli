// Package host collects the plain physical facts a witness check compares a
// manifest against: the architecture, memory, filesystems and the databases
// already running.
//
// The system section already reports most of this as prose — "7.5 GiB used of 30
// GiB (25.1%)" reads well and is useless to a rule. This package produces the same
// observations as numbers, from the same sources, so nothing is measured twice and
// nothing is parsed back out of a sentence.
package host

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/run"
)

// Collect fills the host-level fields of caps.
func Collect(runner *run.Runner, caps *model.Capabilities, result *model.SectionResult) {
	caps.Arch = arch(runner)
	if caps.Arch == "" {
		result.Degrade("host: the CPU architecture could not be read, so an image/host architecture mismatch cannot be detected")
	}

	mem, err := meminfo("/proc/meminfo")
	if err != nil {
		result.Degrade("host: /proc/meminfo unreadable: " + err.Error())
	}
	caps.MemTotalBytes = mem["MemTotal"] * 1024
	caps.MemAvailableBytes = mem["MemAvailable"] * 1024
	caps.SwapTotalBytes = mem["SwapTotal"] * 1024

	filesystems, notes := Filesystems("/proc/mounts")
	caps.Filesystems = filesystems
	for _, note := range notes {
		result.Degrade("host: " + note)
	}
	if len(filesystems) == 0 {
		result.Degrade("host: no filesystem capacity could be measured, so the disk and inode checks cannot run")
	}
}

// arch reads the machine architecture. `uname -m` rather than runtime.GOARCH: the
// audit reports what the host is, not what this binary was compiled for, and the
// two differ whenever an amd64 build runs under emulation on arm64 — which is
// exactly the situation an architecture-mismatch finding is about.
func arch(runner *run.Runner) string {
	out, err := runner.Output("uname", "-m")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

// meminfo parses /proc/meminfo into kilobyte values.
func meminfo(path string) (map[string]int64, error) {
	out := map[string]int64{}
	raw, err := os.ReadFile(path)
	if err != nil {
		return out, err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		key, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		fields := strings.Fields(value)
		if len(fields) == 0 {
			continue
		}
		if kb, err := strconv.ParseInt(fields[0], 10, 64); err == nil {
			out[strings.TrimSpace(key)] = kb
		}
	}
	return out, nil
}

// pseudoFilesystems carry no capacity a deployment can consume. tmpfs is on the
// list even though it has a size, because its size is memory and it is accounted
// for there; counting it as disk would show a host as having far more space than it
// can actually write to.
var pseudoFilesystems = map[string]bool{
	"autofs": true, "bpf": true, "cgroup": true, "cgroup2": true,
	"configfs": true, "debugfs": true, "devpts": true, "devtmpfs": true,
	"efivarfs": true, "fusectl": true, "hugetlbfs": true, "mqueue": true,
	"nsfs": true, "proc": true, "pstore": true, "ramfs": true,
	"rpc_pipefs": true, "securityfs": true, "selinuxfs": true, "sysfs": true,
	"tmpfs": true, "tracefs": true, "binfmt_misc": true,
	// Read-only image mounts are always exactly full by construction.
	"squashfs": true, "iso9660": true, "erofs": true,
}

// Filesystems measures every real filesystem, capacity and inodes both.
//
// Exported and taking the mounts path so it can be tested against a fixture; the
// statfs call itself needs a real mount point, and the mounts that do not exist in
// a test are reported as skipped rather than silently dropped.
func Filesystems(mountsPath string) (out []model.Filesystem, notes []string) {
	raw, err := os.ReadFile(mountsPath)
	if err != nil {
		return nil, []string{mountsPath + " unreadable: " + err.Error()}
	}

	unreadable := 0
	seen := map[string]bool{}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		device, mount, fstype, options := fields[0], unescapeMount(fields[1]), fields[2], fields[3]
		if pseudoFilesystems[fstype] || seen[mount] {
			continue
		}
		seen[mount] = true

		var stat syscall.Statfs_t
		if err := syscall.Statfs(mount, &stat); err != nil {
			unreadable++
			continue
		}
		total := stat.Blocks * uint64(stat.Bsize)
		if total == 0 {
			continue
		}

		out = append(out, model.Filesystem{
			Mount:  mount,
			Device: device,
			FSType: fstype,
			// Available rather than Free: the blocks reserved for root are not
			// capacity a container can write into, and counting them makes a full
			// disk look like it has room.
			TotalBytes:     total,
			UsedBytes:      total - stat.Bfree*uint64(stat.Bsize),
			AvailableBytes: stat.Bavail * uint64(stat.Bsize),
			// Files/Ffree are the inode counts. A btrfs or an XFS with dynamic
			// inodes reports zero here, which means "no fixed limit" and must not
			// be read as "no inodes left".
			InodesTotal: stat.Files,
			InodesFree:  stat.Ffree,
			ReadOnly:    hasMountOption(options, "ro"),
		})
	}

	if unreadable > 0 {
		notes = append(notes, fmt.Sprintf(
			"%d mount point(s) could not be measured — usually a filesystem this account cannot enter; "+
				"their capacity is absent from the report rather than assumed", unreadable))
	}
	return out, notes
}

func hasMountOption(options, want string) bool {
	for _, opt := range strings.Split(options, ",") {
		if opt == want {
			return true
		}
	}
	return false
}

// unescapeMount decodes the octal escapes /proc/mounts uses for spaces and tabs.
func unescapeMount(path string) string {
	return strings.NewReplacer(
		`\040`, " ",
		`\011`, "\t",
		`\012`, "\n",
		`\134`, `\`,
	).Replace(path)
}

// FilesystemFor returns the filesystem a path would be written to: the longest
// mount point that is a prefix of it. A rule about "will this bind mount fit"
// needs the volume the path actually lands on, not the root filesystem.
func FilesystemFor(path string, filesystems []model.Filesystem) (model.Filesystem, bool) {
	best, found := model.Filesystem{}, false
	for _, fs := range filesystems {
		if !underMount(path, fs.Mount) {
			continue
		}
		if !found || len(fs.Mount) > len(best.Mount) {
			best, found = fs, true
		}
	}
	return best, found
}

func underMount(path, mount string) bool {
	path = filepath.Clean(path)
	mount = filepath.Clean(mount)
	if mount == "/" {
		return strings.HasPrefix(path, "/")
	}
	return path == mount || strings.HasPrefix(path, mount+"/")
}
