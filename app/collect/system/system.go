// Package system collects the host inventory: identity, kernel, hardware,
// storage, network, time and the security posture of the base install.
package system

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/pkgmgr"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/run"
)

// collector accumulates facts. Every probe is best-effort: a fact that cannot be
// read is omitted, never guessed and never rendered as an empty row.
type collector struct {
	runner *run.Runner
	os     model.OSRelease
	result *model.SectionResult
	facts  []model.Fact
}

func (c *collector) add(category, key, value, source string) {
	value = strings.TrimSpace(value)
	if value == "" {
		return
	}
	c.facts = append(c.facts, model.Fact{
		Category: category,
		Key:      key,
		Value:    value,
		Source:   source,
	})
}

// Collect gathers the system section.
func Collect(
	runner *run.Runner,
	osrel model.OSRelease,
	manager pkgmgr.Manager,
	result *model.SectionResult,
) []model.Fact {
	c := &collector{runner: runner, os: osrel, result: result}

	c.identity()
	c.kernel()
	c.hardware()
	c.storage()
	c.network()
	c.timekeeping()
	c.packages(manager)
	c.accounts()
	c.ssh()
	c.mandatoryAccessControl()
	c.firewall()
	c.kernelHardening()
	c.rebootPending(manager)

	return c.facts
}

// fqdn resolves the fully-qualified name without asking a resolver.
//
// `hostname -f` would be the obvious way, and it is the wrong one: it calls
// getaddrinfo, which on a host with a configured nameserver sends a DNS query.
// That is a network operation, and this tool promises not to perform one. The
// allowlist refused the command and that refusal is what surfaced the problem, so
// the FQDN is now read from the two sources already on the machine: the kernel
// hostname when it is qualified, and the /etc/hosts entry for it otherwise.
//
// An empty answer means neither source carries a domain — which is the truth, and
// better than a resolver's guess.
func fqdn() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		return ""
	}
	if strings.Contains(host, ".") {
		return host
	}

	raw, err := os.ReadFile("/etc/hosts")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if idx := strings.IndexByte(line, '#'); idx >= 0 {
			line = line[:idx]
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		// The first qualified alias on a line that also names this host: the
		// canonical form of `127.0.1.1 web.example.com web`.
		hasHost, qualified := false, ""
		for _, name := range fields[1:] {
			if name == host {
				hasHost = true
			}
			if qualified == "" && strings.Contains(name, ".") && strings.HasPrefix(name, host+".") {
				qualified = name
			}
		}
		if hasHost && qualified != "" {
			return qualified
		}
	}
	return ""
}

// ---------------------------------------------------------------- identity

func (c *collector) identity() {
	if host, err := os.Hostname(); err == nil {
		c.add("host", "hostname", host, "os.Hostname")
	}
	c.add("host", "machine-id", readTrimmed("/etc/machine-id"), "/etc/machine-id")
	c.add("host", "fqdn", fqdn(), "os.Hostname / /etc/hosts")

	c.add("os", "distribution", c.os.PrettyName, "/etc/os-release")
	c.add("os", "id", c.os.ID, "/etc/os-release")
	c.add("os", "version-id", c.os.VersionID, "/etc/os-release")
	c.add("os", "codename", c.os.Codename, "/etc/os-release")
	c.add("os", "build-id", c.os.BuildID, "/etc/os-release")
	c.add("os", "family", c.os.Family(), "derived")

	c.add("host", "virtualization", c.virtualization(), "systemd-detect-virt")
	c.add("host", "container", c.containerHint(), "filesystem markers")
}

// virtualization reports the hypervisor or container technology. Exit code 1
// means bare metal, which is an answer, not a failure.
func (c *collector) virtualization() string {
	out, _, err := c.runner.OutputAllowExit([]int{1}, "systemd-detect-virt")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}

func (c *collector) containerHint() string {
	markers := map[string]string{
		"/.dockerenv":            "docker",
		"/run/.containerenv":     "podman",
		"/run/systemd/container": "systemd-nspawn",
	}
	var found []string
	for path, name := range markers {
		if _, err := os.Stat(path); err == nil {
			found = append(found, name)
		}
	}
	sort.Strings(found)
	return strings.Join(found, ", ")
}

// ---------------------------------------------------------------- kernel

func (c *collector) kernel() {
	c.add("kernel", "name", readTrimmed("/proc/sys/kernel/ostype"), "/proc/sys/kernel/ostype")
	c.add("kernel", "release", readTrimmed("/proc/sys/kernel/osrelease"), "/proc/sys/kernel/osrelease")
	c.add("kernel", "version", readTrimmed("/proc/sys/kernel/version"), "/proc/sys/kernel/version")

	arch := c.command("uname", "-m")
	if arch == "" {
		arch = runtime.GOARCH
	}
	c.add("kernel", "architecture", arch, "uname -m")

	if uptime, boot, ok := uptime(); ok {
		c.add("kernel", "uptime", uptime.Truncate(time.Second).String(), "/proc/uptime")
		// UTC, per the platform convention: the reader's timezone is applied on
		// display, never baked into the data.
		c.add("kernel", "booted-at", boot.UTC().Format("2006-01-02 15:04:05")+" UTC", "/proc/uptime")
	}
	c.add("kernel", "load-average", readTrimmed("/proc/loadavg"), "/proc/loadavg")
}

func uptime() (time.Duration, time.Time, bool) {
	raw := readTrimmed("/proc/uptime")
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return 0, time.Time{}, false
	}
	seconds, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, time.Time{}, false
	}
	d := time.Duration(seconds * float64(time.Second))
	return d, time.Now().Add(-d), true
}

// ---------------------------------------------------------------- hardware

func (c *collector) hardware() {
	cpuModel, cores := cpuInfo()
	c.add("hardware", "cpu-model", cpuModel, "/proc/cpuinfo")
	if cores > 0 {
		c.add("hardware", "cpu-threads", strconv.Itoa(cores), "/proc/cpuinfo")
	}

	mem := meminfo()
	for _, key := range []string{"MemTotal", "MemAvailable", "SwapTotal"} {
		if kb, ok := mem[key]; ok {
			c.add("hardware", strings.ToLower(key), humanKB(kb), "/proc/meminfo")
		}
	}

	c.add("hardware", "product", readTrimmed("/sys/class/dmi/id/product_name"), "/sys/class/dmi/id")
	c.add("hardware", "vendor", readTrimmed("/sys/class/dmi/id/sys_vendor"), "/sys/class/dmi/id")
}

func cpuInfo() (string, int) {
	raw, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return "", 0
	}

	name := ""
	count := 0
	for _, line := range strings.Split(string(raw), "\n") {
		key, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		switch key {
		case "model name", "Model":
			if name == "" {
				name = value
			}
		case "processor":
			count++
		}
	}
	return name, count
}

func meminfo() map[string]int64 {
	out := map[string]int64{}
	raw, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return out
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
	return out
}

func humanKB(kb int64) string {
	return humanBytes(uint64(kb) * 1024)
}

func humanBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit && exp < 4; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTP"[exp])
}

// ---------------------------------------------------------------- storage

// skippedFilesystems have no capacity worth auditing: kernel-backed pseudo
// filesystems, and the read-only image mounts (snap, appimage) that are always
// exactly 100% full by construction and would otherwise bury the real volumes
// under dozens of false "disk full" rows.
var skippedFilesystems = map[string]bool{
	"autofs": true, "bpf": true, "cgroup": true, "cgroup2": true,
	"configfs": true, "debugfs": true, "devpts": true, "devtmpfs": true,
	"efivarfs": true, "fusectl": true, "hugetlbfs": true, "mqueue": true,
	"nsfs": true, "proc": true, "pstore": true, "ramfs": true,
	"rpc_pipefs": true, "securityfs": true, "selinuxfs": true, "sysfs": true,
	"tmpfs": true, "tracefs": true, "binfmt_misc": true,
	"squashfs": true, "iso9660": true, "erofs": true,
}

func (c *collector) storage() {
	raw, err := os.ReadFile("/proc/mounts")
	if err != nil {
		c.result.Degrade("storage: /proc/mounts unreadable: " + err.Error())
		return
	}

	seen := map[string]bool{}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		device, mount, fstype := fields[0], unescapeMount(fields[1]), fields[2]
		if skippedFilesystems[fstype] || seen[mount] {
			continue
		}
		seen[mount] = true

		var stat syscall.Statfs_t
		if err := syscall.Statfs(mount, &stat); err != nil {
			continue
		}
		total := stat.Blocks * uint64(stat.Bsize)
		if total == 0 {
			continue
		}
		// Available, not Free: the reserved blocks root keeps are not capacity a
		// service can use, and reporting them makes a full disk look healthy.
		available := stat.Bavail * uint64(stat.Bsize)
		used := total - stat.Bfree*uint64(stat.Bsize)

		c.add("storage", mount, fmt.Sprintf("%s used of %s (%.1f%%), %s available, %s on %s",
			humanBytes(used), humanBytes(total),
			float64(used)/float64(total)*100,
			humanBytes(available), fstype, device),
			"/proc/mounts + statfs")
	}
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

// ---------------------------------------------------------------- network

func (c *collector) network() {
	interfaces, err := net.Interfaces()
	if err != nil {
		c.result.Degrade("network: interfaces unreadable: " + err.Error())
		return
	}

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil || len(addrs) == 0 {
			continue
		}
		var list []string
		for _, addr := range addrs {
			list = append(list, addr.String())
		}
		value := strings.Join(list, ", ")
		if iface.HardwareAddr != nil {
			value += " (mac " + iface.HardwareAddr.String() + ")"
		}
		c.add("network", iface.Name, value, "net.Interfaces")
	}

	c.add("network", "dns-servers", strings.Join(resolvers(), ", "), "/etc/resolv.conf")
	c.add("network", "default-route", c.defaultRoute(), "/proc/net/route")
}

func resolvers() []string {
	raw, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "nameserver" {
			out = append(out, fields[1])
		}
	}
	return out
}

// defaultRoute reads the gateway from /proc/net/route, whose addresses are
// little-endian hex.
func (c *collector) defaultRoute() string {
	raw, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(raw), "\n")[1:] {
		fields := strings.Fields(line)
		if len(fields) < 3 || fields[1] != "00000000" {
			continue
		}
		gateway, err := strconv.ParseUint(fields[2], 16, 32)
		if err != nil {
			continue
		}
		return fmt.Sprintf("%d.%d.%d.%d via %s",
			gateway&0xff, (gateway>>8)&0xff, (gateway>>16)&0xff, (gateway>>24)&0xff,
			fields[0])
	}
	return ""
}

// ---------------------------------------------------------------- time

func (c *collector) timekeeping() {
	c.add("time", "audit-generated-at", time.Now().UTC().Format("2006-01-02 15:04:05")+" UTC", "deploy-witness")
	c.add("time", "timezone", localTimezone(), "/etc/localtime")

	if out, err := c.runner.Output("timedatectl", "show",
		"--property=Timezone", "--property=NTPSynchronized", "--property=NTP"); err == nil {
		for _, line := range run.Lines(out) {
			key, value, found := strings.Cut(line, "=")
			if !found {
				continue
			}
			c.add("time", strings.ToLower(key), value, "timedatectl")
		}
	}
}

// localTimezone resolves the zone name from the /etc/localtime symlink, which is
// how systemd records it; /etc/timezone is Debian-only.
func localTimezone() string {
	if target, err := os.Readlink("/etc/localtime"); err == nil {
		if i := strings.Index(target, "zoneinfo/"); i >= 0 {
			return target[i+len("zoneinfo/"):]
		}
		return filepath.Base(target)
	}
	return readTrimmed("/etc/timezone")
}

// ---------------------------------------------------------------- packages

func (c *collector) packages(manager pkgmgr.Manager) {
	if manager == nil {
		return
	}
	c.add("packages", "manager", manager.Name(), "detected")

	ecosystem := manager.Ecosystem()
	if ecosystem == "" {
		ecosystem = "none published by OSV"
	}
	c.add("packages", "osv-ecosystem", ecosystem, "derived")

	if installed, err := manager.Installed(); err == nil {
		c.add("packages", "installed-count", strconv.Itoa(len(installed)), manager.Name())
	} else {
		c.result.Degrade("packages: " + err.Error())
	}
}

// rebootPending answers the question every update report raises next.
func (c *collector) rebootPending(manager pkgmgr.Manager) {
	if _, err := os.Stat("/var/run/reboot-required"); err == nil {
		reason := readTrimmed("/var/run/reboot-required.pkgs")
		value := "yes"
		if reason != "" {
			value += " (" + strings.Join(strings.Fields(reason), ", ") + ")"
		}
		c.add("updates", "reboot-required", value, "/var/run/reboot-required")
		return
	}

	if run.Available("needs-restarting") {
		// Exit 1 means a reboot is needed; that is the answer, not an error.
		_, code, err := c.runner.OutputAllowExit([]int{1}, "needs-restarting", "-r")
		if err == nil {
			c.add("updates", "reboot-required", map[bool]string{true: "yes", false: "no"}[code == 1],
				"needs-restarting -r")
		}
	}
}

// ---------------------------------------------------------------- helpers

func readTrimmed(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

func (c *collector) command(name string, args ...string) string {
	out, err := c.runner.Output(name, args...)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(out)
}
