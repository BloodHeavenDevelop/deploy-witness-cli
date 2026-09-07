package system

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/run"
)

// ---------------------------------------------------------------- accounts

func (c *collector) accounts() {
	raw, err := os.ReadFile("/etc/passwd")
	if err != nil {
		c.result.Degrade("accounts: /etc/passwd unreadable: " + err.Error())
		return
	}

	// Shells that exist specifically to deny interactive login.
	deniedShells := map[string]bool{
		"/usr/sbin/nologin": true, "/sbin/nologin": true, "/bin/false": true,
		"/usr/bin/false": true, "/bin/sync": true, "/usr/bin/sync": true,
		"": true,
	}

	var total int
	var rootAccounts, interactive []string

	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < 7 {
			continue
		}
		total++

		name, uid, shell := fields[0], fields[2], fields[6]
		// A second UID 0 account is a privilege-escalation backdoor that no
		// package manager will ever report, so it is called out by name.
		if uid == "0" {
			rootAccounts = append(rootAccounts, name)
		}
		if !deniedShells[shell] {
			interactive = append(interactive, name+" ("+shell+")")
		}
	}

	sort.Strings(rootAccounts)
	sort.Strings(interactive)

	c.add("accounts", "total", strconv.Itoa(total), "/etc/passwd")
	c.add("accounts", "uid-0", strings.Join(rootAccounts, ", "), "/etc/passwd")
	c.add("accounts", "interactive-shells", strings.Join(interactive, ", "), "/etc/passwd")

	c.passwordlessAccounts()
	c.sudoRules()
}

// passwordlessAccounts needs /etc/shadow, which is root-only. Running unprivileged
// is normal, so a permission error is reported as a gap in coverage rather than a
// failure — and never as "no passwordless accounts found".
func (c *collector) passwordlessAccounts() {
	raw, err := os.ReadFile("/etc/shadow")
	if err != nil {
		c.result.Degrade("accounts: /etc/shadow unreadable (run as root to audit password hashes): " + err.Error())
		return
	}

	var empty, locked []string
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < 2 {
			continue
		}
		switch {
		case fields[1] == "":
			empty = append(empty, fields[0])
		case strings.HasPrefix(fields[1], "!"), strings.HasPrefix(fields[1], "*"):
			locked = append(locked, fields[0])
		}
	}

	c.add("accounts", "empty-password", strings.Join(empty, ", "), "/etc/shadow")
	c.add("accounts", "locked-count", strconv.Itoa(len(locked)), "/etc/shadow")
}

func (c *collector) sudoRules() {
	files := []string{"/etc/sudoers"}
	if entries, err := filepath.Glob("/etc/sudoers.d/*"); err == nil {
		files = append(files, entries...)
	}

	var nopasswd []string
	readable := 0
	for _, path := range files {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		readable++
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			if strings.Contains(line, "NOPASSWD") {
				nopasswd = append(nopasswd, filepath.Base(path)+": "+line)
			}
		}
	}

	if readable == 0 {
		c.result.Degrade("accounts: sudoers unreadable (run as root to audit sudo rules)")
		return
	}
	c.add("accounts", "sudo-nopasswd-rules", strings.Join(nopasswd, " | "), "/etc/sudoers*")
}

// ---------------------------------------------------------------- ssh

// sshInterestingKeys are the sshd settings that decide who can reach the host.
var sshInterestingKeys = []string{
	"port", "permitrootlogin", "passwordauthentication", "pubkeyauthentication",
	"permitemptypasswords", "kbdinteractiveauthentication", "challengeresponseauthentication",
	"x11forwarding", "allowtcpforwarding", "maxauthtries", "clientaliveinterval",
	"allowusers", "allowgroups", "denyusers", "denygroups",
}

func (c *collector) ssh() {
	values, source := c.sshEffectiveConfig()
	if values == nil {
		return
	}

	for _, key := range sshInterestingKeys {
		if value, ok := values[key]; ok {
			c.add("ssh", key, value, source)
		}
	}
}

// sshEffectiveConfig prefers `sshd -T`, which resolves Include directives, Match
// blocks and compiled-in defaults. Parsing the files by hand misses all three and
// will happily report PasswordAuthentication as absent on a host where a dropped-in
// file turns it on.
func (c *collector) sshEffectiveConfig() (map[string]string, string) {
	for _, binary := range []string{"sshd", "/usr/sbin/sshd"} {
		if !run.Available(binary) && !fileExists(binary) {
			continue
		}
		out, err := c.runner.Output(binary, "-T")
		if err != nil {
			continue
		}
		values := map[string]string{}
		for _, line := range run.Lines(out) {
			key, value, found := strings.Cut(line, " ")
			if !found {
				continue
			}
			key = strings.ToLower(key)
			// Repeated keys (allowusers, subsystem) accumulate.
			if existing, ok := values[key]; ok {
				values[key] = existing + " " + value
				continue
			}
			values[key] = value
		}
		return values, binary + " -T"
	}

	config := "/etc/ssh/sshd_config"
	if !fileExists(config) {
		return nil, ""
	}
	c.result.Degrade("ssh: `sshd -T` unavailable, falling back to parsing sshd_config (Include and Match blocks are not resolved)")

	values := map[string]string{}
	for _, path := range append([]string{config}, sshIncludes(config)...) {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 2 {
				continue
			}
			values[strings.ToLower(fields[0])] = strings.Join(fields[1:], " ")
		}
	}
	return values, config
}

func sshIncludes(config string) []string {
	raw, err := os.ReadFile(config)
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) < 2 || !strings.EqualFold(fields[0], "Include") {
			continue
		}
		for _, pattern := range fields[1:] {
			if !filepath.IsAbs(pattern) {
				pattern = filepath.Join(filepath.Dir(config), pattern)
			}
			if matches, err := filepath.Glob(pattern); err == nil {
				out = append(out, matches...)
			}
		}
	}
	return out
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// ---------------------------------------------------------------- MAC

func (c *collector) mandatoryAccessControl() {
	switch readTrimmed("/sys/fs/selinux/enforce") {
	case "1":
		c.add("hardening", "selinux", "enforcing", "/sys/fs/selinux/enforce")
	case "0":
		c.add("hardening", "selinux", "permissive", "/sys/fs/selinux/enforce")
	}

	if enabled := readTrimmed("/sys/module/apparmor/parameters/enabled"); enabled != "" {
		state := "disabled"
		if enabled == "Y" {
			state = "enabled"
		}
		c.add("hardening", "apparmor", state, "/sys/module/apparmor/parameters/enabled")
	}
}

// ---------------------------------------------------------------- firewall

func (c *collector) firewall() {
	active := []string{}
	for _, unit := range []string{"firewalld", "ufw", "nftables", "iptables", "ip6tables"} {
		// is-active exits 3 when the unit is inactive, which is an answer.
		out, _, err := c.runner.OutputAllowExit([]int{1, 3, 4}, "systemctl", "is-active", unit)
		if err != nil {
			continue
		}
		if strings.TrimSpace(out) == "active" {
			active = append(active, unit)
		}
	}
	c.add("hardening", "firewall-units-active", strings.Join(active, ", "), "systemctl is-active")

	// Rule counts need CAP_NET_ADMIN; without it the section says so rather than
	// reporting a firewall with zero rules, which reads as "wide open".
	if out, err := c.runner.Output("nft", "list", "ruleset"); err == nil {
		rules := 0
		for _, line := range run.Lines(out) {
			if strings.HasPrefix(line, "chain ") {
				continue
			}
			if strings.Contains(line, "accept") || strings.Contains(line, "drop") ||
				strings.Contains(line, "reject") {
				rules++
			}
		}
		c.add("hardening", "nftables-rules", strconv.Itoa(rules), "nft list ruleset")
	} else if len(active) == 0 {
		c.add("hardening", "firewall", "no firewall unit active and the ruleset could not be read", "derived")
	}
}

// ---------------------------------------------------------------- sysctl

// hardeningSysctls are kernel settings whose value changes the host's exposure.
// Each is reported verbatim; the report states facts and leaves policy to the
// reader, because the safe value for ip_forward on a router is the dangerous one
// on an application server.
var hardeningSysctls = []struct{ path, key string }{
	{"/proc/sys/kernel/kptr_restrict", "kernel.kptr_restrict"},
	{"/proc/sys/kernel/dmesg_restrict", "kernel.dmesg_restrict"},
	{"/proc/sys/kernel/randomize_va_space", "kernel.randomize_va_space"},
	{"/proc/sys/kernel/yama/ptrace_scope", "kernel.yama.ptrace_scope"},
	{"/proc/sys/kernel/unprivileged_bpf_disabled", "kernel.unprivileged_bpf_disabled"},
	{"/proc/sys/kernel/unprivileged_userns_clone", "kernel.unprivileged_userns_clone"},
	{"/proc/sys/fs/protected_hardlinks", "fs.protected_hardlinks"},
	{"/proc/sys/fs/protected_symlinks", "fs.protected_symlinks"},
	{"/proc/sys/fs/suid_dumpable", "fs.suid_dumpable"},
	{"/proc/sys/net/ipv4/ip_forward", "net.ipv4.ip_forward"},
	{"/proc/sys/net/ipv4/tcp_syncookies", "net.ipv4.tcp_syncookies"},
	{"/proc/sys/net/ipv4/conf/all/accept_redirects", "net.ipv4.conf.all.accept_redirects"},
	{"/proc/sys/net/ipv4/conf/all/accept_source_route", "net.ipv4.conf.all.accept_source_route"},
	{"/proc/sys/net/ipv4/conf/all/rp_filter", "net.ipv4.conf.all.rp_filter"},
	{"/proc/sys/net/ipv6/conf/all/disable_ipv6", "net.ipv6.conf.all.disable_ipv6"},
}

func (c *collector) kernelHardening() {
	for _, s := range hardeningSysctls {
		c.add("hardening", s.key, readTrimmed(s.path), s.path)
	}
}
