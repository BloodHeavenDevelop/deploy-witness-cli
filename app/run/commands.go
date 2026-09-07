package run

// This is the exhaustive list of commands this binary is able to execute. Nothing
// outside it runs — see allowlist.go for the enforcement.
//
// It is meant to be read by somebody deciding whether to run this tool on their
// production host, so it is one flat, grouped, commented list rather than a set of
// registrations scattered across the collectors. Adding a command means editing
// this file, which means it shows up in the diff and in `--commands` at once.
//
// Every entry must be read-only. Two of them look like exceptions and are not:
//
//   - `apt-get … dist-upgrade` carries `-s`, which is apt's simulation mode. The
//     flag is part of the allowlist entry, so the unsimulated form is refused.
//   - `dnf/yum -C` forbids touching the network: `-C` means "cache only", and it
//     is what keeps a pending-updates check from refreshing a repository.
var commands = []Spec{
	// ── core ────────────────────────────────────────────────────────────────────
	{
		Binary: "uname", Args: []string{"-m"},
		Section: "core", Purpose: "the CPU architecture, to tell an arm64 host from an amd64 one",
	},

	// ── system ──────────────────────────────────────────────────────────────────
	{
		Binary: "systemd-detect-virt", Section: "system",
		Purpose: "whether the host is bare metal, a VM or a container",
	},
	{
		Binary: "timedatectl",
		Args: []string{"show", "--property=Timezone", "--property=NTPSynchronized",
			"--property=NTP"},
		Section: "system", Purpose: "timezone and whether the clock is synchronised",
	},
	{
		Binary: "needs-restarting", Args: []string{"-r"},
		Section: "system", Purpose: "whether the running kernel or libraries are older than the installed ones",
	},
	{
		Binary: "sshd", Args: []string{"-T"},
		Section: "system",
		Purpose: "the effective sshd configuration — resolves Include and Match, which parsing the files by hand does not",
	},
	{
		Binary: "/usr/sbin/sshd", Args: []string{"-T"},
		Section: "system", Purpose: "the same, on hosts where sshd is not on PATH",
	},
	{
		Binary: "systemctl", Args: []string{"is-active", "<unit>"},
		Section: "system", Purpose: "whether one firewall unit is running",
	},
	{
		Binary: "nft", Args: []string{"list", "ruleset"},
		Section: "system", Purpose: "how many nftables rules exist, to tell a loaded firewall from an empty one",
	},

	// ── services ────────────────────────────────────────────────────────────────
	{
		Binary: "systemctl",
		Args: []string{"list-units", "--type=service", "--all", "--no-pager",
			"--plain", "--no-legend"},
		Section: "services", Purpose: "the service inventory",
	},
	{
		Binary: "systemctl",
		Args: []string{"list-unit-files", "--type=service", "--no-pager", "--plain",
			"--no-legend"},
		Section: "services", Purpose: "which services are enabled at boot",
	},
	{
		Binary: "systemctl",
		Args: []string{"show", "--property=Id", "--property=MainPID", "--property=User",
			"--property=ActiveEnterTimestamp", "<unit>..."},
		Section: "services", MaxRepeat: 128,
		Purpose: "the pid, account and start time of each service, in batches",
	},
	{
		Binary: "rc-status", Args: []string{"--all"},
		Section: "services", Purpose: "the service inventory on OpenRC hosts",
	},
	{
		Binary: "service", Args: []string{"--status-all"},
		Section: "services", Purpose: "the service inventory on SysV hosts",
	},

	// ── ports ───────────────────────────────────────────────────────────────────
	{
		Binary: "ss", Args: []string{"-lntupH"},
		Section: "ports",
		Purpose: "listening sockets with the owning process, when /proc/net alone cannot attribute them",
	},

	// ── witness: the container runtime ────────────────────────────────────────
	//
	// Every one of these is a query. `docker` has subcommands that start, stop and
	// remove things; none of them appear here, so none of them can be run. The
	// `--format {{json .}}` forms are asked for deliberately: parsing docker's
	// human table output is where a collector starts guessing.
	{
		Binary: "docker", Args: []string{"version", "--format", "{{json .}}"},
		Section: "witness", Purpose: "the engine and API versions",
	},
	{
		Binary: "docker", Args: []string{"info", "--format", "{{json .}}"},
		Section: "witness", Purpose: "the storage driver, the root directory and the container counts",
	},
	{
		Binary: "docker", Args: []string{"ps", "-a", "--format", "{{json .}}"},
		Section: "witness", Purpose: "existing containers, running or not, and the ports they hold",
	},
	{
		Binary: "docker", Args: []string{"network", "ls", "--format", "{{json .}}"},
		Section: "witness", Purpose: "existing networks, to find a name collision",
	},
	{
		Binary: "docker", Args: []string{"network", "inspect", "<container>", "--format", "{{json .IPAM}}"},
		Section: "witness", Purpose: "one network's subnet, to find an address-range overlap",
	},
	{
		Binary: "docker", Args: []string{"volume", "ls", "--format", "{{json .}}"},
		Section: "witness", Purpose: "existing volumes, to find a name collision",
	},
	{
		Binary: "docker", Args: []string{"image", "ls", "--all", "--digests", "--format", "{{json .}}"},
		Section: "witness", Purpose: "images already on the host",
	},
	{
		Binary: "docker", Args: []string{"image", "inspect", "<image>", "--format", "{{json .}}"},
		Section: "witness", Purpose: "one image's architecture and OS, to catch an arm64/amd64 mismatch",
	},
	{
		Binary: "docker", Args: []string{"compose", "version", "--short"},
		Section: "witness", Purpose: "the Compose V2 plugin version",
	},
	{
		Binary: "docker-compose", Args: []string{"version", "--short"},
		Section: "witness", Purpose: "the standalone Compose V1 version, on hosts that still have it",
	},
	{
		Binary: "podman", Args: []string{"version", "--format", "{{json .}}"},
		Section: "witness", Purpose: "the same, on a Podman host",
	},
	{
		Binary: "podman", Args: []string{"info", "--format", "{{json .}}"},
		Section: "witness", Purpose: "the same, on a Podman host",
	},
	{
		Binary: "podman", Args: []string{"ps", "-a", "--format", "{{json .}}"},
		Section: "witness", Purpose: "the same, on a Podman host",
	},
	{
		Binary: "podman", Args: []string{"network", "ls", "--format", "{{json .}}"},
		Section: "witness", Purpose: "the same, on a Podman host",
	},
	{
		Binary: "podman", Args: []string{"network", "inspect", "<container>", "--format", "{{json .}}"},
		Section: "witness", Purpose: "the same, on a Podman host",
	},
	{
		Binary: "podman", Args: []string{"volume", "ls", "--format", "{{json .}}"},
		Section: "witness", Purpose: "the same, on a Podman host",
	},
	{
		Binary: "podman", Args: []string{"image", "ls", "--all", "--digests", "--format", "{{json .}}"},
		Section: "witness", Purpose: "the same, on a Podman host",
	},
	{
		Binary: "podman", Args: []string{"image", "inspect", "<image>", "--format", "{{json .}}"},
		Section: "witness", Purpose: "the same, on a Podman host",
	},
	{
		Binary: "podman-compose", Args: []string{"version", "--short"},
		Section: "witness", Purpose: "the podman-compose version",
	},

	// ── witness: the web front end ────────────────────────────────────────────
	{
		Binary: "nginx", Args: []string{"-v"},
		Section: "witness", Purpose: "the nginx version",
	},
	{
		Binary: "nginx", Args: []string{"-T"},
		Section: "witness",
		Purpose: "the effective nginx configuration — the server names, ports and certificate paths already in use, with includes resolved",
	},
	{
		Binary: "apachectl", Args: []string{"-v"},
		Section: "witness", Purpose: "the Apache version",
	},
	{
		Binary: "apachectl", Args: []string{"-S"},
		Section: "witness", Purpose: "the Apache virtual host map: which names and ports are already served",
	},
	{
		Binary: "apache2ctl", Args: []string{"-v"},
		Section: "witness", Purpose: "the same, on Debian-family hosts",
	},
	{
		Binary: "apache2ctl", Args: []string{"-S"},
		Section: "witness", Purpose: "the same, on Debian-family hosts",
	},
	{
		Binary: "httpd", Args: []string{"-v"},
		Section: "witness", Purpose: "the same, on RHEL-family hosts",
	},
	{
		Binary: "httpd", Args: []string{"-S"},
		Section: "witness", Purpose: "the same, on RHEL-family hosts",
	},

	// ── witness: scheduled work ───────────────────────────────────────────────
	{
		Binary: "systemctl", Args: []string{"list-timers", "--all", "--no-pager", "--plain", "--no-legend"},
		Section: "witness", Purpose: "systemd timers, which is where scheduled work lives on a modern host",
	},
	{
		Binary: "crontab", Args: []string{"-l", "-u", "<user>"},
		Section: "witness", Purpose: "one account's crontab, for the entries that are not in /etc",
	},

	// ── witness: backup tooling ───────────────────────────────────────────────
	//
	// Only version probes. Every one of these tools can also restore, prune and
	// delete, and none of those forms is listed, so none of them can run.
	{
		Binary: "restic", Args: []string{"version"},
		Section: "witness", Purpose: "whether restic is installed, and which version",
	},
	{
		Binary: "borg", Args: []string{"--version"},
		Section: "witness", Purpose: "whether borg is installed, and which version",
	},
	{
		Binary: "duplicity", Args: []string{"--version"},
		Section: "witness", Purpose: "whether duplicity is installed, and which version",
	},
	{
		Binary: "rsnapshot", Args: []string{"--version"},
		Section: "witness", Purpose: "whether rsnapshot is installed, and which version",
	},

	// ── updates and vulnerabilities: Debian/Ubuntu ──────────────────────────────
	{
		Binary:  "dpkg-query",
		Args:    []string{"-W", "-f=${Package}\t${Version}\t${Architecture}\t${db:Status-Status}\n"},
		Section: "updates", Purpose: "the installed package inventory",
	},
	{
		Binary: "apt-get",
		Args: []string{"-s", "-q", "-o", "Debug::NoLocking=1", "-o",
			"APT::Get::Show-User-Simulation-Note=0", "dist-upgrade"},
		Section: "updates",
		Purpose: "pending updates, as a simulation (-s): apt computes the upgrade and installs nothing",
	},
	{
		Binary: "lsb_release", Args: []string{"-cs"},
		Section: "updates", Purpose: "the release codename, needed to pick the right advisory suite",
	},
	{
		Binary: "debsecan", Args: []string{"--format", "summary"},
		Section: "vulnerabilities", Purpose: "Debian security advisories affecting installed packages",
	},
	{
		Binary: "debsecan", Args: []string{"--format", "summary", "--suite", "<suite>"},
		Section: "vulnerabilities", Purpose: "the same, pinned to the host's suite",
	},

	// ── updates and vulnerabilities: RHEL family ────────────────────────────────
	{
		Binary: "rpm", Args: []string{"-qa", "--qf", "%{NAME}\t%{EPOCH}:%{VERSION}-%{RELEASE}\t%{ARCH}\n"},
		Section: "updates", Purpose: "the installed package inventory",
	},
	{
		Binary: "dnf", Args: []string{"-C", "-q", "check-update"},
		Section: "updates", Purpose: "pending updates from cached metadata (-C: no repository refresh)",
	},
	{
		Binary: "yum", Args: []string{"-C", "-q", "check-update"},
		Section: "updates", Purpose: "the same, on hosts that still ship yum",
	},
	{
		Binary: "dnf", Args: []string{"-C", "-q", "updateinfo", "list", "--security"},
		Section: "vulnerabilities", Purpose: "which pending updates come from a security channel",
	},
	{
		Binary: "dnf", Args: []string{"-C", "-q", "updateinfo", "list", "--security", "--with-cve"},
		Section: "vulnerabilities", Purpose: "the same, with the CVE identifiers",
	},
	{
		Binary: "yum", Args: []string{"-C", "-q", "updateinfo", "list", "--security"},
		Section: "vulnerabilities", Purpose: "the same, on hosts that still ship yum",
	},
	{
		Binary: "yum", Args: []string{"-C", "-q", "updateinfo", "list", "--security", "--with-cve"},
		Section: "vulnerabilities", Purpose: "the same, on hosts that still ship yum",
	},

	// ── updates and vulnerabilities: SUSE ───────────────────────────────────────
	{
		Binary: "zypper", Args: []string{"--non-interactive", "--quiet", "list-updates"},
		Section: "updates", Purpose: "pending updates",
	},
	{
		Binary: "zypper",
		Args: []string{"--non-interactive", "--quiet", "list-patches", "--category",
			"security", "--cve"},
		Section: "vulnerabilities", Purpose: "security patches with their CVE identifiers",
	},

	// ── updates and vulnerabilities: Arch ───────────────────────────────────────
	{
		Binary: "pacman", Args: []string{"-Q"},
		Section: "updates", Purpose: "the installed package inventory",
	},
	{
		Binary: "pacman", Args: []string{"-Qu"},
		Section: "updates", Purpose: "pending updates from the local sync database",
	},
	{
		Binary: "pacman", Args: []string{"-Sl"},
		Section: "updates", Purpose: "which repository each package comes from",
	},
	{
		Binary: "arch-audit", Args: []string{"--json"},
		Section: "vulnerabilities", Purpose: "Arch security advisories affecting installed packages",
	},

	// ── updates and vulnerabilities: Alpine ─────────────────────────────────────
	{
		Binary: "apk", Args: []string{"info", "-v"},
		Section: "updates", Purpose: "the installed package inventory",
	},
	{
		Binary: "apk", Args: []string{"--print-arch"},
		Section: "updates", Purpose: "the package architecture",
	},
	{
		Binary: "apk", Args: []string{"version", "-l", "<"},
		Section: "updates", Purpose: "packages with a newer version available",
	},
}
