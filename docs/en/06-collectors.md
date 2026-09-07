# 6. Collectors

## system

A flat table of `category, key, value, source` rows. It is a key/value table
rather than a struct-per-topic so that a machine with an unusual layout simply
contributes fewer rows instead of forcing empty columns on everyone else. A fact
that cannot be read is omitted, never guessed.

| Category | Read from |
|---|---|
| `host` | `os.Hostname`, `hostname -f`, `/etc/machine-id`, `systemd-detect-virt`, container markers (`/.dockerenv`, `/run/.containerenv`, `/run/systemd/container`) |
| `os` | `/etc/os-release` (falling back to `/usr/lib/os-release`) |
| `kernel` | `/proc/sys/kernel/{ostype,osrelease,version}`, `uname -m`, `/proc/uptime`, `/proc/loadavg` |
| `hardware` | `/proc/cpuinfo`, `/proc/meminfo`, `/sys/class/dmi/id` |
| `storage` | `/proc/mounts` + `statfs(2)` per mount |
| `network` | `net.Interfaces`, `/etc/resolv.conf`, `/proc/net/route` |
| `time` | `/etc/localtime` symlink, `timedatectl show` |
| `packages` | The detected package manager |
| `accounts` | `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/sudoers.d/*` |
| `ssh` | `sshd -T`, falling back to parsing `sshd_config` |
| `hardening` | `/sys/fs/selinux/enforce`, `/sys/module/apparmor/...`, `systemctl is-active`, `nft list ruleset`, fifteen `/proc/sys` values |
| `updates` | `/var/run/reboot-required`, `needs-restarting -r` |

Notes on specific probes:

- **Storage skips pseudo filesystems and read-only image mounts.** `squashfs`,
  `iso9660` and `erofs` are excluded along with `proc`, `sysfs`, `tmpfs` and the
  rest: a snap mount is always exactly 100% full by construction, and a dozen of
  them would bury the real volumes under false "disk full" rows. Free space is
  reported from `Bavail`, not `Bfree` — the blocks reserved for root are not
  capacity a service can use.
- **`sshd -T` is preferred over reading the file.** It resolves `Include`
  directives, `Match` blocks and compiled-in defaults. Parsing `sshd_config` by
  hand misses all three and would report `PasswordAuthentication` as absent on a
  host where a drop-in file turns it on. When `sshd -T` is unavailable the
  fallback is used and the section is marked `partial`.
- **UID 0 accounts are listed by name.** A second UID 0 account is a
  privilege-escalation backdoor no package manager will ever report.
- **Hardening sysctls are reported verbatim, not judged.** The safe value for
  `net.ipv4.ip_forward` on a router is the dangerous one on an application
  server; the report states facts and leaves policy to the reader.
- **A firewall with no readable ruleset is not a firewall with no rules.**
  Counting rules needs `CAP_NET_ADMIN`; without it the section says the ruleset
  could not be read rather than reporting zero.

**Needs root:** `/etc/shadow`, `sudoers`, `nft list ruleset`.

## updates

One row per upgradable package, from metadata already on disk. **No repository is
refreshed** — that is a network operation, and on Arch a partial sync is the
documented way to break the system.

| Manager | Query | Security channel detection |
|---|---|---|
| apt | `apt-get -s -q dist-upgrade` | Origin string contains `security` |
| dnf / yum | `dnf -C -q check-update` | `dnf -C -q updateinfo list --security --with-cve` |
| zypper | `zypper --non-interactive list-updates` | via `list-patches` in the vulnerability section |
| pacman | `pacman -Qu` | none published |
| apk | `apk version -l '<'` | none published |

`apt list --upgradable` is deliberately not used: it names no origin, and the
origin is the only way to tell a security update from a routine one without
network access.

## vulnerabilities

Covered in full in [07 — Vulnerability sources](07-vulnerability-sources.md).

## ports

Listening sockets, read from `/proc/net/{tcp,tcp6,udp,udp6}` and attributed to
processes by walking `/proc/<pid>/fd` for `socket:[inode]` links.

- **TCP:** state `0A` (LISTEN) only.
- **UDP:** unconnected sockets only. A UDP socket with a remote peer is a client,
  not a listener.
- **Addresses** in these tables are hex, with each 32-bit word in host byte order
  while the port is big-endian. Decoding both the same way is the classic route
  to reporting `1.0.0.127`.

Each row carries an **exposure** class, which is what turns a socket list into an
audit — a database on `127.0.0.1` and the same database on `0.0.0.0` are the same
service and completely different risks:

| Exposure | Meaning |
|---|---|
| `loopback` | Bound to `127.0.0.0/8` or `::1`; reachable only from this host |
| `interface` | Bound to one specific address |
| `all-interfaces` | Bound to `0.0.0.0` or `::`; reachable on every interface |

**Needs root** for process attribution of sockets owned by other users. Without
it the sockets are still listed, with the count of unreadable processes noted.

## services

Running service units. `--services-all` widens this to every known unit.

| Init system | Source |
|---|---|
| systemd | `systemctl list-units` for runtime state, `list-unit-files` for boot enablement, `systemctl show` for main PID, user and activation time |
| OpenRC | `rc-status --all` |
| SysV | `service --status-all` |
| none | `/proc`, listing processes reparented to PID 1, labelled `manager=process-table` |

Runtime state and boot enablement are read from two different commands on
purpose: a service can be running now and disabled at boot, and that difference
is the point of the `Enabled` column.

`systemctl show` is invoked in chunks of 100 units so the argument list stays
well inside `ARG_MAX` on hosts with thousands of units. Activation timestamps are
converted to UTC.

## witness

The only section with two sides. `app/collect/manifest` reads what a deployment
**asks for**; seven collectors read what the host **offers**; `app/witness`
compares them. Nothing in the first two judges, and nothing in the third observes
— which is what makes a finding explainable to the person who has to act on it.

The rules themselves, with every finding code, are
[10 — Witness rules](10-witness-rules.md).

### The requirements side: `app/collect/manifest`

One file on disk, the one named by `--compose`. No command is run, no socket is
opened and no registry is contacted, so this collector is as offline as the rest
of the tool.

| Read | From |
|---|---|
| Services, in file order | `services:` — image (registry/repository/tag/digest split apart), `build`, `container_name`, `platform`, `ports`, `expose`, `volumes`, `networks`, `network_mode`, `depends_on` (both forms), `restart`, `healthcheck` presence, `deploy.resources` memory and CPU, `privileged`, `cap_add`, `devices`, `extra_hosts`, `dns`, `labels` |
| Environment | The **names** declared under `environment:`, and for `env_file:` the path plus whether it exists |
| Networks, volumes | `driver`, `external`, and a network's explicit IPAM subnets |
| Substitution | `${VARIABLE}` from the process environment first, then a `.env` file beside the compose file — Compose's own precedence |

What it deliberately does not read:

- **Environment variable values, ever.** `environment:` contributes names only.
  An `env_file` contributes its path and whether the path resolves; its contents
  are never opened. The `.env` beside the compose file is read for `${VARIABLE}`
  substitution alone — its keys and values are not collected, not returned and not
  reported.
- **Other compose files.** `include:` is noted as a warning rather than followed:
  this collector parses the one file it was given, and a manifest short of what
  an include would have added must say so.

Both port syntaxes are handled (`"8080:80"` and the long form), along with
ranges, both volume syntaxes, memory suffixes, YAML anchors and merge keys
(`<<: *base`, which real compose files use heavily). The file is read as a
`yaml.Node` tree rather than decoded into structs, so key order and line numbers
survive and a field in an unexpected shape can be reported and skipped instead of
failing the document.

**An unresolved `${VARIABLE}` is never silently replaced with an empty string.**
That is what turns `${DB_PORT}:5432` into `:5432`, which the reader cannot trace
back to anything. The literal stays and a warning names the variable. Every such
warning appears twice: in `Manifest.Warnings`, which travels with the report, and
through `Degrade`, so the section cannot be labelled complete. A requirement that
was not understood is not a requirement that was met.

**Needs root:** nothing. It needs read access to the compose file, which
`--compose` validates at startup.

### The capabilities side

The seven collectors run in dependency order, because three of them read what an
earlier one produced: `panels` reads the service units, `certs` needs the job
inventory `scheduler` builds to tell an installed renewal tool from a renewal that
actually runs, and `host.Databases` reads the listening sockets.

#### `app/collect/host`

| Read | From |
|---|---|
| Architecture | `uname -m` — what the host *is*, not what this binary was compiled for; the two differ under emulation, which is exactly the case an architecture mismatch is about |
| Memory | `/proc/meminfo`: `MemTotal`, `MemAvailable`, `SwapTotal` |
| Filesystems | `/proc/mounts` + `statfs(2)`, **with inodes** |
| Databases | The listening sockets already collected, plus the data directory of a recognised engine: `postgres`, `mysql`, `mariadb`, `mongodb`, `redis`, or `unknown` |

The system section reports most of this as prose — "7.5 GiB used of 30 GiB
(25.1%)" reads well and is useless to a rule — so this collector produces the same
observations as numbers, from the same sources. Nothing is measured twice and
nothing is parsed back out of a sentence.

**Inodes are collected because a deployment can exhaust them long before it fills
the bytes.** A container image is thousands of small files; a report that showed
only capacity would call the host healthy right up to the failure, and the failure
says "no space left on device" while `df` still shows free space.

**Nothing connects to a database.** Which engine, which version, which port,
whether it is bound beyond loopback and how much disk its data directory occupies
are all visible from outside. The moment a tool authenticates to somebody's
production database to answer a question it could have answered by looking, it has
stopped being an audit. A port that looks like a database but is served by an
unrecognised process is reported as `unknown` rather than guessed at.

**Needs root:** nothing, but an unprivileged run cannot enter every mount point or
every data directory. Mount points that could not be measured are named in the
notes and are absent from the report rather than assumed, and a data-directory
walk that stops early says the size is a partial total.

#### `app/collect/docker`

| Read | From |
|---|---|
| Engine and versions | `docker version`, `docker info`, and the podman equivalents |
| Compose implementation | `docker compose version --short` (plugin), `docker-compose version --short` (standalone V1), `podman-compose version --short` |
| Containers | `docker ps -a --format {{json .}}` — including stopped ones, with their published ports and their Compose project/service labels |
| Networks, volumes | `... network ls`, `... volume ls`, plus `network inspect` for subnets |
| Images | `... image ls --all --digests`, plus `image inspect` for architecture, OS and size |

Every command is a query. None of them starts, stops, pulls or removes anything.

**Nothing reads a container's environment.** `docker inspect` of a *container* is
not on the allowlist for exactly that reason: neither the names nor the values of
a running container's variables are collected.

**"No runtime" and "a runtime that would not answer" are different answers.** The
first leaves `Capabilities.Runtime` nil. The second sets `Reachable = false` with
a note and degrades the section, because an empty container list on an unreachable
daemon reads as "this host runs nothing" — and produces a conflict list that looks
reassuringly short.

`image inspect` is capped at 200 images and `network inspect` at 100 networks;
images sharing an id are inspected once, so a repository with five tags costs one
call. When a cap bites, it is reported.

**Needs root** (or membership of the `docker` group) to reach the engine socket.
Without it the engine is detected, `Reachable` is false, and the report says every
container-related check was skipped.

#### `app/collect/proxy`

| Read | From |
|---|---|
| Effective configuration | `nginx -T`, or `apachectl -S` / `apache2ctl -S` / `httpd -S` |
| Version | `nginx -v`, `apachectl -v` and friends |
| Fallback | A bounded walk of the configuration tree, when the dump will not run |

**The effective configuration is asked for, not reconstructed.** `nginx -T`
resolves every include, every `sites-enabled` symlink and whatever a control panel
regenerated last night. A hand-rolled walk of `/etc/nginx` sees none of that, so
the walk exists only as the fallback — which is what happens unprivileged — and
when it is used the report says the list is incomplete rather than presenting a
partial answer as everything the server answers for. The walk is bounded at depth
8, 256 files, 4 MiB per file and 1000 server names, and every bound that bites is
noted.

**Every server name carries the file and the line it is configured at.** "This
domain is already served on this host" is only actionable if the reader can open
the vhost.

**Certificate *paths* are collected, never certificate contents** — and never a
private key or a `.htpasswd`. Parsing certificates is `app/collect/certs`' job.

When both nginx and Apache are installed only nginx is inspected; the other is
named in a note and the section degrades, because `model.Proxy` holds one front
end and dropping the second silently would hide a port it may hold.

`nginx -v` prints to stderr, which the runner does not capture, so on most hosts
the allowlisted command yields nothing and the version is read from the string
compiled into the binary instead — a bounded read of a file already on disk.

**Needs root** for `nginx -T` on most distributions (it reads the whole
configuration tree, including files under `/etc/nginx` that are not
world-readable). Unprivileged, expect the walk fallback and a `partial` section.

#### `app/collect/panels`

Detects Plesk, cPanel/WHM, DirectAdmin, ISPmanager, Coolify, CapRover, Portainer,
aaPanel, HestiaCP, VestaCP, Virtualmin, Webmin, CyberPanel and ISPConfig.

A panel matters out of all proportion to the few directories that give it away: it
owns ports 80 and 443, it rewrites the web server's configuration on its own
schedule, and it will silently undo a hand-made change. A vhost added by hand to a
Plesk or cPanel host survives exactly until the panel next regenerates its
templates. A deployment planned without knowing a panel is there is a deployment
that will be reverted by software nobody remembered was running.

Detection is deliberately cheap and deliberately conservative: it stats a fixed
list of paths — no walking — and runs at most one `systemctl is-active` per unit of
an already-detected panel. Coolify, CapRover and Portainer ship as containers
rather than packages, so they are also recognised from the container names the
runtime already reported, with the image tag as the version — better evidence than
a data directory, which may well outlive the panel.

**A marker that other software could have left behind is reported as inferred.**
A data directory outlives an uninstall and a unit file only proves a package was
once installed, so presence established from weak markers only says so, naming the
marker, instead of asserting the panel is installed. Ports are the documented
defaults, plus a moved admin port where the panel writes one to a file.

**Needs root** for some markers. A path that could not be stat'ed degrades the
section with a note that the panel could neither be confirmed nor ruled out —
observed on an unprivileged Arch run, where `/var/lib/docker/volumes/portainer_data`
was unreadable.

#### `app/collect/certs`

| Read | From |
|---|---|
| Certificates | A bounded walk of a fixed root list: `/etc/letsencrypt/{live,archive}`, `/etc/ssl/certs`, `/etc/pki/tls/certs`, `/etc/nginx/{ssl,certs}`, `/etc/apache2/ssl`, `/etc/httpd/{ssl,conf/ssl.crt}`, and the panel certificate stores (Plesk, HestiaCP, VestaCP, DirectAdmin, ISPmanager, cPanel) |
| Parsing | `crypto/x509` + `encoding/pem` — **no subprocess at all** |
| Renewal owner | certbot renewal configs, `acme.sh` records, `lego` paths, or a panel |
| Renewal job | The scheduled jobs `app/collect/scheduler` collected |

**The distinction between a renewal *tool* and a renewal *job* is the point of
this collector.** "certbot is installed" and "this certificate will be renewed"
are different statements, and conflating them is exactly how a certificate expires
on a host that had the tooling all along: the package was there, the timer was
never enabled, and every report said "managed by certbot". So `Manager` records who
issued or owns the file and `AutoRenew` is set only when a scheduled job that runs
that tool was actually found.

**Private key directories are enumerated by name and never opened.**
`/etc/ssl/private` and `/etc/pki/tls/private` are listed so the reader can see a
key exists; a tool that reads one has to be trusted rather than checked.

Bounds: depth 4, 512 candidate files, 512 KiB per certificate. A file that will
not parse is named (up to five of them, then summarised with a count) rather than
skipped. CA certificates reached through the system trust store are skipped and
counted — they are the distribution's roots, not certificates this host serves.

**Needs root** to read certificates under `/etc/letsencrypt`, which is
`root`-only on every distribution that ships it. Unprivileged, expect the
expiry rule to have nothing to work with, and the section to say so.

#### `app/collect/scheduler`

Cron hides in more places than anybody remembers, and all of them are read:

```
/etc/crontab                 system crontab, with a user field
/etc/cron.d/*                drop-ins, also with a user field
/etc/cron.{hourly,daily,…}   scripts run by run-parts, not crontab lines
/var/spool/cron/*            per-user crontabs (RHEL layout)
/var/spool/cron/crontabs/*   per-user crontabs (Debian/SUSE layout)
/var/spool/at*               one-shot at jobs
systemd timers               systemctl list-timers, plus show for the owning account
```

**The per-user spool directories are root-only.** Running unprivileged this
collector finds no per-user jobs beyond `crontab -l -u <the current account>`, and
it says so with `Degrade` rather than returning a short list that reads like a
complete one. "There are no cron jobs" and "we were not allowed to look" are
different answers.

**An `at` job is counted but its command is not reported.** An `at` spool file
embeds the submitting shell's entire environment, and that is not something to
copy into a CSV.

**Every reported command is swept for credentials at the moment the line is
parsed**, through the shared `app/redact` patterns — one set of patterns in this
binary, not two that disagree. Cron is the most reliable place on a Linux host to
find a plaintext credential: `mysqldump -pS3cret`, `PGPASSWORD=… pg_dump`,
`restic -r sftp://user:pass@host/repo`.

Bounds: 256 KiB per crontab, 512 entries per directory, 2000 jobs in total, each
reported when it bites.

**Needs root:** `/var/spool/cron/*` and `/var/spool/cron/crontabs/*`.

#### `app/collect/backup`

Three different kinds of evidence, deliberately kept apart:

| Field | Evidence | Strength |
|---|---|---|
| `Tools` | A backup tool is installed (restic, borg, borgmatic, duplicity, rsnapshot, rclone, kopia, pgbackrest, veeam, snapper, timeshift and a dozen more) | Weak on its own — an installed restic that nothing invokes is not a backup |
| `Jobs` | Something scheduled appears to run one, taken from the scheduler's output | Stronger: this is intent |
| `Locations` | Something has been written, **and here is the date of the newest file** | The one that can contradict the other two, and usually does |

A dump tool (`mysqldump`, `pg_dump`, `mongodump` and friends) is reported but
labelled: its presence proves nothing, because it ships with the client package. A
cron line calling it is the real evidence.

Directories checked whether or not a tool is installed: `/backup`, `/backups`,
`/var/backups`, `/srv/backup`, `/mnt/backup`, plus up to eight repository paths
taken from the scheduled jobs. A nightly `tar | ssh` writes into `/backup` just as
happily as restic does.

**Nothing opens a backup file.** Sizes and modification times come from `stat`;
contents are never read, never parsed and never reported. The date is the whole
point — it is what tells a live backup from an abandoned one, and it is why a
`/backup` directory whose newest file is fourteen months old is a finding rather
than reassurance.

When none of the three finds anything, that is a real, reportable state of the
host — "this machine has no backups" — and it goes in the note as a statement, not
as an error.

**Needs root** to enter most backup directories and to see other accounts'
scheduled jobs.

## What has actually been exercised

The unit tests cover the parsers against fixtures — the compose parser, the
`nginx -T` and `apachectl -S` parsers, the panel signature table, the certificate
walk, the cron parsers, the backup freshness logic, the allowlist matcher, the
redaction patterns and every witness rule. None of them needs a host in a
particular state.

The collectors themselves are verified by running the tool, and the honest state
of that is:

- **Arch only.** Every collector added for the `witness` section has been run
  against a real Arch host, privileged and unprivileged, with Docker present. The
  `pacman` backend is likewise the only package-manager backend exercised on a real
  system.
- **The apt, dnf, zypper and apk backends** are written from their documented
  output formats and should be confirmed on a real host of that family before
  being relied on.
- **Apache, podman, every control panel, and every backup tool** are recognised
  from their documented layouts and file markers, not from a machine that had them
  installed. The parsers have fixtures; the detection has not met the real thing.
  A panel or a tool this collector fails to notice is reported as nothing found,
  which is exactly the shape of gap the second promise is about — so treat an empty
  `Panels` list on a host you suspect has one as a reason to check by hand.

