# 9. Command allowlist and journal

This tool is run on production hosts, by people who did not write it, often as
root. "It only reads" is easy to say and impossible to verify by reading a
promise. Two mechanisms exist so it does not have to be taken on trust: the binary
can execute exactly one published list of commands, and it ships the record of
what it actually executed alongside the report.

## The allowlist

`app/run/commands.go` is the list. `app/run/allowlist.go` enforces it. The design
is deliberately restrictive rather than merely conventional:

- **A command that is not on the list cannot be executed.** Not "should not":
  `run.Runner` refuses it, and the refusal is recorded in the journal so it appears
  in the report rather than in a log nobody kept.
- **The check happens before the binary is looked up.** Whether a command exists
  on this host is nobody's business until it has been established that running it
  is permitted.
- **Arguments are matched too, not just the binary name.** Being allowed to run
  `apt-get` is not the same as being allowed to install packages.
- **Nothing goes through a shell.** Commands are executed with `exec`, with an
  argument vector. There is no `sh -c` anywhere in this tool.
- **`--commands` prints the enforced list itself**, not a description of it, so
  what the tool says it can run and what it can actually run cannot drift apart.
  There is one source for both.

Adding a command means editing `app/run/commands.go` — which is what makes it show
up in a code review and in `--commands` at the same moment.

### What the arguments may be

Most entries are fixed argument vectors, matched literally. Where a value has to
be filled in at run time it is written as `<kind>` (or `<kind>...` for one or more
at the end), and each kind is bounded by an anchored character class. None of them
admits a space, a quote, a semicolon, a backtick, a dollar sign or a pipe:

| Kind | Pattern | Used for |
|---|---|---|
| `unit` | `^[A-Za-z0-9@:._\-]{1,255}$`, backslash also allowed | A systemd unit or timer name |
| `suite` | `^[A-Za-z0-9._-]{1,64}$` | A distribution suite or codename (`bookworm`, `42`) |
| `path` | `^/[A-Za-z0-9@:+,%._/-]{0,1000}$` | An absolute path. Relative paths are rejected: every path this tool passes to a command comes from a directory it walked itself |
| `container` | `^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$` | A container, volume or network name, or a short id |
| `image` | `^[A-Za-z0-9][A-Za-z0-9_.:/@-]{0,255}$` | An image reference, tag and digest included |
| `user` | `^[A-Za-z0-9._-]{1,64}$` | A local account name |
| `name` | `^[A-Za-z0-9@+._-]{1,128}$` | The fallback for a plain identifier: a package, a profile, a zone |

The `unit` kind admits a backslash on evidence rather than on principle. A real
host in this family runs

```
systemd-fsck@dev-disk-by\x2duuid-F9EA\x2dEBDF.service
```

— systemd's own escaping of a device path, and an ordinary `--type=service` unit.
Excluding the backslash cost a whole batch of `systemctl show` output on the first
machine the allowlist was tried on. It is admitted because nothing goes through a
shell: to `execve`, a backslash is an ordinary byte in an argument.

A repeated argument (`<unit>...`) is bounded too — 256 by default, 128 for
`systemctl show`. An argv longer than that is a bug in the caller, not a host with
many units. A placeholder naming a kind that does not exist is a typo in
`commands.go`, and it refuses rather than becoming a wildcard.

As of 0.2.0 only `unit`, `suite`, `container`, `image` and `user` are actually used
by an entry; `path` and `name` are defined and unused.

### The arguments that make a read a read

Three entries would be dangerous without the exact flags they are pinned to, and
those flags are part of the match:

| Entry | Why the flag matters |
|---|---|
| `apt-get -s -q … dist-upgrade` | `-s` is simulate: apt computes the upgrade and installs nothing. `dist-upgrade` is only ever permitted *with* `-s`, so the same binary cannot be asked to do the real thing |
| `dnf -C …` / `yum -C …` | `-C` means cached metadata only. It cannot refresh a repository, which is both a network operation and, on some hosts, a slow one |
| `pacman -Q`, `-Qu`, `-Sl` | Query and list operations only. There is no `-S` or `-Sy` entry: on Arch a partial sync is the documented way to break the system |

Nothing on the list starts, stops, enables, disables, pulls or removes anything.
The container entries are `ps`, `ls`, `info`, `version` and `inspect` of an
*image* or a *network* — `docker inspect` of a **container** is deliberately absent,
because a container's inspect output carries its environment variables.

### The list

The authority is the binary in your hand:

```bash
deploy-witness --commands
```

It prints the list it enforces, grouped by the section that needs it, with the
reason each entry is read for. What follows is that output as of 0.2.0 —
**68 commands**. Where two entries share a purpose line reading "the same, …", the
line above it is the one being described.

```
[core]
  uname -m                          the CPU architecture, to tell an arm64 host from an amd64 one

[ports]
  ss -lntupH                        listening sockets with the owning process, when /proc/net
                                    alone cannot attribute them

[witness]                         33 entries
  nginx -T                          the effective nginx configuration — server names, ports and
                                    certificate paths already in use, with includes resolved
  nginx -v                          the nginx version
  apachectl -S | -v                 the Apache virtual host map and version
  apache2ctl -S | -v                the same, on Debian-family hosts
  httpd -S | -v                     the same, on RHEL-family hosts
  docker version --format {{json .}}
  docker info --format {{json .}}
  docker compose version --short
  docker-compose version --short
  docker ps -a --format {{json .}}
  docker network ls --format {{json .}}
  docker network inspect <container> --format {{json .IPAM}}
  docker volume ls --format {{json .}}
  docker image ls --all --digests --format {{json .}}
  docker image inspect <image> --format {{json .}}
  podman … (the eight equivalents), podman-compose version --short
  crontab -l -u <user>              one account's crontab, for the entries not in /etc
  systemctl list-timers --all --no-pager --plain --no-legend
  restic version | borg --version | duplicity --version | rsnapshot --version
                                    whether each backup tool is installed, and which version

[services]                          5 entries
  systemctl list-units --type=service --all --no-pager --plain --no-legend
  systemctl list-unit-files --type=service --no-pager --plain --no-legend
  systemctl show --property=Id --property=MainPID --property=User
                 --property=ActiveEnterTimestamp <unit>...
  rc-status --all                   the service inventory on OpenRC hosts
  service --status-all              the service inventory on SysV hosts

[system]                            7 entries
  sshd -T | /usr/sbin/sshd -T       the effective sshd configuration: resolves Include and Match
  systemd-detect-virt               bare metal, a VM or a container
  timedatectl show --property=Timezone --property=NTPSynchronized --property=NTP
  systemctl is-active <unit>        whether one firewall unit is running
  nft list ruleset                  how many nftables rules exist
  needs-restarting -r               whether the running kernel is older than the installed one

[updates]                           13 entries
  apt-get -s -q -o Debug::NoLocking=1 -o APT::Get::Show-User-Simulation-Note=0 dist-upgrade
  dpkg-query -W -f=…                the installed package inventory
  lsb_release -cs                   the release codename, to pick the right advisory suite
  dnf -C -q check-update | yum -C -q check-update
  rpm -qa --qf …                    the installed package inventory
  zypper --non-interactive --quiet list-updates
  pacman -Q | -Qu | -Sl             inventory, pending updates, and the repository of each package
  apk info -v | apk version -l < | apk --print-arch

[vulnerabilities]                   8 entries
  arch-audit --json                 Arch advisories affecting installed packages
  debsecan --format summary [--suite <suite>]
  dnf -C -q updateinfo list --security [--with-cve]     (and the yum equivalents)
  zypper --non-interactive --quiet list-patches --category security --cve
```

The grouping above collapses the near-identical Podman and yum entries for
readability; `--commands` prints every one of the 68 separately, and it is the
list that is enforced. **If this page and `--commands` ever disagree, `--commands`
is right.**

## The journal

Every call through `run.Runner` is recorded, and the record ships as
`commands.csv` — columns, outcomes and their meanings are in
[08 — Report format](08-report-format.md#commandscsv). Four properties are worth
stating here:

**Everything is recorded, not just the successes.** A command that timed out, one
whose binary is not installed, and one that was refused all get a row. A journal
of only the successful calls would be an advertisement rather than a record.

**The journal is a property of the `Runner`, not of its callers.** A collector
cannot opt out of either the allowlist or the journal by forgetting to ask for
them.

**A `refused` row is a bug in this tool.** It means a collector asked for a
command the published list does not cover. It is never a property of the host, it
is logged at error level, and it does not change the exit code — the report is
still valid, minus whatever that collector wanted. Nothing hides it, because a
client comparing the journal against the published list must not be the first to
notice.

**The whole journal is uploaded** when `--upload` is used, as
`command_journal` in the contract. A client who ran an unfamiliar binary on their
production host is owed the full list of what it did, and "it tried something it
was not allowed to do" is the single most important line that list could ever
contain.

## Verifying it yourself

```bash
# 1. What can this thing do to my server? Before running it.
deploy-witness --commands

# 2. Run the audit.
sudo deploy-witness --compose /srv/app/docker-compose.yml --out /tmp/audit

# 3. What did it actually do? Every row should be an entry from step 1.
cut -d, -f1,5 /tmp/audit/commands.csv

# 4. Anything refused? There should be nothing.
grep refused /tmp/audit/commands.csv
```

The commands the tool did *not* run also matter, and there are two classes of them
that no journal can show, because they never involve a subprocess:

- Files it read. Those are named in the `Source` column of `system.csv` and in the
  `Command` column of `evidence.csv`, which holds a path wherever an observation
  came from a file rather than a command.
- The one outbound connection behind `--egress` (a TCP connect, no data sent) and
  the OSV API behind `--online`. Neither is a subprocess, so neither appears in
  `commands.csv`; both are off by default, and `--egress` also leaves a note in
  `summary.csv` saying how many registry hosts were contacted.
