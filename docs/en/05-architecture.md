# 5. Architecture

## Run flow

```
main.go
  └─ config.Load(argv, env)          flags → Config, or an error before anything runs
  └─ --commands? print run.Commands() and exit         (the enforced allowlist itself)
  └─ logging.New(stderr, level)      diagnostics never touch stdout
  └─ audit.New(cfg, log).Run()
       ├─ model.ReadOSRelease()      /etc/os-release → distribution identity
       ├─ pkgmgr.Detect(os, runner)  which package manager this host actually has
       └─ for each selected section:
            ├─ system.Collect()      → []model.Fact
            ├─ manager.Updates()     → []model.Update
            ├─ vuln.Collect()        → []model.Vulnerability   (three feeds, merged)
            ├─ ports.Collect()       → []model.Port
            ├─ services.Collect()    → []model.Service
            └─ witnessSection()    → manifest + capabilities → findings
                 ├─ manifest.Parse(--compose)         the requirements side
                 ├─ host/docker/proxy/panels/          the capabilities side,
                 │  scheduler/certs/backup + databases in dependency order
                 └─ witness.Evaluate()              24 rules, findings + changes + rollback
            each producing a model.SectionResult: status, counts, duration, notes
       └─ report.Commands = runner.Journal()   every command, including refusals
  └─ redact.Report(result)           the last thing before anything is written
  └─ report.WriteDir() | WriteCombined() | WriteJSONFile() | WriteJSON()
  └─ report.Upload()                 only with --upload and --upload-token
  └─ exit code derived from the section statuses, or 3 if the upload failed
```

Sections run in a fixed order, not the order they were requested. The
vulnerability section reuses the installed-package inventory the earlier work
built; on a host with three thousand packages, reading it twice is the single
most expensive thing the tool could do. `witness` runs last for the same
reason: it reads the ports and the services already in the report.

Two steps of the flow are worth reading twice.

**The allowlist is checked inside `run.Runner`, before the binary is looked up.**
Whether a command exists on this host is nobody's business until it has been
established that running it is permitted. A refusal is recorded in the journal and
logged at error level; it never becomes an exception a collector can swallow.

**`redact.Report` runs after every collector and before every writer.** It is the
last line, not the first: no collector reads a secret on purpose. It exists
because a report also carries free-form text nobody designed — a cron line, a
process command line, a proxy directive — and this report may be uploaded.

## Packages

| Package | Responsibility |
|---|---|
| `app/config` | Flag and `AUDIT_*` environment parsing. Every input is validated here, so a bad argument fails before a single command runs. |
| `app/logging` | A stderr-only leveled logger. |
| `app/csv` | The CSV generator, copied verbatim from `utils/csv` so the build needs no private repository. Do not edit in place — see `app/csv/doc.go`. |
| `app/contract/auditv1` | The generated Go for `bloodheaven.audit.v1`, copied verbatim from `contracts` for the same reason. Do not edit — see `app/contract/auditv1/doc.go`. |
| `app/model` | Record types, the severity vocabulary, the CVSS base-score calculator, `/etc/os-release` parsing, and the three witness vocabularies (manifest, capabilities, findings). Depends on nothing else in the tree. |
| `app/run` | External command execution: shared timeout, `LC_ALL=C`, the exit-code allowlist — and the **command allowlist** (`allowlist.go`) with the list itself (`commands.go`) plus the journal of every execution. |
| `app/redact` | The credential sweep over a finished report. |
| `app/pkgmgr` | The `Manager` interface and its apt, dnf/yum, zypper, pacman and apk backends, plus the dpkg, rpm and generic version comparators. |
| `app/vuln` | OSV record types and range evaluation, the offline dataset loader, the API client, and the merge that turns three feeds into one table. |
| `app/collect/system` | Host inventory and hardening posture. |
| `app/collect/ports` | Listening sockets from `/proc/net`. |
| `app/collect/services` | Service units from systemd, OpenRC, SysV or the process table. |
| `app/collect/manifest` | The compose-file parser: the *requirements* side of witness. Reads one user-supplied file and the `.env` beside it. Observes nothing about the host. |
| `app/collect/host` | Architecture, memory, filesystems with inodes, and the databases already installed — as numbers, not prose. |
| `app/collect/docker` | The container runtime: engine, compose implementation, containers, networks, volumes, images. |
| `app/collect/proxy` | nginx / Apache: the effective configuration, server names with file and line, listen ports, certificate paths. |
| `app/collect/panels` | Hosting control panels, from a fixed list of filesystem markers. |
| `app/collect/certs` | TLS certificates on disk, parsed with `crypto/x509`, and whether anything actually renews them. |
| `app/collect/scheduler` | Scheduled work: cron in every form, plus systemd timers. |
| `app/collect/backup` | Backup tools, backup jobs, and the date of the newest file in each backup directory. |
| `app/witness` | The 24 rules, the change list and the rollback plan. Pure functions of manifest + capabilities; observes nothing. |
| `app/report` | CSV rendering through `app/csv`, the JSON document, the shared audit contract and the upload. |
| `app/audit` | Section orchestration and the shared inventory cache. |

Dependencies point one way: `audit` → collectors → `pkgmgr`/`run` → `model`.
Nothing in `model` imports anything above it, which is why the comparators, the
CVSS calculator and every witness rule are testable without a host in any
particular state.

`app/witness` and `app/collect/*` are kept strictly apart, and the split is the
reason a finding can be explained to the person who has to act on it: a collector
never judges, and a rule never observes. The one exception is a helper —
`app/witness` imports `app/collect/host` for `FilesystemFor`, which picks the
filesystem a mount point falls under, and that is arithmetic rather than
observation.

## Design decisions worth knowing

**The binary can run exactly one published list of commands.** Not by convention:
`run.Runner` refuses anything outside `app/run/commands.go` before looking the
binary up, arguments included. Adding a command means editing that file, which is
what makes it appear in the diff and in `--commands` at the same time. See
[09 — Command allowlist and journal](09-command-allowlist.md).

**The kernel is read directly, tools are not.** Sockets come from
`/proc/net/{tcp,tcp6,udp,udp6}` rather than from `ss` or `netstat`. Neither is
installed on a minimal image, and a security audit is the wrong place to be
adding dependencies to the host being audited. `ss` remains a fallback for hosts
that hide `/proc/net`.

**Certificates are parsed in Go, not by shelling out to `openssl`.**
`crypto/x509` plus `encoding/pem` is a dozen lines, it cannot be affected by which
openssl the host ships, and it keeps the published allowlist from growing an entry
a reader would then have to reason about. `app/collect/certs` runs no subprocess
at all.

**Non-zero exit is not automatically failure.** `dnf check-update` exits 100 when
updates exist. `pacman -Qu` exits 1 when there are none. `apk version -l` exits 1
on an empty result. `systemd-detect-virt` exits 1 on bare metal. Treating any of
those as errors would report "updates unavailable" on a host whose updates were
read perfectly well, so `run.Runner.OutputAllowExit` takes the codes that mean
success for each tool.

**`LC_ALL=C` on every command.** These parsers key on English column headers. A
host with a Russian or German `LC_MESSAGES` rewrites all of them.

**One subprocess per host, not per package.** Resolving pacman repositories one
package at a time would spawn a process per upgradable package — several hundred
on a rolling release. `pacman -Sl` builds the same index once. The same reasoning
bounds the witness collectors: `docker image inspect` is capped at 200 images
and `docker network inspect` at 100 networks, and when a cap bites it is reported.

**Errors are values that travel with the data.** Collectors return what they
managed to gather *alongside* their error, and record the problem in the
section's `Note`/`Degrade`. A non-nil error never implies an empty result, and an
empty result never implies a clean host.

**A nil pointer and an empty slice are different answers.** `Capabilities.Runtime`
is nil when no container engine exists, and non-nil with `Reachable = false` when
one exists but would not answer. The rules act on the difference, because an empty
container list from an unreachable daemon reads as "this host runs nothing".

## Dependencies

Two modules, both public, both neighbours of the standard library:

| Module | Used for |
|---|---|
| `google.golang.org/protobuf` | `protojson`, to render the audit contract with its enum *names* (`SEVERITY_BLOCKER`) rather than integers. |
| `gopkg.in/yaml.v3` | Reading the compose file as a `yaml.Node` tree, which keeps key order, line numbers and merge keys — all three of which a struct decode throws away. |

Everything else is the standard library. The platform's shared `utils/logger` is
deliberately not used — see [CLAUDE.md](../../CLAUDE.md) for why. `protobuf`
appears in exactly one file (`app/report/contract.go`); nothing else in the tool
knows protobuf exists.

**No module of the organisation is imported.** The two pieces of shared code the
tool needs live in the tree as verbatim copies (`app/csv` from `utils/csv`,
`app/contract/auditv1` from `contracts`), refreshed with `make sync-shared`, so a
build never asks for credentials to a repository the reader cannot see — see
[03 — Installation](03-installation.md).
