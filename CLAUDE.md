# deploy-witness — repository rules

A standalone Go binary that audits the host it runs on and writes a CSV report.
Derived from `ai-template`'s repository conventions (Makefile-driven builds,
`docs/<lang>` kept in sync, a CHANGELOG entry per change), **not** from its
runtime stack.

## What this repository is not

It has no backend service, no frontend, no database, no HTTP server and no
message broker. Those parts of the platform template are deliberately absent.
It does now speak to one platform service — `--upload` POSTs the finished report
to `DeployWitness` — but as a client, once, only when asked, and with no retry, no
queue and no default endpoint. Consequences for anyone extending it:

- **No GORM, no Postgres, no migrations.** There is no schema. A collector that
  needs to remember something between runs is a design error — the tool is a
  single pass over the machine.
- **The platform AMQP rule does not apply.** Nothing here creates or mutates
  platform entities, so there is nothing to publish to `messengers-gateway`. If
  this tool ever gains a reporting backend, that backend is where the rule lands.
- **No design system.** There is no UI. `DESIGN_MANIFEST.md` is irrelevant here.
- **`utils/logger` is deliberately not used.** It writes to stdout, which is
  where the CSV goes under `--stdout`, and it ships lines to Loki when `LOKI_URL`
  is set, which would make an offline audit tool open an outbound connection. It
  also pulls a web framework and a database driver into a binary whose value is
  being small enough to read before running it on a production host.
  `app/logging` replaces it. `utils/csv` **is** used — it is pure stdlib and it
  is exactly the shared helper this deliverable needs.
- **Four dependencies, and each one has to earn its place.** `utils` (for
  `utils/csv`), `contracts` (the generated Go for `bloodheaven.audit.v1`, so the
  upload shape cannot diverge from what `DeployWitness` accepts),
  `google.golang.org/protobuf` (protojson, so the contract's enums go out as
  names) and `gopkg.in/yaml.v3` (the compose file, read as a `yaml.Node` tree).
  `protobuf` is confined to `app/report/contract.go`; nothing else in the tool
  knows protobuf exists. Adding a fifth dependency needs an argument about the
  binary somebody has to read before running it as root.

## The two promises

Every change must preserve both. They are the product.

1. **Offline by default.** The tool reads the kernel, `/etc`, package metadata
   already on disk, and the compose file it was pointed at. On a default run it
   must not refresh a repository, resolve a hostname or open a socket. There are
   exactly three exceptions, all off by default and all requiring the flag to be
   typed:
   - `--online` — the OSV API, for advisory detail.
   - `--egress` — one TCP connect to port 443 of each registry the manifest pulls
     from. No TLS handshake, no HTTP request, no image fetched, nothing sent.
   - `--upload` — one POST of the finished report, only with `--upload-token`
     alongside it. No default endpoint, no retry, no telemetry.

   A new collector that needs the network does not belong here, and a fourth
   network path needs a better reason than the first three had.
2. **Honest.** A gap in coverage is reported, never rendered as a clean result.
   "We could not read `/etc/shadow`" and "there are no passwordless accounts" are
   different answers, and only one of them is true when running unprivileged.
   Anything a section could not do goes into `SectionResult.Note`/`Degrade` and
   surfaces in `summary.csv`.

Concretely: never return an empty slice to mean "nothing found" when the real
answer is "the probe failed". Never cap a result set silently — if a limit
applies, say so in a note.

## Layout

```
main.go                     flags → audit → CSV/JSON, upload, and the exit code
app/config/                 flag and AUDIT_* environment parsing
app/logging/                stderr-only leveled logger
app/model/                  record types, severity vocabulary, CVSS, os-release
                            witness.go: manifest / capabilities / finding types
app/run/                    external command execution (timeout, exit allowlist)
    allowlist.go            the command allowlist: enforcement + the journal
    commands.go             the list itself — the only place a command is added
app/redact/                 the credential sweep over a finished report
app/pkgmgr/                 package manager abstraction + version comparators
    apt.go dnf.go zypper.go pacman.go apk.go
app/vuln/                   the three vulnerability feeds and their merge
    osv.go offline.go online.go collect.go
app/collect/system/         host inventory and hardening posture
app/collect/ports/          listening sockets from /proc/net
app/collect/services/       service units from systemd/OpenRC/SysV
app/collect/manifest/       docker-compose parser — the requirements side
app/collect/host/           arch, memory, filesystems with inodes, databases
app/collect/docker/         docker/podman: containers, networks, volumes, images
app/collect/proxy/          nginx -T / apache -S: names, ports, cert paths
app/collect/panels/         hosting control panels, from filesystem markers
app/collect/certs/          TLS certs (crypto/x509) + who actually renews them
app/collect/scheduler/      cron in every form + systemd timers
app/collect/backup/         backup tools, jobs, and backup freshness
app/witness/              the 24 rules, the change list, the rollback plan
    *.rules.go changes.go
app/report/                 CSV + JSON rendering, the audit contract, the upload
app/audit/                  section orchestration (audit.go, witness.go)
```

## Conventions

- **Build with `make`.** Never invoke `go build` ad hoc when a target exists.
- **Every command this binary runs is on the allowlist in `app/run/commands.go`.**
  `run.Runner` refuses anything else before it even looks the binary up, and
  records the refusal in the journal that ships as `commands.csv`. Adding a
  command means editing that one file, which is what makes it show up in the diff
  and in `--commands` at the same time — never widen a pattern or add a shell to
  get around it. Arguments are matched too: keep `-s` on `apt-get dist-upgrade`
  and `-C` on `dnf`/`yum`, and give a free-form argument one of the existing
  `ArgKind` classes rather than a looser new one.
- **A refused command is a bug here, never a property of the host.** If one shows
  up in `commands.csv`, the fix is the missing allowlist entry, not a workaround
  in the collector.
- **`app/collect/manifest` reads a user-supplied file**: the `docker-compose.yml`
  named by `--compose` and the `.env` beside it. That `.env` is read for
  `${VARIABLE}` substitution only — its keys and values are never collected,
  returned or reported, and `environment:` contributes variable *names* alone.
  Nothing else in the tool reads a file it was handed rather than found.
- **`app/redact` is the last thing before any write, not the first.** Collectors
  must still be written never to read a secret; the sweep exists for the
  free-form text nobody designed (a cron line, a process command line). A new
  free-form field on a report type needs a line in `redact.Report`.
- **Time is UTC.** Timestamps are stored and rendered as `YYYY-MM-DD HH:MM:SS`
  followed by `UTC`, per the platform rule. Nothing here converts to a local
  timezone; the reader does that.
- **Never use `replace` in `go.mod`.** `utils` is consumed as a tagged version.
- **`LC_ALL=C` on every external command.** `app/run` sets it. Parsers depend on
  English column headers; a Russian or German locale rewrites all of them.
- **Non-zero exit is not automatically failure.** `dnf check-update` exits 100
  when updates exist, `pacman -Qu` exits 1 when there are none. Use
  `Runner.OutputAllowExit` with the codes that mean success for that tool.
- **One subprocess per host, not per package.** Building a lookup table from one
  command beats invoking it in a loop; on a rolling release the difference is
  several hundred processes.
- **Adding a package manager:** implement `pkgmgr.Manager`, register it in
  `Detect`, map its OSV ecosystem in `osvEcosystem` (returning `""` when OSV
  publishes none — do not invent one), and pick or write a version comparator.
- **Adding a section:** add the `model.Section` constant, extend
  `model.AllSections` (the six today are `system`, `updates`, `vulnerabilities`,
  `ports`, `services`, `witness` — and that order is a dependency order, not a
  preference), add the case in `audit.Run`, and add a table in `report.tables`. A
  section that produces no rows still gets a header-only file. A section that
  needs an input reports `skipped` with a note when it is missing, the way
  `witness` does without `--compose` — never an empty result.
- **Adding a witness rule:** register it in `witness.rules()`, give it a
  `witness.*` code that will not change afterwards, attach evidence to every
  finding it produces (the engine drops findings without it), and keep it a pure
  function of `Input`. A rule that observes the host, or a collector that decides
  something is wrong, is the mistake the `collect`/`witness` split exists to
  prevent. Document the code in `docs/<lang>/10-witness-rules.md`.
- **CSV columns are append-only.** Consumers read by position as often as by
  header; inserting a column silently breaks them.

## Testing

`make test`. The comparators, the CVSS calculator, the `/proc/net` parser, the
OSV range evaluator, the offline loader and the config parser are unit-tested
against fixtures — none of them need a host in a particular state.

The collectors themselves are verified by running the tool. Only the `pacman`
backend has been exercised against a real system; the apt, dnf, zypper and apk
backends are written from their documented output formats and should be
confirmed on a real host of that family before being relied on.

The same caveat applies to everything added for the `witness` section: it has
been run against a real **Arch** host, privileged and unprivileged, with Docker
installed. Apache, podman, every control panel and every backup tool are
recognised from documented layouts and file markers, with fixtures for the
parsers but no machine that actually had them. Say so when documenting them
rather than implying coverage that has not been exercised.

## Documentation

`docs/en/` and `docs/ru/` must stay in sync — never update one without the
other, in the same change.

| Changed | Update |
|---|---|
| Purpose, scope, the two promises | `01-introduction.md` |
| A new doc file | `02-table-of-contents.md` |
| Build, cross-compilation, install, dependencies | `03-installation.md` |
| Any flag, env var or exit code | `04-cli-reference.md` |
| Package layout, run flow | `05-architecture.md` |
| What a collector reads, privilege needs | `06-collectors.md` |
| Feeds, ecosystems, severity grading | `07-vulnerability-sources.md` |
| Any CSV column, the JSON document, what `--upload` sends | `08-report-format.md` |
| An entry in `app/run/commands.go`, an `ArgKind`, the journal | `09-command-allowlist.md` |
| A witness rule, finding code, severity or threshold | `10-witness-rules.md` |

## CHANGELOG

Every file-modifying change adds an entry, in the same change. Keep a Changelog
format, SemVer. Cut a release at the end of every session that modified files:
replace `## [Unreleased]` with `## [X.Y.Z] - YYYY-MM-DD` and add a fresh empty
`## [Unreleased]` above it. The `Makefile` reads the version from the first
numbered heading and stamps it into the binary, so an unreleased tree builds with
an empty version string — that is expected, not a bug.
