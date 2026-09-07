# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.1.0] - 2026-09-07

### Changed

- **The build no longer needs access to a private repository** ([go.mod](go.mod),
  [app/csv/](app/csv/), [app/contract/auditv1/](app/contract/auditv1/),
  [Makefile](Makefile)). `github.com/BloodHeavenDevelop/utils` and
  `github.com/BloodHeavenDevelop/contracts` are gone from `go.mod`; what the tool
  actually used from them is carried in the tree as byte-for-byte copies —
  `app/csv` (from `utils/csv` v0.9.0) and `app/contract/auditv1` (from
  `contracts` v0.9.0, `gen/go/bloodheaven/audit/v1`), each with a `doc.go` naming
  its source release. The two remaining dependencies, `google.golang.org/protobuf`
  and `gopkg.in/yaml.v3`, come from the public module proxy, so a clean checkout
  builds with no credentials, no `GOPRIVATE` and no organisation membership.

  This is the point of the tool, not a packaging detail: it asks to be run as root
  on somebody's production server, and its answer to "why should I trust this
  binary?" is "read the source and build it yourself" — which is not an answer if
  the build first demands a token for a repository the reader cannot see. Copying
  *generated* code is not the same as restating the contract by hand: the `.proto`
  in `contracts` stays the single source of truth, the wire format and the
  descriptor's file name are unchanged, and a divergence now shows up in a diff
  instead of on the first upload.
- **`make sync-shared`** ([Makefile](Makefile)) — refreshes both copies from local
  checkouts (`UTILS`, `CONTRACTS`, defaulting to `../utils` and `../contracts`),
  then builds and runs the affected tests. Maintainers only; building never needs
  those repositories. The releases the copies came from are recorded as
  `UTILS_VERSION` / `CONTRACTS_VERSION`.

### Fixed

- **`--upload` in the README took an endpoint that would have 404'd**
  ([README.md](README.md)). The example passed `https://deploywitness.io/api`,
  but the flag takes the service's *base* URL and the tool appends
  `/api/public/audit/upload` itself — so that URL resolved to `/api/api/…`. The
  example is the origin again, and the README now states the endpoint and the
  `X-Upload-Token` header, which only the CLI reference carried before.

## [1.0.0] - 2026-09-07

### Changed

- **BREAKING: the repository is `deploy-witness-cli` and the binary is `deploy-witness`** ([go.mod](go.mod), [Makefile](Makefile)). The module path is now `github.com/BloodHeavenDevelop/deploy-witness-cli`, `make build` writes `./deploy-witness`, and the cross-compiled artefacts are `bin/deploy-witness-linux-{amd64,arm64}`. The tool is a CLI, not an agent: it makes one pass, leaves nothing resident and opens no connection unless a network flag is typed — so the repository name says `cli`, and no file in the tree calls it an agent.
- **BREAKING: the `preflight` section is the `witness` section** ([app/witness/](app/witness/), [app/audit/witness.go](app/audit/witness.go), [app/model](app/model)). `--sections witness` selects it, the findings land in `witness.csv`, and all 24 finding codes are now `witness.*` (`witness.port_conflict`, `witness.memory_headroom`, …). The codes were declared stable, so this is the one break they get: the product they belong to was renamed, and leaving them under the old name would have made the CSV disagree with every other name in the report. Consumers that key off the code column must map `preflight.<x>` → `witness.<x>`; nothing else about the rows changed, and the column order is untouched.
- **The upload target is DeployWitness** ([README.md](README.md), [CLAUDE.md](CLAUDE.md), [docs/](docs/)). `--upload` still takes an explicit endpoint and a one-time token, still sends the `bloodheaven.audit.v1` contract, still retries nothing — only the name of the service on the other end changed.
- **Documentation renamed with the section**: `docs/{en,ru}/10-preflight-rules.md` is now `10-witness-rules.md`, and both languages are updated together.

## [0.2.0] - 2026-08-17

### Added

- `app/run/commands.go` + `app/run/allowlist.go` — a command allowlist. The binary
  can execute exactly the 68 commands on that list and nothing else: `run.Runner`
  refuses anything outside it before it even looks the binary up. Arguments are
  matched too, not only the binary name — `apt-get … dist-upgrade` is permitted
  only with `-s` (simulation) and `dnf`/`yum` only with `-C` (cache-only, so no
  repository can be refreshed). Free-form arguments (`<unit>`, `<path>`,
  `<container>`, `<image>`, `<user>`, `<suite>`, `<name>`) are each bounded by a
  character class that admits no shell metacharacter, and nothing goes through a
  shell.
- `--commands` — prints the enforced list itself, grouped by section, with the
  reason each entry is read for, and exits. The published list and the enforced
  one cannot drift because there is one source for both.
- A command journal, shipped as `commands.csv` (columns: `Command`, `Started at`,
  `Duration`, `Exit code`, `Outcome`). Every execution is recorded, including
  timeouts, missing binaries and refusals; outcomes are `ok`, `failed`, `timeout`,
  `missing` and `refused`. The file is written on every run, whatever `--sections`
  said, and the whole journal is included in an upload. A `refused` row is a defect
  in this tool, never a property of the host, and it is logged at error level
  rather than hidden.
- `app/redact` — a credential sweep over the finished report, run after every
  collector and before every writer. It masks credential-looking material in
  free-form text (cron lines, process command lines, notes, evidence output,
  manifest labels) with the visible marker `***redacted***`; a mask that silently
  deleted the value would make the evidence a lie. The number of fields changed is
  logged. `app/collect/scheduler` reuses the same patterns at parse time, so there
  is one set of patterns in the binary rather than two that disagree.
- A new `preflight` section: it compares a `docker-compose.yml` against the host
  and reports where the two disagree. Needs `--compose <path>`; without it the
  section reports itself as `skipped` with a note rather than empty.
- `--compose <path>` (`AUDIT_COMPOSE`) — the manifest the `preflight` section
  checks the host against. Validated at startup, so a missing file is exit code `2`
  rather than a degraded section. Its directory is the project directory: `.env` is
  read there for `${VARIABLE}` substitution, relative paths resolve against it, and
  its name becomes the Compose project name, which is what separates "this port is
  taken by something else" from "this port is taken by the previous version of this
  very deployment".
- `app/collect/manifest` — a compose-file parser: both port and volume syntaxes,
  ranges, `${VAR}` substitution with `.env`, memory suffixes, YAML anchors and
  merge keys, read as a `yaml.Node` tree so key order and line numbers survive.
  Environment variable **names** only — values are never read, stored or reported,
  and an `env_file` contributes its path and whether it exists. An unresolved
  `${VARIABLE}` is left as a literal with a warning rather than silently becoming
  an empty string.
- `app/collect/host` — architecture (`uname -m`), memory (`/proc/meminfo`),
  filesystems **with inodes** (`/proc/mounts` + `statfs`), and the databases
  already on the host. Nothing connects to a database: the engine, version, port,
  exposure and data-directory size are all observable from outside.
- `app/collect/docker` — docker/podman engine and compose implementation,
  containers (including stopped ones, with their project labels), networks,
  volumes and images. No container's environment is read; `docker inspect` of a
  container is deliberately absent from the allowlist. An installed engine that
  will not answer sets `Reachable = false` and degrades the section instead of
  reporting an empty container list.
- `app/collect/proxy` — the effective nginx (`nginx -T`) or Apache (`apachectl -S`)
  configuration: server names with the file and line they are configured at, listen
  ports, and certificate *paths*. A bounded walk of the configuration tree is the
  fallback when the dump cannot run, and the report says the result is incomplete.
- `app/collect/panels` — detection of Plesk, cPanel/WHM, DirectAdmin, ISPmanager,
  Coolify, CapRover, Portainer, aaPanel, HestiaCP, VestaCP, Virtualmin, Webmin,
  CyberPanel and ISPConfig, from a fixed list of filesystem markers plus the
  container names for the ones that ship as containers. Presence established only
  from a weak marker is reported as inferred, naming the marker.
- `app/collect/certs` — TLS certificates on disk, parsed with `crypto/x509` rather
  than by shelling out to `openssl` (this collector runs no subprocess at all). It
  distinguishes "a renewal tool is installed" from "a renewal job for this
  certificate exists", which is exactly how a certificate expires on a host that
  had certbot all along. Private key directories are enumerated by name and never
  opened.
- `app/collect/scheduler` — scheduled work in every place it hides: `/etc/crontab`,
  `/etc/cron.d`, the `cron.*` script directories, both per-user spool layouts, `at`
  jobs and systemd timers. The per-user spools are root-only, and an unprivileged
  run says so with `Degrade` rather than returning a short list. An `at` job is
  counted but its command is not reported, because the spool file embeds the
  submitting shell's whole environment.
- `app/collect/backup` — installed backup tools, scheduled backup jobs, and the
  **date of the newest file** in each backup directory. Contents are never read;
  the date is what tells a live backup from an abandoned one.
- `app/preflight` — 24 rules producing the findings, plus the change list ("what
  the deployment will actually do") and the rollback plan. Every rule is a pure
  function of the manifest and the collected capabilities: nothing here observes
  the host, and a finding with no evidence is discarded with the discard counted in
  the section's notes. The codes are stable identifiers an integration can match
  on: `port_conflict`, `container_name_conflict`, `volume_name_conflict`,
  `bind_path_conflict`, `network_name_conflict`, `subnet_overlap`,
  `insufficient_memory`, `insufficient_disk`, `insufficient_inodes`,
  `architecture_mismatch`, `runtime_missing_or_old`, `registry_unreachable`,
  `proxy_conflict`, `domain_conflict`, `database_version_mismatch`,
  `env_file_missing`, `no_healthcheck`, `floating_image_tag`,
  `privileged_container`, `backup_gap`, `no_rollback_plan`,
  `certificate_expiring`, `reboot_required`, `disk_at_limit` — all prefixed
  `preflight.`.
- New CSV files: `preflight.csv` (the findings, with `Why it matters` and `What to
  do` per row), `evidence.csv` (every capture behind every finding, with a
  `Truncated` flag), `changes.csv`, `rollback.csv` and `commands.csv`.
- `--egress` (`AUDIT_EGRESS`) — the only outbound check in the audit: a TCP connect
  to port 443 of each registry the manifest pulls from, 5 s each. No TLS handshake,
  no HTTP request, no image fetched, nothing sent. Off by default; without it the
  reachability rule reports "not checked" instead of concluding anything, and with
  it `summary.csv` records how many registry hosts were contacted.
- `--format csv|json` (`AUDIT_FORMAT`) — `json` writes one `report.json` instead of
  the CSV directory, with two named halves: `upload` (the shared
  `bloodheaven.audit.v1` contract as protojson — exactly the bytes `--upload`
  sends) and `audit` (everything that stays local: host inventory, pending updates,
  CVEs, the parsed manifest and the observed capabilities). The naming is the
  point: the operator can read the file and see which half would leave their
  machine.
- `--upload <base-url>` + `--upload-token <token>` (`AUDIT_UPLOAD`,
  `AUDIT_UPLOAD_TOKEN`) — one `POST` of the contract half to
  `<base-url>/api/public/audit/upload`, with the token in an `X-Upload-Token`
  header rather than the URL. One request, no retries, no queue, no telemetry, no
  default endpoint; either flag without the other is a usage error. The host is
  identified by a **salted SHA-256 of `/etc/machine-id`**, never the id itself, and
  by nothing at all when that file cannot be read.
- Exit code `3` — the report was written but `--upload` could not deliver it. It
  takes precedence over `1`, because the point of the command the operator typed
  was to deliver the file.
- New docs, in both languages: `09-command-allowlist.md` (the allowlist, the
  argument classes and the journal — the trust argument, not a footnote) and
  `10-preflight-rules.md` (all 24 finding codes with their severities, triggers and
  thresholds).

### Changed

- The first promise in `CLAUDE.md`, `README.md` and `docs/*/01-introduction.md` now
  reads **"offline by default"** and names all three network flags (`--online`,
  `--egress`, `--upload`) instead of `--online` alone. Nothing about the default
  run changed; the wording did, because "offline" full stop was no longer true of
  the flag surface.
- `--sections` accepts `preflight`, and `model.AllSections` runs it last so it can
  reuse the listening sockets and service units the earlier sections collected
  rather than gathering them twice. Selecting `preflight` without `ports` degrades
  the section with a note.
- `report.tables` gained five tables, appended after the existing six. No existing
  column moved — the CSV column contract is append-only.
- `summary.csv` reuses its `Critical` and `High` counters for the `preflight` row:
  `Critical` holds the blocker count, `High` the warning count, so a reader
  scanning the index sees the blockers without opening the section.
- `go.mod` — three new dependencies:
  `github.com/BloodHeavenDevelop/contracts v0.9.0` (the shared audit contract, so
  the upload shape cannot diverge from what `preflight` accepts),
  `google.golang.org/protobuf` (protojson, so the contract's enums go out as names
  like `SEVERITY_BLOCKER` rather than integers) and `gopkg.in/yaml.v3` (the compose
  parser). `protobuf` is confined to `app/report/contract.go`.
- `docs/*/07-vulnerability-sources.md` no longer claims `--online` is the only
  network access the tool makes.

### Security

- **Nothing outside `app/run/commands.go` can be executed.** The refusal happens
  inside `run.Runner`, before the binary is looked up, so a collector cannot opt
  out of it by forgetting to ask — and every refusal is recorded in the journal
  that ships with the report.
- **No new write path.** Every allowlisted command is a query: the container
  entries are `ps`, `ls`, `info`, `version` and `inspect` of an image or a network,
  and nothing starts, stops, pulls or removes anything. `apt-get dist-upgrade` is
  reachable only with `-s`, and `dnf`/`yum` only with `-C`.
- **Credentials are masked before the report is written**, with a visible marker,
  and cron lines are swept at the moment they are parsed. This matters more than it
  did in 0.1.0 because a report can now be uploaded.
- **`--upload` sends a findings document, not an inventory.** The package list, the
  pending updates and the CVE list stay on the machine: sending them would be
  volunteering a full software inventory of somebody's production host to a service
  that did not ask for one.
- **No environment values are collected anywhere.** `environment:` yields names,
  `env_file:` yields a path and whether it resolves, `.env` is read for
  substitution only, and `docker inspect` of a container — whose output carries a
  container's environment — is deliberately not on the allowlist.
- **Nothing connects to a database and nothing opens a backup file.** Database
  identity and size, and backup freshness, are established from listening sockets
  and `stat`.

### Fixed

- `app/audit/preflight.go` — `preflight.reboot_required` now fires on the apt family.
  The system collector writes the fact as `yes (linux-image-generic, …)` there, naming
  the packages that asked for the reboot, and the rule compared the whole string
  against `yes` — so the finding silently never appeared on Debian or Ubuntu while
  working wherever the answer came from `needs-restarting -r`.
- `main.go` — an unstamped build (`go build`, `go run .`) now reports its version as
  `dev` instead of a hardcoded release number. The constant went stale the moment a
  release was cut, and it went stale in three visible places: `--version`, the
  `--commands` header, and the `producer` field of every uploaded report.
- `app/run/allowlist.go` — `--commands` escapes the tab and newline inside the
  `dpkg-query` and `rpm` format strings instead of emitting them raw, which was
  breaking the published command list into stray blank lines.
- `app/collect/ports/ports.go` — an address `ss` prints in a form `net.ParseIP` will
  not take is now classified as reaching all interfaces rather than one. Understating
  an exposure is the wrong direction to be wrong in.
- `app/redact/redact.go` — the sweep now also covers `Capabilities.Backup.Jobs` and
  its note, which carry cron lines and therefore the credentials people put in them.

## [0.1.0] - 2026-08-13

### Added

- Initial release: `server-audit`, a standalone Go binary that audits the machine
  it runs on and writes a CSV report. No database, no HTTP server, no frontend;
  offline unless `--online` is passed.
- `app/collect/system` — host inventory section: identity, os-release, kernel,
  hardware, storage (`/proc/mounts` + `statfs`), network interfaces and routes,
  timekeeping, package manager, accounts (`/etc/passwd`, `/etc/shadow`,
  `sudoers`), effective sshd configuration (`sshd -T` with a file-parsing
  fallback), SELinux/AppArmor state, firewall units and fifteen hardening
  sysctls.
- `app/collect/ports` — listening TCP/UDP sockets read directly from
  `/proc/net/{tcp,tcp6,udp,udp6}`, attributed to the owning process through
  `/proc/<pid>/fd`, each classified as `loopback`, `interface` or
  `all-interfaces`. Falls back to `ss` when `/proc/net` is unreadable.
- `app/collect/services` — service units from systemd (runtime state plus
  unit-file enablement, main PID, user and activation time), with OpenRC, SysV
  and process-table fallbacks. Running units only unless `--services-all`.
- `app/pkgmgr` — package-manager abstraction with apt/dpkg, dnf/yum, zypper,
  pacman and apk backends, plus dpkg, rpm and generic version comparators. All
  update queries read metadata already on disk; no repository is refreshed.
- `app/vuln` — vulnerability resolution from three independent feeds: the
  distribution's own advisories (`dnf updateinfo`, `debsecan`, `arch-audit`,
  `zypper list-patches`, apt security origins), an offline OSV dataset
  (`--vuln-db`, accepting `.json`, `.jsonl`, `.gz`, `.zip` or a directory) and
  the OSV API (`--online`). Findings are merged, deduplicated by package and
  CVE, and graded through a CVSS v3.1/v2 base-score calculator.
- `app/report` — CSV rendering via the shared `utils/csv` helper: one file per
  section plus `summary.csv`, or a single combined stream with `--stdout`.
- `app/config` — flags with `AUDIT_`-prefixed environment fallbacks:
  `--out`, `--stdout`, `--sections`, `--vuln-db`, `--online`, `--osv-url`,
  `--ecosystem`, `--min-severity`, `--timeout`, `--services-all`,
  `--max-osv-lookups`, `--verbose`, `--quiet`, `--version`.
- `app/logging` — a stderr-only leveled logger, so `--stdout` yields a clean CSV
  stream.
- `Makefile` targets: `development`, `build`, `run`, `build-linux-amd64`,
  `build-linux-arm64`, `build-all`, `install`, `clean`, `fmt`, `vet`, `lint`,
  `test`.
- Documentation in `docs/en/` and `docs/ru/`.

[Unreleased]: https://github.com/BloodHeavenDevelop/server-audit/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/BloodHeavenDevelop/server-audit/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/BloodHeavenDevelop/server-audit/releases/tag/v0.1.0
