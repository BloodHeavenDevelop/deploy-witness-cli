# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.5.0] - 2026-10-19

### Added

- **Pilot errors become permanent tests** (DW-90, `docs/<lang>/13-pilot-regressions.md`):
  a confirmed false alarm, miss or unjustified unknown goes error → cause → scenario
  on artificial data → expected outcome → fix → permanent test, as a case under
  `app/witness/testdata/regressions/<task>-<slug>/` (`case.yaml` + `input.json` in the
  report's own manifest/capabilities shapes). `TestPilotRegressions` runs every case
  in `make test` — so before every release — and names the defect that came back;
  pilot cases record the minutes their manual recheck took.
  `TestRegressionArchiveHoldsNoClientData` refuses a case with anything the
  credential sweep masks, a public IP, a non-reserved domain, an e-mail address, or an
  engine/machine/image id. `make regression NAME=<task>-<slug>` starts one from the
  template. Seeded with the seven defects fixed so far (DW-24, DW-52, DW-79, DW-80,
  DW-81, DW-83, DW-87); each was checked to fail with its fix reverted. Seven bench
  scenarios carry the same tasks as `regression:`, which the release gate blocks on.

- **Quality measurement and release criteria** (DW-84, [bench/score](bench/score/score.go),
  `docs/<lang>/12-quality-and-release.md`): `make bench-score` gives every rule its
  detected problems, misses, false findings, unknowns and situation coverage from a
  bench run, compared scenario by scenario with the committed baseline
  (`bench/baseline/results.json`); unknown is never a detection — it counts against
  the detection rate. `make release-gate` blocks a release on a bench error, an audit
  side effect, broken ground truth, a failing critical or regression scenario, a
  scenario that passed in the baseline and fails now, or a baseline scenario missing
  from the run. The released 1.4.0, graded on the same 46 scenarios
  (`bench/history/1.4.0.json`): 25/46 as specified, detection 76%, false findings
  32%; this tree: 46/46, 100%, 0%, gate PASS. The bench grades a CLI that predates
  rule outcomes by its severities, so versions stay comparable.

- **A reproducible test bench** (DW-83): `make bench` stages every scenario under
  `bench/scenarios` in one disposable Docker-in-Docker container (pinned
  `docker:27.5.1-dind` — Engine 27.5.1, Compose 2.33.0 — `--network none`, images
  loaded from this machine, nothing pulled), runs the audit (the prediction), then
  the planned `docker compose up` (the actual behaviour), and writes
  `bench/out/<timestamp>/results.json` and `results.csv`: per scenario the input,
  the expected outcome, the CLI's prediction, Docker's exit, output and whether its
  containers stayed up, and two verdicts. Bench failures and anything the audit
  itself changed in the engine or the scenario directory are recorded apart. 46
  scenarios over 15 rules — problem, a similar situation without it, and
  insufficient data (an unprivileged audit) for each engine-dependent rule
  ([bench/dwbench](bench/dwbench/main.go), `docs/<lang>/11-test-bench.md`). First full
  run: prediction as specified 46/46, Docker as expected 36/36 (10 advisory), no
  bench error, no side effect.

- **Bind mount sources examined on the host** (DW-88,
  [app/collect/host/binds.go](app/collect/host/binds.go),
  [app/witness/binds.go](app/witness/binds.go)): every source is resolved as Compose
  resolves it (relative to the project directory, `~` to the home directory — the
  built-in parser warns that it can only use the audit account's) and examined by
  `lstat`/`stat` alone — nothing is created, opened or read. `bind_path_conflict`
  now also states a missing source with `create_host_path: false` (blocker), a
  read/write mount on a read-only filesystem (warning), and as `unknown`: a source
  this account could not stat (never "missing"), a dangling symlink, a missing
  source whose creation depends on the Compose version, a missing file-like source
  the engine would create as a directory, and mode bits that refuse the container
  user. The container user is the service's `user:`, else the image's `Config.User`
  (now read by `image inspect`), else unknown; access is never claimed proven —
  every bind row of `changes.csv` says it is not verified (ACLs, user namespaces,
  SELinux are not read) and lists the options not evaluated (`z`, `Z`, propagation,
  consistency). `VolumeMount` gains `declared`, `createHostPath`, `options`;
  `capabilities.bindSources` records what each stat showed.

- **Volumes and networks matched by their names in the engine** (DW-87): `name:`,
  the key of an external resource (or `external: {name: …}`), `<project>_<key>` for
  what Compose creates — as `docker compose config` resolves it, and by
  `manifest.ResolveEngineNames` for the built-in parser. A volume or network Compose
  would create and that already exists without this project's label is now a warning
  (Compose warns and reuses it, data included) instead of passing unnoticed; one not
  there yet is a planned creation in `changes.csv`, never a conflict; only volumes a
  planned service mounts are checked. Presence is kept apart from usability: a
  swarm network that is not attachable is a blocker, one whose attachability was not
  read is `unknown`. Every volume/network observation names the engine it came from
  (`engine <ID>, <name>`). `docker network inspect` now asks for the whole network
  object (`{{json .}}`) to read `Attachable`; `network ls` contributes the scope.

- **Port conflicts decided from the binding, not the number** (DW-86): whether an
  IPv6 wildcard socket also answers IPv4 is now read per socket from `ss` (`*:port`
  dual-stack, `[::]:port` IPv6-only) into a new appended `V6 only` column of
  `ports.csv`, and whether the host has IPv6 (`/proc/sys/net/ipv6`) decides whether a
  publish without `host_ip` also lands on `[::]` — both used to be `unknown` on
  every host. A host range to one container port (`8000-8010:80`) binds one free
  port of it and is a conflict only when all are held; a publish with no host port is
  ephemeral and never collides; `network_mode: host` services are checked on their
  declared ports, with the application's choice of address kept undecided; built-in
  parsing keeps the container end of a range (`ContainerPortEnd`) so `8000-8001:8000-8001`
  and `8000-8001:80` are no longer read alike. `changes.csv` follows (`ephemeral/tcp`,
  one row per dynamic range, host-network rows). Verified on Docker 29.7.2: a
  dual-stack listener blocks `0.0.0.0:<port>` exactly as predicted, an IPv6-only one
  does not.

- **Container ownership and the replacement plan** (DW-85,
  [app/witness/ownership.go](app/witness/ownership.go)): every existing container is
  classified from the Compose labels it carries (`project`, `service`,
  `project.working_dir`, `project.config_files`, `oneoff`, `config-hash`) against the
  planned run — this deployment (kept when its config hash equals the plan's from
  `docker compose config --hash`, recreated otherwise), an orphan, a one-off run,
  another checkout using the same project name, this directory under another project
  name, another project, unmanaged, or unknown (no labels). New rule
  `witness.project_ownership` (25 rules) states another checkout (`problem`), an older
  project name and orphans left running (`manual-check`) and unlabelled containers
  (`unknown`). `port_conflict`, `container_name_conflict` and the `container` rows of
  `changes.csv` follow the same classification, so an update is never a conflict with
  itself and a port held by an orphan, a one-off run or the previous project name is.
- **`--remove-orphans`, `--force-recreate`, `--no-recreate`** (DW-85) describe the
  planned `docker compose up`; allowlist `docker compose <options> config --hash *`
  (73 commands).

- **Evidence provenance** (DW-82): every report carries `provenance.csv` /
  `audit.provenance` — tool and rules version (`witness.RulesVersion`, `2`), host and
  server fingerprint, engine and its `docker info` ID, Compose, the plan's resolver
  and digest, the run's timeline (started, plan resolved, observed from/until,
  compared, finished), NTP state, the engine's clock skew, completeness per source,
  and `recheck-after`. The timeline is checked: a clock going backwards, an
  observation or evidence timed outside the run, an unsynchronised clock, an engine
  clock more than 5 s off and observations more than 10 min apart are each a
  `time-check` row and a `time:` note. The `witness` notes carry a `provenance: …`
  line, so the upload has it too.
- **Evidence separates observation from interpretation** (DW-82): `evidence.csv`
  gains `Origin` (`plan`, `host`, `rule`) and `Source` (the observation source), and
  `Captured at` is now the moment the source was read or the plan resolved — no longer
  the comparison time for every row ([app/witness/preflight.go](app/witness/preflight.go)).
- **`--recheck <report.json>`** (DW-82, [app/audit/recheck.go](app/audit/recheck.go)):
  before deploying, confirm that a report still describes this plan (plan digest),
  on this engine (engine ID), within `--max-age` (default 1 h), under the same rules
  and with a consistent timeline. Prints `ok:`/`re-run:` lines, exits `0` or the new
  `4`; collects and writes nothing. A changed plan is never confirmed by an old report.

- **A Compose preflight checks the exact planned run** (DW-81): `--compose` is
  repeatable (merge order kept), plus `--env-file`, `--profile`, `--project-name`,
  `--project-directory` and `--compose-service`, mirroring `docker compose`
  (`AUDIT_COMPOSE` takes a `:`-separated list). The model is resolved by
  `docker compose <the same flags> config --format json --no-env-resolution`
  ([app/audit/plan.go](app/audit/plan.go),
  [app/collect/manifest/resolved.go](app/collect/manifest/resolved.go)) — merge,
  profiles, interpolation, relative paths and the project name exactly as Compose
  does them, offline and without the daemon; its output is parsed in memory and
  never written (environment variable names only). New `plan.csv` / `audit.plan`
  record the files, project name and its source, env files, profiles, services and
  what they start, the resolver and its version, the `COMPOSE_*`/`DOCKER_*` variable
  names present, and the engine (context, endpoint, `docker info` ID and name).
  `--compose-service` narrows the plan to the named services and their
  dependencies.
- **Allowlist** (DW-81): `docker compose <options> config --format json
  [--no-env-resolution]`, with `<options>` an explicit table of option pairs
  (`--file`, `--env-file`, `--project-directory`: path; `--profile`,
  `--project-name`: name); `docker context show`; `docker context inspect --format
  {{json .Endpoints.docker.Host}}`. 72 commands.

- **Every witness rule ends in exactly one outcome** (DW-80): `problem`,
  `no-problem`, `unknown` (insufficient data), `manual-check` or `not-applicable`
  ([app/witness/outcomes.go](app/witness/outcomes.go), `model.Outcome`). The outcome
  is a third axis, kept apart from the section status (did the comparison run?) and
  from the severity (does the reader have to stop?). New `rules.csv` — one row per
  rule, finding or not, with the reason and the data the rule needs — and
  `audit.rules` in `report.json`; `witness.csv` gains an appended `Outcome` column and
  every finding an `outcome` field. A rule that ends `unknown` or `manual-check`
  without a finding saying so gets one of its own, so the gap reaches the upload too.
  `docs/<lang>/10-witness-rules.md` documents the three situations of every rule in
  an outcome matrix, which `app/witness/outcomes_test.go` executes.
- **Observation completeness** (DW-80): `audit.capabilities.observations` records,
  per source (containers, networks, network subnets, volumes, images, sockets, arch,
  memory, filesystems, proxy), whether it was read `complete`, `partial`, `failed` or
  `not-collected`. Absence is concluded only from a list read in full.

### Changed

- **The project name is the one Compose resolves** (DW-81) — `--project-name`,
  `COMPOSE_PROJECT_NAME`, a top-level `name:`, then the project directory — instead
  of always the directory name, which made a deployment with `-p` or `name:` read
  its own containers as foreign.
- **A plan that cannot be prepared is exit 2 with no report** (DW-81): `docker
  compose config` rejecting the plan (its reason quoted, credentials masked), a
  remote `include:` (resolving it would fetch it), a plan aimed at a remote engine
  (`DOCKER_HOST` or the active context over `ssh://`/`tcp://`), a
  `--compose-service` not in the resolved plan, or a plan the built-in parser cannot
  reproduce when Compose is not installed. Without Compose a one-file plan is read
  by the built-in parser and the preflight is `partial`, never presented as
  Compose's own resolution.

- **Only a proven problem can be a blocker; "no problem" is always `info`** (DW-80).
  Enforced by the engine, and a correction is counted as a bug in the section notes.
- **The `witness` row of `summary.csv` counts proven problems only** (DW-80):
  `Critical`/`High` no longer include findings whose outcome is `unknown` or
  `manual-check`. Its notes end with `rule outcomes: 24 rules — …`, which the upload's
  `witness` collector note carries as well (the contract has no outcome field yet).
  The `preflight` row adds `result: …` — counts per outcome — after its status.

### Fixed

- **Found by the bench** (DW-83): a hand-made external network (no project label)
  is no longer "shared with another stack"; `create_host_path` in Compose's resolved
  model is decoded by the Compose version that printed it — 2.x omits `false`, 5.x
  omits `true` — so a missing source with `create_host_path: false` is a blocker on
  Compose 2.x too.
- **An external volume created by hand is not "somebody else's data"** (DW-87): a
  volume with no project label is what `external: true` is for; only one carrying
  another project's label is a warning.
- **A multi-file Compose project's labels are read whole** (DW-85): docker packs
  labels as `k=v,k=v`, and `config_files` of a two-file project contains a comma; the
  rest of the value was read as a label of its own.

- **A docker context pointing at a remote engine no longer makes a host audit
  connect to it** (DW-81): the context is read and every docker command is pinned to
  `DOCKER_CONTEXT=default`, with a warning. This was a documented gap of the offline
  promise.
- **`env_file` with `required: false` is not a missing file** (DW-81), and an
  env file whose existence could not be checked is `unknown`, not missing.

- **An engine that did not answer no longer produces "does not exist" blockers**
  (DW-80). An external volume or network missing from an engine list that was not
  read is now `unknown` (warning), not a blocker; a port held by a socket while the
  engine's containers could not be listed is `unknown` (it may be the deployment's
  own `docker-proxy`), and `changes.csv` says the port may be taken instead of
  promising it is.
- **Silent rules now say why they are silent** (DW-80): an unknown host
  architecture, an image not yet on the host, unparseable certificates, an unknown
  reboot state, unmeasured filesystems and a backup tool with no visible backup
  location used to produce nothing; each now ends `unknown` or `manual-check` with a
  finding naming the missing source.

## [1.4.0] - 2026-10-11

### Fixed

- **`changes.csv` no longer promises to replace somebody else's container**
  (DW-52, DW-79). A container of the same name was always reported as `replaced
  (currently …) with …`, including one of another Compose project or one created by
  hand and never started — on which `docker compose up` fails, exactly as the
  `witness.container_name_conflict` blocker says. Only a container of this
  deployment's own project is `replaced` now; any other is `not created: a container
  named … already exists (state …, image …, no Compose project | Compose project "…")
  and does not belong to this deployment …` ([app/witness/changes.go](app/witness/changes.go)).
  A container whose published port is held by something else is `created …, but it
  cannot start: host port … is already held`, and that port's `firewall-port` row is
  `not opened: … already held by …` instead of `opened by …` — decided by the same
  matching as `witness.port_conflict`. With the engine unreachable the container row
  says the name could not be checked instead of promising a clean creation, and
  without the `ports` section the `firewall-port` row says the binding was not
  checked instead of promising it opens.
- **What cannot be seen is "unable to verify", not "not available"** (DW-79). The
  `snapshot` and `proxy-config` rollback rows were `false`, which reads as
  "established missing", while their own text said it could not be seen from inside
  the host. Rollback items now have a state — `available`, `unavailable`,
  `unable-to-verify` ([app/model/preflight.go](app/model/preflight.go)): `rollback.csv`
  `Available` is `true`, `false` or `unknown`, `report.json` `audit.rollback[]`
  gains `state`, and an unverified detail opens with `unable to verify:` (the
  upload's boolean stays `false` — the contract has no third value).
- **`witness.no_rollback_plan` no longer concludes there is no way back**
  (DW-79). With something established missing it is a warning, "Part of the way
  back from this deployment is missing", subject `N of M missing`; with only
  unverifiable items it is info, "The way back could not be fully verified", subject
  `N of M unverified`. The description and evidence list `Missing:` and `Unable to
  verify:` separately ([app/witness/hygiene.rules.go](app/witness/hygiene.rules.go)).

### Added

- **`--format csv,json`** (DW-79) writes the CSV tables and `report.json` into
  `--out` from **one** audit, so the two carry the same `Checked at`, PIDs and
  evidence timestamps. Producing both used to take two runs, seconds apart — the
  site-materials kit did exactly that, and its terminal log (CSV run) and its JSON
  evidence (JSON run) disagreed by three seconds. Refused with `--stdout`.
  `docs/<lang>/08-report-format.md` now states what each timestamp of one run means
  (`Checked at` = start, evidence `Captured at` = when the witness section
  compared, the log's `wrote …` = when the files were written).

- **End-to-end tests of an explicitly requested preflight with a broken input**
  (DW-70, [main_test.go](main_test.go)): missing file, unreadable file, a
  directory, and three unparseable files (not YAML, a top-level list, an empty
  file) — each asserts exit `2`, the reason in the log and that no report directory
  was created. `docs/<lang>/04-cli-reference.md` lists the binary's verbatim output
  for each case. `main` now runs through `runCLI(args, stdout, stderr)` so the tests
  drive it as a user does.

### Changed

- **The site-materials kit is one run per scenario** (DW-79):
  `docs/site-materials/run.sh` uses `--format csv,json`, `terminal-json.txt` is gone,
  and every output was regenerated with the released binary.

- **In a host audit the witness section is "not applicable", not "skipped"**
  (DW-70). A run without `--compose` never set out to compare a deployment, so the
  missing comparison is outside its scope rather than a gap in it. New section
  status `not-applicable` ([app/model/model.go](app/model/model.go)): the `witness`
  and `preflight` rows of `summary.csv` carry it, with notes opening
  `host-audit: not applicable`, and so does `audit.sections` in `report.json`; a host
  audit whose sections completed now has no `skipped`, `partial` or `failed` row on
  account of the absent Compose file. The log says "witness not applicable" instead
  of describing a missing preflight.
- **The upload of a host audit no longer contains a `witness` collector** (DW-70).
  It used to go out as `COLLECTOR_STATUS_SKIPPED`, which the receiving service counts
  against completeness and stored the run as `partial`. `bloodheaven.audit.v1` has
  no "not applicable" status, so a section outside the run's scope is left out of
  `collectors` ([app/report/contract.go](app/report/contract.go)); a Compose
  preflight always sends its `witness` collector, which is how the receiver tells
  the two apart. A `NOT_APPLICABLE` status or a mode field is a change for the
  `contracts` repository.

## [1.3.0] - 2026-10-10

### Security

- **A default run no longer reaches the network through child processes** (DW-53).
  `debsecan` and `arch-audit` download their advisory data on every call; their
  allowlist entries now carry `Network: "--online"` ([app/run/commands.go](app/run/commands.go)),
  the collectors skip them without `--online` and say so in `summary.csv`
  ([app/pkgmgr/apt.go](app/pkgmgr/apt.go), [app/pkgmgr/pacman.go](app/pkgmgr/pacman.go)),
  and `run.Runner` refuses them on a run without that flag. Both `zypper` entries
  gained `--no-refresh`, so an expired repository is never auto-refreshed.
- **Network paths are enabled only by a typed flag** (DW-56). `AUDIT_ONLINE`,
  `AUDIT_EGRESS`, `AUDIT_UPLOAD` and `AUDIT_OSV_URL` are no longer read; a run that
  finds one set logs a warning naming it ([app/config/config.go](app/config/config.go)).
  `AUDIT_UPLOAD_TOKEN` is still read, only together with a typed `--upload`, and is
  now the recommended way to pass the token (it stays out of `/proc/<pid>/cmdline`).
- **Upload: `https://` only, no redirects** (DW-57). `--upload` and `--osv-url` must be
  `https://` (`http://` only for `localhost`, `127.0.0.0/8`, `::1`), with no
  credentials, query or fragment — checked before the audit runs (exit `2`). Neither
  the upload nor the OSV client follows a redirect: a `3xx` is a failure naming where
  it pointed, and the token and report are not sent there (exit `3` for an upload)
  ([app/netpath](app/netpath)).
- `DOCKER_HOST`/`CONTAINER_HOST` pointing at anything but a `unix://` socket are
  removed from the environment of every command the audit runs, with a warning, so
  the docker/podman entries cannot be redirected to a remote engine by a variable.

### Added

- **`network.csv`** and a `network` row in `summary.csv`: one row per network path
  (`osv-api`, `distro-feeds`, `registry-egress`, `upload`), enabled or not, with the
  recipient, what is sent and how many contacts the run made — so an offline run says
  so in the report ([app/audit/network.go](app/audit/network.go)). Also in the `audit`
  half of `report.json` as `network`; never uploaded.
- **Recipients are printed before anything is sent**: the network plan is logged
  before the audit starts (`network: none …` on a default run), and the exact upload
  endpoint, with any proxy, right before the request.
- A `Network` column appended to `commands.csv`, and `network: yes — runs only with
  --online` under the networked entries in `--commands`.
- `app/netpath/static_test.go`: fails if a network API appears in any file other than
  the three network paths.

### Changed

- **Two explicit run modes: host audit and Compose preflight** (DW-70). A run without
  `--compose` is a **host audit** (`host-audit`): the witness section is not run, and
  the report says so instead of looking like a full audit with one skipped section.
  `--compose` makes it a **Compose preflight** (`compose-preflight`), which always
  runs the witness section. New `--mode host-audit|compose-preflight`
  (`AUDIT_MODE`; default: decided by `--compose`) lets a job assert the mode, so a
  preflight whose Compose file went missing stops instead of degrading into a host
  audit. Refused with exit `2` before anything is collected: `witness` in
  `--sections` without `--compose`, `--mode compose-preflight` without `--compose`,
  `--mode host-audit` with `--compose`, `--compose` with a `--sections` that leaves
  `witness` out, and a `--compose` path that is missing, not a regular file or
  unreadable ([app/config/config.go](app/config/config.go)). A Compose file that does
  not parse now stops the run with exit `2` and **no report written**, instead of
  a report whose witness row failed ([app/audit/audit.go](app/audit/audit.go) `Prepare`,
  [main.go](main.go)). The report names the mode everywhere: `mode:` log line at the
  start, `audit.mode` in `report.json`, the `report` row of `summary.csv` opens with
  `host audit:`/`Compose preflight:`, and a new `preflight` row says whether a
  planned deployment was compared (`skipped` for a host audit, the witness status
  for a preflight — `failed` when the comparison did not complete, never `ok`). A
  host audit always carries a `witness` row with status `skipped` and a note opening
  with `host-audit:` — in `summary.csv`, `report.json` and the uploaded collector
  list — so an uploaded host audit can never arrive as a run with every collector
  complete and no findings ([app/audit/witness.go](app/audit/witness.go),
  [app/report/csv.go](app/report/csv.go)). The `bloodheaven.audit.v1` contract is
  unchanged.

### Fixed

- `--egress` evidence and the section note named port 443 for a registry with an
  explicit port (`127.0.0.1:18444` became `127.0.0.1:18444:443`); they now name the
  `host:port` actually dialled (DW-50).
- The `main.go` package comment claimed the OSV API was the only network path (DW-62).

### Documentation

- **Site materials kit** in [docs/site-materials](docs/site-materials/README.md) (DW-73):
  control Compose scenarios (conflict, no conflict, two "could not check" cases,
  external volumes, manifest rules), the exact commands, the reports they produced
  (CSV + `report.json`, sanitised with marked placeholders and trimmed of unrelated
  host inventory), `run.sh` to recreate the host states, run and clean up, and a
  [verification matrix](docs/site-materials/MATRIX.md) of every public claim —
  verified on what, by which scenario, or not verified / not supported. Recorded with
  the tree at `5ab9f51`, which `make build` stamps `1.2.0` because the version comes
  from the first numbered CHANGELOG heading. `.gitignore` admits the sample CSVs;
  both tables of contents link the kit.
- `04-cli-reference.md`: a "Network behaviour" table per mode (who is contacted, what
  is sent, where it is recorded), how to verify an offline run, the token-through-the-
  environment recipe (`sudo --preserve-env`), what an upload contains (host name,
  absolute compose path, journal arguments) and that the returned public link is
  readable by anyone holding it (DW-62). `01`, `03`, `05`, `06`, `07`, `08`, `09` and
  the README updated to match, in English and Russian.

## [1.2.0] - 2026-10-06

### Added

- **Prebuilt binaries in `dist/`** for Linux, macOS and Windows on amd64 and arm64,
  with a sha256 manifest `dist/checksums.txt`, produced by the new `make dist`
  ([Makefile](Makefile)) and committed with the release they were built from.
- **`install.sh`** ([install.sh](install.sh)): downloads the binary for this Linux or
  macOS machine from `dist/` on GitHub, refuses it on a checksum mismatch, installs it
  to `/usr/local/bin` and runs it with the flags it was given — the one command
  DeployWitness hands out with an upload token. `--no-run` installs only;
  `DEPLOY_WITNESS_REF` picks the ref.

### Changed

- **The tool builds for macOS and Windows.** `statfs` and file ownership moved behind
  build tags (`statfs_unix.go`/`statfs_windows.go` in
  [app/collect/system](app/collect/system) and [app/collect/host](app/collect/host),
  `owner_unix.go`/`owner_windows.go` in [app/collect/scheduler](app/collect/scheduler)).
  Nothing changes on Linux. On Windows filesystems are reported unmeasurable and `at`
  job owners `unknown`; the collectors still read Linux paths, so most sections on
  those systems come back `partial` or `skipped`, with the reason.

## [1.1.1] - 2026-09-24

### Fixed

- **`witness.port_conflict` compares bindings, not port numbers**
  ([app/witness/portmatch.go](app/witness/portmatch.go),
  [app/witness/conflicts.rules.go](app/witness/conflicts.rules.go)). The rule
  indexed listening sockets and publishing containers by the port *number* alone,
  discarding the protocol and the host address that `app/collect/ports` and the
  compose parser had already gathered correctly. `53:53/udp` beside a TCP-53
  resolver was a blocker; so was `127.0.0.1:8080` beside a listener on
  `192.168.1.10:8080`. Both sides are now reduced to a protocol + host address +
  port binding and compared per address family, and neither of those is a finding
  any more.

  The answer is three-valued, because two of the cases genuinely cannot be
  decided from what an offline tool reads: an IPv6 wildcard `[::]` also answers
  IPv4 unless `net.ipv6.bindv6only` says otherwise, and a publish naming no
  `host_ip` gets an IPv6 binding only when the daemon has IPv6 enabled. Those,
  and a `host_ip` left as an unresolved `${VARIABLE}`, are **warnings** whose
  `WhatToDo` names the two commands that settle them — not blockers, and not
  silence. A publish over a protocol the kernel has no socket table for (anything
  but TCP and UDP) gets its own `warning` saying the port was *not checked*.

  `Subject` is now the whole binding (`127.0.0.1:8080/tcp`,
  `[fd00::1]:8080/tcp`); a publish that names no address keeps the previous
  `8080/tcp` form. Each published host port yields at most one finding, so a
  container of this deployment that is also visible as its own `docker-proxy`
  socket is stated once.

- **`witness.proxy_conflict` states a collision only against a TCP publish**
  ([app/witness/frontend.rules.go](app/witness/frontend.rules.go)). The same
  class of error: a QUIC publish on `443/udp` was a blocker against nginx.
  `Proxy.ListenPorts` and `Panel.OwnsPorts` are collected as bare port numbers
  with no protocol and no address, so a non-TCP publish on 80 or 443 is now a
  `warning` that says the front end's listen protocol was not recorded. The
  missing addresses remain a documented limitation of the proxy collector.

### Changed

- [docs/en/10-witness-rules.md](docs/en/10-witness-rules.md),
  [docs/ru/10-witness-rules.md](docs/ru/10-witness-rules.md): both rules' severity
  tables, the three undecidable cases and the new `Subject` format.

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
