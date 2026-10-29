# 8. Report format

## Files

By default the tool writes one directory containing fifteen files:

```
audit-<host>-<UTC timestamp>/
├── summary.csv           read this first
├── system.csv
├── updates.csv
├── vulnerabilities.csv
├── ports.csv
├── services.csv
├── witness.csv         the findings
├── rules.csv             one outcome per rule, finding or not
├── plan.csv              the exact Compose run the preflight checked
├── provenance.csv        build, rules, plan, server, engine, timeline, completeness
├── evidence.csv          what each finding rests on
├── changes.csv           what deploying will actually do
├── rollback.csv          and how to undo it
├── commands.csv          every command this run executed, or tried to
└── network.csv           every network path, used or not, and who it contacted
```

The last five are new in 0.2.0. Four of them belong to the `witness` section;
`commands.csv` belongs to the run itself and is written on every run, whatever
`--sections` said. So does `network.csv`, added in the release after 1.2.0.
`rules.csv` and `plan.csv`, added in the release after 1.4.0, belong to `witness`;
`provenance.csv`, added in the same release, to the run (it is written in a host
audit too).

**A section that produced no rows still gets a file containing its header row.**
An absent file is indistinguishable from a section that was never run, and the
difference between "nothing is listening" and "we did not look" is the whole
value of an audit. `commands.csv` follows the same rule for the same reason: "this
audit ran no commands at all" should be a visible claim, not a missing file.

With `--stdout` the same tables are written to one stream, each preceded by a
`# <name>` line and separated by a blank line. Spreadsheets and `csvkit` both
read this; a single flat table cannot hold fifteen different column sets.

With `--format json` one `report.json` is written *instead of* the CSV files. See
[report.json](#reportjson) below.

Encoding is UTF-8, the separator is a comma, and quoting follows RFC 4180.
Timestamps are UTC. Most of them are formatted `YYYY-MM-DD HH:MM:SS UTC`; the two
exceptions are noted where they occur — `commands.csv` omits the literal `UTC`
suffix, and evidence capture times are RFC 3339 (`2026-08-17T09:39:13Z`).

**Credentials are masked before anything is written.** Every free-form field —
cron lines, process command lines, notes, evidence output, manifest label values —
goes through `app/redact` on its way out, and a masked value is replaced with the
visible marker `***redacted***` rather than deleted: `password=***redacted***`
tells the reader something was there, and silently dropping it would make the
evidence a lie. The number of fields changed is logged, because a sweep that fires
on a normal host means either a collector is reading something it should not or
the patterns are too eager, and both are worth knowing.

**Columns are append-only.** Consumers read by position as often as by header, so
new columns are added at the end and existing ones never move.

## summary.csv

The index. One row per section, preceded by three rows about the run itself:

- `report` — identifies the run, and its note opens with the mode: `host audit:` or
  `Compose preflight:` (see [04 — Modes](04-cli-reference.md#modes)).
- `network` — whether the run used the network: `offline: --online, --egress and
  --upload were not given; no network path was used (network.csv)`, or one entry per
  enabled path with its contact count (`--online osv-api: 3 contact(s)`) or, for an
  upload, its recipient.
- `preflight` — whether a planned deployment was compared with this host. The note
  opens with the stable mode identifier, `host-audit:` or `compose-preflight:`, so a
  script can match on it.

| Mode | `preflight` status | Meaning |
|---|---|---|
| host audit | `not-applicable` | No `--compose`: a comparison is outside the scope of this run — not a gap, and not a preflight result |
| Compose preflight | `ok` | The Compose file was compared with the host |
| Compose preflight | `partial` | Compared, but part of the comparison could not be made — the `witness` row says what |
| Compose preflight | `failed` | The comparison did not complete — this is not a preflight result |

The status says whether the comparison **ran**; what it **concluded** is a second
statement, at the end of the note: `result: N rule(s) found a problem, N could not
decide (unknown), N need a manual check, N found no problem, N not applicable
(rules.csv)`. The two are never folded into each other — an `ok` comparison whose
rules could not decide is not a clean preflight, and a `partial` one that proved a
blocker still proved it. See [10 — Outcomes](10-witness-rules.md#outcomes-problem-no-problem-insufficient-data).

The `preflight` row is never `ok` in a host audit. A host audit also carries a
`witness` row, `not-applicable`, with a note opening `host-audit: not applicable` —
the same row is in `report.json` (`audit.sections`). Neither counts against the
report's completeness: a host audit whose sections are all `ok` has no `skipped`,
`partial` or `failed` row, and the upload leaves the `witness` collector out (see
[report.json](#reportjson), the `upload` half).

| Column | Contents |
|---|---|
| `Section` | `report`, `network`, `preflight`, or the section name |
| `Status` | `ok`, `partial`, `skipped`, `failed` or `not-applicable` |
| `Records` | Rows the section produced |
| `Critical` | Critical findings (vulnerabilities only) |
| `High` | High findings (vulnerabilities only) |
| `Duration` | How long the section took |
| `Notes` | Everything the section could not do, joined by `; ` |

Statuses:

| Status | Meaning |
|---|---|
| `ok` | The section ran to completion |
| `partial` | It produced rows but hit at least one problem — read `Notes` |
| `skipped` | It belonged to this run but did not run, and the note says why. A gap. A section that was not selected has no row |
| `failed` | It produced nothing usable |
| `not-applicable` | It is outside the scope of this kind of run — `witness` (and `preflight`) in a host audit. Not a gap: nothing was expected of it |

`partial` is load-bearing. A section that collected some rows and then hit an
error is never reported as `ok`, or the reader takes a truncated table for a
complete one.

## system.csv

| Column | Contents |
|---|---|
| `Category` | `host`, `os`, `kernel`, `hardware`, `storage`, `network`, `time`, `packages`, `accounts`, `ssh`, `hardening`, `updates` |
| `Key` | The fact name, e.g. `hostname`, `kernel.kptr_restrict`, or a mount point |
| `Value` | The value as read |
| `Source` | Exactly where it came from, e.g. `/proc/meminfo`, `sshd -T` |

The `Source` column exists so any row can be independently verified on the host.

## updates.csv

| Column | Contents |
|---|---|
| `Package` | Package name |
| `Installed` | Currently installed version |
| `Available` | Version waiting in the repositories |
| `Arch` | Architecture, where the manager reports one |
| `Repository` | Origin, e.g. `Debian-Security:12/stable`, `extra` |
| `Security` | `true` when the update comes from a security channel |
| `Severity` | Vendor severity where published, otherwise `unknown` |
| `Advisory` | Advisory id where published |
| `Source` | The command the row came from |

## vulnerabilities.csv

Sorted worst-first.

| Column | Contents |
|---|---|
| `Package` | Affected installed package |
| `Installed` | Installed version |
| `Fixed in` | Version that fixes it, where the advisory names one |
| `Severity` | `critical`, `high`, `medium`, `low`, `none` or `unknown` |
| `Score` | Supporting CVSS base score, e.g. `9.8 (CVSS_V3)` |
| `Id` | Primary identifier, a CVE where one exists |
| `Aliases` | Every identifier the feeds gave it |
| `Summary` | One-line description |
| `Ecosystem` | The OSV ecosystem it was matched in |
| `Source` | `distro-metadata`, `offline-db`, `osv-api`, or several joined by `+` |
| `Reference` | Advisory URL |

A `Source` naming two feeds means both found it independently — stronger evidence
than a single-feed row.

## ports.csv

Sorted by port.

| Column | Contents |
|---|---|
| `Protocol` | `tcp`, `tcp6`, `udp` or `udp6` |
| `Address` | Bound address |
| `Port` | Bound port |
| `Exposure` | `loopback`, `interface` or `all-interfaces` |
| `State` | `LISTEN` for TCP, `OPEN` for unconnected UDP |
| `PID` | Owning process, `0` when it could not be attributed |
| `Process` | Process name |
| `User` | Owning user, falling back to the numeric UID |
| `Command` | Command line, truncated at 200 characters |
| `V6 only` | For a socket on the IPv6 wildcard: `yes` (IPv6 only, `ss` shows `[::]:port`), `no` (dual-stack, `ss` shows `*:port`, also answers IPv4), empty when not established (appended in the release after 1.4.0) |

Sort by `Exposure` to get the network-facing surface first. A `PID` of `0` means
the process could not be read, not that no process owns the socket — run as root
for full attribution.

## services.csv

Sorted by name.

| Column | Contents |
|---|---|
| `Name` | Unit name |
| `Description` | Unit description |
| `Load` | systemd load state, e.g. `loaded`, `not-found` |
| `Active` | `active`, `inactive`, `failed` |
| `Sub` | Sub-state, e.g. `running`, `exited`, `dead` |
| `Enabled` | Boot enablement: `enabled`, `disabled`, `static`, `masked` |
| `Main PID` | Main process, `0` when the unit has none |
| `User` | User the unit runs as |
| `Active since` | Activation time, UTC |
| `Manager` | `systemd`, `openrc`, `sysv` or `process-table` |

`Active` and `Enabled` come from different commands and answer different
questions: what is running now, and what will run after a reboot. A service that
is `active` and `disabled` disappears on the next boot.

## witness.csv

One row per finding, sorted worst first, then by rule, then by the rule's own
ordering, then by subject — so two runs of the same audit produce the same file.

| Column | Contents |
|---|---|
| `Code` | The stable finding identifier, e.g. `witness.port_conflict`. This is what an integration matches on; the full catalogue is [10 — Witness rules](10-witness-rules.md) |
| `Collector` | Which rule produced it, e.g. `port-conflict`, `certificate` |
| `Category` | `conflict`, `resource`, `security`, `expiry` or `missing` — what kind of trouble, not how bad |
| `Severity` | `blocker`, `warning` or `info` |
| `Subject` | What the finding is about: a port, a service name, a path, a domain |
| `Title` | What is wrong, in one line |
| `Description` | On what basis, with the observed numbers in it |
| `Why it matters` | What breaks if it is ignored |
| `What to do` | The next action |
| `Confidence` | `high`, `medium` or `low` |
| `Evidence` | `N in evidence.csv, first: <command>`, or `none` |
| `Outcome` | `problem`, `no-problem`, `unknown`, `manual-check` or `not-applicable` — what the finding concludes, a separate axis from `Severity` (appended in the release after 1.4.0; see [10 — Outcomes](10-witness-rules.md#outcomes-problem-no-problem-insufficient-data)) |

Three severities, not the six of the CVE scale used in `vulnerabilities.csv`. A
vulnerability feed grades how bad a flaw is in the abstract; a witness finding
answers a different question — whether the person reading it has to stop:

| Severity | Meaning |
|---|---|
| `blocker` | Already broken, or already exploitable. Deliberately rare: a false blocker stops a deployment that would have been fine, and the next one goes out with the checks switched off |
| `warning` | A real problem that is not breaking anything yet |
| `info` | Worth knowing, nothing is wrong — including "this check could not run", which is reported rather than omitted |

`Confidence` is `high` only for a direct observation. Anything inferred from a
fingerprint, an index or a parse of free-form text is at most `medium`.

`Severity` and `Outcome` are tied by two invariants the engine enforces: only a
`problem` can be a `blocker`, and a `no-problem` or `not-applicable` finding is
`info`. A finding that breaks either is downgraded and the downgrade is counted in
the section's notes as a bug in `deploy-witness`.

In `summary.csv` the `witness` row reuses the two counters: `Critical` holds the
blocker count and `High` the warning count **of proven problems only** — a finding
whose outcome is `unknown` or `manual-check` is never counted, so a run that could
not look does not read as one that found. The row's notes end with
`rule outcomes: 25 rules — N problem (codes); N unknown (codes); …`.

## rules.csv

One row per witness rule, **whether or not it published a finding**. "No problem"
and "not applicable" are lines a reader can point at rather than absences they have
to trust.

| Column | Contents |
|---|---|
| `Code` | The rule's finding code |
| `Rule` | The rule's short name — the `Collector` of its findings |
| `Outcome` | `problem`, `no-problem`, `unknown`, `manual-check` or `not-applicable` — the rule's single result on this run |
| `Findings` | How many findings it published |
| `Reason` | Why it ended there, in one sentence: what was checked, or what was missing |
| `Requires` | The data the rule cannot decide without |

A rule's outcome is the most pressing one among its findings and its own verdict,
in the order `problem` → `unknown` → `manual-check` → `no-problem` →
`not-applicable`. A rule that ends `unknown` or `manual-check` always has a finding
saying so in `witness.csv`, so the gap travels with the upload too.

## plan.csv

The exact run a Compose preflight checked, as `Key`,`Value` rows — a list as one row
per item, so the order of the Compose files stays visible. Header only in a host
audit. See [04 — The planned run](04-cli-reference.md#the-planned-run).

| Key | Value |
|---|---|
| `file` | A Compose file, in merge order |
| `project-directory` | Where `.env` is read and relative paths resolve |
| `project-name`, `project-name-source` | The name Compose uses, and where it came from: `--project-name`, `COMPOSE_PROJECT_NAME`, `name: in the Compose file`, `the project directory` |
| `env-file`, `profile`, `service` | The plan's `--env-file`, `--profile` and `--compose-service` values |
| `starts` | What the plan starts: the named services and their dependencies, or every service of the active profiles |
| `resolver`, `resolver-version` | `docker compose config` and its version, or `built-in parser` |
| `environment` | Names of the `COMPOSE_*`, `DOCKER_HOST`, `DOCKER_CONTEXT` variables present — never their values |
| `engine-context`, `engine-endpoint`, `engine-local` | The docker context the run would use, its endpoint, and whether it is this host's |
| `engine-id`, `engine-name`, `engine-version` | The engine that answered, from `docker info` |
| `note` | What the resolution could not reproduce |

The `witness` notes carry the same in one line (`plan: project shop (from
--project-name), 2 Compose file(s), …`) for a person reading `summary.csv`. The
upload carries the plan as a field of its own (`plan`, see
[report.json](#reportjson)); the note is no longer its only carrier.

## provenance.csv

What every conclusion of the report rests on, as `Key`,`Value` rows. Written on every
run; in a host audit the plan rows are empty.

| Key | Value |
|---|---|
| `tool`, `rules-version` | The build, and the rule set (`witness.RulesVersion`), which changes whenever a rule's logic does — independently of the tool version |
| `host`, `server-fingerprint` | The host name, and the salted hash of `/etc/machine-id` the upload carries |
| `engine`, `engine-id`, `compose` | The engine and its `docker info` ID, the Compose implementation |
| `engine-fingerprint` | The salted hash of the engine ID, computed like `server-fingerprint` — the only form of the engine's identity the upload carries |
| `plan-source`, `plan-digest` | The plan's resolver and its digest — what `--recheck` compares |
| `started-at`, `plan-resolved-at`, `observed-from`, `observed-until`, `compared-at`, `finished-at` | The run's timeline, RFC 3339 UTC |
| `clock-synchronized` | `yes`, `no` or `unknown` (timedatectl `NTPSynchronized`) |
| `engine-clock-skew` | The engine's clock minus this host's, measured when `docker info` answered |
| `completeness` | `N of M sources read in full; partial: …; failed: …` |
| `recheck-after` | `finished-at` + 1 h: past it, `--recheck` (or a new audit) before deploying — see [04](04-cli-reference.md#recheck-before-deploying) |
| `observation` | One row per source, in the order the host was read: `<source>: <state> at <time> — <what was read and what it answered>` — see [Observations](#observations) |
| `time-check` | `consistent`, or one row per inconsistency: the clock going backwards, an observation or evidence timed outside the run, an unsynchronised clock, an engine clock more than 5 s off, observations more than 10 min apart |

The `witness` notes carry it in one line (`provenance: deploy-witness 1.5.0, rules
2; engine docker 29.7.2 (id …); …`) and each time inconsistency as a `time:` note,
for a person reading `summary.csv`. The upload carries it as a field of its own
(`provenance`, with the observations); in the upload the engine ID in those notes is
replaced by its fingerprint.

### Observations

An observation is one source the run read: what was checked, the values it
answered, the moment it was read on this host (RFC 3339 UTC, inside
`started-at` … `finished-at`) and how completely (`complete`, `partial`, `failed`,
`not-collected`). Since 1.7.0 **every section** records them, in a host audit as in
a preflight, so a check that finished without a finding carries what proves the
"nothing found" — a list of commands that exited 0 is not that proof; a count is.

| Source | Recorded | Note |
|---|---|---|
| `<section>` — `system`, `updates`, `vulnerabilities`, `ports`, `services`, `witness` | Once per section that ran, when its collector returned; state from the section's status | What it read and the counts it got — e.g. `pacman: 0 pending update(s), 0 from a security channel`, `/proc/net/{tcp,tcp6,udp,udp6}: 47 listening socket(s); by exposure: …`, `1537 installed package(s) via pacman checked, offline (no --online): 0 advisory row(s)` — followed by the section's notes |
| `system:<category>` | One per fact category (`os`, `kernel`, `ssh`, `hardening`, `accounts`, …) | The keys read and their files/commands. Posture categories (`os`, `kernel`, `time`, `ssh`, `hardening`, `packages`) quote their values; the others name their keys and quote counts only (`total=49`, `uid-0: 1 entr(ies)`) — addresses, account names, hardware and `/etc/machine-id` stay in `system.csv` |
| `<section>:<program>` | One per program the section ran, timed at its latest launch | Every invocation with outcome, exit code and duration. All `ok` → `complete`; not installed → `not-collected`; none `ok` → `failed`; mixed → `partial` |
| `containers`, `networks`, `network-subnets`, `volumes`, `images`, `sockets`, `arch`, `memory`, `filesystems`, `proxy`, `bind-sources` | Preflight only: the host sources the witness section compared, as before | How each was read |

The receiver matches an observation to its collector by the part of `source`
before the colon. A note is cut at 600 characters, and says so; it is swept for
credentials like every other free-form field. Package names, versions, CVE
identifiers, port numbers and unit names are never in a note — counts are the
values that prove a result, and the inventory stays in the CSV.

`observed-from` … `observed-until` spans the sources a conclusion was drawn from:
in a preflight the host sources the rules compared (the 10-minute time check is
about them, so a slow `--online` section before them does not trip it), in a host
audit every observation. `completeness` counts every observation.

## evidence.csv

Every piece of evidence behind every finding, one row each. It is a file of its
own rather than a cell in `witness.csv` because a finding may have several
pieces, each with a multi-line capture, and the whole promise of the section is
that the reader can check them.

| Column | Contents |
|---|---|
| `Code` | The finding this supports — join on it |
| `Subject` | The finding's subject, so a code with several rows can be told apart |
| `Command` | What to run to see the same thing: a command from the published allowlist, or a path on disk, or the manifest and the service (`docker-compose.yml (service db)`) |
| `Output` | What was observed, rendered compactly from the parsed values |
| `Truncated` | `true` when the capture was cut at 1500 characters. A shortened capture that does not admit it invites the reader to conclude too much from it |
| `Captured at` | RFC 3339 UTC: **when what `Output` shows was observed** — the moment its source was read on the host (`provenance.csv`, `observation` rows), or, for the manifest, the moment the plan was resolved. Not the moment the rules compared (that is `compared-at`). Between the run's `started-at` and `finished-at`; one that is not is a time check in `provenance.csv` (since the release after 1.4.0 — before it, every row carried the comparison time) |
| `Origin` | `plan` (the resolved Compose model), `host` (the machine and its engine) or `rule` (what a rule established about the run, such as a check it could not make). The evidence is the observation; the finding's `Description` is the interpretation (appended in the release after 1.4.0) |
| `Source` | The observation source the evidence came from — `containers`, `volumes`, `networks`, `network-subnets`, `images`, `sockets`, `arch`, `memory`, `filesystems`, `proxy` — or empty (appended in the release after 1.4.0) |

**A finding with no evidence is never published.** The engine discards it and
counts the discard in the section's notes, as a bug in `deploy-witness` rather than
a property of the host.

## changes.csv

"What the deployment will actually do" — the section somebody shows their own
client when asked what was changed on the server. Deliberately specific: full
paths, exact ports, named containers. A change list that says "configuration will
be updated" is worth nothing to the person who has to answer for it.

| Column | Contents |
|---|---|
| `Kind` | `container`, `command`, `firewall-port`, `file` or `disk-space` |
| `Target` | The thing that changes: a container name, an image reference, `8080/tcp`, a host path, a mount point |
| `Detail` | What happens to it, e.g. `replaced (currently running, image nginx:1.25) with nginx:latest` |

| Kind | Rows it produces |
|---|---|
| `container` | One per service, plus one per non-external network the manifest declares. A service's row says one of: `created from <image>`; `replaced (currently <state>, image <image>) with <image> — recreated: its configuration changed (config hash …)` or `kept: its configuration is unchanged` — only for a container of **this** deployment, decided as Compose decides, by the configuration hash (`--force-recreate`/`--no-recreate` respected); `taken over: it carries this project's name but was deployed from <dir>` — another checkout (`witness.project_ownership`); `not created: a container named <name> already exists … and does not belong to this deployment` — another project's container, or one created by hand (running or not), on which `docker compose up` fails (`witness.container_name_conflict`); `created from <image>, but it cannot start: host port <port> is already held` (`witness.port_conflict`); or, with the engine unreachable, `created … unless a container named <name> already exists — … could not be checked` |
| `command` | An image that has to be pulled, with the registry it comes from; or a service that is built locally, with its build context |
| `firewall-port` | One per published host port, with how far it will be reachable — a port published without a host IP is on every interface, which is the part people do not expect. When something else already holds the binding the row says `not opened: … already held by …`, and when that could not be decided it adds `if the binding is free, which could not be established` — the same matching as `witness.port_conflict`. Without the `ports` section it adds `if the binding is free, which was not checked`. A host range to one container port is one row, `8000-8010/tcp`: `one port of 8000-8010, the first the engine finds free … (N free, N held, N undecided)`, or `not opened` when every port is held. A publish with no host port is `ephemeral/<protocol>`. A `network_mode: host` service gets `bound directly by <service> on the host network` per declared port |
| `file` | Every bind mount (with read/write or read only) and every named volume |
| `disk-space` | Space available on the filesystem holding the container store, and how many images still have to be pulled |
| `file` (bind) | The resolved source path: `bind-mounted into <service> at <target> (read/write\|read only)`, then what the host shows (`directory, mode 0755, owner 0:0`, or `it does not exist, so the engine creates it as an empty directory owned by root`), and always `access for the container user (<user>) not verified — ACLs, user namespaces and SELinux are not read`, plus `options not evaluated: …` when the plan sets any |
| `file` (volume) | `volume <engine name>`: `created empty by Compose`, `reused: it exists and was created by this project, with its data`, `reused with its data although it was not created by Compose for this project`, `external, exists`, or `external and missing, so docker compose up fails` — then where it is mounted. A `network <engine name>` row (`container`) says `created`, `reused …`, `joined (external, exists)` or `not joined …` the same way |
| `container` (existing) | One per existing container the plan affects without naming it: an orphan of the project (`left running …` or `removed (--remove-orphans)`), another checkout's container (`taken over …`), this directory under another project name or a one-off run (`left as it is …`) |

The disk row is deliberately incomplete and says so: how much the missing images
need cannot be known without contacting a registry, which this audit does not do.

`model.ChangeItem` also names a `dns-record` kind, which nothing produces yet.
It is in the vocabulary rather than in the output.

## rollback.csv

The answer to "and how do we undo it". `Available: false` is the interesting
value, and the reason this is not merely a list of instructions.

| Column | Contents |
|---|---|
| `Kind` | `image-tag`, `volume-backup`, `proxy-config` or `snapshot` |
| `Available` | `true` — established to exist right now (or nothing is needed); `false` — established **not** to exist on this host; `unknown` — **unable to verify** from inside the host. `unknown` is never rendered as `false`: what the audit cannot see is not evidence of absence |
| `Detail` | What it is, or precisely what is missing; an `unknown` row opens with `unable to verify:` |

| Kind | What it checks |
|---|---|
| `image-tag` | Whether the digest of each currently running image is recorded on this host. A tag is not enough: the tag is what moved |
| `volume-backup` | Whether a backup exists, and whether it is recent — a stale one would return the data to a state older than anyone expects |
| `proxy-config` | Always `unknown`: whether a copy of the web server configuration is kept outside the host cannot be seen from inside it, and a proxy that fails to start takes every site on the host down, not only the new one |
| `snapshot` | Always `unknown`: whether a hypervisor or provider snapshot exists cannot be seen from inside the machine, and saying so beats omitting the line — or calling it missing |

In `report.json`, `audit.rollback[]` carries `state` (`available`,
`unavailable`, `unable-to-verify`) next to the boolean `available`, which is `true`
only for `available`. The upload's `rollback[]` has the boolean alone — the contract
has no third value — so an unverified item goes out as `available: false` with its
detail opening `unable to verify:`.

`witness.no_rollback_plan` is raised from this table when any row is `false` or
`unknown` — see [10](10-witness-rules.md#witnessno_rollback_plan) for how the two
differ in the finding.

## commands.csv

The journal: every command this run executed, or tried to, in order. It is not a
section — it is what the run *did*, not something it found — and it is written on
every run.

| Column | Contents |
|---|---|
| `Command` | The full argv, joined for reading. Nothing goes through a shell, so this is a description rather than something to paste back |
| `Started at` | `YYYY-MM-DD HH:MM:SS`, UTC (no literal suffix) |
| `Duration` | Rounded to the millisecond, e.g. `36ms`, `1.204s` |
| `Exit code` | The process exit code, or `-1` when nothing was launched |
| `Outcome` | `ok`, `failed`, `timeout`, `missing` or `refused` |
| `Network` | The flag that permitted a command reaching the network itself (`--online` for `debsecan` and `arch-audit`), empty for every command that works from data on this host. Appended after 1.2.0 |

| Outcome | Meaning |
|---|---|
| `ok` | Exit 0, or one of the non-zero codes that means success for that tool |
| `failed` | The command ran and failed |
| `timeout` | It exceeded `--timeout` and was killed |
| `missing` | The binary is not installed on this host. Normal, and not a failure — it is how the tool reports "this host does not use that tool" |
| `refused` | The command is **not on the published allowlist** — or it reaches the network and the run was not given the flag for it — and was never launched |

**A `refused` row is a defect in `deploy-witness`, never a property of the host.**
It means a collector asked for something the published list does not cover. It is
printed rather than hidden precisely because it would be the most important line
in the file: it is also logged at error level, and it does not change the exit
code. Compare this file against `deploy-witness --commands` — the two agreeing is
what turns "it only reads" from a claim into something you can check. See
[09 — Command allowlist and journal](09-command-allowlist.md).

## network.csv

One row per network path, **whether it was enabled or not**, so that "this run was
offline" is a line in a file rather than the absence of one. It is not a section and
it is written on every run. The paths and what each sends are described in
[04 — CLI reference](04-cli-reference.md#network-behaviour).

| Column | Contents |
|---|---|
| `Path` | `osv-api`, `distro-feeds`, `registry-egress` or `upload` |
| `Flag` | The flag that enables it: `--online`, `--online`, `--egress`, `--upload` |
| `Enabled` | `true` when that flag was typed on this run |
| `Recipient` | Who receives the traffic: the OSV URL, the distribution trackers, the registries actually dialled as `host:port`, or the upload endpoint — with `(via proxy host:port)` when the environment routes it through one. Empty when the path was not enabled |
| `Sends` | What goes over the connection |
| `Contacts` | Requests, connects or tool runs this run actually made on the path. Always `0` for `upload`, which happens after the report is written — its outcome is on stdout and in the exit code |
| `Note` | Why a path was unused, an ignored `AUDIT_*` variable, the tools that ran |

On a default run all four rows have `Enabled=false` and `Contacts=0`. `network.csv`
is local only: it is in the `audit` half of `report.json`, never in `upload`.

## report.json

With `--format json` the tool writes one `report.json` with two named halves, and
the naming is the point:

```json
{
  "schemaVersion": "1.0",
  "upload": { "schema_version": "1.0", "level": 2, "server_fingerprint": "…", "…": "…" },
  "audit":  { "generatedAt": "…", "system": [], "updates": [], "…": "…" }
}
```

| Key | Contents | Leaves the machine? |
|---|---|---|
| `schemaVersion` | The contract version of the `upload` half. A receiver checks it first, so an agent built months ago is told its report is not understood rather than having it half-read | — |
| `upload` | The shared `bloodheaven.audit.v1` contract, rendered as protojson: `findings` with their evidence and `outcome`, `collectors` (the section outcomes), `changes`, `rollback`, `command_journal`, `rule_results` (one per rule), `plan` (preflight only), `provenance` (with `observations`), plus `level`, `server_fingerprint`, `server_hostname`, `generated_at`, `stale_after` and `producer` | **Yes** — these are the exact bytes `--upload` sends |
| `audit` | Everything that stays local: the run's `mode` (`host-audit` or `compose-preflight`), the host inventory, the pending updates, the CVE list, the parsed manifest, the observed capabilities (with `observations`: how completely each source — containers, volumes, sockets, memory… — was read), the network record (`network`, as in `network.csv`), the same findings in this tool's own shape (each with its `outcome`, evidence with `origin` and `source`), `rules`, as in `rules.csv`, `plan`, as in `plan.csv`, and `provenance`, as in `provenance.csv` | No |

A client can read the file, see which half would leave their machine, and diff it
against what actually arrives. That is a good deal more convincing than a promise
about it — and the two cannot drift, because the uploader sends the same bytes
this file was written from rather than building a second document.

Details worth knowing:

- **`server_fingerprint` is a salted SHA-256 of `/etc/machine-id`, never the id
  itself.** The receiver needs to recognise the same host across two uploads; it
  does not need an identifier that works as a key into anything else about the
  machine. A bare hash of a 32-hex-character id is a rainbow-table lookup away
  from the original, so the digest is salted to be specific to this purpose. When
  `/etc/machine-id` is unreadable the field is empty rather than substituted with
  something weaker.
- **`level` is always `2`** — the on-server witness. Levels 0 and 1 are the
  domain-side checks and belong to the `witness` service.
- **`stale_after` is `generated_at` + 7 days.** Server state drifts; a week later
  the picture may not hold, and the reader is told so rather than left to guess.
- **`command_journal` carries the whole journal**, refusals included, as
  `command — outcome (duration)` lines. That means the arguments travel too: the
  image names given to `docker image inspect`, docker network names, the systemd
  unit names, the user named in `crontab -l -u`.
- **`server_hostname` is the host name, and evidence quotes paths verbatim**,
  including the absolute path of the `--compose` file. Section notes
  (`collectors[].note`) are sent as written.
- **The enums go out as names** (`SEVERITY_BLOCKER`, `CATEGORY_CONFLICT`,
  `COLLECTOR_STATUS_PARTIAL`), which is what the receiving service parses.
  `partial` maps to `PARTIAL` and not to `OK`: it first went out as `OK`, and the
  receiving service duly stored a run that had degraded on an unprivileged host as
  a complete audit of that machine.
- **The contract has no mode field and no "not applicable" status.** Every
  `CollectorStatus` other than `OK` counts against a run's completeness on the
  receiving side, so a section outside the run's scope is not sent at all: a host
  audit's upload has **no `witness` collector**, while a Compose preflight always
  has one, carrying the comparison's own status (`OK`, `PARTIAL`, `FAILED`). That
  presence is how the receiver tells the two modes apart. The `host-audit: not
  applicable` note stays in `audit.sections` of `report.json`; carrying the mode or a
  `NOT_APPLICABLE` status in the contract itself needs a change in the `contracts`
  repository.
- **Every finding states its `outcome`, and every rule has a `rule_results` entry**
  (contracts v0.15.0): `OUTCOME_PROBLEM`, `OUTCOME_NO_PROBLEM`, `OUTCOME_UNKNOWN`,
  `OUTCOME_MANUAL_CHECK` or `OUTCOME_NOT_APPLICABLE` — the five values of
  `rules.csv`. Only `OUTCOME_PROBLEM` is a detected problem; an unknown is a
  question the run could not settle. A finding that states no outcome goes out as
  `OUTCOME_UNSPECIFIED` and is read by its severity, never guessed into a problem.
  The `witness` collector's `note` still ends with `rule outcomes: 25 rules — N
  problem (codes); N unknown (codes); …`, and an undecided finding's title still
  says so — for a person reading them, no longer as the only carrier.
- **`plan` is the launch plan the preflight checked**, as in `plan.csv`, with two
  things left out: the engine's endpoint (`engine_context` and `engine_local` name
  the engine instead) and the per-service configuration hashes. A host audit
  checked no plan and leaves `plan` unset. No variable value is in it — the plan
  carries names only, and env files appear as paths and SHA-256 digests.
- **`provenance` is `provenance.csv` with the observations**, each with its
  `OBSERVATION_STATE_*` and time — every section's (see
  [Observations](#observations)), so a host audit carries them too. Host name and server fingerprint are not repeated
  there (they are `server_hostname`/`server_fingerprint`).
- **The engine is named by `engine_fingerprint`, never by its ID.** Like
  `server_fingerprint` it is a salted SHA-256 — of the `docker info` ID, the same
  scheme and salt. The rules write the raw ID into evidence to tell two engines'
  answers apart, and the provenance note names it; before the upload is rendered
  every string of the document is swept and the raw ID replaced by the
  fingerprint, so the receiver can still match those lines against
  `engine_fingerprint`. The local half (`audit`, the CSV files) keeps the raw ID
  beside the fingerprint, for matching against `docker info` by hand.
- **`schema_version` stays `1.0`.** The new fields are additive: the receiver
  decodes with unknown fields discarded and checks the version for equality, so an
  older receiver reads a new report as before and a newer one reads an older
  report by its severities.
- **The package inventory, the pending updates and the CVE list are not in
  `upload`.** The contract is a findings document, and sending them would be
  volunteering a full software inventory of somebody's production host to a
  service that did not ask for one.

`report.json` is written `0600` in a `0750` directory, like the CSV files, and
indented — a report a client is expected to inspect before uploading has to be
inspectable without a formatter. With `--format json --stdout` the same document
goes to stdout instead.
