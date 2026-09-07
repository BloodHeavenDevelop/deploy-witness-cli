# 8. Report format

## Files

By default the tool writes one directory containing eleven files:

```
audit-<host>-<UTC timestamp>/
├── summary.csv           read this first
├── system.csv
├── updates.csv
├── vulnerabilities.csv
├── ports.csv
├── services.csv
├── witness.csv         the findings
├── evidence.csv          what each finding rests on
├── changes.csv           what deploying will actually do
├── rollback.csv          and how to undo it
└── commands.csv          every command this run executed, or tried to
```

The last five are new in 0.2.0. Four of them belong to the `witness` section;
`commands.csv` belongs to the run itself and is written on every run, whatever
`--sections` said.

**A section that produced no rows still gets a file containing its header row.**
An absent file is indistinguishable from a section that was never run, and the
difference between "nothing is listening" and "we did not look" is the whole
value of an audit. `commands.csv` follows the same rule for the same reason: "this
audit ran no commands at all" should be a visible claim, not a missing file.

With `--stdout` the same tables are written to one stream, each preceded by a
`# <name>` line and separated by a blank line. Spreadsheets and `csvkit` both
read this; a single flat table cannot hold eleven different column sets.

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

The index. One row per section, preceded by a `report` row identifying the run.

| Column | Contents |
|---|---|
| `Section` | `report`, or the section name |
| `Status` | `ok`, `partial`, `skipped` or `failed` |
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
| `skipped` | It was not selected |
| `failed` | It produced nothing usable |

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

In `summary.csv` the `witness` row reuses the two counters: `Critical` holds the
blocker count and `High` the warning count, so a reader scanning the index sees
the blockers without opening the section.

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
| `Captured at` | RFC 3339 UTC |

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
| `container` | One per service (created, or replaced — naming what it replaces), plus one per non-external network the manifest declares |
| `command` | An image that has to be pulled, with the registry it comes from; or a service that is built locally, with its build context |
| `firewall-port` | One per published host port, with how far it will be reachable — a port published without a host IP is on every interface, which is the part people do not expect |
| `file` | Every bind mount (with read/write or read only) and every named volume |
| `disk-space` | Space available on the filesystem holding the container store, and how many images still have to be pulled |

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
| `Available` | Whether the thing exists **right now** |
| `Detail` | What it is, or precisely what is missing |

| Kind | What it checks |
|---|---|
| `image-tag` | Whether the digest of each currently running image is recorded on this host. A tag is not enough: the tag is what moved |
| `volume-backup` | Whether a backup exists, and whether it is recent — a stale one would return the data to a state older than anyone expects |
| `proxy-config` | Always `false`: this audit copies nobody's nginx configuration anywhere, and a proxy that fails to start takes every site on the host down, not only the new one |
| `snapshot` | Always `false`: whether a hypervisor or provider snapshot exists cannot be seen from inside the machine, and saying so beats omitting the line |

`witness.no_rollback_plan` is raised from this table when any row is
unavailable.

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

| Outcome | Meaning |
|---|---|
| `ok` | Exit 0, or one of the non-zero codes that means success for that tool |
| `failed` | The command ran and failed |
| `timeout` | It exceeded `--timeout` and was killed |
| `missing` | The binary is not installed on this host. Normal, and not a failure — it is how the tool reports "this host does not use that tool" |
| `refused` | The command is **not on the published allowlist** and was never launched |

**A `refused` row is a defect in `deploy-witness`, never a property of the host.**
It means a collector asked for something the published list does not cover. It is
printed rather than hidden precisely because it would be the most important line
in the file: it is also logged at error level, and it does not change the exit
code. Compare this file against `deploy-witness --commands` — the two agreeing is
what turns "it only reads" from a claim into something you can check. See
[09 — Command allowlist and journal](09-command-allowlist.md).

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
| `upload` | The shared `bloodheaven.audit.v1` contract, rendered as protojson: `findings` with their evidence, `collectors` (the section outcomes), `changes`, `rollback`, `command_journal`, plus `level`, `server_fingerprint`, `server_hostname`, `generated_at`, `stale_after` and `producer` | **Yes** — these are the exact bytes `--upload` sends |
| `audit` | Everything that stays local: the host inventory, the pending updates, the CVE list, the parsed manifest, the observed capabilities, and the same findings in this tool's own shape | No |

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
  `command — outcome (duration)` lines.
- **The enums go out as names** (`SEVERITY_BLOCKER`, `CATEGORY_CONFLICT`,
  `COLLECTOR_STATUS_PARTIAL`), which is what the receiving service parses.
  `partial` maps to `PARTIAL` and not to `OK`: it first went out as `OK`, and the
  receiving service duly stored a run that had degraded on an unprivileged host as
  a complete audit of that machine.
- **The package inventory, the pending updates and the CVE list are not in
  `upload`.** The contract is a findings document, and sending them would be
  volunteering a full software inventory of somebody's production host to a
  service that did not ask for one.

`report.json` is written `0600` in a `0750` directory, like the CSV files, and
indented — a report a client is expected to inspect before uploading has to be
inspectable without a formatter. With `--format json --stdout` the same document
goes to stdout instead.
