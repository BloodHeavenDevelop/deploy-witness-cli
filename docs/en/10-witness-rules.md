# 10. Witness rules

The `witness` section compares one `docker-compose.yml` against one host and
states every disagreement. This page is the catalogue: 25 rules, 25 finding codes,
what each one is looking at, and what makes it fire.

**The codes are stable identifiers.** They are what an integration matches on, and
what a report from six months ago is compared against, so they do not change with
the wording of a title. Everything else in a finding — the title, the description,
the thresholds — may be reworded to read better; the code will not.

**The section runs only in a Compose preflight** — a run given `--compose`. A run
without it is a host audit: the section is outside its scope, its row is
`not-applicable` with a note opening `host-audit:` (not a gap), and nothing in that
report is a preflight result. A Compose
file that cannot be read or parsed stops the run with exit `2` before any section,
rather than producing an empty finding list. See
[04 — Modes](04-cli-reference.md#modes).

## How a finding is built

Every rule is a pure function of two inputs: the parsed manifest (what is asked
for) and the collected capabilities (what the host offers). No rule observes the
host, and no collector decides anything is wrong. That split is what makes a
finding explainable to the person who has to act on it.

Three invariants hold for every finding here:

- **It carries evidence.** A finding with none is discarded before it reaches any
  output, and the discard is counted in the section's notes as a bug in
  `deploy-witness`. A claim about somebody's production server that cannot be checked
  is worse than silence.
- **A blocker is rare.** It means "this will not work" or "this is already
  exploitable", not "this worries me". A false blocker is the most expensive
  mistake this product can make: it stops a deployment that would have been fine,
  and the next one goes out with the checks switched off.
- **"Not checked" is never rendered as "fine".** A rule whose input was not
  observed ends `unknown` and says so in a finding of its own rather than staying
  quiet — see [Outcomes](#outcomes-problem-no-problem-insufficient-data).

**The evidence is the observation; the description is the interpretation.** Each
piece of evidence says what it observed (`Origin`: the `plan`, the `host`, or a
`rule` about the run itself), from which source, and **when that source was read** —
not when the rules compared. The report's `provenance.csv` ties all of it to one
build, one rule set (`rules-version`, which changes whenever a rule's logic does),
one resolved plan (`plan-digest`), one server and one engine (`engine-id`), with the
run's timeline and its consistency. A report confirms only that plan on that engine
while it is fresh — see [04 — Recheck before deploying](04-cli-reference.md#recheck-before-deploying).

Findings are sorted worst first, then by rule, then by the rule's own ordering,
then by subject, so two runs of the same audit produce the same file.

### The project name, and why it matters

Compose reuses its own containers, networks and volumes on purpose. A collision
with the previous version of the same deployment is information, not a conflict —
so several rules ask whether the thing in the way carries this deployment's own
project label, and downgrade to `info` when it does.

The project name is resolved, not guessed: it is the name **Compose itself resolves
for the planned run** — `--project-name`, then `COMPOSE_PROJECT_NAME`, then a
top-level `name:` in the files, then the project directory, normalised the way
Compose normalises it (lowercased, everything outside `[a-z0-9_-]` dropped). Where it
came from is in `plan.csv` (`project-name-source`). Getting this wrong would turn
every redeployment into a wall of false conflicts with itself, so pass the same
`--project-name` (or the same environment) you deploy with — see
[04 — The planned run](04-cli-reference.md#the-planned-run).

## Outcomes: problem, no problem, insufficient data

A report answers three different questions, and each has its own vocabulary:

| Question | Where | Values |
|---|---|---|
| Did the check **run** to completion? | section `Status` (`summary.csv`) | `ok`, `partial`, `skipped`, `failed`, `not-applicable` |
| What did it **conclude**? | `Outcome` (`witness.csv`, `rules.csv`) | `problem`, `no-problem`, `unknown`, `manual-check`, `not-applicable` |
| How much **attention** does it need? | `Severity` (`witness.csv`) | `blocker`, `warning`, `info` |

The outcomes, as stable identifiers:

| Outcome | Means |
|---|---|
| `problem` | The problem is proven by the evidence attached |
| `no-problem` | The rule had everything it needs and found nothing wrong — or what it found is not a problem (this deployment's own container on its own port) |
| `unknown` | The data the rule needs was not there: an engine that did not answer, a section that was not selected, a file that could not be parsed. **Never counted as a detected problem, and never as a clean result** |
| `manual-check` | The question cannot be settled from inside the host by design — a provider snapshot, a protocol with no socket table, an intent only the owner knows. The finding says what to check by hand |
| `not-applicable` | The plan gives the rule nothing to check — no external volume, no published port. Not a gap |

**Every rule ends in exactly one outcome per run**, published in `rules.csv`
whether or not the rule produced a finding. It is the most pressing outcome among
the rule's findings and its own verdict, in the order `problem` → `unknown` →
`manual-check` → `no-problem` → `not-applicable`. An `unknown` or `manual-check`
that no finding states gets one of its own ("… could not be decided", "… needs a
manual check", `info`, evidence naming the missing source), so what a rule could not
decide reaches `witness.csv` and the upload, not only `rules.csv`.

Two invariants tie severity to outcome, and the engine enforces them rather than
trusting each rule: **only a `problem` can be a `blocker`**, and a `no-problem` or
`not-applicable` finding is **`info`**. An undecided port, volume or network is at
most a `warning`.

**Absence is proven only by a list that was read in full.** Each source of host data
records how completely it was read (`audit.capabilities.observations` in
`report.json`: `complete`, `partial`, `failed`, `not-collected`). A rule that needs
to conclude "it does not exist" from an engine list consults it first: a failed or
partial list proves presence, never absence. A host with no container engine at all
is the one case where an empty list is complete — nothing can exist in an engine
that is not installed.

**A host audit has no rule outcomes.** Without `--compose` there is no plan to
compare, the `witness` section is `not-applicable` (see
[04 — Modes](04-cli-reference.md#modes)), and the missing Compose file is not an
error, a gap or an `unknown`.

### The outcome matrix

For every rule: what it needs, and what makes each outcome. Exceptions and limits
are under each rule below; thresholds are in [Thresholds](#thresholds).

| Code | Needs | `problem` when | `no-problem` when | `unknown` when | `not-applicable` / `manual-check` when |
|---|---|---|---|---|---|
| `port_conflict` | published ports; sockets (ports section); container publications | a binding is certainly held by something that is not this deployment's own container | nothing holds the bindings, or only this deployment's own container does | sockets not read; overlap undecidable offline (`[::]`, no `host_ip`, unresolved `host_ip`); a socket holds it and the engine's containers were not listed, so it may be our own `docker-proxy` | n/a: nothing published · manual: protocol with no socket table (`sctp`) |
| `container_name_conflict` | `container_name`; container list | a container of that name exists and is not this deployment's service | no container of that name, or it is this deployment's | the engine did not answer; its labels were not reported | n/a: no `container_name` |
| `project_ownership` | containers with their Compose labels; the plan's project, directory, services | another checkout uses this project name | every container of the project is this deployment's previous version, or there is none | the engine did not answer; a container's labels were not reported | manual: this directory under another project name; orphans left running |
| `volume_name_conflict` | mounted named volumes by engine name; volume list (complete) | an external volume is missing from a complete list or carries another project's label; a volume Compose would create exists without this project's label | every external volume exists; every created one is absent (a planned creation) or this project's | the volume list was not read in full | n/a: no named volume mounted |
| `bind_path_conflict` | bind mounts, resolved; each source's stat on this host; the container user | a source is a sensitive host path; missing with `create_host_path: false`; mounted read/write on a read-only filesystem | no source is sensitive, each exists or is created by the engine, and no mode bits refuse the container user (access itself is never proven) | the sources were not examined; one could not be stat'ed; a dangling symlink; missing with the engine's behaviour unknown or a file-like name; mode bits deny the container user | n/a: no bind mount |
| `network_name_conflict` | networks by engine name; network list (complete) with scope and attachability | an external network is missing from a complete list, or is a non-attachable swarm network; a network Compose would create exists without this project's label | every external network exists and can be joined; every created one is absent or this project's | the network list was not read in full; a swarm network's attachability was not read | n/a: no network · manual: an external network shared with another stack |
| `subnet_overlap` | explicit IPAM subnets; every network's subnets | a requested subnet overlaps another project's network | no overlap with any network | networks not listed, or the subnets of some were not read | n/a: no explicit subnet |
| `insufficient_memory` | reservations/limits; `/proc/meminfo` | the declared amount exceeds what is available | it fits | `/proc/meminfo` unreadable | n/a: nothing declared |
| `insufficient_disk` | images to pull; image list; container-store filesystem | images must be pulled and less than 2 GiB is free | nothing to pull, or headroom | no filesystem measured; images not listed | — |
| `insufficient_inodes` | container-store filesystem with a fixed inode count | ≥ 90% of inodes used | below that | no filesystem measured | n/a: no fixed inode count (btrfs, dynamic XFS) |
| `architecture_mismatch` | `uname -m`; `platform:`; architecture of images present | a pinned platform or a present image is for another architecture | every pinned platform and present image matches | host architecture unread; an image is not on the host (its variant is chosen at pull time) | — |
| `runtime_missing_or_old` | engine binary and answer; Compose implementation | no engine; no Compose; only Compose V1 | engine answers and Compose V2 is present | engine installed but did not answer | — |
| `registry_unreachable` | registries; a TCP connect each (`--egress`) | a registry did not accept a connect | every registry accepted one | `--egress` not given | n/a: everything built locally |
| `proxy_conflict` | 80/443 of the plan; web server and panel listen ports | a TCP publish of 80/443 meets a web server or panel holding it | none holds it | the publish is not TCP (protocol not recorded); web server configuration unreadable | n/a: neither 80 nor 443 published |
| `domain_conflict` | domains in labels; server names | an existing vhost serves the domain | no vhost serves it, or no web server is installed | web server configuration unreadable | n/a: no domain in labels · manual: a catch-all vhost would answer |
| `database_version_mismatch` | database images and tags; host databases | the image's major version differs from the host database's | they agree, or no database of that kind is on the host | the tag names no major version (`latest`) while one is installed | n/a: no database image |
| `env_file_missing` | `env_file`; existence of each | a file is missing | every file exists | — | n/a: no `env_file` |
| `no_healthcheck` | healthcheck of each service | a service has none | every service has one | — (the plan is the whole input) | n/a: no service |
| `floating_image_tag` | image references | a pulled image is not pinned by digest | every pulled image is | — | n/a: everything built locally |
| `privileged_container` | privileged, cap_add, devices, network_mode, socket mounts | any of them is set | none is | — | n/a: no service |
| `backup_gap` | persistent data; backup tools, jobs, directories | no backup tooling or directory; only stale directories | a directory written to within 30 days | — | n/a: no persistent data · manual: a tool is installed but writes nowhere visible locally |
| `no_rollback_plan` | the rollback section | an item is established missing | — (a provider snapshot is never visible from inside the host) | — | manual: only unverifiable items remain |
| `certificate_expiring` | certificates found, parsed | ≤ 30 days left, or expired | none expiring, or none found | a certificate file could not be parsed | — |
| `reboot_required` | `needs-restarting -r` / `/var/run/reboot-required` | a reboot is pending | none is | the answer is `unknown` (or the system section was not selected) | — |
| `disk_at_limit` | capacity of every writable filesystem | one is ≥ 90% full | none is | no filesystem measured | — |

The same table is executed as a test: `app/witness/outcomes_test.go` builds every
situation in it and asserts the rule's outcome, so a rule cannot drift from what is
written here without the build failing.

## Thresholds

Every number a rule compares against, in one place:

| Threshold | Value | Used by |
|---|---|---|
| Disk / inode warning | 90% used | `insufficient_inodes`, `disk_at_limit` |
| Disk / inode blocker | 97% used | `insufficient_inodes`, `disk_at_limit` |
| Minimum pull headroom | 2 GiB | `insufficient_disk` |
| Certificate warning | 30 days left | `certificate_expiring` |
| Certificate blocker | 7 days left, or expired | `certificate_expiring` |
| Backup staleness | newest file older than 30 days | `backup_gap`, and the `volume-backup` rollback row |
| Evidence capture | 1500 characters, then marked truncated | all |

90% is where filesystem performance starts degrading on most layouts and where an
unattended deployment has no headroom; 97% is where writes begin failing. 30 days
is when a renewal that has silently stopped can still be fixed calmly, and 7 is
when it cannot. 30 days of backup staleness is long enough not to nag about a
weekly schedule and short enough to catch a job that quietly stopped.

## The conflict rules

Six variations on one question: is something already holding the name, port, path
or address range this deployment wants?

### `witness.port_conflict`

| Case | Severity | Confidence | Fires when |
|---|---|---|---|
| Own container | `info` | `high` | The binding is held by a container the planned run releases first — this deployment's previous version (recreated or kept), an orphan with `--remove-orphans` — see [`project_ownership`](#witnessproject_ownership) |
| Taken | **blocker** | `high` | The binding is certainly held — by a listening socket from `ports.csv`, or by a container the plan does not release: another project, this directory under an older project name, an orphan left running, a one-off run |
| Undecidable | **warning** | `medium` | Something is on that port and whether the two bindings overlap cannot be established offline |
| Owner unknown | **warning** (`unknown`) | `medium` | A socket certainly holds the binding, but the engine's containers were not listed — the socket may be this deployment's own `docker-proxy`, which Compose replaces |
| Not checked | **warning** | `low` | The publish uses a protocol the kernel has no socket table for (anything other than TCP or UDP) |
| Evidence | | | The manifest line, plus `ss -lntupH` output and/or the `docker ps` row |

**The comparison is between bindings, not port numbers.** A binding is a
protocol, a host address and a port, and two of them collide only when all three
overlap. `53/tcp` and `53/udp` are two different sockets on one number;
`127.0.0.1:8080` and `192.168.1.10:8080` are two different sockets on one number
as well. Comparing the number alone produced a blocker for both, which stops a
deployment that would have worked.

The address family is read off the address, not off the protocol: `tcp6` is the
name of the `/proc/net` table the socket came from, and the collector normalises
an IPv4-mapped address such as `::ffff:127.0.0.1` into dotted form, so it is
matched as IPv4. The `*` that `ss` prints means every interface, both families.

Two questions of address family are settled from the host itself where they can
be:

- **A listener on the IPv6 wildcard against an IPv4 publish.** It also answers IPv4
  unless the socket is IPv6-only — a per-socket option (`IPV6_V6ONLY`) that
  `/proc/net` does not show and `ss` does: `*:port` is dual-stack, `[::]:port`
  IPv6-only. The ports section runs `ss -lntupH` for exactly this and records it as
  `V6 only` in `ports.csv`. Dual-stack is a certain overlap, IPv6-only certainly
  none. `net.ipv6.bindv6only` is only the default a socket may override, so it is
  quoted, never relied on.
- **A publish with no `host_ip` against an IPv6 listener.** On a host with IPv6
  the engine publishes on `[::]` as well as `0.0.0.0` (as `docker ps` shows); on a
  host without IPv6 (`/proc/sys/net/ipv6` absent, or `disable_ipv6=1`) it cannot.

What remains undecidable produces the **warning** (`unknown`) rather than a
blocker or silence: an IPv6 wildcard whose kind `ss` could not tell (not installed,
or both kinds on one port), a host whose IPv6 state could not be read, and a
`host_ip` that is not an address, such as an unresolved `${HOST_IP}`. The finding
names the command that settles it: `ss -lntup | grep ':<port> '`. Reporting them as
blockers would be the false blocker this rule exists to avoid; reporting them as
clean would break the second promise.

Publishes that are not one host port per number:

- **A host range to one container port** (`8000-8010:80`) binds **one** port of
  the range, the first the engine finds free. It is a conflict only when every port
  of it is held (`problem`); one free port settles it (no finding), and none free
  with some undecided is `unknown`. `8000-8001:8000-8001` binds both, and each is
  checked like any other port.
- **No host port** (`"80"`, `127.0.0.1::80`) gets an ephemeral port from the
  engine: it cannot collide, and `changes.csv` says so (`ephemeral/tcp`).
- **The container port is not a host port.** `18080:8080` claims host port 18080;
  a listener on 8080 is irrelevant. `expose:` publishes nothing.
- **`network_mode: host`** publishes nothing: the engine discards `ports:` and the
  application binds its declared ports (the container side of `ports:`, and
  `expose:`) directly on the host, at addresses of its own choosing. A wildcard
  holder of such a port is a `problem`; a holder on a specific address, or one that
  may be the service's own previous container (a host-network socket carries no
  label), is `unknown`; a host-network service that declares no port at all is a
  `manual-check`.

`Subject` is the whole binding — `127.0.0.1:8080/tcp`, `[fd00::1]:8080/tcp`. A
publish that names no address keeps the shorter `8080/tcp` form, because there is
nothing more to say about it.

Each published host port produces **at most one finding**, so a container of this
deployment that is also visible as a raw socket — its own `docker-proxy` — is
stated once rather than twice.

The `info` case is stated rather than dropped: Compose stops its own container
before starting the new one, so nothing is blocked, but the engine's "port is
already allocated" message may still appear and should not be mistaken for a
conflict with an unrelated service.

When a socket exists but could not be attributed to a process — which is what
happens unprivileged — the finding says "an unidentified process listening on
`<address>` (the owner is only visible to root)" rather than naming a guess.

### `witness.container_name_conflict`

| | |
|---|---|
| Severity | **blocker**, or `info` when the existing container is this deployment's own (same project **and** service); **warning** (`unknown`) when the engine reported no labels for it |
| Fires when | A service sets `container_name:` and a container with that name already exists |

An explicit `container_name` is precisely the case Compose cannot work around by
prefixing the project name, so the deployment fails outright.

### `witness.project_ownership`

| | |
|---|---|
| Severity | **warning** (`problem`) when another checkout uses this project name; `info` (`manual-check`) for this directory under another project name, and for orphans left running; **warning** (`unknown`) when the engine reported no labels |
| Fires when | An existing container is tied to this deployment by name or directory but is not simply its previous version |

Whose a container is comes from what Compose wrote on it when it created it, read
through the engine that was inspected: `com.docker.compose.project`, `.service`,
`.project.working_dir`, `.project.config_files`, `.oneoff` and `.config-hash`.
Against the planned run (project name, project directory, services, `up` options)
every existing container is one of:

| Ownership | What `up` does to it | Released before the new containers bind? |
|---|---|---|
| this deployment — the project, a planned service | **kept** when its config hash equals the plan's (`docker compose config --hash`), **recreated** when it differs (stopped and removed, then created), per `--force-recreate`/`--no-recreate` | yes |
| an orphan — the project, a service the plan does not start | left running; removed with `--remove-orphans` | only with `--remove-orphans` |
| a one-off `docker compose run` of the project | left as it is | no |
| another checkout — the project name, another `working_dir` | taken over: Compose cannot tell the two apart | yes — and that is the finding |
| this directory under another project name | left as it is | no |
| another Compose project, or no Compose labels | left as it is | no |
| labels not reported by the engine | unknown | no — and that is a finding |

The same classification decides `port_conflict` (a port held by a container the
plan releases is not a conflict; one held by an orphan, a one-off run, an older
project name or anything else is), `container_name_conflict` and the `container`
rows of `changes.csv`, so the three never disagree.

### `witness.volume_name_conflict`

| | |
|---|---|
| Severity | **blocker** when an external volume is missing from a complete volume list; **warning** when an external volume carries another project's label, or when a volume Compose would create already exists without this project's label; **warning** (`unknown`) when the engine's volumes could not be listed — absence is never concluded from a list that was not read |
| Fires when | A named volume a planned service mounts is compared, **by its name in the engine**, with the engine's volume list |

A volume is matched by the name it has in the engine, not by the key the services
use: `name:` if the plan sets one, the key itself for an external volume (or the
legacy `external: {name: …}`), and `<project>_<key>` for one Compose creates —
exactly as `docker compose config` resolves it. Only the volumes a planned service
mounts are checked; Compose looks up no other. Three questions stay separate:

| | Absent | Present, this project's | Present, no label | Present, another project's |
|---|---|---|---|---|
| external | `problem` (blocker) — Compose refuses to start; `unknown` if the list was not read in full | fine | fine — what `external: true` is for | `problem` (warning): its data is attached |
| created by Compose | fine — a planned creation (`changes.csv`: `created empty by Compose`), not a conflict | fine — reused with its data | `problem` (warning): Compose warns "already exists but was not created by Docker Compose" and mounts it, data and all | `problem` (warning): the same, "created for project …" |

The warning cases are the interesting ones: nothing fails. The deployment
succeeds, and the new service starts on top of existing data nobody declared it
would use. Every observation names the engine it came from (`engine <ID>`), so the
same volume name on two servers is never one answer.

### `witness.bind_path_conflict`

| | |
|---|---|
| Severity | **warning** for a sensitive source or a read/write mount on a read-only filesystem; **blocker** for a missing source with `create_host_path: false`; **warning** (`unknown`) when the source could not be examined, is a dangling symlink, is missing with the engine's behaviour unknown or with a file-like name, or its mode bits deny the container user |
| Fires when | A bind mount's source, resolved and examined on this host, is sensitive, missing in a way that breaks the start, unwritable, or possibly unreachable for the container's user |

**The source is the path Compose mounts.** Relative sources resolve against the
project directory and `~` against the home directory — by Compose itself when it
resolves the plan; by the built-in parser otherwise, which can only use the home of
the account running the audit and says so in a parser warning.

**Sensitive paths.** A source where a container writing through the mount changes
how the host itself behaves: `/`, `/etc` or below, `/run`, `/var/run`, anything
ending in `docker.sock` or `podman.sock`, `/home`, `/root`, `/var/lib/docker` or
below, `/sys` or `/proc` or below. The list is short on purpose — a longer one would
fire on ordinary layouts and teach the reader to skip the category.

**What the host shows, by stat alone.** Every source is `lstat`ed (and the symlink
followed, since the engine mounts its target); nothing is created, opened or read —
a missing directory stays missing:

| On this host | Outcome |
|---|---|
| exists — directory, file, socket … | fine as far as the path goes; type, mode and owner in `changes.csv` |
| missing, and the engine creates it (short syntax; Compose's resolved model unless `create_host_path: false`) | a planned change — `changes.csv`: "creates it as an empty directory owned by root" — unless the name looks like a file (`app.conf`): then `unknown`, since a directory where the container expects a file fails it |
| missing, `create_host_path: false` | `problem` (blocker): the container is not created |
| missing, long syntax without `create_host_path`, resolved by the built-in parser | `unknown`: Compose 5.x creates it, older versions refuse |
| could not be stat'ed by this account | `unknown` — never "missing" |
| a dangling symlink | `unknown` |
| on a read-only filesystem, mounted read/write | `problem` (warning): every write fails |

**Access for the container's user is never claimed.** The user is the service's
`user:`, else the image's default (`Config.User` from `image inspect`, root when
empty), else unknown. When it is numeric, the source's mode bits are checked for
read, write (unless `:ro`) and, for a directory, enter; mode bits that refuse it are
`unknown`, not `problem`, because ACLs, user-namespace remapping, rootless engines
and SELinux labels are not read — and mode bits that allow it are not proof either:
every bind row of `changes.csv` ends "access for the container user (…) not
verified". A user name cannot be mapped to a uid without the image's `/etc/passwd`,
which is not read. SELinux relabelling (`z`, `Z`), propagation and consistency are
listed as "options not evaluated".

### `witness.network_name_conflict`

| | |
|---|---|
| Severity | **blocker** when an external network is missing from a complete network list, or exists but is a swarm network that is not attachable; **warning** when a network Compose would create already exists without this project's label (Compose warns and joins it); `info` (`manual-check`) when an external network belongs to another stack; **warning** (`unknown`) when the networks could not be listed, or a swarm network's attachability was not read |
| Fires when | A network of the plan is compared, by its name in the engine, with the engine's network list |

Networks are matched by engine name exactly as volumes are (`name:`, the key of an
external one, `<project>_<key>` — `<project>_default` included when Compose lists
it). Presence is kept apart from **usability**: a network can exist and still refuse
the deployment's containers — a swarm-scoped network that is not attachable takes no
standalone container, which is what Compose creates. The scope comes from `network
ls`, attachability from `network inspect`.

The `info` case says the deployment will join a shared network: often the intent,
and also a statement that a service here becomes reachable from whatever else is on
it.

### `witness.subnet_overlap`

| | |
|---|---|
| Severity | **blocker** |
| Fires when | An explicit `ipam` subnet in the manifest overlaps a subnet of an existing runtime network that belongs to another project |

Either prefix containing the other's base address counts as an overlap. The engine
refuses to create such a network; when it does create one, routing becomes
ambiguous and the symptom appears later, as traffic reaching the wrong container.

## The capacity rules

All four state the assumption they computed under, inside the finding. A capacity
claim without its assumption is unfalsifiable, and the reader has no way to tell a
real shortfall from a manifest that simply declares generous reservations.

### `witness.insufficient_memory`

| Case | Severity | Fires when |
|---|---|---|
| Not measured | `info` | `/proc/meminfo` could not be read. Explicitly a gap in the audit, not a statement about the host |
| Nothing declared | `info` | No service sets `deploy.resources.reservations.memory` or a memory limit, so there is nothing to compare against |
| Shortfall | **warning** | Reservations (plus the limits of services that declare a limit and no reservation) exceed `MemAvailable` |
| Impossible | **blocker** | The same total exceeds `MemTotal` — more than the machine physically has, which is not a matter of what else happens to be running |

The finding names the services that declare nothing at all, because they are the
part of the arithmetic that is missing. Confidence is `medium`: this is computed
from what the manifest declares, not from measured usage.

### `witness.insufficient_disk`

| Case | Severity | Fires when |
|---|---|---|
| Not measured | `info` | No filesystem capacity could be collected |
| Shortfall | **blocker** | At least one image is not present on the host **and** the filesystem holding the container store has less than 2 GiB available |

The target filesystem is the one holding `/var/lib/docker` (or `/var/lib/containers`
on Podman), falling back to `/`.

**The requirement side is deliberately unknown.** How much an absent image needs
cannot be known without contacting a registry, which this audit does not do. So the
check is about headroom, and the finding says so.

### `witness.insufficient_inodes`

| | |
|---|---|
| Severity | **warning** at 90% of inodes used, **blocker** at 97% |
| Fires when | The deployment's filesystem reports a fixed inode count and that count is nearly exhausted |
| Silent when | `InodesTotal` is 0 — btrfs and XFS with dynamic allocation report no fixed count, and reading that as "none left" would produce a confident finding about a limit that does not exist |

Running out of inodes fails writes with "no space left on device" while `df` still
shows free space, which is one of the more expensive hours an operator can spend.
Container images are thousands of small files, so a pull consumes inodes far faster
than it consumes bytes.

### `witness.disk_at_limit`

| | |
|---|---|
| Severity | **warning** at 90% full, **blocker** at 97% |
| Fires when | Any writable filesystem the host reports is that full — not only the deployment's own |
| Silent for | Read-only mounts and anything with a zero total |

## The compatibility rules

The deployment and the machine are each internally consistent, and wrong about each
other.

### `witness.architecture_mismatch`

| Case | Severity | Fires when |
|---|---|---|
| Manifest pin | **blocker** | A service sets `platform:` to an architecture that is not this host's. The one case that can be established without the image being present |
| Image on disk | **blocker** | An image the manifest uses is already on the host and reports a different architecture |

Architecture names are normalised before comparison: `uname -m` says `x86_64`
where an image says `amd64`, and `aarch64` where an image says `arm64`. Comparing
them literally would report a mismatch on every arm host.

Without an emulation layer the container will not start at all; with one it starts
and runs several times slower, which is harder to notice and worse to inherit.

### `witness.runtime_missing_or_old`

| Case | Severity | Fires when |
|---|---|---|
| No engine | **blocker** | Neither `docker` nor `podman` is on `PATH`, and the manifest describes containers |
| Engine silent | **warning** | The binary exists but querying the engine failed — usually a permission problem. **Every conflict check that compares against existing containers, networks, volumes and images was skipped**, and this finding is what says so |
| No Compose | **blocker** | An engine is installed but neither the `docker compose` plugin nor a standalone `docker-compose` answered |
| Compose V1 only | **warning** | Only the Python V1 `docker-compose` is present. It reached end of life and *ignores* fields it does not understand — `deploy.resources` outside swarm mode, the long `depends_on` form, profiles — rather than refusing, so the deployment comes up subtly different from what the file says |

The "engine silent" case is the honesty case that matters most in this section:
with the engine unreachable, an empty conflict list means nothing was looked at.

### `witness.registry_unreachable`

| Case | Severity | Fires when |
|---|---|---|
| Not checked | `info` | The manifest pulls at least one image and `--egress` was not passed. The offline promise wins over the completeness of this check, and the report says which |
| Unreachable | **blocker** | With `--egress`, the TCP connect to a registry's port 443 failed. The failing error is quoted in the evidence |

A host behind an egress firewall passes every other check in this report and then
fails at the pull. Registries are taken from each service's image reference, with
`docker.io` assumed when none is named; services that are built rather than pulled
are excluded.

### `witness.database_version_mismatch`

| | |
|---|---|
| Severity | **warning**, or **blocker** when the service bind-mounts the existing data directory |
| Fires when | A service's image is a recognised database (`postgres`/`postgresql`, `mysql`, `mariadb`, `mongo`/`mongodb`, `redis`/`valkey`, namespaced or not) with a numeric major version in its tag, and the host already runs the same engine at a different major version |
| Confidence | `medium` |

A tag with no leading number (`latest`, `alpine`) stops the rule rather than
letting it compare nonsense. PostgreSQL refuses to start on a data directory from
another major version; MySQL will start and then need an upgrade pass that is not
reversible. Neither is something to discover during a deployment.

## The front-of-the-machine rules

### `witness.proxy_conflict`

| Case | Severity | Confidence | Fires when |
|---|---|---|---|
| Panel | **blocker** | `medium` | The manifest publishes 80 or 443 **over TCP** and a detected control panel holds that port |
| Web server | **blocker** | `high` | The manifest publishes 80 or 443 **over TCP** and nginx or Apache is configured to listen on it |
| Another protocol | **warning** | `low` | The same, but the publish is not TCP — a QUIC publish on `443/udp`, for instance |

The panel case is reported first and separately because a panel does not merely
occupy the port: it owns the web server configuration and rewrites it on its own
schedule, so a hand-made vhost placed alongside it survives only until the panel
next regenerates.

A front end's listen ports are collected as bare port numbers: `Proxy.ListenPorts`
and `Panel.OwnsPorts` record neither the protocol nor the address behind them. So
the only collision this rule can *state* is against a TCP publish, which is what a
web server listens on; `443:443/udp` beside nginx is a question and is reported as
one. The address half cannot be narrowed at all — that is a limitation of what the
proxy collector records, not something the rule can decide, and it is the reason
this rule's confidence is lower than `witness.port_conflict`'s.

### `witness.domain_conflict`

| Case | Severity | Fires when |
|---|---|---|
| Taken | **warning** | A domain the manifest expects is already served by a vhost on this host. The existing vhost's file and line are in the finding |
| Catch-all | `info` | No vhost serves the domain yet, but the proxy has a catch-all server block (`server_name _` or `*`) that will answer for it |
| Confidence | `medium` | Both cases |

Domains come from labels, because labels are the only place a compose file says
which name a service expects to be reached at: Traefik router rules
(`Host(\`example.com\`)`) and the `VIRTUAL_HOST`-style proxy labels. Anything else
is not guessed at, so a deployment whose domains live only in an nginx config the
audit has not seen yet produces no findings here.

The catch-all case matters because requests for the new domain will be *answered*
rather than failing visibly, so a missing or mistyped vhost looks like a working
site showing the wrong content.

## The rules about what is missing

None of these is about a collision. Each is about something the deployment or the
host does not have, and they are the ones most often argued with — so each says
plainly what it is claiming.

### `witness.env_file_missing`

| | |
|---|---|
| Severity | **blocker** |
| Fires when | A service's `env_file:` path does not resolve |

Compose refuses to start a service whose `env_file` is missing. The evidence says
in as many words that the file's contents are never read by this audit — only
whether the path exists.

### `witness.no_healthcheck`

| | |
|---|---|
| Severity | **warning** |
| Fires when | Any service defines no `healthcheck` |

**One finding for the whole manifest**, listing the services, rather than one per
service: a stack with no healthchecks is a single decision, and twelve identical
findings would bury the ones that are specific.

Without a healthcheck the engine reports a container as running the moment its
process starts, which is not the same as the service being able to answer.
`depends_on` cannot help — it waits for "started". A restart policy has the same
blind spot: a process that is alive and wedged is never restarted.

### `witness.floating_image_tag`

| Case | Severity | Fires when |
|---|---|---|
| Moving tag | **warning** | A pulled image is not pinned by digest — `latest`, or a name-like tag |
| Version-like tag | `info` | The tag starts with a number and is not `latest`. Still mutable, but the blast radius of a moved `16.2` is smaller than that of `latest` |
| Silent for | — | Services with a `build:` context, and images pinned by `@sha256:` |

A tag can be moved, which makes the deployment unreproducible in the direction
that matters: rolling back to "the version that worked" pulls whatever the tag
points at today.

### `witness.privileged_container`

| | |
|---|---|
| Severity | **blocker** for `privileged: true` or a bind-mounted container runtime socket; **warning** otherwise |
| Fires when | A service declares any of: `privileged: true`, a mount of the Docker/Podman socket, `cap_add`, `devices`, `network_mode: host` |
| Category | `security` |

Every reason found is listed in one finding per service. These flags are sometimes
genuinely required — a monitoring agent, a backup tool, a container that manages
other containers. The finding is not that they are wrong; it is that anyone who
compromises this service has the host, and that has to be a decision somebody made
on purpose rather than a line copied from an example.

### `witness.backup_gap`

| Case | Severity | Fires when |
|---|---|---|
| Nothing at all | **warning** | The manifest declares persistent data and the host has no backup tool **and** no backup directory |
| Stale | **warning** | Backup directories exist but the newest file in each is older than 30 days, or the directory is empty or unreadable |
| Silent when | — | The manifest declares no persistent data (no named volumes, no writable bind mounts) — there is nothing to lose, and advice would be noise |
| Confidence | `medium` | Both cases |

An existing `/backup` directory reads as reassurance, and a stale one is worse than
an absent one for exactly that reason: the reassurance is false. Nothing reads the
contents of a backup — the date is what tells a live backup from an abandoned one.

### `witness.no_rollback_plan`

| | |
|---|---|
| Case | Severity | Subject | Title |
|---|---|---|---|
| A row is `false` — established missing (no digest for a running image, no or stale backup) | **warning** | `N of M missing` | Part of the way back from this deployment is missing |
| No row is `false`, but some are `unknown` — unable to verify | **info** | `N of M unverified` | The way back could not be fully verified |
| Every row `true` | — | — | not raised |

The description lists the two kinds separately — `Missing: …` and `Unable to
verify: …` — and so does the evidence. The finding never concludes that there is
no way back: a provider snapshot and an off-host copy of the proxy configuration
cannot be seen from inside the machine, and what cannot be seen is neither present
nor absent. Since the `snapshot` row is always `unknown`, the finding appears on
every preflight, as `info` unless something is known to be missing. Before 1.4.0
both of those rows were `false` and the finding was always a warning titled "There
is no way back from this deployment" — a conclusion the data did not support.

### `witness.certificate_expiring`

| | |
|---|---|
| Severity | **warning** at 30 days left, **blocker** at 7 or already expired |
| Fires when | A certificate on disk parsed successfully and is inside those windows |
| Silent when | The certificate could not be parsed — that is reported in the section's notes instead, not as an expiry claim |
| Category | `expiry` |

The description distinguishes three states, and the difference is the point of the
`certs` collector: a renewal tool that owns the file *and* has a renewal job; a
tool that issued it with **no renewal job found**, which is not the same as the
tool being installed; and nothing on the host claiming to renew it at all. The
advice differs accordingly.

### `witness.reboot_required`

| | |
|---|---|
| Severity | **warning** |
| Fires when | The `system` section's `updates` / `reboot-required` fact is exactly `yes` |
| Silent when | The answer is `no` **or** `unknown` — `unknown` is a real answer and is not collapsed into either one |

Deploying now means the next reboot restarts the host with both a new kernel and a
new deployment at once. If something then fails, there are two changes to untangle
instead of one.

**Known limitation.** The rule matches the fact value exactly. On hosts where the
answer comes from `needs-restarting -r` (RHEL family, and Arch where the tool is
installed) the value is a bare `yes` and the rule works. On Debian and Ubuntu,
where the answer comes from `/var/run/reboot-required`, the `system` section
appends the package list — `yes (linux-image-…, …)` — whenever
`/var/run/reboot-required.pkgs` exists, and the rule then does not fire. The
pending reboot is still reported, as a row in `system.csv`; only the witness
finding is missing. Read the `updates` / `reboot-required` row on a Debian-family
host rather than relying on this finding.

## Everything the section outputs

| Output | Where |
|---|---|
| The findings | `witness.csv` |
| Their evidence | `evidence.csv` |
| What deploying will do | `changes.csv` |
| How to undo it | `rollback.csv` |
| What the section could not check | the `witness` row of `summary.csv` |

Columns for all of these are in [08 — Report format](08-report-format.md). The
change list and the rollback plan are not findings: they say what is about to
happen and how to undo it, and they exist because that is the document somebody
shows their own client when asked "what did you do to our server?".
