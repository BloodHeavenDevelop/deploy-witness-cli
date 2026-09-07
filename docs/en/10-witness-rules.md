# 10. Witness rules

The `witness` section compares one `docker-compose.yml` against one host and
states every disagreement. This page is the catalogue: 24 rules, 24 finding codes,
what each one is looking at, and what makes it fire.

**The codes are stable identifiers.** They are what an integration matches on, and
what a report from six months ago is compared against, so they do not change with
the wording of a title. Everything else in a finding — the title, the description,
the thresholds — may be reworded to read better; the code will not.

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
  observed says so in its own `info` finding rather than staying quiet. Three codes
  exist mostly to do this: `insufficient_memory`, `insufficient_disk` and
  `registry_unreachable`.

Findings are sorted worst first, then by rule, then by the rule's own ordering,
then by subject, so two runs of the same audit produce the same file.

### The project name, and why it matters

Compose reuses its own containers, networks and volumes on purpose. A collision
with the previous version of the same deployment is information, not a conflict —
so several rules ask whether the thing in the way carries this deployment's own
project label, and downgrade to `info` when it does.

The project name is derived, not guessed: it is the **name of the directory holding
the compose file**, which is Compose's own default, normalised the way Compose
normalises it (lowercased, everything outside `[a-z0-9_-]` dropped). Getting this
wrong would turn every redeployment into a wall of false conflicts with itself.

If you deploy with an explicit `-p`/`COMPOSE_PROJECT_NAME` that differs from the
directory name, the "this is your own container" downgrades will not apply and
those findings will read as conflicts with an unrelated stack.

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

| | |
|---|---|
| Severity | **blocker**, or `info` when the holder is this deployment's own container |
| Fires when | A host port the manifest publishes (ranges expanded to individual ports) is already bound — either by a listening socket in `ports.csv`, or by an existing container that publishes it |
| Evidence | The manifest line, plus `ss -lntupH` output or the `docker ps` row |

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
| Severity | **blocker**, or `info` when the existing container is this deployment's own |
| Fires when | A service sets `container_name:` and a container with that name already exists |

An explicit `container_name` is precisely the case Compose cannot work around by
prefixing the project name, so the deployment fails outright.

### `witness.volume_name_conflict`

| | |
|---|---|
| Severity | **blocker** when the volume is missing; **warning** when it exists under another project |
| Fires when | A volume declared `external: true` is either absent from the host, or present with a different project label |

Only external volumes are checked. Compose prefixes a project's own volumes with
the project name, so a plain declaration cannot collide with an unrelated stack; an
`external` volume is referenced by its literal name, which can.

The warning case is the more interesting one: it does not fail. It succeeds, and
the new service starts on top of existing data belonging to something else — which
is worse, because nothing announces it.

### `witness.bind_path_conflict`

| | |
|---|---|
| Severity | **warning** |
| Fires when | A service bind-mounts an absolute host path where a container writing through the mount changes how the host itself behaves: `/`, `/etc` or below, `/run`, `/var/run`, anything ending in `docker.sock` or `podman.sock`, `/home`, `/root`, `/var/lib/docker` or below, `/sys` or `/proc` or below |

A relative bind source is reported as-is rather than resolved and judged. The list
of sensitive paths is short on purpose — a longer one would fire on ordinary
layouts and teach the reader to skip the category.

### `witness.network_name_conflict`

| | |
|---|---|
| Severity | **blocker** when the network is missing; `info` when it exists under another project |
| Fires when | A network declared `external: true` is absent, or present and owned by another stack |

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
| Panel | **blocker** | `medium` | The manifest publishes port 80 or 443 and a detected control panel holds that port |
| Web server | **blocker** | `high` | The manifest publishes 80 or 443 and nginx or Apache is configured to listen on it |

The panel case is reported first and separately because a panel does not merely
occupy the port: it owns the web server configuration and rewrites it on its own
schedule, so a hand-made vhost placed alongside it survives only until the panel
next regenerates.

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
| Severity | **warning** |
| Fires when | Any row of the rollback plan is unavailable — see [08 — rollback.csv](08-report-format.md#rollbackcsv) |

On a host with a web server this fires on nearly every run, because two rows are
`false` by construction: the proxy configuration is not copied anywhere by this
audit, and whether a provider snapshot exists cannot be seen from inside the
machine. That is the intended reading, not a false positive — every other finding
in the report is about whether the deployment will work, and this one is about what
happens when it does not. It is the only one that cannot be fixed after the fact.

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
