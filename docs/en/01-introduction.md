# 1. Introduction

`deploy-witness` is a single Go binary that inspects the machine it runs on and
writes what it finds as CSV. It is built from source, copied onto the server
being audited, and run there. Nothing else is involved: no database, no HTTP
server, no frontend, no agent that phones home.

## Scope

Six sections, each written to its own CSV file:

- **system** — what this machine is: identity, distribution, kernel, hardware,
  disks, network, time, accounts, sshd configuration and the security posture of
  the base install.
- **updates** — which installed packages have a newer version waiting, where it
  comes from, and whether that repository is a security channel.
- **vulnerabilities** — which known CVEs affect the installed packages, graded by
  severity, from three independent feeds.
- **ports** — which TCP and UDP sockets are listening, which process owns each,
  and how far each one reaches.
- **services** — which service units are running, whether they start at boot, and
  since when.
- **witness** — what a `docker-compose.yml` asks for, what this host actually
  offers, and every place the two disagree. It is the only section that needs an
  input, and it runs only in a Compose preflight (below).
  See [10 — Witness rules](10-witness-rules.md).

The first five sections describe the machine. The sixth answers a different
question — "will this deployment work here, and what will it change?" — and it is
why the tool grew a manifest parser, a change list and a rollback plan.

## Two modes

Every run is one of two kinds, and the report says which:

- **Host audit** (`host-audit`) — no `--compose`. The first five sections, the host
  on its own. Comparing a planned deployment is **outside the scope** of this mode,
  not missing from it: the `witness` and `preflight` rows are `not-applicable`, with
  a note opening `host-audit:`, and neither counts as a gap — a host audit whose
  sections all completed is a complete report. It is still never a preflight
  result, however clean it looks.
- **Compose preflight** (`compose-preflight`) — `--compose <docker-compose.yml>`.
  Everything above plus the witness section. It cannot start without its input: a
  Compose file that is missing, unreadable or does not parse stops the run with exit
  code `2` and no report, rather than producing a report with nothing compared in
  it.

`--mode` asserts one of the two explicitly; see
[04 — CLI reference](04-cli-reference.md#modes).

## The two promises

Everything in this repository is built to preserve two properties.

### It is offline by default

Every fact comes from the kernel, from `/etc`, from package metadata already
present on the disk, or from the compose file you pointed it at. On a default run
the tool never refreshes a package repository, never resolves a hostname and never
opens a socket — and it does not run any of the commands that would do one of those
for it: `debsecan` and `arch-audit`, which download their advisory data on every
call, run only with `--online`, and `zypper` is called with `--no-refresh`.

Three flags, all off by default, are the only code paths that touch the network.
Each of them has to be **typed**: there is no `AUDIT_ONLINE`, `AUDIT_EGRESS` or
`AUDIT_UPLOAD` — a variable left in an image, a CI runner or a login profile is
ignored, and the run says so:

| Flag | What it does | Why it is opt-in |
|---|---|---|
| `--online` | Queries the OSV API for advisory detail, and runs `debsecan` / `arch-audit` if installed | The query discloses the host's complete package inventory to a third party. That is a reasonable trade for many operators and an unacceptable one for others, and not a decision the tool should make on their behalf. |
| `--egress` | One TCP connect to each registry the manifest pulls from (port 443, or the port the image names) | No TLS handshake, no HTTP request, no image fetched, nothing sent — the question is only whether this host's egress reaches the registry at all. Without it the report says reachability was *not checked* instead of implying it is fine. |
| `--upload` | Sends the report to a witness service, once | It needs a one-time token alongside it, there is no default endpoint, no retry and no telemetry; only `https://`, and a redirect is refused rather than followed. What is sent is the `upload` half of the JSON document and nothing else, so it can be read before it is sent. |

The offline claim is checkable, not only stated. Before the audit starts the tool
logs who each enabled path will contact and what it will send — or
`network: none` — and every report carries `network.csv`: one row per path, enabled
or not, with its recipient and how many contacts the run made. The full per-mode
table is in [04 — CLI reference](04-cli-reference.md#network-behaviour).

Two further properties belong to the same promise:

- **The binary can execute exactly one published list of commands.** `--commands`
  prints that list — the enforced one, not a description of it — and every
  execution, refusal included, is recorded in `commands.csv`. See
  [09 — Command allowlist and journal](09-command-allowlist.md).
- **Nothing it runs changes the machine.** `apt-get dist-upgrade` is permitted
  only with `-s` (simulate), `dnf`/`yum` only with `-C` (cached metadata, so no
  repository can be refreshed), and no container is started, stopped or removed.

### It is honest about what it could not see

An audit that quietly omits what it failed to read is worse than no audit,
because it reads as a clean result. Every gap in coverage is recorded and appears
in `summary.csv`:

- Running unprivileged, `/etc/shadow` and `sudoers` are unreadable, sockets owned
  by other users cannot be attributed to a process, and the per-user crontabs
  under `/var/spool/cron` cannot be listed. All of them are reported as gaps, not
  as absences.
- A distribution that ships no local security metadata (Arch without
  `arch-audit`, Alpine at all) is reported as such, not as a host with no
  vulnerabilities. So is an installed `debsecan` or `arch-audit` that was not run
  because `--online` was not given.
- A container engine that is installed but will not answer sets
  `Runtime.Reachable = false` and degrades the section. An empty container list on
  an unreachable daemon would read as "this host runs nothing", which is the worst
  lie the witness section could tell.
- Registry reachability with no `--egress` produces an explicit
  `witness.registry_unreachable` / `info` finding saying it was not checked.
- A witness finding with no evidence attached is *discarded*, and the discard is
  counted in the section's notes. A claim about somebody's production server that
  cannot be checked is worse than silence.
- A section that hit an error after collecting some rows is marked `partial`,
  never `ok`.

Read `summary.csv` first. It says what ran, what it found, and what it could not
reach.

## Where it fits

The platform's other services are long-running: a Go backend, a Nuxt frontend, a
database, a broker. This is not one of them. The closest relative in the
workspace is `health-monitor/agent` — a standalone binary that is built,
deployed onto a host, and does one job there.

The `witness` section is level 2 of the `witness` product: the on-server
check. Levels 0 and 1 — the external, domain-side checks — live in the
`witness` repository and are not this binary's business. Both speak the same
`bloodheaven.audit.v1` contract, generated from the `contracts` repository and
carried here as a copy in `app/contract/auditv1` so that building this binary needs
nothing private. That contract is what `--upload` sends when it is asked to.
