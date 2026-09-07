# deploy-witness

A standalone Go binary that audits the machine it runs on and writes a CSV
report. No database, no HTTP server, no frontend — build it, copy it to the
server, run it, read the CSV.

Two promises, and they are the product:

**It is offline by default.** Everything it reports comes from the kernel, `/etc`,
package metadata already on disk, or the compose file you pointed it at. Three
flags touch the network, all off unless you type them: `--online` (the OSV
advisory API), `--egress` (a TCP connect to each image registry, nothing sent) and
`--upload` (one POST of the finished report). On top of that, the binary can
execute exactly one published list of commands — `deploy-witness --commands` prints
it, and nothing outside it can run.

**It is honest about what it could not see.** A gap in coverage is reported, never
rendered as a clean result. "We could not read `/etc/shadow`" and "there are no
passwordless accounts" are different answers, and so are "the Docker socket did not
answer" and "nothing is running here". Every gap lands in `summary.csv`.

## What it reports

| Section | Contents |
|---|---|
| `system` | Host identity, distribution, kernel, hardware, disk usage, network interfaces, timekeeping, accounts, effective sshd configuration, SELinux/AppArmor, firewall units, hardening sysctls |
| `updates` | Upgradable packages, with the repository each comes from and whether it is a security channel |
| `vulnerabilities` | Known CVEs affecting installed packages, from three independent feeds, graded and deduplicated |
| `ports` | Listening TCP/UDP sockets, the process behind each, and how far each one reaches |
| `services` | Running service units, whether they are enabled at boot, their main PID, user and activation time |
| `witness` | What a `docker-compose.yml` asks for against what this host offers: port, name, path and subnet conflicts, memory/disk/inode capacity, architecture and runtime compatibility, proxy and domain collisions, certificates, backups, and a rollback plan. Needs `--compose` |

## Build

```bash
make build                # ./deploy-witness for this machine
make build-linux-amd64    # ./bin/deploy-witness-linux-amd64
make build-linux-arm64    # ./bin/deploy-witness-linux-arm64
```

The binaries are static (`CGO_ENABLED=0`) and depend on nothing at runtime, so a
cross-compiled binary runs on any Linux host of that architecture. Building needs
access to two private modules of the organisation — `utils` and `contracts` — so
set `GOPRIVATE=github.com/BloodHeavenDevelop/*`.

## Run

```bash
./deploy-witness --commands                # every command this binary can execute, then exit
./deploy-witness                           # writes ./audit-<host>-<UTC timestamp>/*.csv
./deploy-witness --out /var/log/audit      # writes into a chosen directory
./deploy-witness --stdout > report.csv     # one combined CSV on stdout
sudo ./deploy-witness                      # full coverage — see below
```

Running as root is not required, but it changes what can be seen: without it,
`/etc/shadow` and `sudoers` cannot be read, sockets owned by other users have no
attributed process, the container engine socket and `/etc/letsencrypt` are out of
reach, and the per-user crontabs cannot be listed. Every such gap is recorded in
`summary.csv` rather than being silently omitted.

## Witness: checking a deployment against the host

```bash
# Will this stack work here, and what will it change?
sudo ./deploy-witness --compose /srv/app/docker-compose.yml

# Also test whether the registries it pulls from are reachable.
sudo ./deploy-witness --compose /srv/app/docker-compose.yml --egress
```

The section produces four files: the findings (`witness.csv`), the evidence
behind each one (`evidence.csv`), what deploying will actually do (`changes.csv`)
and how to undo it (`rollback.csv`). Every finding carries evidence — a command
from the published allowlist, or a path — because a claim about somebody's
production server that cannot be checked is worse than silence. There is no
"Ready" verdict.

Environment variable *values* are never read. `environment:` contributes names,
`env_file:` contributes a path and whether it exists, and the `.env` beside the
compose file is used for `${VARIABLE}` substitution only.

## Vulnerabilities

Three feeds, used together and labelled per row in the `source` column:

```bash
# 1. Distribution metadata — always on, nothing to configure.
./deploy-witness --sections vulnerabilities

# 2. An offline OSV dataset you supply.
./deploy-witness --vuln-db /var/lib/osv/all.zip

# 3. The OSV API, explicitly opted into.
./deploy-witness --online
```

They disagree by design: the distribution knows which fixes were backported into
a version whose number never changed, OSV knows about flaws the distribution has
not triaged yet. Neither is a superset of the other.

**Arch and Fedora have no OSV ecosystem.** On those hosts feeds 2 and 3 have
nothing to match against and say so in `summary.csv`; `arch-audit` is the only
CVE source Arch publishes. Pass `--ecosystem` to force a mapping if you know
better.

## JSON and upload

```bash
# One document, with the two halves named: what stays here, and what would be sent.
sudo ./deploy-witness --compose /srv/app/docker-compose.yml --format json

# Send it. One request, no retries, no telemetry.
sudo ./deploy-witness --compose /srv/app/docker-compose.yml \
  --upload https://deploywitness.example.com --upload-token "$TOKEN"
```

`report.json` has an `upload` half — the shared `bloodheaven.audit.v1` contract,
exactly the bytes `--upload` sends — and an `audit` half that stays local: the host
inventory, the pending updates and the CVE list. You can read the file and see
which half would leave the machine before deciding to send it. The host is
identified by a salted hash of `/etc/machine-id`, never the id itself.

Credentials found in free-form text (a cron line, a process command line) are
masked with a visible `***redacted***` marker before anything is written.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | The report was written. Sections may still carry notes. |
| `1` | The report was written, but at least one section failed. |
| `2` | Bad arguments, or the report could not be written. |
| `3` | The report was written, but `--upload` could not deliver it. |

## Documentation

Full documentation lives in [`docs/en/`](docs/en/) and [`docs/ru/`](docs/ru/) —
including the [command allowlist](docs/en/09-command-allowlist.md) and the
[24 witness finding codes](docs/en/10-witness-rules.md).
