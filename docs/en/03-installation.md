# 3. Installation

## Requirements

- Go 1.25 or newer, to build.
- Nothing at all, to run. The binary is static (`CGO_ENABLED=0`) and calls the
  distribution's own tooling only when it is present.
- **Nothing private.** The two dependencies — `google.golang.org/protobuf` and
  `gopkg.in/yaml.v3` — come from the public module proxy like any other. No
  credentials, no `GOPRIVATE`, no organisation membership, and no `protoc` or
  `buf`. A clean checkout on a machine that has never heard of this organisation
  builds with `make build`.

  That is deliberate. The tool asks to be run as root on somebody's production
  server, and the answer to "why should I trust this binary?" is "read the source
  and build it yourself" — which is not an answer if the build first demands a
  token for a repository the reader cannot see. So the two pieces of shared code it
  needs are copied into the tree instead of imported:

  | Copy | From | Why it is needed |
  |---|---|---|
  | `app/csv` | `utils/csv` v0.9.0 | The CSV generator that renders every table. |
  | `app/contract/auditv1` | `contracts` v0.9.0, `gen/go/bloodheaven/audit/v1` | The generated Go for `bloodheaven.audit.v1`, the report contract `--upload` sends. |

  Both are byte-for-byte copies, each with a `doc.go` recording the release it
  came from. A maintainer with checkouts of the two repositories refreshes them in
  one step — `make sync-shared UTILS=../utils CONTRACTS=../contracts` — and the
  diff is the whole record of what the shared code did. The contract stays
  generated from its `.proto`; nobody restates the shape here by hand, which is
  what would make a divergence show up only on the first upload.

Nothing about the run-time requirements changed: the binary is still static, still
has no runtime dependencies, and still needs nothing installed on the audited host.
Reading a `docker-compose.yml` with `--compose` needs no Docker, no Compose and no
network — the parser is `gopkg.in/yaml.v3` compiled into the binary. A host with no
container engine at all produces a `witness` section whose first finding is that
there is nothing here to run the deployment.

## Building

```bash
make build                # ./deploy-witness for this machine
make build-linux-amd64    # ./bin/deploy-witness-linux-amd64
make build-linux-arm64    # ./bin/deploy-witness-linux-arm64
make build-all            # both cross-compiled targets
```

The version stamped into the binary comes from the first numbered heading in
`CHANGELOG.md`. A tree whose latest section is still `## [Unreleased]` builds
with an empty version — expected, not a fault.

A build made without the `Makefile` — `go build`, or `go run .` — reports its
version as `dev`, because nothing stamped one in. That is deliberate: the source
default used to be a hardcoded release number, which went stale the moment the next
release was cut and then misreported itself in `--version`, in the `--commands`
header, and in the `producer` field of every uploaded report. A report should not
attribute its findings to a release it was not built from.

## Running from source

```bash
make development ARGS="--sections ports,services --stdout"
```

## Installing

```bash
sudo make install         # /usr/local/bin/deploy-witness
```

Or copy a cross-compiled binary onto the target host — it has no runtime
dependencies:

```bash
make build-linux-amd64
scp bin/deploy-witness-linux-amd64 server:/usr/local/bin/deploy-witness
ssh server 'sudo deploy-witness --out /var/log/deploy-witness'
```

## Privileges

The tool runs unprivileged and reports what it could not reach. Running it as
root adds exactly this and nothing else:

| Needs root | Otherwise |
|---|---|
| `/etc/shadow` — accounts with empty or locked passwords | Reported as an unreadable gap |
| `/etc/sudoers`, `/etc/sudoers.d/*` — `NOPASSWD` rules | Reported as an unreadable gap |
| `/proc/<pid>/fd` for other users' processes | Sockets are listed with no owning process |
| `nft list ruleset` | The ruleset is reported as unreadable, never as empty |
| The container engine socket (root, or the `docker` group) | The engine is detected but `Reachable` is false, and every conflict check against existing containers, networks, volumes and images is skipped and said to be skipped |
| `nginx -T` on most distributions | The proxy falls back to a bounded walk of the configuration tree, and the section says the name and port list is incomplete |
| `/etc/letsencrypt` | Certificates there cannot be parsed, so the expiry rule has nothing to work with |
| `/var/spool/cron/*`, `/var/spool/cron/crontabs/*` | Only the current account's crontab is collected; the rest are reported as unread, not as absent |
| Some control-panel marker paths | The panel is reported as neither confirmed nor ruled out |

Every one of these is a `Degrade` with a note, so an unprivileged run is usable and
labelled `partial` rather than quietly narrower.

Nothing in the tool writes outside the output directory, and nothing it runs
changes system state. Every external command it invokes is a query, and the
complete list of commands it is *able* to invoke is printed by
`deploy-witness --commands` — see
[09 — Command allowlist and journal](09-command-allowlist.md).

## Scheduling

There is no built-in scheduler; the tool is a single pass that exits. Use cron or
a systemd timer:

```cron
# Daily at 03:00, keeping one directory per day.
0 3 * * * /usr/local/bin/deploy-witness --quiet --out /var/log/deploy-witness/$(date -u +\%F)
```

The exit code is meaningful for automation: `0` if the report was written, `1` if
it was written but a section failed, `2` if it could not be written at all, `3` if
it was written but `--upload` could not deliver it.

A scheduled run that also checks a deployment needs the manifest path, and only
that:

```cron
# Daily, and a witness check of the stack in /srv/app against this host.
0 3 * * * /usr/local/bin/deploy-witness --quiet --compose /srv/app/docker-compose.yml \
  --out /var/log/deploy-witness/$(date -u +\%F)
```

## Report permissions

The output directory is created `0750` and every CSV `0600`; `report.json` is
`0600` too. The report is a reconnaissance summary of the host — accounts, open
ports, unpatched packages, and now the deployment's own layout — and should not be
world-readable. `.gitignore` excludes `*.csv` and `/audit-*/` for the same reason —
which covers a `report.json` written into a default output directory, but not one
written by `--out` somewhere else inside a repository. Point `--out` outside your
working tree when using `--format json`.

Credentials found in free-form text (a cron line, a process command line, a proxy
directive) are masked with a visible `***redacted***` marker before anything is
written, so the file is safe to attach to a ticket — but it is still a description
of how to attack the host, and the permissions are the real protection.
