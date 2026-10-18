# 4. CLI reference

```
deploy-witness [flags]
```

Almost every flag also reads an `AUDIT_`-prefixed environment variable. The flag
wins; the environment variable is the fallback; the documented default applies
when neither is set. An empty environment variable counts as unset, and a value
that cannot be parsed as a boolean or an integer falls back to the default
silently.

The exceptions have no environment variable at all:

- `--online`, `--egress`, `--upload` and `--osv-url` — everything that opens the
  network or chooses who receives data. A variable baked into an image, a CI runner
  or a login profile must not turn an offline audit into one that connects
  somewhere. `AUDIT_ONLINE`, `AUDIT_EGRESS`, `AUDIT_UPLOAD` and `AUDIT_OSV_URL` are
  ignored, and a run that finds one set logs a warning naming it and repeats it in
  `network.csv`. See [Network behaviour](#network-behaviour).
- `--version` and `--commands`, because a flag that makes the tool print and exit is
  not something an image should be able to switch on.

`AUDIT_UPLOAD_TOKEN` *is* read — it is a secret, not a switch, and it takes effect
only together with a typed `--upload`.

## Output

| Flag | Environment | Default | Meaning |
|---|---|---|---|
| `--out <dir>` | `AUDIT_OUT` | `./audit-<host>-<UTC timestamp>` | Directory to write the report into. Created if missing. |
| `--stdout` | `AUDIT_STDOUT` | `false` | Write the report to stdout instead of a directory. Diagnostics go to stderr, so the stream is pipeable. |
| `--format <csv\|json\|csv,json>` | `AUDIT_FORMAT` | `csv` | `csv` is a directory of tables for a person; `json` is one `report.json` for a machine; `csv,json` writes both into `--out` from the same run. Anything else — and `csv,json` with `--stdout` — is rejected before the audit runs. |
| `--sections <list>` | `AUDIT_SECTIONS` | all the mode runs | Comma-separated subset of `system,updates,vulnerabilities,ports,services,witness`. Order is normalised — see below. `witness` is accepted only in a Compose preflight, and a Compose preflight must include it — see [Modes](#modes). |
| `--services-all` | `AUDIT_SERVICES_ALL` | `false` | Include inactive service units, not only running ones. |

`--sections` is reordered to the canonical run order regardless of how it is
written, because later sections consume what earlier ones built: the vulnerability
section reuses the installed-package inventory, and `witness` reuses the
listening sockets and the service units rather than gathering them a second time.
Selecting `witness` without `ports` is allowed and degrades the section with a
note — port conflicts are the most useful thing it has, and a conflict list that
was never populated must not read as a short one.

`--format json` writes `report.json` **instead of** the CSV files. To have both,
use `--format csv,json`: the tables and `report.json` are rendered from one audit,
so they carry the same `Checked at`, the same PIDs and the same evidence timestamps.
Two separate runs — one per format — are two audits, seconds apart, and can
disagree.

## Modes

| Flag | Environment | Default | Meaning |
|---|---|---|---|
| `--mode <host-audit\|compose-preflight>` | `AUDIT_MODE` | `compose-preflight` with `--compose`, `host-audit` without | Which kind of run this is. `host` and `preflight` are accepted as short forms. |

- **`host-audit`** — the host on its own. No Compose file is read and the witness
  section is not run: it is outside the scope of this mode. Default sections: all
  but `witness`. The `witness` and `preflight` rows of `summary.csv` are
  `not-applicable` with a note opening `host-audit:`, the upload carries no
  `witness` collector, and nothing counts the absent comparison as a gap — see
  [08](08-report-format.md#summarycsv).
- **`compose-preflight`** — the host, plus a comparison of `--compose` with it.
  The witness section always runs.

Every combination that would let one mode pass for the other is a usage error
(exit `2`), reported before anything is collected:

| Given | Why it is refused |
|---|---|
| `witness` in `--sections`, no `--compose` | The section is the comparison; without a file there is nothing to compare. |
| `--mode compose-preflight`, no `--compose` | Same. This is how a scheduled job asserts it is a preflight: an `AUDIT_COMPOSE` that went missing stops the run instead of quietly turning it into a host audit. |
| `--mode host-audit` with `--compose` (or `AUDIT_COMPOSE`) | A host audit reads no Compose file; a file given anyway would be silently ignored. |
| `--compose` with a `--sections` that leaves out `witness` | A preflight that does not compare is not a preflight. |
| A `--compose` path that is missing, a directory, or unreadable | The preflight has no input. |
| A `--compose` file that does not parse (not YAML, a top level that is not a mapping, an empty file) | Same — checked after the network plan is printed and before the first section runs. **No report is written.** |

A file that parses but has problems inside — one unparsable port, an `include:`
that is not followed — is not refused: the preflight runs and its `witness` row is
`partial` with the reason.

What an explicitly requested preflight (`--mode compose-preflight --compose <file>
--out ./report`) prints for each broken input, verbatim from the 1.3.x binary; in
every case the exit code is `2` and `./report` is not created:

| Input | Output (stderr) |
|---|---|
| file missing | `deploy-witness: --compose "./missing.yml": the Compose preflight needs a readable Compose file: stat ./missing.yml: no such file or directory` |
| file unreadable (mode `0000`, unprivileged) | `deploy-witness: --compose "./locked.yml": the Compose preflight needs a readable Compose file: open ./locked.yml: permission denied` |
| a directory | `deploy-witness: --compose "./.": the Compose preflight needs a Compose file, and this is not a regular file` |
| not YAML (`services: [unclosed`) | the `network: none …` line, then `ERROR the Compose preflight cannot start, the Compose file could not be parsed: <abs path>: yaml: line 1: did not find expected ',' or ']'; no report was written` |
| top level is a list | same, ending `…: expected a compose file at the top level, got a sequence; no report was written` |
| empty (comments only) | same, ending `…: the file declares nothing; no report was written` |

The first three are refused while the flags are read, so nothing else is printed;
the last three after the network plan and before the first section.

## Witness

| Flag | Environment | Default | Meaning |
|---|---|---|---|
| `--compose <path>` | `AUDIT_COMPOSE` | none | The `docker-compose.yml` the `witness` section compares this host against; giving it makes the run a Compose preflight. The file is checked at startup — missing, unreadable or unparseable is exit code `2` with no report, not a degraded section — and the path is resolved to an absolute one. Its directory is the project directory: `.env` is looked for there, relative `env_file` paths resolve against it, and its **name** becomes the Compose project name, which is how the section tells "this port is taken by something else" from "this port is taken by the previous version of this very deployment". |
| `--egress` | — | `false` | Permit the one outbound check: a TCP connect to each registry the manifest pulls from — port 443, or the port the image reference names (`registry.local:5000/app`) — 5 s per registry. The address actually dialled is what the evidence and the section note name. No TLS handshake, no HTTP request, no authentication, no image manifest fetched. Without it the reachability rule reports "not checked" rather than concluding anything. |

Without `--compose` the run is a host audit and the witness section is out of its
scope (see [Modes](#modes)); the report says so in its `report` row and in the
`preflight` and `witness` rows, both `not-applicable`.

## Vulnerabilities

| Flag | Environment | Default | Meaning |
|---|---|---|---|
| `--vuln-db <path>` | `AUDIT_VULN_DB` | none | An offline OSV dataset: a `.json` or `.jsonl` file, a `.gz`, a `.zip` export, or a directory of OSV records (searched recursively). |
| `--online` | — | `false` | Additionally query the OSV API, and run `debsecan` (Debian/Ubuntu) or `arch-audit` (Arch) if installed — both download their advisory data on every call, so without `--online` they are not run and the section says so. |
| `--osv-url <url>` | — | `https://api.osv.dev` | OSV API base URL. Used only with `--online`. Must be `https://` (`http://` only for a loopback host); a redirect is not followed. |
| `--ecosystem <name>` | `AUDIT_ECOSYSTEM` | derived | Override the OSV ecosystem, e.g. `Debian:12`. Needed on distributions OSV does not publish. |
| `--min-severity <level>` | `AUDIT_MIN_SEVERITY` | `low` | Drop findings below this level: `low`, `medium`, `high`, `critical`. Ungraded findings are never dropped. |
| `--max-osv-lookups <n>` | `AUDIT_MAX_OSV_LOOKUPS` | `1500` | Cap on advisory detail requests per run, with `--online`. When it bites, `summary.csv` says so. |

## Upload

| Flag | Environment | Default | Meaning |
|---|---|---|---|
| `--upload <base-url>` | — | none | Send the report to a witness service. One `POST` to `<base-url>/api/public/audit/upload`, `Content-Type: application/json`, 30 s timeout, no retries. Needs a token. `https://` only — `http://` is accepted only for `localhost`, `127.0.0.0/8` or `::1`, for a development stack. No credentials, query or fragment in the URL. Checked before the audit runs (exit `2`). |
| `--upload-token <token>` | `AUDIT_UPLOAD_TOKEN` | none | One-time token authorising the upload. Sent as the `X-Upload-Token` header, never in the URL. Requires `--upload`; from the environment it is used only when `--upload` is typed. |

`--upload` without a token, or `--upload-token` without `--upload`, is a usage
error (exit `2`), because a partially configured upload that silently does nothing
is worse than a refusal to start.

**Pass the token through the environment.** A token typed as `--upload-token` sits
in the shell history and in `/proc/<pid>/cmdline`, which every local user can read
while the audit runs. `AUDIT_UPLOAD_TOKEN` keeps it out of the process list (the
environment of a process is readable only by its owner and root). Read it without
echoing it, and remember that `sudo` drops the environment unless told otherwise:

```bash
read -rs AUDIT_UPLOAD_TOKEN && export AUDIT_UPLOAD_TOKEN
sudo --preserve-env=AUDIT_UPLOAD_TOKEN deploy-witness --compose /srv/app/docker-compose.yml \
  --upload https://deploywitness.example.com
```

**A redirect is refused, not followed.** If the address answers `3xx`, the upload
fails with exit `3` and the message names where the redirect pointed; neither the
token nor the report is sent there. Give the final address instead.

**The recipient is printed before anything is sent**: the network plan at the start
of the run, and `uploading <n> bytes … to <endpoint>` immediately before the request
(both at info level, so `--quiet` hides them).

What is sent is the `upload` half of the JSON document: the findings with their
evidence, the collector outcomes and their notes, the change list, the rollback plan
and the command journal. That includes the host name, the absolute path of the
`--compose` file (in the evidence), and — through the journal — the image names,
network names, unit names and local user names the commands were run against. The
host inventory, the pending updates and the CVE list are **not** sent. The host is
identified by a salted SHA-256 of `/etc/machine-id`, never the id itself — see
[08 — Report format](08-report-format.md#reportjson). Read it first with
`--format json`.

On success the service's response body is printed to stdout when it is non-empty.
For DeployWitness that is a small JSON document such as
`{"publicToken":"…","level":2,"findings":8,"refused":0,"hostname":"…"}`; the public
token is the report's link, and **anyone holding it can read the report** without
signing in.

## Network behaviour

There are three network paths, each enabled only by a flag typed on the command
line. This is everything the tool, and every command it runs, sends anywhere:

| Mode | Who is contacted | What is sent | Where it is recorded |
|---|---|---|---|
| **Default** (no network flag) | Nobody. | Nothing. No DNS lookup and no network socket: the binary uses only netlink (to list this host's interface addresses) and local unix sockets (D-Bus for `timedatectl`/`systemctl`, the docker/podman socket). Commands that would fetch data are not run (`debsecan`, `arch-audit`) or are pinned to cached metadata (`apt-get -s`, `dnf`/`yum -C`, `zypper --no-refresh`). | Log line `network: none …`; `summary.csv` row `network` = `offline: …`; `network.csv` has all four paths with `Enabled=false`, `Contacts=0`. |
| `--online` | The OSV API at `--osv-url` (default `https://api.osv.dev`). If installed: `debsecan` → `security-tracker.debian.org`, `arch-audit` → `security.archlinux.org` — those addresses are chosen by the distribution tools. | OSV: name, version and ecosystem of **every installed package** (`POST /v1/querybatch`, 1000 per request), then one `GET /v1/vulns/<id>` per advisory found, up to `--max-osv-lookups`; `User-Agent: deploy-witness/<version>`. Feeds: each tool's own download of its advisory data (debsecan's request names the release codename); the comparison with the installed packages happens on this host. | `network.csv`: `osv-api` contacts = HTTP requests sent; `distro-feeds` contacts = tool runs, which also appear in `commands.csv` with `Network=--online`. |
| `--egress` (needs a Compose preflight) | Each registry named by an `image:` in the compose file (`docker.io` for an unqualified image), on port 443 or the port the reference names. | A DNS lookup through the system resolver, then one TCP connect, closed at once. No TLS, no HTTP, not a byte of payload. | `network.csv`: recipients as `host:port`, contacts = connects; the section note and the finding's evidence name the same `host:port`. |
| `--upload` | Exactly `<base-url>/api/public/audit/upload`, as typed. | One `POST`: the `upload` half of the report (see above) and the `X-Upload-Token` header. | The recipient line before sending; the outcome on stdout and in the exit code. `network.csv` lists the recipient — the upload happens after the report is written, so its contacts column stays `0`. |

Rules the three paths share:

- **Typed flags only.** No environment variable enables a path or chooses a
  recipient (see the top of this page).
- **`https://` only** for `--osv-url` and `--upload`. Plain `http://` is accepted
  only for a literal loopback host (`localhost`, `127.0.0.0/8`, `::1`), where
  nothing crosses a network: a development stack, or a test. A name that merely
  resolves to loopback does not count.
- **No redirects.** A `3xx` answer is an error naming where it pointed; nothing is
  re-sent there.
- **Recipients first.** The plan is logged before the audit starts, and the same
  table is written to `network.csv`.
- **Proxies.** `--online` and `--upload` honour `HTTPS_PROXY`/`HTTP_PROXY`/
  `NO_PROXY`; the proxy's `host:port` is printed next to the recipient (never its
  credentials). Through a proxy the request stays TLS end to end; the proxy learns
  the destination host, not the content. `--egress` always dials directly.

Child processes:

- `DOCKER_HOST` or `CONTAINER_HOST` pointing anywhere but a `unix://` socket is
  removed from the environment of every command the audit runs, with a warning: the
  docker and podman commands on the allowlist are asked about this host's local
  engine only. **Not covered:** a docker *context* selected in `~/.docker/config.json`
  that points at a remote engine — the docker CLI follows it. Check
  `docker context show` before auditing a host where that may be set.
- `--commands` marks the commands that reach the network themselves
  (`network: yes — runs only with --online`), and the Runner refuses them on a run
  without that flag.

### Checking it yourself

- Read `network.csv` and the `network` row of `summary.csv` in the report.
- Trace a run: `strace -f -e trace=connect,sendto,sendmsg -o trace.txt deploy-witness …`
  and look for `AF_INET`/`AF_INET6`. On a default run the only such lines are
  OpenSSH's `sshd -T` probing its address families with a UDP `connect` to
  `0.0.0.0:65535` / `[::]:65535`, which sends no packet.
- `unshare -rn deploy-witness …` runs the audit with no network at all. That proves
  it *works* offline, not that it would not *try*: use the trace for that.
- In the source, `app/netpath/static_test.go` fails the build's tests if a network
  API appears in any file other than the three network paths.

## Behaviour

| Flag | Environment | Default | Meaning |
|---|---|---|---|
| `--timeout <duration>` | `AUDIT_TIMEOUT` | `60s` | Per-command timeout, e.g. `30s`, `2m`. Must be positive. A command that hits it is recorded in `commands.csv` with outcome `timeout`. |
| `--verbose` | `AUDIT_VERBOSE` | `false` | Log every probe. |
| `--quiet` | `AUDIT_QUIET` | `false` | Log errors only. Wins over `--verbose`. |
| `--commands` | — | — | Print every command this binary is able to run, and exit. The list printed is the list enforced; nothing else can be executed. See [09](09-command-allowlist.md). |
| `--version` | — | — | Print the version and exit. |
| `-h`, `--help` | — | — | Print usage and exit. |

## Exit codes

| Code | Meaning |
|---|---|
| `0` | The report was written. Sections may still carry notes in `summary.csv`. |
| `1` | The report was written, but at least one section failed outright. |
| `2` | Bad arguments — including an `--upload`/`--osv-url` address that is not `https://`, a mode conflict, or a `--compose` file that is missing, unreadable or does not parse (no report is written) — or the report could not be written. |
| `3` | The report was written, but `--upload` could not deliver it — including when the address answered with a redirect, which is never followed. |

A `partial` section does not change the exit code — a partial section still
produced usable rows. Read `summary.csv` to see which.

`3` takes precedence over `1`: the upload is attempted after the report is
written, and its failure is what the operator needs to know first, since the whole
point of the command they typed was to deliver the file. The report is on disk
either way.

A refused command does **not** change the exit code. It is a defect in this tool
rather than a property of the host, and it surfaces as an error-level log line and
a `refused` row in `commands.csv`.

## Examples

```bash
# Host audit: everything about the host, into a timestamped directory. Not a preflight.
sudo deploy-witness

# What can this binary do to my server? Answered without running it.
deploy-witness --commands

# Only what is exposed to the network, piped straight into a spreadsheet tool.
deploy-witness --sections ports,services --stdout > exposure.csv

# Compose preflight: check a deployment against this host before deploying it.
sudo deploy-witness --compose /srv/app/docker-compose.yml

# The same, for a scheduled job that must never degrade into a host audit.
sudo deploy-witness --mode compose-preflight --compose /srv/app/docker-compose.yml

# The witness section only, and test whether the registries are reachable.
sudo deploy-witness --sections ports,services,witness \
  --compose /srv/app/docker-compose.yml --egress

# One JSON document, so the operator can read exactly what an upload would send.
sudo deploy-witness --compose /srv/app/docker-compose.yml --format json

# Same run, delivered to a witness service. Exit 3 means it was written but not sent.
# The token comes from the environment, so it never appears in the process list.
read -rs AUDIT_UPLOAD_TOKEN && export AUDIT_UPLOAD_TOKEN
sudo --preserve-env=AUDIT_UPLOAD_TOKEN deploy-witness --compose /srv/app/docker-compose.yml \
  --upload https://deploywitness.example.com

# Critical findings only, using an offline OSV export.
sudo deploy-witness --vuln-db /var/lib/osv/all.zip --min-severity critical

# All three vulnerability feeds at once.
sudo deploy-witness --vuln-db /var/lib/osv/all.zip --online

# On Arch, forcing an ecosystem OSV does publish (see 07).
deploy-witness --sections vulnerabilities --ecosystem Arch --vuln-db ./arch-osv/

# Unattended, quiet, exit code checked by the caller.
deploy-witness --quiet --out /var/log/deploy-witness/$(date -u +%F) || echo "audit degraded"
```
