# 4. CLI reference

```
deploy-witness [flags]
```

Almost every flag also reads an `AUDIT_`-prefixed environment variable. The flag
wins; the environment variable is the fallback; the documented default applies
when neither is set. An empty environment variable counts as unset, and a value
that cannot be parsed as a boolean or an integer falls back to the default
silently. `--version` and `--commands` are the two exceptions: they have no
environment variable, because a flag that makes the tool print and exit is not
something an image should be able to switch on.

## Output

| Flag | Environment | Default | Meaning |
|---|---|---|---|
| `--out <dir>` | `AUDIT_OUT` | `./audit-<host>-<UTC timestamp>` | Directory to write the report into. Created if missing. |
| `--stdout` | `AUDIT_STDOUT` | `false` | Write the report to stdout instead of a directory. Diagnostics go to stderr, so the stream is pipeable. |
| `--format <csv\|json>` | `AUDIT_FORMAT` | `csv` | `csv` is a directory of tables for a person; `json` is one `report.json` for a machine. Anything else is rejected before the audit runs. |
| `--sections <list>` | `AUDIT_SECTIONS` | all | Comma-separated subset of `system,updates,vulnerabilities,ports,services,witness`. Order is normalised — see below. |
| `--services-all` | `AUDIT_SERVICES_ALL` | `false` | Include inactive service units, not only running ones. |

`--sections` is reordered to the canonical run order regardless of how it is
written, because later sections consume what earlier ones built: the vulnerability
section reuses the installed-package inventory, and `witness` reuses the
listening sockets and the service units rather than gathering them a second time.
Selecting `witness` without `ports` is allowed and degrades the section with a
note — port conflicts are the most useful thing it has, and a conflict list that
was never populated must not read as a short one.

`--format json` writes `report.json` **instead of** the CSV files, not alongside
them.

## Witness

| Flag | Environment | Default | Meaning |
|---|---|---|---|
| `--compose <path>` | `AUDIT_COMPOSE` | none | The `docker-compose.yml` the `witness` section compares this host against. The path is checked at startup — a missing file is exit code `2`, not a degraded section — and resolved to an absolute path. Its directory is the project directory: `.env` is looked for there, relative `env_file` paths resolve against it, and its **name** becomes the Compose project name, which is how the section tells "this port is taken by something else" from "this port is taken by the previous version of this very deployment". |
| `--egress` | `AUDIT_EGRESS` | `false` | Permit the one outbound check: a TCP connect to port 443 of each registry the manifest pulls from, 5 s per registry. No TLS handshake, no HTTP request, no authentication, no image manifest fetched. Without it the reachability rule reports "not checked" rather than concluding anything. |

Without `--compose` the section is `skipped` and says so; everything else in the
report still applies.

## Vulnerabilities

| Flag | Environment | Default | Meaning |
|---|---|---|---|
| `--vuln-db <path>` | `AUDIT_VULN_DB` | none | An offline OSV dataset: a `.json` or `.jsonl` file, a `.gz`, a `.zip` export, or a directory of OSV records (searched recursively). |
| `--online` | `AUDIT_ONLINE` | `false` | Additionally query the OSV API. |
| `--osv-url <url>` | `AUDIT_OSV_URL` | `https://api.osv.dev` | OSV API base URL. Used only with `--online`. |
| `--ecosystem <name>` | `AUDIT_ECOSYSTEM` | derived | Override the OSV ecosystem, e.g. `Debian:12`. Needed on distributions OSV does not publish. |
| `--min-severity <level>` | `AUDIT_MIN_SEVERITY` | `low` | Drop findings below this level: `low`, `medium`, `high`, `critical`. Ungraded findings are never dropped. |
| `--max-osv-lookups <n>` | `AUDIT_MAX_OSV_LOOKUPS` | `1500` | Cap on advisory detail requests per run, with `--online`. When it bites, `summary.csv` says so. |

## Upload

| Flag | Environment | Default | Meaning |
|---|---|---|---|
| `--upload <base-url>` | `AUDIT_UPLOAD` | none | Send the report to a witness service. One `POST` to `<base-url>/api/public/audit/upload`, `Content-Type: application/json`, 30 s timeout, no retries. Requires `--upload-token`. |
| `--upload-token <token>` | `AUDIT_UPLOAD_TOKEN` | none | One-time token authorising the upload. Sent as the `X-Upload-Token` header, never in the URL — a URL ends up in proxy logs and in shell history. Requires `--upload`. |

Giving one without the other is a usage error (exit `2`), because a partially
configured upload that silently does nothing is worse than a refusal to start.

What is sent is the `upload` half of the JSON document: the findings with their
evidence, the collector outcomes, the change list, the rollback plan and the
command journal. The host inventory, the pending updates and the CVE list are
**not** sent. The host is identified by a salted SHA-256 of `/etc/machine-id`,
never the id itself — see [08 — Report format](08-report-format.md#reportjson).

On success the service's response body is printed to stdout when it is non-empty;
that is the URL of the stored report.

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
| `2` | Bad arguments, or the report could not be written. |
| `3` | The report was written, but `--upload` could not deliver it. |

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
# Everything, into a timestamped directory.
sudo deploy-witness

# What can this binary do to my server? Answered without running it.
deploy-witness --commands

# Only what is exposed to the network, piped straight into a spreadsheet tool.
deploy-witness --sections ports,services --stdout > exposure.csv

# Check a deployment against this host before deploying it.
sudo deploy-witness --compose /srv/app/docker-compose.yml

# The witness section only, and test whether the registries are reachable.
sudo deploy-witness --sections ports,services,witness \
  --compose /srv/app/docker-compose.yml --egress

# One JSON document, so the operator can read exactly what an upload would send.
sudo deploy-witness --compose /srv/app/docker-compose.yml --format json

# Same run, delivered to a witness service. Exit 3 means it was written but not sent.
sudo deploy-witness --compose /srv/app/docker-compose.yml \
  --upload https://deploywitness.example.com --upload-token "$TOKEN"

# Critical findings only, using an offline OSV export.
sudo deploy-witness --vuln-db /var/lib/osv/all.zip --min-severity critical

# All three vulnerability feeds at once.
sudo deploy-witness --vuln-db /var/lib/osv/all.zip --online

# On Arch, forcing an ecosystem OSV does publish (see 07).
deploy-witness --sections vulnerabilities --ecosystem Arch --vuln-db ./arch-osv/

# Unattended, quiet, exit code checked by the caller.
deploy-witness --quiet --out /var/log/deploy-witness/$(date -u +%F) || echo "audit degraded"
```
