# Verification matrix — what the site may claim about the CLI

One row per public claim or check. A claim may appear on the site only with status
**Verified** or **Verified with limitations**, and only together with its
limitation. The base is the DW-37 matrix (CLI 1.1.1); every row says whether it was
re-run for this kit or is carried over from DW-37.

## Statuses

| Status | Meaning |
|---|---|
| **Verified** | Positive and negative outcome reproduced on a real host; no defect that breaks the result. |
| **Verified with limitations** | Reproduced, but with a documented blind spot, a minor defect, or part of the outcomes only by simulation / unit test. The limitation must be published with it. |
| **Not ready** | A reproduced defect gives a false blocker or a false clean result — do not claim until fixed. |
| **Not verified** | Implemented (from documented formats and fixtures), never run on a real host of that kind. |
| **Not supported** | The CLI does not do it. |

## Environments

| Id | CLI | Host | Privileges | Docker | Date |
|---|---|---|---|---|---|
| **K** (this kit) | `deploy-witness 1.4.0` built from `364f143` (release 1.4.0) | Manjaro (Arch family), kernel 6.18, x86_64, systemd | unprivileged, `docker` group | Engine 29.7.2, Compose 5.5.0 | 2026-10-11 |
| **D37** (carried over) | `deploy-witness 1.1.1`, `49d0652` | same host family (Manjaro), x86_64 | unprivileged, `docker` group | Engine 29.7.2, Compose 5.5.0 | 2026-10-03 / 2026-10-05 |

**Privileged runs: not verified.** No run in K or D37 was made as root, and no
recorded output of a privileged run exists. Everything that needs root (process
owner of other users' sockets, `/etc/shadow`, sudoers, `sshd -T`, `nft list
ruleset`, `/etc/letsencrypt`, other users' crontabs, backup directories) was seen
only in its "not readable" form. **Distributions: only Arch family.** Debian/Ubuntu,
RHEL family, SUSE and Alpine are not verified.

Scenario ids `a`…`e` are the directories under [`outputs/`](outputs) (see
[README](README.md#scenarios)); `K:adhoc` are the one-off checks listed at the
bottom; `S-xx`/`c01…` are the DW-37 scenarios.

## Run modes and cross-cutting promises

| Claim | Status | Verified on | Proof | Limitation to publish |
|---|---|---|---|---|
| Two modes: a run with `--compose` is a **Compose preflight**, without it a **host audit**, and the report says which | Verified | K | `a`…`e`: log `mode: Compose preflight of …`, `summary.csv` `preflight` row; K:adhoc host audit: `preflight,not-applicable` and `witness,not-applicable` with `host-audit: not applicable`, no `witness` collector in the upload | — |
| A preflight with no usable input stops (exit `2`, no report) instead of degrading | Verified | K | K:adhoc: missing file, `chmod 000`, broken YAML, `--compose` without `witness`, `witness` without `--compose` → all exit 2, no report directory | — |
| **Checks, does not deploy**: only read commands, nothing created on the host | Verified | K | `a`…`e` `commands.csv`: 66–67 / 12 commands, all read-only, none of `docker run/create/pull/start`, `compose up/pull/run/create`; `docker ps -a`, `network ls`, `volume ls`, `images` identical before and after `run.sh` | — |
| **Offline by default**: no network contact without `--online`/`--egress`/`--upload` | Verified with limitations | K, D37/DW-39 | `a`…`e`: log `network: none …`, `summary.csv` `network` = `offline: …`, `network.csv` all paths disabled, `Contacts=0`; `make test` includes `app/netpath/static_test.go` | Syscall trace not repeated in K (`strace` not installed); see DW-39/DW-72. A docker *context* pointing at a remote engine is followed by the docker CLI (documented in `04-cli-reference`) |
| Opt-in network paths (`--online` OSV API, `--egress` registry connect) | Verified with limitations | D37 | S-12 (`--egress` against local listeners), S-17 (`--online` against a local OSV mock) | Never run against the real `api.osv.dev` or a real registry. Not re-run in K; the D9 evidence fix (DW-50) is unit-tested only |
| `--upload` | Not verified (here) | — | not part of this kit | Covered by the DeployWitness service tasks, not by this matrix |
| Every command the binary can run is on a published allowlist | Verified with limitations | K | `--commands`: 68 commands; every journal row `ok`/`failed`, none `refused` | The `refused` outcome has never been observed on a real run; DW-45 can rewrite an image name inside a journal line |
| **Honest gaps**: what could not be checked is reported, not shown as clean | Verified with limitations | K | `c1`: engine unreachable → no `container_name_conflict` although the container exists, warning `runtime_missing_or_old` + "lists are unknown rather than empty", `partial`; `c2`: no `ports` → "port conflicts could not be checked", `partial`; ports note "N processes were not readable" | **Fails for external volumes and networks** (`d2`, DW-43): they are declared missing on the unknown list. Publish the claim only without them |
| Unprivileged runs work and say what they missed | Verified | K | `a`: `ports` note "370 processes were not readable … run as root", witness notes on unmeasured mount points and other users' crontabs | — |
| Exit code | Verified | K | exit `0` in every scenario, including with blockers | **Not supported: failing a pipeline on a blocker.** `0` means "report written"; CI must read `summary.csv`/`witness.csv` |
| JSON report (`--format json`, `--format csv,json`) | Verified | K | `report.json` in every scenario, written in the same run as the CSV files (`csv,json`), `audit.mode` set | — |
| Credential masking before writing | Verified with limitations | K | `a`: "masked credential-looking material in 1 field(s)" | False positive on image names containing token/secret/pass (DW-45) — seen in K on a host image |
| What the deployment will change (`changes.csv`) and how to undo it (`rollback.csv`) | Verified with limitations | K, D37 | `a`: foreign container `not created …`, held port `not opened …`; `b`: `created`, `opened`; `c1`: name "could not be checked"; `c2`: port "was not checked"; `rollback.csv` `unknown` for what cannot be seen | A local image under another spelling is listed as "to pull" (DW-44, S-23). "Replaced" for this project's own container: unit test only |

## Witness rules (Compose preflight)

| Check | Status | Verified on | Proof | Limitation to publish |
|---|---|---|---|---|
| Port conflicts (`port_conflict`) | Verified with limitations | K, D37 | `a` blocker with compose + socket evidence; `b` none; `c1` still found without Docker; `c2` "could not be checked"; D37: 17-case DW-24 matrix (address, protocol, IPv6, ranges, own project) | Needs the `ports` section. `[::]` listeners and the daemon's IPv6 setting give a warning, not a verdict. Without root another user's socket owner is unidentified |
| Container names (`container_name_conflict`) | Verified with limitations | K, D37 | `a` blocker with `docker ps -a` evidence; `b` none; `c1` not checked (warning instead); D37: own project → info | Project = directory name; neither `-p` nor top-level `name:` is honoured. Needs a reachable engine |
| External volumes (`volume_name_conflict`) | **Not ready** | K | `d1`: `name:` ignored → false blocker (DW-42); `d2`: unreachable engine → false blocker (DW-43) | Do not claim |
| External networks (`network_name_conflict`) | **Not ready** | D37 | S-03/S-09: same two defects as volumes; not re-run in K | Do not claim |
| Subnet overlaps (`subnet_overlap`) | Verified with limitations | K, D37 | `e`: `10.250.73.0/24` vs network `dwkit-net` → blocker; D37 S-06 none | Compared with Docker networks only, not routes/VPNs |
| Sensitive bind mounts (`bind_path_conflict`) | Verified | K | `e`: `/etc`, `/var/run/docker.sock` → warning ×2; `a` none | Absolute paths only |
| Memory (`insufficient_memory`) | Verified | K, D37 | `e`: 100 GiB reservation → blocker; `a` (256M limit) none; D37: nothing declared → info | Declared, not measured, usage |
| Disk use (`disk_at_limit`) | Verified | D37 | S-03/S-06 warning at 92 %; K: none (disk has room) | Mount points the account cannot enter are listed as unmeasured |
| Inodes (`insufficient_inodes`) | Verified with limitations | D37 | negative on real host; positive only in unit tests | btrfs/XFS not judged |
| Disk for images (`insufficient_disk`) | **Not ready** | D37 | DW-44 | Do not claim |
| Architecture (`architecture_mismatch`) | Verified with limitations | K, D37 | `e`: `platform: linux/arm64` on x86_64 → blocker | The "image already on disk" branch: unit tests only |
| Runtime / Compose present (`runtime_missing_or_old`) | Verified with limitations | K, D37 | `c1`: engine not answering → warning; D37 S-10/S-11: no engine / no Compose / Compose V1 (simulated via `PATH` stubs) | Docker only; Podman not verified |
| Registry reachability (`registry_unreachable`) | Verified with limitations | K, D37 | `a`…`e`: info "not checked" without `--egress`; D37 S-12: blocker for a closed local port | TCP connect only; a successful connect does not prove a pull will work |
| Web-server ports (`proxy_conflict`) | Verified with limitations | D37 | S-13 (Apache, TCP → blocker), S-07 (UDP → warning low) | Apache only; nginx on the host and control panels not verified; DW-49 evidence label |
| Domains (`domain_conflict`) | **Not ready** | — | positive outcome never observed | Do not claim |
| `env_file` missing (`env_file_missing`) | Verified | K | `e` blocker; `a` none (no `env_file`) | Path checked, contents never read |
| No healthcheck (`no_healthcheck`) | Verified | K | `e` warning; `a`/`b` none (healthcheck declared) | — |
| Floating image tag (`floating_image_tag`) | Verified with limitations | K | `e` `nginx:latest` → warning; `a` `1.27-alpine` → info; D37 digest → none | DW-45 can mask names with token/secret/pass |
| Host-level authority (`privileged_container`) | Verified | K | `e`: `privileged` + docker socket → blocker | — |
| Rollback plan (`no_rollback_plan`) | Verified | K | `a`, `b`, `c1`, `c2`: info "2 of 4 unverified"; `d1`, `d2`, `e`: warning "1 of 4 missing" (persistent data, no backup location) | Present on every preflight by design: a provider snapshot cannot be seen from inside the host, so it is "unable to verify" — never claimed missing |
| Database versions (`database_version_mismatch`) | **Not ready** | — | never fires for containerised DBs, mongodb, redis | Do not claim |
| Backups (`backup_gap`) | **Not ready** | D37 | DW-46 | Do not claim |
| Certificates (`certificate_expiring`) | **Not ready** | — | unit tests only | Do not claim |
| Reboot required (`reboot_required`) | **Not ready** | — | no source on the test host | Do not claim |

## Host-audit sections

| Check | Status | Verified on | Proof | Limitation to publish |
|---|---|---|---|---|
| Host inventory (OS, kernel, hardware, filesystems, interfaces) | Verified | D37, K:adhoc | S-01; K host audit: `system,partial,79` | Every row names its source |
| Accounts, SSH, firewall posture | Verified with limitations | D37 | S-01 | Without root: shadow, sudoers, `sshd -T`, nft ruleset not readable (said so); DW-47, DW-48 |
| Listening ports | Verified with limitations | K | `a`…`e`, K:adhoc | Without root, other users' socket owners are unknown |
| Services (systemd) | Verified | D37, K:adhoc | S-01; K: `services,ok,56` | — |
| Services (OpenRC, SysV) | Not verified | — | — | — |
| Pending updates — pacman | Verified with limitations | D37, K:adhoc | S-01, S-14; K: `updates,ok` "no repository refresh was performed" | As fresh as the local sync DB |
| Pending updates — apt, dnf, zypper, apk | Not verified | — | parsers written from documented formats | Do not claim |
| Vulnerabilities — offline OSV dataset (`--vuln-db`) | Verified with limitations | D37 | S-16 | Synthetic dataset; Arch/Fedora need `--ecosystem` |
| Vulnerabilities — distribution feeds | **Not ready** | D37 | S-15 (stub only); since DW-53 they run only with `--online` | Do not claim |
| macOS / Windows hosts | Not supported (audit) | — | `dist/` has builds for them, but collectors read Linux paths; most sections come back `partial`/`skipped` | Linux only |
| Podman, hosting control panels, backup tools | Not verified | — | recognised from documented layouts / markers | Do not claim |

## K:adhoc — one-off checks on this commit (not in `outputs/`)

The host audit was re-run on 2026-10-11 with the 1.4.0 binary; the other rows were
run on 2026-10-10 with the previous kit binary and re-checked for 1.4.0 by the
end-to-end tests in `main_test.go` (their verbatim 1.4.0 output is in
`docs/<lang>/04-cli-reference.md`). Outputs not kept (a host audit is all host
inventory):

| Command | Result |
|---|---|
| `deploy-witness --out h1` | exit 0; `mode: host audit — no --compose was given; comparing a planned deployment with this host (the witness section) is outside the scope of this run`; `preflight,not-applicable`, `witness,not-applicable` (`host-audit: not applicable …`); `system,partial,79`, `updates,ok`, `vulnerabilities,partial` ("pacman ships no local security metadata reader" — DW-51), `ports,partial,146`, `services,ok,56` |
| `--compose ./nope.yml` | exit 2, "needs a readable Compose file: stat ./nope.yml: no such file or directory", no report |
| `--compose bad/docker-compose.yml` (`services: [`) | exit 2, "the Compose file could not be parsed … no report was written" |
| `--compose locked/docker-compose.yml` (`chmod 000`) | exit 2, "open …: permission denied", no report |
| `--sections ports --compose …` | exit 2, "--sections leaves witness out" |
| `--sections witness` (no `--compose`) | exit 2, "needs --compose" |
| `--commands` | "can run exactly these 68 commands and nothing else" |
