# Site materials — verified runs for examples and public claims

Every example and every capability the DeployWitness site publishes about the CLI
must trace back to a run in this directory. Nothing here is written by hand except
this README, [MATRIX.md](MATRIX.md), the Compose files and the two scripts: every
file under `outputs/` is what `deploy-witness` produced, sanitised as described in
[Sanitisation](#sanitisation).

The kit is in English; a short Russian summary is at the end.

| Path | What it is |
|---|---|
| [`run.sh`](run.sh) | Recreates every host state, runs every scenario, cleans up, sanitises into `outputs/` |
| [`sanitize.py`](sanitize.py) | Trims host-wide inventories and replaces machine identifiers with placeholders |
| [`scenarios/`](scenarios) | The Compose files: `orders/` (conflict / no conflict / insufficient data), `shop/` (external volume), `rules/` (manifest rules) |
| [`outputs/`](outputs) | One directory per scenario: `terminal.txt`, every CSV file, `report.json`, `TRIMMED.md` |
| [`MATRIX.md`](MATRIX.md) | Each public claim → verified on what, by which scenario, or not verified / not supported |

## The CLI these materials were produced with

| | |
|---|---|
| `deploy-witness --version` | `deploy-witness 1.2.0` |
| Source | commit `5ab9f51f3228e85a2449a193832a304caba007ef` (branch `task/DW-70`: 1.2.0 + the Unreleased changes DW-50, 53, 56, 57, 62, 70, 72). DW-73 adds this directory only — no code changed |
| Build | `make build` → `CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=1.2.0"`, Go 1.26.6 linux/amd64; binary sha256 `4e04cbf342ca53730ab5e208ce1955b53fd5759563f024f33130eef365143647` |
| Allowlist | `deploy-witness --commands`: "can run exactly these 68 commands and nothing else" |
| `make test`, `make vet`, `make lint` | green on that commit |
| Run date | 2026-10-10, UTC timestamps in every file |

**How the version is stamped, and why "1.2.0" here is not the released 1.2.0.** The
`Makefile` takes the first *numbered* heading of `CHANGELOG.md`
(`sed -n 's/^## \[\([0-9][^]]*\)\].*/\1/p' | head -1`) and passes it as
`-X main.version`. `## [Unreleased]` is not numbered, so a tree with unreleased
changes is stamped with the **previous** release — 1.2.0 — although it contains the
mode split (DW-70) and the network changes (DW-72) that 1.2.0 does not. The
`summary.csv` `report` row, the `producer` field of `report.json` and the log lines
all say 1.2.0 for that reason. The binaries committed in `dist/` *are* 1.2.0 and do
not behave like these outputs (no `mode:` line, no `preflight` row, no `network.csv`).
**Before the site quotes a version number, cut the release that contains these
changes and re-run `run.sh` on it**; the outputs will differ only in the version
string, timestamps, PIDs and host-specific numbers.

## Test host

| | |
|---|---|
| OS | Manjaro Linux (Arch family), kernel 6.18, x86_64, systemd; package manager pacman |
| Privileges | **unprivileged** user, member of the `docker` group. No run in this kit is privileged (no root was available) |
| Container runtime | Docker Engine 29.7.2, Compose plugin 5.5.0 |
| Other software that shows in the outputs | Apache 2.4.68 installed but inactive (`/etc/httpd`) — the reason `no_rollback_plan` counts `proxy-config`; restic and duplicity installed |
| Network | `deploy-witness` ran with no `--online`, `--egress` or `--upload` in every scenario |

## Reproducing

Requirements: Linux with Docker that answers for your user (`docker info`), `python3`,
`ss` and `ip` (iproute2), host port 8080 free, no container named `orders-api`, no
volume `dwkit-data`, no network `dwkit-net` and no docker network on
`10.250.73.0/24`, and the image `alpine:3.21` already local (or another local image
in `DW_BLOCKER_IMAGE`). The script refuses to start otherwise, so it never touches
anything it did not create, and it pulls nothing.

```bash
make build                       # in the repository root
docs/site-materials/run.sh       # ~30 s; rewrites docs/site-materials/outputs/
```

`run.sh` creates, and removes on exit (also on failure or Ctrl-C): a `python3 -m
http.server` listener on `0.0.0.0:8080`, a container named `orders-api` that is
created but never started, the volume `dwkit-data` and the network `dwkit-net`. On
the run recorded here, snapshots of `docker ps -a`, `docker network ls`,
`docker volume ls` and `docker images` taken before and after were identical, and
nothing listened on 8080 afterwards.

Every scenario is run **twice in the same host state**: once as CSV and once with
`--format json`, because the tool writes one format per run. `terminal.txt` belongs
to the CSV run, `terminal-json.txt` to the JSON run; timestamps differ by a second
or two. The command shown in `terminal.txt` is the one to publish (`--out
./report`); the script itself passes an absolute `--out` under its scratch
directory, which is why the log says `wrote 12 CSV files to <WORKDIR>/raw/…`.

The unsanitised reports stay in the scratch directory the script prints (`DW_WORK`,
default `mktemp -d`). Delete it when done; never commit it.

## Scenarios

All runs: `deploy-witness --sections ports,witness --compose ./docker-compose.yml`
from the scenario directory, unprivileged, offline, exit code `0` in every one.

| Output | Host state | Command difference | Result (from `witness.csv`) | Proves |
|---|---|---|---|---|
| [`a-conflict`](outputs/a-conflict) | foreign listener on `0.0.0.0:8080`; foreign container `orders-api` | — | **blocker** `witness.port_conflict` `8080/tcp` (evidence: compose line + socket held by `python3`); **blocker** `witness.container_name_conflict` `orders-api` (evidence: compose line + `docker ps -a`); warning `no_rollback_plan`; info `floating_image_tag`, `registry_unreachable` | conflict detected, with evidence |
| [`b-no-conflict`](outputs/b-no-conflict) | both removed | — | no `port_conflict`, no `container_name_conflict`; the other three rows identical to `a` | no conflict within the checks made |
| [`c1-docker-unreachable`](outputs/c1-docker-unreachable) | as `a` | `DOCKER_HOST=unix:///nonexistent/docker.sock` | `port_conflict` still a blocker (sockets come from `/proc/net`); **no** `container_name_conflict` although the container exists; instead warning `witness.runtime_missing_or_old` "docker is installed but did not answer" and the note "the container, network, volume and image lists are unknown rather than empty"; `witness` and `preflight` rows `partial` | insufficient data → "could not check", not a clean result |
| [`c2-ports-not-selected`](outputs/c2-ports-not-selected) | as `a` | `--sections witness` | `container_name_conflict` blocker, **no** `port_conflict`; `witness` row `partial` with "the ports section was not selected, so port conflicts could not be checked" | insufficient data → "could not check" |
| [`d1-external-volume`](outputs/d1-external-volume) | volume `dwkit-data` exists, no project label | `shop/` | `dwkit-data` (key = real name): warning "already holds somebody else's data" — correct. `aliased` (`external: true, name: dwkit-data`): **blocker "does not exist" — false**, known defect DW-42 | **do not publish**: external volumes are Not ready |
| [`d2-external-volume-docker-unreachable`](outputs/d2-external-volume-docker-unreachable) | as `d1` | `shop/` + `DOCKER_HOST=unix:///nonexistent/docker.sock` | runtime warning and the "unknown rather than empty" note — **and** two blockers "External volume … does not exist" built on the list it just called unknown: known defect DW-43 | **do not publish**: the honest-gap promise fails here |
| [`e-manifest-rules`](outputs/e-manifest-rules) | network `dwkit-net` on `10.250.73.0/24` | `rules/` | blockers: `architecture_mismatch` (arm64 on x86_64), `env_file_missing`, `insufficient_memory` (100 GiB), `privileged_container`, `subnet_overlap` (with `dwkit-net`); warnings: `bind_path_conflict` ×2 (`/etc`, docker socket), `floating_image_tag` (`latest`), `no_healthcheck`, `no_rollback_plan` | the manifest-driven rules fire, each with evidence |

What the scenarios also show, in every run: the log line `network: none …`, the
`network` row `offline: …` and `network.csv` with all four paths disabled and `0`
contacts; `commands.csv` contains only read commands (63 in `a`, all `ok`; 12 in
`c1`, two `failed` because the engine is unreachable) and no `docker run/create/pull`
or `compose up/pull/run/create`.

### Which results are deterministic and which belong to this host

Deterministic given the scenario (reproduce on any Linux host with Docker): the two
conflicts and their absence, the `c1`/`c2` gaps, `floating_image_tag`,
`registry_unreachable` (info, "not checked"), and everything in `e` except the
available-memory figure.

Properties of this host, not of the scenario — do not present them as typical:
`no_rollback_plan` "2 of 4" (it is "2 of 4" because Apache is installed; on a host
without a web server the count differs), the `disk-space` line in `changes.csv`, the
available memory, the counts in the `ports` note ("327 processes were not readable",
"21 of 145 … all interfaces"), the witness notes about 17 unmeasured mount points,
`/var/spool/cron` and 122 CA certificates, and the `masked credential-looking
material in 1 field(s)` log line (see below).

### Known defects visible in these outputs

| Where | What | Task |
|---|---|---|
| `a`, `b`, `c2`, `d1`, `e`: log line "masked credential-looking material in 1 field(s)" and one `docker image inspect <host-image-NN>` journal line | `app/redact` rewrites the tag of an image on this host whose name contains "token"; nothing in the scenarios is a secret | DW-45 |
| `a`, `c1`: `changes.csv` `container,orders-api,"replaced (currently created, image alpine:3.21) with nginx:1.27-alpine"` | the foreign container would not be replaced — `docker compose up` fails on the name, as the blocker says | DW-52 |
| `d1` | `name:` of an external volume ignored → false blocker | DW-42 |
| `d2` | unreachable engine → external volumes declared missing | DW-43 |

## What the landing demo (DW-79) should show

Source: [`outputs/a-conflict`](outputs/a-conflict), with
[`outputs/c1-docker-unreachable`](outputs/c1-docker-unreachable) as the
"what we could not check" example and [`outputs/b-no-conflict`](outputs/b-no-conflict)
as the control.

| Demo element | Field |
|---|---|
| Command | the `$ deploy-witness …` line of `terminal.txt` |
| Terminal | the log lines of `terminal.txt` (keep the `network: none` and `mode:` lines; drop or explain the masking line) |
| Context | `summary.csv` row `report`: mode, version, `Checked at`; `preflight` row status; Compose path from `evidence.csv` (`<WORKDIR>` → a demo path such as `/srv/orders`, marked as demo) |
| Finding list | `witness.csv`: `Severity`, `Code`, `Subject`, `Title` — already sorted worst first |
| Finding detail | `Description`, `Why it matters`, `What to do`, `Confidence` |
| Evidence | `evidence.csv` rows of that `Code`: `Command` + `Output` (+ `Captured at`) |
| Raw details | the matching object in `report.json` → `upload.findings[]` |
| Limitations | the `Notes` of the `ports` and `witness` rows in `summary.csv` — a finding has no limitations field of its own |
| Changes / rollback | `changes.csv` without the DW-52 `replaced` row; `rollback.csv` |
| Network | `network.csv` / the `network` row: "offline" |
| Could not check | from `c1`: the `runtime_missing_or_old` finding and its note "lists are unknown rather than empty", next to the missing `container_name_conflict` |

Do not claim: a non-zero exit code on blockers (it is `0` — the code reports
whether the audit ran, `summary.csv`/`witness.csv` carry the verdict); anything from
`d1`/`d2`; a privileged run; any distribution other than Arch-family.

## Sanitisation

Applied by [`sanitize.py`](sanitize.py), the same way to every file of every
scenario in one generation, so a placeholder means the same value everywhere.
Placeholders are always in angle brackets:

| Placeholder | Replaces |
|---|---|
| `<WORKDIR>` | the scratch directory the scenarios ran in (absolute path) |
| `<HOME>`, `<USER>` | the home directory and login name of the account that ran them |
| `<HOSTNAME>` | the machine's host name (`summary.csv` `report` row, `report.json` `server_hostname`/`hostname`) |
| `<SERVER-FINGERPRINT>` | `report.json` `upload.server_fingerprint` — already a salted SHA-256 of `/etc/machine-id`, replaced anyway |
| `<HOST-IPV4-n>`, `<HOST-IPV6-n>` | this machine's interface addresses (loopback kept) |
| `<host-image-NN>`, `<host-image-id-NN>` | images already on the machine, by reference and by short ID — except `nginx:1.27-alpine` and `alpine:3.21`, which the scenarios use |
| `<host-network-NN>`, `<host-volume-NN>`, `<host-container-NN>` | the machine's own docker networks, volumes and containers — except `bridge`, `host`, `none` and what `run.sh` created |

Trimmed (counts per scenario in each `TRIMMED.md`): `ports.csv` and
`report.json` `audit.ports` / `audit.capabilities.ports` keep only the sockets on
port 8080; `report.json` `audit.capabilities` keeps only the scenario's containers,
networks, volumes and images, and drops the machine's scheduled jobs and the
databases found on it. Findings, evidence, notes, changes, rollback, network and the
command journal are never trimmed. The CSV files of sections that were not selected
(`system`, `updates`, `vulnerabilities`, `services`) are header-only because the tool
writes them that way.

Kept as produced: PIDs, timestamps, memory and disk figures, the filesystem device
name, unit names in the `systemctl show` journal line, `/etc/httpd`.

---

## Кратко по-русски

Комплект подтверждённых материалов для сайта (DW-73): реальные прогоны CLI, из
которых берутся примеры и публичные утверждения.

- **Версия:** `deploy-witness 1.2.0` (вывод `--version`), исходники — коммит
  `5ab9f51` (ветка `task/DW-70`). Makefile берёт версию из первого *номерного*
  заголовка CHANGELOG, поэтому дерево с изменениями `Unreleased` (DW-70, DW-72 и др.)
  помечено предыдущим релизом 1.2.0. Это не тот же 1.2.0, что в `dist/`. Перед
  публикацией номера версии на сайте нужно выпустить релиз и перезапустить `run.sh`.
- **Хост:** Manjaro (Arch), без root (группа `docker`), Docker 29.7.2, Compose 5.5.0,
  офлайн-режим.
- **Воспроизвести:** `make build && docs/site-materials/run.sh`. Скрипт создаёт
  слушатель на 8080, контейнер `orders-api`, том `dwkit-data` и сеть `dwkit-net`.
  После прогона всё это удаляется. Чужие объекты скрипт не трогает и ничего не
  скачивает.
- **Сценарии:**
  - `a`: конфликт порта и имени контейнера, оба blocker с evidence;
  - `b`: без конфликта;
  - `c1`: Docker недоступен, проверка имени не выполнена — warning и пометка «unknown rather than empty», а не «чисто»;
  - `c2`: секция ports не выбрана — пометка «could not be checked»;
  - `d1`/`d2`: external volume — **известные дефекты DW-42/DW-43, не публиковать**;
  - `e`: правила, которые определяются самим Compose-файлом.
- **Санитизация:** путь, hostname, пользователь, IP, отпечаток машины, имена чужих
  образов, сетей, томов и контейнеров заменены плейсхолдерами `<…>`. Инвентарь хоста,
  не относящийся к сценарию, обрезан; что именно обрезано — в `TRIMMED.md`.
- **Что можно заявлять, а что нет:** см. [MATRIX.md](MATRIX.md).
