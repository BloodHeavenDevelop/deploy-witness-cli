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
| `deploy-witness --version` | `deploy-witness 1.4.0` — a released version: `CHANGELOG.md` `## [1.4.0] - 2026-10-11` |
| Source | commit `364f14335490f6ce68694614837d6df2e16a346e` (`chore(release): 1.4.0`, branch `task/DW-79`). The commit that adds these outputs changes nothing outside `docs/site-materials/` |
| Build | `make build` → `CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=1.4.0"`, Go 1.26.6 linux/amd64; binary sha256 `8ac2d433ffd879fc2bc3ea004a8e04069fa89a5bb954e595786fc1c34d8a8827` |
| Allowlist | `deploy-witness --commands`: "can run exactly these 68 commands and nothing else" |
| `make test`, `make vet`, `make lint` | green on that commit |
| Run date | 2026-10-11, UTC timestamps in every file |

The `Makefile` stamps the version from the first *numbered* heading of
`CHANGELOG.md`, so a tree with only `## [Unreleased]` changes on top of a release is
stamped with that older release. The previous generation of this kit (2026-10-10)
said "1.2.0" for that reason while containing unreleased code; this one was run on
the released 1.4.0, so the version in `summary.csv`, `report.json` (`producer`) and
the log is the version of the source. The binaries committed in `dist/` were **not**
rebuilt for 1.4.0 (they are older) and do not behave like these outputs.

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

Every scenario is **one run**: `--format csv,json` (new in 1.4.0) writes the CSV
tables and `report.json` from the same audit, so `terminal.txt`, every CSV file and
`report.json` describe the same run — the same `Checked at`, PIDs and evidence
times. (The previous generation ran each scenario twice, once per format, and its
terminal log and its JSON evidence were three seconds apart — DW-79.) The command
shown in `terminal.txt` is the one to publish (`--out ./report`); the script itself
passes an absolute `--out` under its scratch directory, which is why the log says
`wrote 12 CSV files to <WORKDIR>/raw/…/report`.

Three timestamps of one run, and what each means (in `a-conflict`):

| Where | Value | Means |
|---|---|---|
| `summary.csv` `report` row (`… at …`), `report.json` `generated_at` | `20:46:11` | the run started |
| `evidence.csv` `Captured at`, `report.json` `captured_at` | `20:46:13` | the witness section compared the manifest with what it had collected — after the ~2 s of collection |
| log `wrote 12 CSV files …`, `wrote …/report.json` | `20:46:13` | the files were written |

The unsanitised reports stay in the scratch directory the script prints (`DW_WORK`,
default `mktemp -d`). Delete it when done; never commit it.

## Scenarios

All runs: `deploy-witness --sections ports,witness --compose ./docker-compose.yml`
from the scenario directory, unprivileged, offline, exit code `0` in every one.

| Output | Host state | Command difference | Result (from `witness.csv`) | Proves |
|---|---|---|---|---|
| [`a-conflict`](outputs/a-conflict) | foreign listener on `0.0.0.0:8080`; foreign container `orders-api` (created, never started, no Compose project) | — | **blocker** `witness.port_conflict` `8080/tcp` (evidence: compose line + socket held by `python3`); **blocker** `witness.container_name_conflict` `orders-api` (evidence: compose line + `docker ps -a`); info `floating_image_tag`, `registry_unreachable`, `no_rollback_plan` "2 of 4 unverified". `changes.csv`: container `not created …`, port `not opened …`; `rollback.csv`: `proxy-config` and `snapshot` `unknown` ("unable to verify") | conflict detected, with evidence |
| [`b-no-conflict`](outputs/b-no-conflict) | both removed | — | no `port_conflict`, no `container_name_conflict`; the other three rows identical to `a` | no conflict within the checks made |
| [`c1-docker-unreachable`](outputs/c1-docker-unreachable) | as `a` | `DOCKER_HOST=unix:///nonexistent/docker.sock` | `port_conflict` still a blocker (sockets come from `/proc/net`); **no** `container_name_conflict` although the container exists; instead warning `witness.runtime_missing_or_old` "docker is installed but did not answer" and the note "the container, network, volume and image lists are unknown rather than empty"; `witness` and `preflight` rows `partial` | insufficient data → "could not check", not a clean result |
| [`c2-ports-not-selected`](outputs/c2-ports-not-selected) | as `a` | `--sections witness` | `container_name_conflict` blocker, **no** `port_conflict`; `witness` row `partial` with "the ports section was not selected, so port conflicts could not be checked" | insufficient data → "could not check" |
| [`d1-external-volume`](outputs/d1-external-volume) | volume `dwkit-data` exists, no project label | `shop/` | `dwkit-data` (key = real name): warning "already holds somebody else's data" — correct. `aliased` (`external: true, name: dwkit-data`): **blocker "does not exist" — false**, known defect DW-42 | **do not publish**: external volumes are Not ready |
| [`d2-external-volume-docker-unreachable`](outputs/d2-external-volume-docker-unreachable) | as `d1` | `shop/` + `DOCKER_HOST=unix:///nonexistent/docker.sock` | runtime warning and the "unknown rather than empty" note — **and** two blockers "External volume … does not exist" built on the list it just called unknown: known defect DW-43 | **do not publish**: the honest-gap promise fails here |
| [`e-manifest-rules`](outputs/e-manifest-rules) | network `dwkit-net` on `10.250.73.0/24` | `rules/` | blockers: `architecture_mismatch` (arm64 on x86_64), `env_file_missing`, `insufficient_memory` (100 GiB), `privileged_container`, `subnet_overlap` (with `dwkit-net`); warnings: `bind_path_conflict` ×2 (`/etc`, docker socket), `floating_image_tag` (`latest`), `no_healthcheck`, `no_rollback_plan` "1 of 4 missing" (writable bind mounts and no backup location) | the manifest-driven rules fire, each with evidence |

What the scenarios also show, in every run: the log line `network: none …`, the
`network` row `offline: …` and `network.csv` with all four paths disabled and `0`
contacts; `commands.csv` contains only read commands (66 in `a`, all `ok`; 12 in
`c1`, two `failed` because the engine is unreachable) and no `docker run/create/pull`
or `compose up/pull/run/create`.

### Which results are deterministic and which belong to this host

Deterministic given the scenario (reproduce on any Linux host with Docker): the two
conflicts and their absence, the `c1`/`c2` gaps, `floating_image_tag`,
`registry_unreachable` (info, "not checked"), and everything in `e` except the
available-memory figure.

Properties of this host, not of the scenario — do not present them as typical:
`no_rollback_plan` "2 of 4 unverified" (it lists `proxy-config` because Apache is
installed; on a host without a web server it is "1 of 3"), the `disk-space` line in
`changes.csv`, the available memory, the counts in the `ports` note ("370 processes
were not readable", "15 of 147 … all interfaces"), the witness notes about 17 unmeasured mount points,
`/var/spool/cron` and 122 CA certificates, and the `masked credential-looking
material in 1 field(s)` log line (see below).

### Known defects visible in these outputs

| Where | What | Task |
|---|---|---|
| `a`, `b`, `c2`, `d1`, `e`: log line "masked credential-looking material in 1 field(s)" and one `docker image inspect <host-image-NN>` journal line | `app/redact` rewrites the tag of an image on this host whose name contains "token"; nothing in the scenarios is a secret | DW-45 |
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
| Changes / rollback | `changes.csv` and `rollback.csv` as they are. Since 1.4.0 the foreign container is `not created …` and port 8080 `not opened …` (DW-52 fixed), and a rollback row the host cannot show is `unknown` / "unable to verify", never "not available" |
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

- **Версия:** `deploy-witness 1.4.0` (вывод `--version`) — выпущенная версия,
  коммит `364f143` (`chore(release): 1.4.0`, ветка `task/DW-79`). Бинарники в `dist/`
  под 1.4.0 не пересобирались.
- **Один прогон на сценарий:** `--format csv,json` пишет CSV и `report.json` из
  одного аудита, поэтому лог, CSV и JSON относятся к одному прогону (раньше было два
  прогона с разницей в ~3 с). `Checked at` — начало прогона, `Captured at` у
  доказательств — момент сравнения после сбора, `wrote …` в логе — запись файлов.
- **Хост:** Manjaro (Arch), без root (группа `docker`), Docker 29.7.2, Compose 5.5.0,
  офлайн-режим.
- **Воспроизвести:** `make build && docs/site-materials/run.sh`. Скрипт создаёт
  слушатель на 8080, контейнер `orders-api`, том `dwkit-data` и сеть `dwkit-net`.
  После прогона всё это удаляется. Чужие объекты скрипт не трогает и ничего не
  скачивает.
- **Сценарии:**
  - `a`: конфликт порта и имени контейнера, оба blocker с evidence; в `changes.csv`
    контейнер `not created`, порт `not opened`; в `rollback.csv` snapshot и
    proxy-config — `unknown` («unable to verify»), `no_rollback_plan` — info
    «2 of 4 unverified», а не вывод о невозможности отката;
  - `b`: без конфликта;
  - `c1`: Docker недоступен, проверка имени не выполнена — warning и пометка «unknown rather than empty», а не «чисто»;
  - `c2`: секция ports не выбрана — пометка «could not be checked»;
  - `d1`/`d2`: external volume — **известные дефекты DW-42/DW-43, не публиковать**;
  - `e`: правила, которые определяются самим Compose-файлом.
- **Санитизация:** путь, hostname, пользователь, IP, отпечаток машины, имена чужих
  образов, сетей, томов и контейнеров заменены плейсхолдерами `<…>`. Инвентарь хоста,
  не относящийся к сценарию, обрезан; что именно обрезано — в `TRIMMED.md`.
- **Что можно заявлять, а что нет:** см. [MATRIX.md](MATRIX.md).
