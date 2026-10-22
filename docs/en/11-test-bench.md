# 11. Test bench

The bench compares what the CLI **predicts** with what Docker **actually does**, in
situations staged on purpose. Unit tests prove a rule follows its specification
([10 — the outcome matrix](10-witness-rules.md#the-outcome-matrix)); the bench proves
the specification matches Docker.

```bash
make bench                                   # every scenario, ~3 minutes
make bench BENCH_ARGS="-only port_conflict"  # the scenarios whose id starts with it
```

One command, one disposable environment, one result directory
(`bench/out/<UTC timestamp>/results.json` and `results.csv`).

## The environment

| | |
|---|---|
| Engine | One Docker-in-Docker container from a **pinned image**, `docker:27.5.1-dind` (Docker Engine 27.5.1, Compose plugin **2.33.0**). Another version is `BENCH_ARGS="-image docker:<version>-dind"`; the image's own engine and Compose versions are recorded in every result file |
| Network | `--network none`: the environment reaches nothing outside itself. Compose cannot pull, so a missing image or a foreign platform fails instead of fetching |
| Images | Loaded from this machine's engine (`docker save | docker load`), default `alpine:3.21` (`-images` to change). Nothing is pulled; the bench needs that image present locally |
| CLI | The binary `make build` produced, copied in. Its `--version` and the commit are recorded |
| Privilege | `--privileged`, which Docker-in-Docker needs. It is the only thing the bench asks of the machine it runs on, and the container is removed at the end (`-keep` keeps it for debugging) |
| Accounts | Audits run as `root`, or as an unprivileged account `bench` that cannot reach the engine's socket — the "insufficient data" situation of every engine-dependent rule |

## What one scenario does

Every scenario is a directory under `bench/scenarios/<rule>/<case>/`:

| File | Contents |
|---|---|
| `scenario.yaml` | `id`, `rule` (the finding code), `situation` (`problem`, `no-problem`, `unknown`, `manual-check`, `not-applicable`), `description`, `critical`, `audit.user` and `audit.args`, `project`, `expect.outcome` (and `expect.also` for an equally correct alternative, explained in the description), `docker.up`, `docker.outcome` (`fails`, `succeeds`, `advisory`) and `docker.pattern` |
| `compose.yml` | The plan |
| `setup.sh` | Optional: stages the situation inside the environment, as root, from the scenario's directory — a container that holds a port, a volume created by hand, an earlier deployment |

The harness (`bench/dwbench`), for each scenario in id order:

1. resets the engine to empty — no container, volume or custom network left from the previous scenario;
2. copies the scenario in and runs `setup.sh`;
3. snapshots the engine (containers with state and image, volumes, networks) and the scenario directory;
4. runs the audit — `deploy-witness --compose compose.yml --project-name <project> --format json <args>`, as the scenario's user — and reads the rule's outcome from `rules.csv`'s JSON twin (`audit.rules`); an exit `2` is the prediction `refused`;
5. snapshots again: every difference is an **audit side effect**;
6. runs the planned change, `docker compose -f compose.yml -p <project> <docker.up>` (default `up -d`), and checks a few seconds later that every container is still running — one that starts and dies at once is a failed deployment, whatever `up` returned;
7. records both verdicts.

## Verdicts

| Verdict | Means |
|---|---|
| **prediction as specified** (`specMatch`) | The rule's outcome is the scenario's `expect.outcome` (or one of `expect.also`). A mismatch is a defect in the CLI or in the specification |
| **Docker as expected** (`dockerMatch`) | `docker.outcome: fails` — the change failed (with `docker.pattern` in its output when given); `succeeds` — it succeeded and stayed up. A mismatch means the scenario does not stage what it claims, or Docker behaves differently from what the rule assumes |
| `advisory` | Docker does not decide the rule (a healthcheck, a floating tag, authority over the host, a memory reservation): its result is recorded, not scored |
| **bench error** | The bench itself failed — a reset, a copy or a `setup.sh` that did not run, an audit that wrote no report or crashed. The scenario proves nothing about the CLI and is counted apart, never as a CLI failure |
| **audit side effect** | Something in the engine or the scenario directory changed during the audit. The audit must change nothing; any entry is a defect |

An `unknown` scenario stages a real problem the audit cannot see (the engine does
not answer): Docker then fails, as expected — and the CLI's `unknown` is **not** a
detection — [12 — Quality](12-quality-and-release.md) counts it that way.

## Coverage

| Rule | Scenarios | Situations staged |
|---|---|---|
| `port_conflict` | 9 | foreign container; other protocol; other address; own update; engine unreachable; orphan left running; orphan removed (`--remove-orphans`); dynamic range exhausted / with a free port |
| `container_name_conflict` | 3 | foreign; own; engine unreachable |
| `project_ownership` | 3 | another checkout; this directory under another project name; own |
| `volume_name_conflict` | 4 | external missing / present; engine unreachable; existing without this project's label |
| `network_name_conflict` | 3 | external missing / present; engine unreachable |
| `subnet_overlap` | 3 | overlap; disjoint; engine unreachable |
| `bind_path_conflict` | 4 | missing with `create_host_path: false`; existing; created by the engine; unreadable for the auditing account |
| `env_file_missing` | 2 | missing; `required: false` |
| `architecture_mismatch` | 3 | pinned foreign platform; image absent; matching |
| `registry_unreachable` | 2 | not checked (no `--egress`); refused connection (`--egress`) |
| `runtime_missing_or_old` | 2 | engine answers; engine unreachable |
| `no_healthcheck`, `privileged_container`, `insufficient_memory`, `floating_image_tag` | 8 | problem / no-problem (and not-applicable) — advisory |

Not staged, with the reason: `insufficient_disk`, `insufficient_inodes` and
`disk_at_limit` need a filesystem filled on purpose; `proxy_conflict`,
`domain_conflict`, `database_version_mismatch`, `backup_gap`, `no_rollback_plan`,
`certificate_expiring` and `reboot_required` read host software (nginx, a database,
certbot, the package manager) the Docker-in-Docker environment does not have. They
are covered by the outcome-matrix tests (`app/witness/outcomes_test.go`) and the
pilot regressions ([13](13-pilot-regressions.md)), not by Docker's behaviour.

## What the bench found

Its first runs found four defects, fixed in the same change and now held by
scenarios:

- a hand-made external network (`docker network create`, no project label) was
  reported as "shared with another stack" — `network_name_conflict/no-problem-external-present`;
- Compose 2.x prints `create_host_path` only when `true` and Compose 5.x only when
  `false`, so a missing source with `create_host_path: false` read as creatable on
  Compose 2.33 — `bind_path_conflict/problem-missing-no-create`;
- a container that starts and dies at once (an image for another platform) made
  `up -d` exit `0`: the bench now checks the containers are still running;
- with the network open, Compose pulled a foreign-platform variant over a loaded image
  and every later scenario ran on it: the environment now has no network.

## Adding a scenario

Copy the nearest scenario directory, change the plan and `setup.sh`, set `situation`,
`expect.outcome` and `docker.outcome`, and run it alone
(`make bench BENCH_ARGS="-only <id>"`) until both verdicts hold for the right reason.
Every rule needs its three situations — a problem, a similar situation without it,
and insufficient data — wherever the environment can stage them. `go test
./bench/...` checks every committed scenario loads and is well formed.
