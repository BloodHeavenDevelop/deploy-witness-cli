# 12. Quality and release criteria

Every version gets a reproducible quality score from the [test bench](11-test-bench.md),
on the same scenarios as the version before it, and a release is cut only when the
gate passes.

```bash
make bench-score     # the latest bench run, per rule, against bench/baseline
make release-gate    # a fresh bench run + the gate; exit 1 when it blocks
make bench-baseline  # promote the latest run to the baseline (only if it passes the gate)
```

`bench/dwscore` prints the table and writes `quality.json` next to the run's
`results.json`.

## The figures, per rule

| Column | Counted over | Means |
|---|---|---|
| `scen`, `scored` | every scenario of the rule; those whose ground truth held | A scenario with a bench error, or whose Docker behaviour contradicted it, is not scored |
| `problems`, `found` | staged problems | Predicted `problem` (or the plan `refused` — the deployment cannot start) |
| `missed` | staged problems | Predicted `no-problem` or `not-applicable`: said clean while it is not |
| `unknown` (problems) | staged problems | Predicted `unknown` or `manual-check`: **not a detection**, and it counts against the detection rate |
| `clean`, `false` | staged clean situations | `false` — a finding of a problem that is not there |
| `unknown` (clean) | staged clean situations | An unknown the data did not justify |
| `no-data`, `guessed` | staged insufficient data | `guessed` — a conclusion (either way) drawn without the data |
| `situations` | | Which of the three defining situations the rule's scenarios stage — `problem,no-problem,unknown` is full coverage |

Totals: **detection** = found ÷ staged problems — the unknowns are in the
denominator, not the numerator, so answering "unknown" more often lowers it;
**false findings** = false ÷ clean; **unknown predictions** over all scenarios;
**as specified** over the scored ones.

## Comparing versions

`dwscore` lines the run up with the baseline (`bench/baseline/results.json`)
scenario by scenario: `regression` (passed, fails now), `fixed`, `changed`
(another outcome, still passing), `new`, `removed`. Two runs are only comparable on
the same scenarios, which is why a removed one blocks the gate rather than
improving the figures.

A CLI older than rule outcomes (≤ 1.4.0) has no `audit.rules`; the bench then
derives its outcome the way such a report was read — a blocker or a warning is a
problem, info or nothing is not — and gives it no `--project-name` (it derived the
project from the directory). The starting point is recorded in
`bench/history/1.4.0.json`, the released 1.4.0 (origin/main) graded on today's
scenarios:

| | 1.4.0 | this version |
|---|---|---|
| as specified | 25 / 46 | 46 / 46 |
| detection (unknown is not a detection) | 13 / 17 — 76% | 17 / 17 — 100% |
| false findings | 6 / 19 — 32% | 0 / 19 — 0% |
| unknown predictions | 0 — it had no unknown; an undecided port was a warning, read as a problem | 9 — every staged insufficient-data scenario, and nothing else |
| conclusions without the data (`guessed`) | 9 / 9 | 0 / 9 |

Its misses and false findings are the defects DW-80 to DW-88 fixed: a deployment's
own container read as a conflict when it was deployed with `-p`, a missing
`create_host_path: false` source passing, a volume created by hand not flagged, and
every engine-dependent rule concluding from an engine it could not reach.

## The release gate

A release is blocked by any of:

| Blocks | Why |
|---|---|
| a bench error | The run proves nothing until the bench itself works |
| an audit side effect | The audit must change nothing on the host |
| a scored scenario whose Docker behaviour contradicts it | No ground truth: fix the scenario first |
| a failing **critical** scenario (`critical: true`) | A known critical miss — a false blocker on a routine update, a missed port, name, volume, network, subnet, bind or env-file problem |
| a failing **regression** scenario (`regression: <task>`) | A fixed defect has come back |
| a scenario that passed in the baseline and fails now | A regression, whatever the totals say |
| a baseline scenario missing from the run | Removing a hard test is not an improvement |

Rising unknowns cannot pass for progress either: a scenario that was decided
correctly in the baseline and is `unknown` now is a regression of that scenario.

Before cutting a release: `make release-gate`. When it passes and the scenarios
changed, `make bench-baseline` and a CHANGELOG line saying why the baseline moved.
The baseline committed with this change is the run of 2026-10-19 on
`docker:27.5.1-dind` (Docker 27.5.1, Compose 2.33.0): 46 scenarios, all as
specified, gate PASS.
