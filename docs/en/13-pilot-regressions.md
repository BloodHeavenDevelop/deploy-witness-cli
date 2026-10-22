# 13. Pilot errors become permanent tests

Every confirmed mistake on a pilot — a false alarm, a miss, an unknown the data did
not justify — must make the next version better, and stay fixed. The sequence is
fixed, and each step leaves something in the repository:

| Step | What | Where it lands |
|---|---|---|
| 1. **error** | The finding the client saw, confirmed wrong by a manual recheck: a false alarm (`false-alarm`), a problem not reported (`miss`), or `unknown` where the data was there to decide (`unjustified-unknown`). The time the recheck took is recorded | `case.yaml`: `kind`, `found: pilot`, `summary`, `recheck_minutes` |
| 2. **cause** | Why the CLI got it wrong, in one paragraph — the rule, the collector or the assumption | `case.yaml`: `cause` |
| 3. **scenario** | The situation reproduced on **artificial data**: the plan and what the host showed, as the report's own `audit.manifest`, `audit.capabilities` (and `audit.plan`) shapes, rewritten by hand | `input.json` |
| 4. **expected result** | The outcome each affected rule must reach | `case.yaml`: `expect.rules` (and `no_blocker`, `no_blocker_for`, `changes_contain`) |
| 5. **fix** | The change to the CLI. The case fails before it and passes after it — watch it fail first | the code, `fixed_in` |
| 6. **permanent test** | The case runs in every `make test` (`TestPilotRegressions`), so it runs before every release; when the situation can be staged in Docker, a bench scenario with `regression: <task>` too, which the [release gate](12-quality-and-release.md#the-release-gate) blocks on | `app/witness/testdata/regressions/<task>-<slug>/`, `bench/scenarios/…` |

```bash
make regression NAME=DW-123-short-slug   # copies the template, fills id and task
make test                                # the new case must fail until the fix lands
```

A failing case names itself, its kind and task, and what came back:
`DW-83-hand-made-external-network (false-alarm, DW-83): witness.network_name_conflict
ended "manual-check", want "no-problem" — the defect is back: …`. `go test -v -run
PilotRegressions ./app/witness` also prints how many cases there are and the
manual recheck time they recorded — the cost the pilots paid, kept with the fix.

## What never goes into the archive

The cases are artificial on purpose. Nothing from the client's report is copied in:
no report file, no host name, no public address, no domain, no engine or machine
id, no secret. `TestRegressionArchiveHoldsNoClientData` refuses a case that contains

- anything the credential sweep (`app/redact`) would mask;
- a public IP address — only loopback, RFC 1918, link-local and the documentation
  ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`) pass;
- a domain outside the reserved names (`*.example`, `example.com/.net/.org`,
  `*.test`, `*.invalid`, `*.localhost`);
- an e-mail address outside them;
- a 32- or 64-hex-digit id or a UUID — an engine, machine or image id — unless it
  starts with `00000000`.

The lint itself is tested (`TestClientDataLint`) against each kind.

## The archive today

Seven cases, from the defects fixed so far; none came from a pilot yet, so their
`recheck_minutes` are `0` and `found` is `review` or `bench`:

| Case | Kind | The defect |
|---|---|---|
| `DW-24-port-number-only` | false alarm | ports compared by number: 53/tcp blocked by 53/udp |
| `DW-52-foreign-container-replaced` | miss | the change list replaced another project's container |
| `DW-79-snapshot-called-missing` | false alarm | an unverifiable snapshot reported as missing |
| `DW-80-unreachable-engine-external-volume` | false alarm | "external volume does not exist" from an engine that never answered |
| `DW-81-project-name-flag` | false alarm | a deployment made with `--project-name` read its own container as foreign |
| `DW-83-hand-made-external-network` | false alarm | a hand-made external network read as shared with another stack |
| `DW-87-hand-made-external-volume` | false alarm | a hand-made external volume read as somebody else's data |

Seven bench scenarios carry the same tasks as `regression:` (DW-24, DW-52, DW-80,
DW-81, DW-83 twice, DW-87), so the gate blocks a release on their return in Docker
as well.
