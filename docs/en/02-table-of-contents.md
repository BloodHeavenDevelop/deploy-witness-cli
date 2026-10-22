# 2. Table of contents

| # | Document | Contents |
|---|---|---|
| 01 | [Introduction](01-introduction.md) | What the tool is, its scope, and the two promises it keeps |
| 02 | Table of contents | This page |
| 03 | [Installation](03-installation.md) | Building, cross-compiling, installing, scheduling |
| 04 | [CLI reference](04-cli-reference.md) | Every flag, environment variable and exit code |
| 05 | [Architecture](05-architecture.md) | Package layout and the run flow |
| 06 | [Collectors](06-collectors.md) | What each section reads, and what it needs root for |
| 07 | [Vulnerability sources](07-vulnerability-sources.md) | The three feeds, ecosystems and severity grading |
| 08 | [Report format](08-report-format.md) | Every CSV file, every column, and the JSON document |
| 09 | [Command allowlist and journal](09-command-allowlist.md) | Everything the binary is able to execute, and the record of what it did |
| 10 | [Witness rules](10-witness-rules.md) | The 25 finding codes, their severities and what triggers each |
| 11 | [Test bench](11-test-bench.md) | `make bench`: prediction against Docker's actual behaviour, in staged scenarios, in a disposable environment |
| 12 | [Quality and release criteria](12-quality-and-release.md) | Detection, misses, false findings and unknowns per rule; version comparison; the release gate |
| 13 | [Pilot errors become permanent tests](13-pilot-regressions.md) | error → cause → scenario → expected result → fix → permanent test; what never goes into the archive |
| — | [Site materials](../site-materials/README.md) | Verified runs behind the site's examples and claims: control Compose scenarios, the exact commands, the reports they produced, and the [verification matrix](../site-materials/MATRIX.md). Language-neutral kit, English with a Russian summary |

The same set exists in Russian under [`docs/ru/`](../ru/). Both languages are
updated together, in the same change.
