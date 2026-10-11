# What was trimmed from this run

Host-wide inventory unrelated to the scenario; see ../../README.md § Sanitisation.

- ports.csv: kept 0 of 146 rows (the sockets on port 8080)
- report.json `audit.ports`: kept 0 of 146 entries
- report.json `audit.capabilities.ports`: kept 0 of 146 entries
- report.json `audit.capabilities.containers`: kept 0 of 17 entries
- report.json `audit.capabilities.containerNetworks`: kept 3 of 7 entries
- report.json `audit.capabilities.containerVolumes`: kept 1 of 177 entries
- report.json `audit.capabilities.images`: kept 1 of 44 entries
- report.json `audit.capabilities.jobs`: kept 0 of 13 entries
- report.json `audit.capabilities.databases`: kept 0 of 2 entries
- report.json: re-serialised after trimming (2-space indent, as the tool writes it; key order kept)
