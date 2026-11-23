package scheduler

import "github.com/BloodHeavenDevelop/deploy-witness-cli/app/redact"

// Cron lines are the most reliable place on a Linux host to find a plaintext
// credential. `mysqldump -pS3cret`, `PGPASSWORD=… pg_dump`,
// `curl -H "Authorization: Bearer …"`, `restic -r sftp://user:pass@host/repo` —
// all of them are ordinary, all of them are in somebody's crontab right now, and
// all of them would otherwise be copied verbatim into a CSV that gets emailed
// around. So every Command this package reports is swept at the moment the line
// is parsed, before it is stored anywhere.
//
// The shared sweep in app/redact is the sweep: reusing it means there is one set
// of credential patterns in this binary rather than two that disagree, and one
// marker in the output. From that package, applied here:
//
//   - Authorization: Bearer/Basic/Token headers
//   - NAME=value and NAME: value where NAME contains pass/passwd/password,
//     secret, token, api-key, access-key, private-key or credential — which also
//     catches ?token=… in a URL query string
//   - a glued short password flag, `-pVALUE` (mysqldump, mysql, mysqladmin)
//   - long credential flags: --password=…, --token …, --db-password …, --auth …
//   - `-u user:pass`, how curl, wget and smbclient are told a password
//   - `sshpass -p VALUE`, whose value is a separate argument
//   - a URL userinfo section, scheme://user:pass@host — the account is kept,
//     because it is often the only clue which identity a job runs under
//   - PEM private key bodies, and the token shapes that are recognisable on their
//     own (JWTs, gh*_, xox*-, AKIA…, sk-…)
//
// Deliberately not masked: anything that merely looks like a long random string.
// Archive names, digests and dated filenames all look like that, and blanking
// them would remove most of what the report exists to carry.
//
// Environment *values* are never reported at all: a crontab line that is only an
// assignment is dropped whole in parseCrontab, before it reaches this file.
//
// maskSecrets removes credential-looking material from a command line.
//
// It is applied at the point every job is parsed, so nothing downstream has to
// remember to do it — including the backup collector, whose reported job strings
// are built from these commands and are not reachable by the report-wide sweep.
func maskSecrets(command string) string {
	return redact.String(command)
}
