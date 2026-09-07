package scheduler

import (
	"regexp"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/redact"
)

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
//   - long credential flags: --password=…, --token …, --secret=…, --auth …
//   - a URL userinfo section, scheme://user:pass@host — the account is kept,
//     because it is often the only clue which identity a job runs under
//   - PEM private key bodies, and the token shapes that are recognisable on their
//     own (JWTs, gh*_, xox*-, AKIA…, sk-…)
//
// Two shapes that appear in cron lines and nowhere else are added below, because
// the shared sweep does not carry them:
//
//   - `-u user:pass`, how curl, wget and smbclient are told a password
//   - `sshpass -p VALUE`, whose value is a separate argument rather than glued to
//     the flag, so the shared glued -p rule does not see it
//
// Deliberately not masked: anything that merely looks like a long random string.
// Archive names, digests and dated filenames all look like that, and blanking
// them would remove most of what the report exists to carry.
//
// Environment *values* are never reported at all: a crontab line that is only an
// assignment is dropped whole in parseCrontab, before it reaches this file.
var (
	// userColonPassword is the `-u account:password` form. The account survives.
	userColonPassword = regexp.MustCompile(`(?i)(^|\s)(-u|--user)(\s+)([^\s:]+):\S+`)
	// sshpassPassword is `sshpass -p VALUE`. The pattern stays on one command by
	// refusing to cross a pipe or a separator.
	sshpassPassword = regexp.MustCompile(`(?i)(\bsshpass\b[^|;&]*?\s-p)\s*(?:"[^"]*"|'[^']*'|\S+)`)
)

// maskSecrets removes credential-looking material from a command line.
//
// It is applied at the point every job is parsed, so nothing downstream has to
// remember to do it — including the backup collector, whose reported job strings
// are built from these commands and are not reachable by the report-wide sweep.
func maskSecrets(command string) string {
	if command == "" {
		return ""
	}
	out := redact.String(command)
	out = userColonPassword.ReplaceAllString(out, "${1}${2}${3}${4}:"+redact.Marker)
	out = sshpassPassword.ReplaceAllString(out, "${1} "+redact.Marker)
	return out
}
