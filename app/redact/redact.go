// Package redact sweeps a finished report for credentials before it leaves this
// process.
//
// It is the last line, not the first. Every collector is written not to read secrets
// at all — environment values, `.env` contents, private keys and database contents
// are outside what this tool looks at — and that is what actually keeps them out of
// the report. This pass exists because a report also carries free-form text nobody
// designed: a cron line, a command from `ss`, a proxy directive. People put
// passwords in those, and a report that is uploaded must not carry them onward.
//
// Two properties matter more than coverage:
//
//   - A masked value says it was masked. `password=***redacted***` tells the reader
//     something was there; silently deleting it would make the evidence a lie.
//   - The patterns are conservative about what they blank and generous about what
//     they look at. Masking one field too many costs a reader a little context;
//     missing one publishes somebody's production credential.
package redact

import (
	"regexp"
	"strings"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
)

// Marker is what replaces a matched secret. It is deliberately visible: the reader
// has to be able to tell "there was a credential here" from "there was nothing".
const Marker = "***redacted***"

// pattern is one credential shape. Each expression captures the part that names the
// secret so the name survives and only the value is replaced.
type pattern struct {
	name string
	re   *regexp.Regexp
	// with is the replacement template, referring to the capture groups.
	with string
}

// patterns is the sweep. Every entry is documented with what it is for, because a
// regular expression nobody can read is a regular expression nobody will maintain.
var patterns = []pattern{
	{
		// An Authorization header, however it was quoted. First, so the scheme word
		// is preserved instead of being eaten as a value by the assignment rule.
		name: "authorization header",
		re:   regexp.MustCompile(`(?i)(authorization\s*:\s*(?:bearer|basic|token)\s+)([A-Za-z0-9._~+/=-]{8,})`),
		with: `$1` + Marker,
	},
	{
		// KEY=secret / KEY: secret / KEY "secret", for any key whose name contains a
		// word meaning credential — `MYSQL_PASSWORD` and `PGPASSWORD` matter as much
		// as a bare `password`, so a prefix is allowed.
		//
		// The separator is captured and put back rather than normalised to `=`:
		// rewriting `Authorization: x` into `Authorization=x` changes evidence that
		// the reader is expected to compare against the real file.
		//
		// Only `=` and `:` count as separators, which is what spares the sshd
		// hardening facts: `PasswordAuthentication no` is space-separated and is
		// never touched by this rule.
		name: "named credential assignment",
		re: regexp.MustCompile(
			`(?i)\b([a-z0-9_.-]*(?:pass(?:word|wd)?|secret|token|api[_-]?key|access[_-]?key|` +
				`private[_-]?key|credential)[a-z0-9_-]*)(\s*[:=]\s*)("[^"]*"|'[^']*'|` + "`[^`]*`" + `|[^\s,;&|)"']+)`),
		with: `$1$2` + Marker,
	},
	{
		// mysqldump -pSECRET and friends: the one-letter form with the value glued
		// to the flag, which is exactly how it appears in cron lines.
		name: "glued -p password",
		re:   regexp.MustCompile(`(?i)(\s-p)([^\s'"]+)`),
		with: `${1}` + Marker,
	},
	{
		// --password=SECRET, --token SECRET.
		name: "long credential flag",
		re: regexp.MustCompile(
			`(?i)(--(?:password|passwd|secret|token|api-key|access-key|auth)(?:[=\s]))("[^"]*"|'[^']*'|[^\s]+)`),
		with: `$1` + Marker,
	},
	{
		// A URL with credentials in it: scheme://user:pass@host. The user is kept —
		// it is often the only clue which account a job uses — and the password is not.
		name: "credentials in a URL",
		re:   regexp.MustCompile(`([a-zA-Z][a-zA-Z0-9+.-]*://[^\s:/@]+):([^\s@/]+)@`),
		with: `$1:` + Marker + `@`,
	},

	{
		// PEM private key material. Any report carrying this is a defect upstream,
		// and it must not survive the sweep regardless.
		name: "PEM private key body",
		re: regexp.MustCompile(
			`(?s)(-----BEGIN [A-Z ]*PRIVATE KEY-----).*?(-----END [A-Z ]*PRIVATE KEY-----)`),
		with: `$1` + Marker + `$2`,
	},
	{
		// A long opaque token on its own: JWTs and the provider key formats that are
		// recognisable by shape. Bounded to shapes that cannot be an ordinary word.
		name: "recognisable token shape",
		re: regexp.MustCompile(
			`\b(?:eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}|` +
				`gh[pousr]_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|` +
				`AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9]{20,})\b`),
		with: Marker,
	},
}

// harmlessValues are values that are never secrets no matter what the key is
// called. `PasswordAuthentication no` and `PermitRootLogin prohibit-password` are
// reported on every host by the hardening collector, and masking them would blank
// the very facts somebody reads that section for.
var harmlessValues = map[string]bool{
	"yes": true, "no": true, "true": true, "false": true, "none": true,
	"null": true, "nil": true, "prohibit-password": true, "0": true, "1": true,
	"\"\"": true, "''": true, "-": true,
}

// String masks credentials in one piece of text.
func String(text string) string {
	if text == "" {
		return text
	}
	for _, p := range patterns {
		text = p.re.ReplaceAllStringFunc(text, func(match string) string {
			groups := p.re.FindStringSubmatch(match)
			// The last group is the value for every pattern that has one.
			if len(groups) > 1 {
				value := strings.Trim(strings.ToLower(strings.TrimSpace(groups[len(groups)-1])), `"'`)
				if harmlessValues[value] {
					return match
				}
			}
			return p.re.ReplaceAllString(match, p.with)
		})
	}
	return text
}

// Report sweeps every free-form field of a finished report, in place, and returns
// how many fields changed.
//
// The count is reported rather than kept quiet: if the sweep is masking things on a
// normal host, either a collector is reading something it should not or the patterns
// are too eager, and both are worth knowing about.
func Report(report *model.Report) int {
	changed := 0
	sweep := func(field *string) {
		masked := String(*field)
		if masked != *field {
			*field = masked
			changed++
		}
	}

	for i := range report.System {
		sweep(&report.System[i].Value)
	}
	for i := range report.Ports {
		sweep(&report.Ports[i].Command)
	}
	for i := range report.Services {
		sweep(&report.Services[i].Description)
	}
	for i := range report.Commands {
		sweep(&report.Commands[i].Command)
	}
	for i := range report.Sections {
		for j := range report.Sections[i].Notes {
			sweep(&report.Sections[i].Notes[j])
		}
	}

	for i := range report.Findings {
		finding := &report.Findings[i]
		sweep(&finding.Subject)
		sweep(&finding.Title)
		sweep(&finding.Description)
		sweep(&finding.WhatToDo)
		for j := range finding.Evidence {
			sweep(&finding.Evidence[j].Command)
			sweep(&finding.Evidence[j].Output)
		}
	}
	for i := range report.Changes {
		sweep(&report.Changes[i].Target)
		sweep(&report.Changes[i].Detail)
	}
	for i := range report.Rollback {
		sweep(&report.Rollback[i].Detail)
	}

	if caps := report.Capabilities; caps != nil {
		for i := range caps.Jobs {
			sweep(&caps.Jobs[i].Command)
		}
		for i := range caps.Ports {
			sweep(&caps.Ports[i].Command)
		}
		for i := range caps.Notes {
			sweep(&caps.Notes[i])
		}
		// The backup posture carries cron lines too — `Jobs` is a list of the
		// commands that looked like a backup, and a mysqldump password is exactly
		// what one of those contains.
		for i := range caps.Backup.Jobs {
			sweep(&caps.Backup.Jobs[i])
		}
		sweep(&caps.Backup.Note)
		for i := range caps.Jobs {
			sweep(&caps.Jobs[i].Schedule)
		}
	}
	if manifest := report.Manifest; manifest != nil {
		for i := range manifest.Warnings {
			sweep(&manifest.Warnings[i])
		}
		for i := range manifest.Services {
			// Label values are configuration, but a label is also where somebody
			// occasionally parks a token.
			for key, value := range manifest.Services[i].Labels {
				if masked := String(value); masked != value {
					manifest.Services[i].Labels[key] = masked
					changed++
				}
			}
		}
	}

	return changed
}
