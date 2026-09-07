package redact

import (
	"strings"
	"testing"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
)

func TestStringMasksCredentials(t *testing.T) {
	cases := []struct {
		name string
		in   string
		// gone must not appear in the output.
		gone string
		// kept must still appear: a mask that removes the context makes the evidence
		// useless, and the reader then cannot tell what was there.
		kept []string
	}{
		{
			name: "a mysqldump password glued to the flag",
			in:   "0 3 * * * mysqldump -u backup -phunter2 shop > /backup/shop.sql",
			gone: "hunter2",
			kept: []string{"mysqldump", "-u backup", "/backup/shop.sql"},
		},
		{
			name: "a long password flag",
			in:   "restic --password=correct-horse-battery backup /srv",
			gone: "correct-horse-battery",
			kept: []string{"restic", "backup", "/srv"},
		},
		{
			name: "an assignment in a cron environment line",
			in:   "MYSQL_PASSWORD=s3cr3t-value",
			gone: "s3cr3t-value",
			kept: []string{"MYSQL_PASSWORD"},
		},
		{
			name: "a token in a curl header",
			in:   `curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N" https://api.example.com/hooks`,
			gone: "dozjgNryP4J3jVmNHl0w5N",
			kept: []string{"curl", "https://api.example.com/hooks"},
		},
		{
			name: "credentials inside a URL keep the account name",
			in:   "rclone sync /srv s3://deploy:tops3cret@backups/nightly",
			gone: "tops3cret",
			kept: []string{"deploy", "backups/nightly"},
		},
		{
			name: "a GitHub token by shape alone",
			in:   "git clone https://ghp_1234567890abcdefghijklmnopqrstuvwx@github.com/acme/app",
			gone: "ghp_1234567890abcdefghijklmnopqrstuvwx",
			kept: []string{"github.com/acme/app"},
		},
		{
			name: "an AWS access key by shape alone",
			in:   "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE aws s3 sync /srv s3://bucket",
			gone: "AKIAIOSFODNN7EXAMPLE",
			kept: []string{"aws s3 sync", "s3://bucket"},
		},
		{
			name: "private key material",
			in:   "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA0Z3VS\n-----END RSA PRIVATE KEY-----",
			gone: "MIIEpAIBAAKCAQEA0Z3VS",
			kept: []string{"BEGIN RSA PRIVATE KEY", "END RSA PRIVATE KEY"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := String(tc.in)
			if strings.Contains(got, tc.gone) {
				t.Errorf("the secret survived the sweep:\n in: %s\nout: %s", tc.in, got)
			}
			if !strings.Contains(got, Marker) {
				t.Errorf("nothing was marked as redacted, so the reader cannot tell something was removed: %s", got)
			}
			for _, keep := range tc.kept {
				if !strings.Contains(got, keep) {
					t.Errorf("the sweep removed context it should have kept (%q):\n%s", keep, got)
				}
			}
		})
	}
}

// The sweep must not fire on ordinary text. A pass that masks half a normal report
// makes the report unreadable, which is its own kind of dishonesty.
func TestStringLeavesOrdinaryTextAlone(t *testing.T) {
	untouched := []string{
		"nginx: worker process",
		"/usr/lib/systemd/systemd --user",
		"PasswordAuthentication no",
		"ports: publishes host port 8080 → container port 80",
		"0 4 * * * /usr/local/bin/backup.sh --target /backup",
		"tcp LISTEN 0.0.0.0:5432 pid=1234 process=postgres",
		"image: postgres:16-alpine",
		"ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;",
	}
	for _, text := range untouched {
		if got := String(text); got != text {
			t.Errorf("ordinary text was altered:\n in: %s\nout: %s", text, got)
		}
	}
}

// `PasswordAuthentication no` is the case that decides whether this package is
// usable: it is a key whose name contains "password", its value is not a secret, and
// the hardening section reports it on every host.
func TestSSHHardeningFactsSurvive(t *testing.T) {
	for _, value := range []string{"no", "yes", "prohibit-password"} {
		if got := String("permitrootlogin " + value); got != "permitrootlogin "+value {
			t.Errorf("an sshd setting was masked as if it were a credential: %s", got)
		}
	}
}

func TestReportSweepsEveryFreeFormField(t *testing.T) {
	report := &model.Report{
		System:   []model.Fact{{Category: "cron", Key: "line", Value: "backup -phunter2"}},
		Ports:    []model.Port{{Command: "/app/serve --token=abcdef123456"}},
		Commands: []model.CommandRun{{Command: "mysqldump -psecret"}},
		Findings: []model.Finding{{
			Code:        "witness.example",
			Description: "the job runs `curl -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJhIjoxfQ.sig12345'`",
			Evidence:    []model.Evidence{{Command: "/etc/cron.d/job", Output: "PGPASSWORD=letmein psql"}},
		}},
		Capabilities: &model.Capabilities{
			Jobs: []model.ScheduledJob{{Command: "restic --password=hunter2 backup /srv"}},
		},
	}

	changed := Report(report)
	if changed == 0 {
		t.Fatal("nothing was masked")
	}

	rendered := strings.Join([]string{
		report.System[0].Value,
		report.Ports[0].Command,
		report.Commands[0].Command,
		report.Findings[0].Description,
		report.Findings[0].Evidence[0].Output,
		report.Capabilities.Jobs[0].Command,
	}, "\n")

	for _, secret := range []string{"hunter2", "abcdef123456", "psecret", "letmein", "sig12345"} {
		if strings.Contains(rendered, secret) {
			t.Errorf("%q survived the report sweep:\n%s", secret, rendered)
		}
	}
}
