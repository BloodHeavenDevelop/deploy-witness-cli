package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
)

// Every certificate in these tests is generated in-test with
// x509.CreateCertificate and written into t.TempDir(). Nothing reads the host: a
// certificate collector verified against whatever happens to be in the developer's
// /etc/ssl is a collector nobody can change safely.

// now is the fixed clock the expectations are written against.
var now = time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)

const day = 24 * time.Hour

// issued is a generated certificate and the key that signed it.
type issued struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
}

// issue generates one certificate. parent nil means self-signed.
func issue(t *testing.T, commonName string, dnsNames []string, notBefore, notAfter time.Time,
	isCA bool, parent *issued) issued {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: commonName},
		DNSNames:              dnsNames,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}
	if isCA {
		template.KeyUsage |= x509.KeyUsageCertSign
	}

	signerCert, signerKey := template, key
	if parent != nil {
		signerCert, signerKey = parent.cert, parent.key
	}

	der, err := x509.CreateCertificate(rand.Reader, template, signerCert, &key.PublicKey, signerKey)
	if err != nil {
		t.Fatalf("create certificate %q: %v", commonName, err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse generated certificate %q: %v", commonName, err)
	}

	return issued{
		cert: parsed,
		key:  key,
		pem:  pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}
}

// write puts content at root/rel, creating parents.
func write(t *testing.T, root, rel string, content []byte) string {
	t.Helper()
	path := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", filepath.Dir(rel), err)
	}
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
	return path
}

// byPath indexes a scan result so a test can assert on one certificate. The
// wanted path goes through the same symlink resolution the scanner applies, so a
// TMPDIR that is itself a symlink does not break the comparison.
func byPath(t *testing.T, out scanResult, path string) model.Certificate {
	t.Helper()
	want := resolve(path)
	for _, cert := range out.certificates {
		if cert.Path == want {
			return cert
		}
	}
	t.Fatalf("no certificate reported for %s; got %+v", path, out.certificates)
	return model.Certificate{}
}

func TestScanParsesCertificateFields(t *testing.T) {
	root := t.TempDir()

	plain := issue(t, "plain.example.com", nil, now.Add(-30*day), now.Add(30*day), false, nil)
	plainPath := write(t, root, "etc/nginx/ssl/plain.pem", plain.pem)

	sans := issue(t, "sans.example.com",
		[]string{"sans.example.com", "www.sans.example.com"},
		now.Add(-day), now.Add(400*day), false, nil)
	sansPath := write(t, root, "etc/nginx/ssl/sans.pem", sans.pem)

	// Expired ten days and a bit ago.
	expired := issue(t, "expired.example.com", nil, now.Add(-370*day),
		now.Add(-10*day-time.Hour), false, nil)
	expiredPath := write(t, root, "etc/nginx/ssl/expired.pem", expired.pem)

	// Ten days and a bit left: the case a witness check exists to catch.
	soon := issue(t, "soon.example.com", nil, now.Add(-80*day),
		now.Add(10*day+time.Hour), false, nil)
	soonPath := write(t, root, "etc/nginx/ssl/soon.pem", soon.pem)

	// Signed by a CA rather than by itself.
	ca := issue(t, "Test CA", nil, now.Add(-500*day), now.Add(500*day), true, nil)
	leaf := issue(t, "signed.example.com", []string{"signed.example.com"},
		now.Add(-day), now.Add(90*day), false, &ca)
	leafPath := write(t, root, "etc/nginx/ssl/signed.pem", leaf.pem)

	out := scan(root, nil, now)

	cases := []struct {
		path        string
		subject     string
		issuer      string
		sans        []string
		notAfter    time.Time
		daysLeft    int
		selfSigned  bool
		wantNoSANs  bool
		description string
	}{
		{
			path: plainPath, subject: "plain.example.com", issuer: "plain.example.com",
			notAfter: now.Add(30 * day), daysLeft: 30, selfSigned: true, wantNoSANs: true,
			description: "a plain self-signed certificate",
		},
		{
			path: sansPath, subject: "sans.example.com", issuer: "sans.example.com",
			sans:     []string{"sans.example.com", "www.sans.example.com"},
			notAfter: now.Add(400 * day), daysLeft: 400, selfSigned: true,
			description: "the SAN list is what answers \"does it cover this domain\"",
		},
		{
			path: expiredPath, subject: "expired.example.com", issuer: "expired.example.com",
			notAfter: now.Add(-10*day - time.Hour), daysLeft: -10, selfSigned: true,
			wantNoSANs: true, description: "an expired certificate reports negative days",
		},
		{
			path: soonPath, subject: "soon.example.com", issuer: "soon.example.com",
			notAfter: now.Add(10*day + time.Hour), daysLeft: 10, selfSigned: true,
			wantNoSANs: true, description: "ten days left",
		},
		{
			path: leafPath, subject: "signed.example.com", issuer: "Test CA",
			sans:     []string{"signed.example.com"},
			notAfter: now.Add(90 * day), daysLeft: 90, selfSigned: false,
			description: "a CA-signed certificate is not self-signed",
		},
	}

	for _, c := range cases {
		t.Run(c.description, func(t *testing.T) {
			got := byPath(t, out, c.path)
			if got.Subject != c.subject {
				t.Errorf("subject = %q, want %q", got.Subject, c.subject)
			}
			if got.Issuer != c.issuer {
				t.Errorf("issuer = %q, want %q", got.Issuer, c.issuer)
			}
			if want := c.notAfter.UTC().Format(time.RFC3339); got.NotAfter != want {
				t.Errorf("notAfter = %q, want %q", got.NotAfter, want)
			}
			if got.DaysLeft != c.daysLeft {
				t.Errorf("daysLeft = %d, want %d", got.DaysLeft, c.daysLeft)
			}
			if got.SelfSigned != c.selfSigned {
				t.Errorf("selfSigned = %t, want %t", got.SelfSigned, c.selfSigned)
			}
			if c.wantNoSANs {
				if len(got.SANs) != 0 {
					t.Errorf("sans = %v, want none", got.SANs)
				}
			} else if strings.Join(got.SANs, ",") != strings.Join(c.sans, ",") {
				t.Errorf("sans = %v, want %v", got.SANs, c.sans)
			}
			// Nothing on this fixture host claims to renew /etc/nginx/ssl.
			if got.Manager != "" || got.AutoRenew {
				t.Errorf("manager = %q autoRenew = %t, want unowned and false",
					got.Manager, got.AutoRenew)
			}
		})
	}

	if !hasNote(out.notes, "no renewal owner") {
		t.Errorf("notes = %v, want one saying the certificates are unmanaged", out.notes)
	}
}

// A file that will not parse is the case where silence is most dangerous: an
// empty NotAfter must never be rendered as "no expiry".
func TestScanMalformedFileDegradesInsteadOfLookingImmortal(t *testing.T) {
	root := t.TempDir()
	broken := write(t, root, "etc/nginx/ssl/broken.pem",
		[]byte("-----BEGIN CERTIFICATE-----\nnot base64 at all\n-----END CERTIFICATE-----\n"))
	garbage := write(t, root, "etc/nginx/ssl/garbage.crt", []byte("this is not a certificate\n"))

	out := scan(root, nil, now)

	for _, path := range []string{broken, garbage} {
		got := byPath(t, out, path)
		if got.NotAfter != "" {
			t.Errorf("%s: notAfter = %q, want empty", path, got.NotAfter)
		}
		if got.DaysLeft != 0 {
			t.Errorf("%s: daysLeft = %d, want 0 alongside an empty notAfter", path, got.DaysLeft)
		}
	}
	if len(out.degrades) == 0 {
		t.Fatal("degrades is empty; an unparsable certificate has to degrade the section")
	}
	if !hasNote(out.degrades, "could not be parsed") {
		t.Errorf("degrades = %v, want them to say the file could not be parsed", out.degrades)
	}
}

// A PEM file holding only a key is not a certificate and not a failure either.
func TestScanIgnoresKeyOnlyPEMWithoutDegrading(t *testing.T) {
	root := t.TempDir()
	write(t, root, "etc/nginx/ssl/dhparam.pem",
		pem.EncodeToMemory(&pem.Block{Type: "DH PARAMETERS", Bytes: []byte{0x30, 0x06, 0x02, 0x01, 0x02}}))
	write(t, root, "etc/nginx/ssl/keyed.pem",
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{0x30, 0x03, 0x02, 0x01, 0x00}}))

	out := scan(root, nil, now)
	if len(out.certificates) != 0 {
		t.Errorf("certificates = %+v, want none", out.certificates)
	}
	if len(out.degrades) != 0 {
		t.Errorf("degrades = %v, want none: the file is simply not a certificate", out.degrades)
	}
}

func TestScanBindsLetsEncryptRenewalConfig(t *testing.T) {
	root := t.TempDir()

	cert := issue(t, "example.com", []string{"example.com", "www.example.com"},
		now.Add(-30*day), now.Add(60*day), false, nil)
	fullchain := write(t, root, "etc/letsencrypt/live/example.com/fullchain.pem", cert.pem)
	certPath := write(t, root, "etc/letsencrypt/live/example.com/cert.pem", cert.pem)
	// The private key sits right next to them and is never opened.
	write(t, root, "etc/letsencrypt/live/example.com/privkey.pem", []byte("-----BEGIN PRIVATE KEY-----\n"))

	// A renewal config names absolute paths, which is what binds it to the files.
	conf := "# renew_before_expiry = 30 days\nversion = 2.6.0\n" +
		"archive_dir = " + filepath.Join(root, "etc/letsencrypt/archive/example.com") + "\n" +
		"cert = " + certPath + "\n" +
		"privkey = " + filepath.Join(root, "etc/letsencrypt/live/example.com/privkey.pem") + "\n" +
		"chain = " + filepath.Join(root, "etc/letsencrypt/live/example.com/chain.pem") + "\n" +
		"fullchain = " + fullchain + "\n\n[renewalparams]\nauthenticator = webroot\n"
	write(t, root, "etc/letsencrypt/renewal/example.com.conf", []byte(conf))

	// Step 1: the config binds the certificate, but no job runs certbot. This is
	// the distinction the package exists for — the tooling is there, the renewal
	// is not scheduled, and AutoRenew must stay false.
	out := scan(root, nil, now)
	got := byPath(t, out, fullchain)
	if got.Manager != "certbot" {
		t.Errorf("manager = %q, want certbot from the renewal config", got.Manager)
	}
	if got.AutoRenew {
		t.Error("autoRenew = true with no renewal job on the host")
	}
	if !hasNote(out.notes, "no scheduled job") {
		t.Errorf("notes = %v, want one explaining why AutoRenew is false", out.notes)
	}
	if privkeyReported(out) {
		t.Error("a privkey.pem was reported; private keys are listed by name and never opened")
	}

	// Step 2: an unenabled timer unit is still not a job.
	write(t, root, "usr/lib/systemd/system/certbot.timer",
		[]byte("[Timer]\nOnCalendar=daily\n[Install]\nWantedBy=timers.target\n"))
	out = scan(root, nil, now)
	if byPath(t, out, fullchain).AutoRenew {
		t.Error("autoRenew = true from a timer unit file that was never enabled")
	}

	// Step 3: enable it, and now there is a job.
	write(t, root, "etc/systemd/system/timers.target.wants/certbot.timer", []byte("[Timer]\n"))
	out = scan(root, nil, now)
	if !byPath(t, out, fullchain).AutoRenew {
		t.Error("autoRenew = false although certbot.timer is enabled")
	}
}

func TestScanFindsCertbotCronEntry(t *testing.T) {
	root := t.TempDir()

	cert := issue(t, "cron.example.com", nil, now.Add(-day), now.Add(60*day), false, nil)
	fullchain := write(t, root, "etc/letsencrypt/live/cron.example.com/fullchain.pem", cert.pem)
	write(t, root, "etc/letsencrypt/renewal/cron.example.com.conf",
		[]byte("fullchain = "+fullchain+"\n"))
	write(t, root, "etc/cron.d/certbot",
		[]byte("0 */12 * * * root test -x /usr/bin/certbot && certbot -q renew\n"))

	out := scan(root, nil, now)
	got := byPath(t, out, fullchain)
	if got.Manager != "certbot" || !got.AutoRenew {
		t.Errorf("manager = %q autoRenew = %t, want certbot and true", got.Manager, got.AutoRenew)
	}
}

// A certificate inside certbot's tree that no renewal config mentions is
// certbot's and abandoned — reported as such, not as unowned.
func TestScanReportsOrphanedLetsEncryptCertificate(t *testing.T) {
	root := t.TempDir()
	cert := issue(t, "orphan.example.com", nil, now.Add(-day), now.Add(5*day), false, nil)
	path := write(t, root, "etc/letsencrypt/live/orphan.example.com/fullchain.pem", cert.pem)

	out := scan(root, nil, now)
	got := byPath(t, out, path)
	if got.Manager != "certbot" {
		t.Errorf("manager = %q, want certbot: the file is in certbot's own tree", got.Manager)
	}
	if got.AutoRenew {
		t.Error("autoRenew = true for a certificate no renewal config binds")
	}
}

func TestScanBindsAcmeShInstalledCertificate(t *testing.T) {
	root := t.TempDir()

	cert := issue(t, "acme.example.com", nil, now.Add(-day), now.Add(45*day), false, nil)
	installed := write(t, root, "etc/nginx/ssl/acme.example.com.cer", cert.pem)

	// acme.sh records where it copied the files; that record is the only thing
	// tying a certificate under /etc/nginx back to acme.sh.
	write(t, root, "root/.acme.sh/acme.example.com/acme.example.com.conf",
		[]byte("Le_Domain='acme.example.com'\nLe_RealCertPath=''\nLe_RealFullChainPath='"+
			installed+"'\n"))

	out := scan(root, nil, now)
	got := byPath(t, out, installed)
	if got.Manager != "acme.sh" {
		t.Errorf("manager = %q, want acme.sh", got.Manager)
	}
	if got.AutoRenew {
		t.Error("autoRenew = true with no acme.sh cron line on the host")
	}

	// Add the cron line acme.sh installs and the answer changes.
	write(t, root, "var/spool/cron/crontabs/root",
		[]byte("18 0 * * * \"/root/.acme.sh\"/acme.sh --cron --home \"/root/.acme.sh\" > /dev/null\n"))
	out = scan(root, nil, now)
	if !byPath(t, out, installed).AutoRenew {
		t.Error("autoRenew = false although acme.sh has a cron line")
	}
}

func TestScanRecognisesPanelStoreAndDoesNotAssumeRenewal(t *testing.T) {
	root := t.TempDir()
	cert := issue(t, "panel.example.com", nil, now.Add(-day), now.Add(20*day), false, nil)
	path := write(t, root, "usr/local/psa/var/certificates/cert-abc123.pem", cert.pem)

	out := scan(root, nil, now)
	got := byPath(t, out, path)
	if got.Manager != "panel" {
		t.Errorf("manager = %q, want panel", got.Manager)
	}
	if got.AutoRenew {
		t.Error("autoRenew = true for a panel-managed certificate, which cannot be verified")
	}
	if !hasNote(out.notes, "control panel's store") {
		t.Errorf("notes = %v, want one explaining the panel case", out.notes)
	}
}

// The system CA store would otherwise contribute 150 root certificates and bury
// the four that serve traffic. Skipping is fine; skipping quietly is not.
func TestScanSkipsTheSystemTrustStoreAndSaysSo(t *testing.T) {
	root := t.TempDir()

	rootCA := issue(t, "Some Root CA", nil, now.Add(-1000*day), now.Add(1000*day), true, nil)
	write(t, root, "etc/ssl/certs/Some_Root_CA.pem", rootCA.pem)
	write(t, root, "etc/ssl/certs/ca-certificates.crt", append(append([]byte{}, rootCA.pem...), rootCA.pem...))

	leaf := issue(t, "served.example.com", nil, now.Add(-day), now.Add(50*day), false, nil)
	leafPath := write(t, root, "etc/ssl/certs/served.example.com.pem", leaf.pem)

	out := scan(root, nil, now)
	if len(out.certificates) != 1 {
		t.Fatalf("certificates = %+v, want only the served leaf", out.certificates)
	}
	if out.certificates[0].Path != resolve(leafPath) {
		t.Errorf("reported %s, want %s", out.certificates[0].Path, leafPath)
	}
	if !hasNote(out.notes, "system trust store") {
		t.Errorf("notes = %v, want one stating how many trust-store certificates were skipped",
			out.notes)
	}
}

// A symlink farm must not report the same certificate several times.
func TestScanDeduplicatesBySymlinkTarget(t *testing.T) {
	root := t.TempDir()

	cert := issue(t, "linked.example.com", nil, now.Add(-day), now.Add(30*day), false, nil)
	real := write(t, root, "etc/nginx/ssl/real.pem", cert.pem)

	link := filepath.Join(root, "etc/nginx/certs/link.pem")
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Symlink(real, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	out := scan(root, nil, now)
	if len(out.certificates) != 1 {
		t.Fatalf("certificates = %+v, want one entry for one certificate", out.certificates)
	}
	if out.certificates[0].Path != resolve(real) {
		t.Errorf("path = %s, want the resolved %s", out.certificates[0].Path, real)
	}
}

// The private key directory is listed by name, never opened — and the fact that a
// certificate stored there would be missed is stated rather than glossed over.
func TestScanNeverOpensPrivateKeyDirectory(t *testing.T) {
	root := t.TempDir()
	cert := issue(t, "hidden.example.com", nil, now.Add(-day), now.Add(30*day), false, nil)
	write(t, root, "etc/ssl/private/hidden.example.com.pem", cert.pem)
	write(t, root, "etc/ssl/private/server.key", []byte("-----BEGIN PRIVATE KEY-----\n"))

	out := scan(root, nil, now)
	if len(out.certificates) != 0 {
		t.Errorf("certificates = %+v, want none from the key directory", out.certificates)
	}
	if !hasNote(out.notes, "never opened") {
		t.Errorf("notes = %v, want one stating the key directory was not read", out.notes)
	}
}

// The scheduler collector's inventory is the other source of renewal jobs, and its
// emptiness is reported rather than read as "there are none".
func TestScanUsesTheScheduledJobInventory(t *testing.T) {
	root := t.TempDir()
	cert := issue(t, "timer.example.com", nil, now.Add(-day), now.Add(30*day), false, nil)
	path := write(t, root, "etc/letsencrypt/live/timer.example.com/fullchain.pem", cert.pem)

	jobs := []model.ScheduledJob{
		{Kind: "timer", Owner: "root", Schedule: "daily",
			Command: "/usr/bin/certbot renew", Source: "certbot.timer"},
	}

	out := scan(root, jobs, now)
	if !byPath(t, out, path).AutoRenew {
		t.Error("autoRenew = false although the job inventory holds a certbot timer")
	}
	if hasNote(out.notes, "scheduled-job inventory was empty") {
		t.Errorf("notes = %v, want no emptiness note when the inventory was populated", out.notes)
	}

	empty := scan(root, nil, now)
	if !hasNote(empty.notes, "scheduled-job inventory was empty") {
		t.Errorf("notes = %v, want the emptiness of the inventory admitted", empty.notes)
	}
}

func TestIsCandidate(t *testing.T) {
	cases := map[string]bool{
		"fullchain.pem":       true,
		"cert.pem":            true,
		"server.crt":          true,
		"server.cer":          true,
		"privkey.pem":         false,
		"server.key":          false,
		"server-key.pem":      false,
		"ca-certificates.crt": false,
		"3513523f.0":          false,
		"nginx.conf":          false,
		"monkey.pem":          true,
	}
	for name, want := range cases {
		if got := isCandidate(name); got != want {
			t.Errorf("isCandidate(%q) = %t, want %t", name, got, want)
		}
	}
}

func TestDaysLeftTruncatesTowardsZero(t *testing.T) {
	cases := []struct {
		notAfter time.Time
		want     int
	}{
		{now.Add(10*day + time.Hour), 10},
		{now.Add(10 * day), 10},
		{now.Add(-5*day - time.Hour), -5},
		{now, 0},
	}
	for _, c := range cases {
		if got := daysLeft(c.notAfter, now); got != c.want {
			t.Errorf("daysLeft(%s) = %d, want %d", c.notAfter, got, c.want)
		}
	}
}

func hasNote(notes []string, substring string) bool {
	for _, note := range notes {
		if strings.Contains(note, substring) {
			return true
		}
	}
	return false
}

func privkeyReported(out scanResult) bool {
	for _, cert := range out.certificates {
		if strings.Contains(filepath.Base(cert.Path), "privkey") {
			return true
		}
	}
	return false
}
