// Package certs finds the TLS certificates on the host's disk and works out
// whether anything is going to renew them.
//
// Two decisions shape the whole package.
//
// The first is that certificates are parsed in Go, with crypto/x509 and
// encoding/pem, and never by shelling out to openssl. The parse is a dozen lines,
// it cannot be affected by which openssl the host ships, and it keeps the
// published command allowlist from growing an entry that a reader would then have
// to reason about. This package runs no subprocess at all.
//
// The second is the distinction between a renewal *tool* and a renewal *job*.
// "certbot is installed" and "this certificate will be renewed" are different
// statements, and conflating them is exactly how a certificate expires on a host
// that had the tooling all along: the package was there, the timer was never
// enabled, and every report said "managed by certbot". So Manager records who
// issued or owns the file, from evidence on disk, while AutoRenew is set only
// when a scheduled job that runs that tool was actually found. When neither can
// be established, AutoRenew stays false and the reason is written into the
// section's notes.
package certs

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/model"
	"github.com/BloodHeavenDevelop/deploy-witness-cli/app/run"
)

// The bounds on the walk. A certificate directory is a handful of files; a host
// that presents thousands is either using one as a dumping ground or is not the
// host we think it is, and in both cases stopping and saying so beats reading for
// a minute. Every bound that bites is reported — nothing here caps silently.
const (
	// maxDepth is how far below each root the walk descends. The deepest real
	// layout is /etc/letsencrypt/live/<domain>/<file>, which is two.
	maxDepth = 4
	// maxFiles bounds the total number of candidate certificate files examined.
	maxFiles = 512
	// maxCertBytes bounds one certificate file. A full chain with a long history
	// is a few tens of kilobytes.
	maxCertBytes = 512 << 10
	// maxJobFileBytes bounds one crontab or cron.d file.
	maxJobFileBytes = 256 << 10
	// maxParseNotes is how many individual unparsable files are named before the
	// rest are summarised. The summary states the count, so nothing is hidden.
	maxParseNotes = 5
)

// certRoots are the directories walked for certificates, relative to the scan
// root so the whole scanner can be pointed at a fixture tree.
var certRoots = []string{
	"etc/letsencrypt/live",
	"etc/letsencrypt/archive",
	"etc/ssl/certs",
	"etc/pki/tls/certs",
	"etc/nginx/ssl",
	"etc/nginx/certs",
	"etc/apache2/ssl",
	"etc/httpd/ssl",
	"etc/httpd/conf/ssl.crt",
	// Panel certificate stores, in the places they are trivially reachable.
	"usr/local/psa/var/certificates",
	"usr/local/hestia/ssl",
	"usr/local/vesta/ssl",
	"usr/local/directadmin/conf",
	"usr/local/mgr5/etc/ssl",
	"var/cpanel/ssl",
}

// keyRoots hold private keys. They are enumerated by name and never opened: this
// tool has no reason to read a private key, and a tool that reads one has to be
// trusted rather than checked.
var keyRoots = []string{
	"etc/ssl/private",
	"etc/pki/tls/private",
}

// trustStoreRoots are the system CA stores. They contain 150-odd root
// certificates and a farm of hash symlinks to them; reporting those would bury
// the four certificates that actually serve traffic. CA certificates found under
// these roots are skipped and counted, and the count is reported.
var trustStoreRoots = []string{
	"etc/ssl/certs",
	"etc/pki/tls/certs",
}

// trustStoreTargets are where the trust store's files physically live once the
// symlinks are followed. They are needed because the walk records resolved paths:
// on Arch, /etc/ssl/certs *is* a symlink to /etc/ca-certificates/extracted/cadir,
// so every root CA resolves out from under trustStoreRoots and would be reported
// as a certificate this host serves. That is precisely the 150-row flood the skip
// exists to prevent, and it is why membership is decided by the directory the walk
// started from as well as by the resolved path.
var trustStoreTargets = []string{
	"etc/ca-certificates",
	"usr/share/ca-certificates",
	"usr/share/pki",
	"var/lib/ca-certificates",
}

// panelStoreRoots are the certificate directories owned by a control panel. A
// certificate here is renewed by the panel, on the panel's own schedule, through
// machinery this tool cannot inspect.
var panelStoreRoots = []string{
	"usr/local/psa",
	"usr/local/cpanel",
	"var/cpanel",
	"usr/local/hestia",
	"usr/local/vesta",
	"usr/local/directadmin",
	"usr/local/mgr5",
	"www/server/panel",
	"usr/local/CyberCP",
}

// legoRoots are lego's data directories.
var legoRoots = []string{
	"etc/lego",
	"var/lib/lego",
	"opt/lego",
	"root/.lego",
}

// certExtensions are the file names this scanner will open. `.pem` is included
// and then filtered by name, because a private key is a `.pem` too.
var certExtensions = map[string]bool{
	".pem": true, ".crt": true, ".cer": true, ".cert": true, ".der": true,
}

// keyNamePattern matches the file names that hold a private key rather than a
// certificate. It is applied everywhere, not only under keyRoots.
var keyNamePattern = regexp.MustCompile(`(?i)(^privkey|(^|[._-])key)\.(pem|crt|cer|cert|der)$`)

// bundleNames are the aggregated trust bundles: one file, hundreds of root CAs.
// Note that letsencrypt's own `cert.pem` and `chain.pem` are deliberately not
// here — they are one certificate each, and they are the point of the exercise.
var bundleNames = map[string]bool{
	"ca-certificates.crt": true,
	"ca-bundle.crt":       true,
	"ca-bundle.trust.crt": true,
	"tls-ca-bundle.pem":   true,
	"ca-certificates.pem": true,
}

// hashLinkPattern matches OpenSSL's subject-hash symlinks (`3513523f.0`), which
// are the same root certificates a second time.
var hashLinkPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}\.[0-9]+$`)

// renewTools maps a manager to the strings that identify its scheduled job.
var renewTools = map[string][]string{
	"certbot": {"certbot", "letsencrypt"},
	"acme.sh": {"acme.sh"},
	"lego":    {"lego"},
}

// Collect populates caps.Certificates.
//
// runner is accepted for symmetry with the other collectors and deliberately
// unused: every certificate here is parsed in-process.
func Collect(runner *run.Runner, caps *model.Capabilities, result *model.SectionResult) {
	_ = runner

	out := scan("/", caps.Jobs, time.Now().UTC())

	caps.Certificates = out.certificates
	for _, note := range out.notes {
		result.Note("certificates: " + note)
	}
	for _, degrade := range out.degrades {
		result.Degrade("certificates: " + degrade)
	}
}

// scanResult is what one scan established, plus what it could not.
type scanResult struct {
	certificates []model.Certificate
	// notes are gaps in coverage: a bound that bit, a directory that was skipped,
	// a renewal state that could not be established.
	notes []string
	// degrades are outright failures: a file that would not parse, a directory
	// that would not open.
	degrades []string
}

// scan is the whole collector, with its filesystem root as a parameter so it can
// be run against a fixture tree. jobs is the scheduled-work inventory the
// scheduler collector produced; it may be empty, in which case renewal jobs are
// established from disk alone and the difference is noted.
func scan(root string, jobs []model.ScheduledJob, now time.Time) scanResult {
	var out scanResult

	files := gatherFiles(root, &out)
	renewals := certbotBindings(root, &out)
	acme := acmeBindings(root, &out)
	jobsByManager := renewalJobs(root, jobs, &out)

	var trustStoreSkipped, parseFailures int
	var unmanaged, panelManaged, managedWithoutJob int

	for _, found := range files {
		file := found.path
		cert, err := parseCertificate(file)
		if err != nil {
			if errors.Is(err, errNotACertificate) {
				// A key, a CSR or DH parameters. Not a certificate, so not a gap.
				continue
			}
			parseFailures++
			if parseFailures <= maxParseNotes {
				out.degrades = append(out.degrades, file+" could not be parsed as a "+
					"certificate ("+err.Error()+"); its expiry is unknown, not absent")
			}
			// The row is still emitted, with an empty NotAfter. A file that could
			// not be read must not disappear from the report.
			out.certificates = append(out.certificates, model.Certificate{Path: file})
			continue
		}

		if cert.IsCA && found.trustStore {
			trustStoreSkipped++
			continue
		}

		manager := managerFor(root, file, renewals, acme)
		// The one line this package exists for: a manager is who owns the file, a
		// job is what will actually run. AutoRenew needs both.
		autoRenew := manager != "" && manager != "panel" && len(jobsByManager[manager]) > 0

		switch {
		case manager == "":
			unmanaged++
		case manager == "panel":
			panelManaged++
		case !autoRenew:
			managedWithoutJob++
		}

		out.certificates = append(out.certificates, model.Certificate{
			Path:       file,
			Subject:    name(cert.Subject.CommonName, cert.Subject.String()),
			SANs:       cert.DNSNames,
			Issuer:     name(cert.Issuer.CommonName, cert.Issuer.String()),
			NotAfter:   cert.NotAfter.UTC().Format(time.RFC3339),
			DaysLeft:   daysLeft(cert.NotAfter, now),
			SelfSigned: selfSigned(cert),
			Manager:    manager,
			AutoRenew:  autoRenew,
		})
	}

	if parseFailures > maxParseNotes {
		out.degrades = append(out.degrades, strconv.Itoa(parseFailures)+" file(s) could not "+
			"be parsed as certificates; the first "+strconv.Itoa(maxParseNotes)+
			" are named above and every one of them is in the report with an empty expiry")
	}
	if trustStoreSkipped > 0 {
		stores := make([]string, 0, len(trustStoreRoots))
		for _, rel := range trustStoreRoots {
			stores = append(stores, filepath.Join(root, rel))
		}
		out.notes = append(out.notes, "skipped "+strconv.Itoa(trustStoreSkipped)+
			" CA certificate(s) reached through the system trust store ("+
			strings.Join(stores, ", ")+") — they are the distribution's root "+
			"certificates, not certificates this host serves")
	}
	if unmanaged > 0 {
		out.notes = append(out.notes, strconv.Itoa(unmanaged)+" certificate(s) have no "+
			"renewal owner on this host: no certbot renewal config, acme.sh record, lego "+
			"directory or panel store claims them, so they will have to be replaced by hand")
	}
	if panelManaged > 0 {
		out.notes = append(out.notes, strconv.Itoa(panelManaged)+" certificate(s) live in a "+
			"control panel's store: the panel renews them through its own machinery, which "+
			"this tool cannot inspect, so AutoRenew is left false rather than assumed true")
	}
	if managedWithoutJob > 0 {
		out.notes = append(out.notes, strconv.Itoa(managedWithoutJob)+" certificate(s) were "+
			"issued by a renewal tool but no scheduled job that runs it was found (no enabled "+
			"systemd timer, no cron entry); the tool being installed is not a renewal")
	}

	sort.SliceStable(out.certificates, func(i, j int) bool {
		return out.certificates[i].Path < out.certificates[j].Path
	})
	return out
}

// ------------------------------------------------------------------ the walk

// candidate is one certificate file the walk found.
type candidate struct {
	// path is the resolved path, which is what deduplication and the report use.
	path string
	// trustStore says the file was reached through a system CA store, whether by
	// the directory the walk started from or by where the file physically lives.
	// Membership cannot be decided from the resolved path alone — see
	// trustStoreTargets.
	trustStore bool
}

// gatherFiles collects candidate certificate files under every root, resolving
// symlinks so a link farm does not report the same certificate five times.
func gatherFiles(root string, out *scanResult) []candidate {
	seen := map[string]int{}
	var files []candidate
	truncatedAt := ""
	deepestNoted := false

	for _, rel := range certRoots {
		base := filepath.Join(root, rel)
		fromTrustStore := contains(trustStoreRoots, rel)
		info, err := os.Stat(base)
		if err != nil {
			if !os.IsNotExist(err) {
				out.degrades = append(out.degrades, base+" could not be examined: "+err.Error())
			}
			continue
		}
		if !info.IsDir() {
			continue
		}

		walkErr := filepath.WalkDir(base, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				// One unreadable subdirectory is a gap, not a reason to abandon
				// the rest of the tree.
				out.degrades = append(out.degrades, path+" could not be read: "+err.Error())
				if entry != nil && entry.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			if depth(base, path) > maxDepth {
				if entry.IsDir() {
					if !deepestNoted {
						deepestNoted = true
						out.notes = append(out.notes, "stopped descending at "+path+
							" and at any other directory deeper than the "+
							strconv.Itoa(maxDepth)+"-level walk limit")
					}
					return fs.SkipDir
				}
				return nil
			}
			if entry.IsDir() {
				return nil
			}
			if len(files) >= maxFiles {
				if truncatedAt == "" {
					truncatedAt = path
				}
				return fs.SkipAll
			}
			if !isCandidate(entry.Name()) {
				return nil
			}

			resolved := resolve(path)
			trustStore := fromTrustStore || underAny(root, trustStoreTargets, resolved)
			if index, already := seen[resolved]; already {
				// The same file reached twice. Whether it is a trust-store entry
				// is a property of the file, so either route establishing it
				// wins: a CA reached once through /etc/ssl/certs stays skipped.
				files[index].trustStore = files[index].trustStore || trustStore
				return nil
			}
			seen[resolved] = len(files)
			files = append(files, candidate{path: resolved, trustStore: trustStore})
			return nil
		})
		if walkErr != nil {
			out.degrades = append(out.degrades, base+" walk failed: "+walkErr.Error())
		}
	}

	if truncatedAt != "" {
		out.notes = append(out.notes, "the certificate walk stopped after "+
			strconv.Itoa(maxFiles)+" files, at "+truncatedAt+
			"; files after that point were not examined")
	}

	// Private keys are counted, never opened. A certificate that lives only in a
	// key directory is therefore missed, and this note is where that is admitted.
	for _, rel := range keyRoots {
		base := filepath.Join(root, rel)
		entries, err := os.ReadDir(base)
		if err != nil {
			if !os.IsNotExist(err) {
				out.notes = append(out.notes, base+" could not be listed ("+err.Error()+
					"); private key files there were not counted")
			}
			continue
		}
		var count int
		for _, entry := range entries {
			if !entry.IsDir() {
				count++
			}
		}
		if count > 0 {
			out.notes = append(out.notes, "found "+strconv.Itoa(count)+" file(s) under "+
				base+": that directory holds private keys, so its contents were listed by "+
				"name and never opened — any certificate stored there is not in this report")
		}
	}

	sort.SliceStable(files, func(i, j int) bool { return files[i].path < files[j].path })
	return files
}

// contains reports whether the slice holds the value.
func contains(haystack []string, needle string) bool {
	for _, value := range haystack {
		if value == needle {
			return true
		}
	}
	return false
}

// isCandidate decides from the file name alone whether the file will be opened.
func isCandidate(name string) bool {
	if !certExtensions[strings.ToLower(filepath.Ext(name))] {
		return false
	}
	if keyNamePattern.MatchString(name) {
		return false
	}
	if bundleNames[strings.ToLower(name)] {
		return false
	}
	return !hashLinkPattern.MatchString(name)
}

// depth counts path separators between base and path.
func depth(base, path string) int {
	rel, err := filepath.Rel(base, path)
	if err != nil {
		return 0
	}
	if rel == "." {
		return 0
	}
	return strings.Count(rel, string(filepath.Separator)) + 1
}

// resolve follows symlinks. When it cannot — a dangling link, a permission
// problem — the cleaned path is used, which at worst costs one duplicate row
// instead of dropping a certificate.
func resolve(path string) string {
	if real, err := filepath.EvalSymlinks(path); err == nil {
		return real
	}
	return filepath.Clean(path)
}

// ------------------------------------------------------------------ parsing

// errNotACertificate says the file was read and understood and holds no
// certificate: a private key, a CSR, DH parameters. It is not a defect and does
// not degrade the section — nothing was hidden, the file simply is not a
// certificate.
var errNotACertificate = errors.New("file contains no certificate")

// parseCertificate returns the *leaf* certificate of the file. A fullchain holds
// the leaf followed by its issuers; the leaf is the one whose expiry and names
// decide whether a domain can be served, and the intermediates would triple the
// row count while answering nothing.
func parseCertificate(path string) (*x509.Certificate, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errNotACertificate
	}
	if info.Size() > maxCertBytes {
		// A bound that bites is an error, not a skip: the caller emits the row
		// with an empty expiry and degrades the section, so the file is visible.
		return nil, fmt.Errorf("file is larger than the %dKiB certificate size limit",
			maxCertBytes/1024)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	rest := raw
	sawPEM := false
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		sawPEM = true
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil {
			return nil, parseErr
		}
		return cert, nil
	}

	if sawPEM {
		// PEM blocks, none of them a certificate: a key or a CSR.
		return nil, errNotACertificate
	}

	// No PEM at all. `.crt` and `.cer` files are frequently raw DER.
	cert, err := x509.ParseCertificate(raw)
	if err != nil {
		return nil, fmt.Errorf("neither PEM nor DER: %w", err)
	}
	return cert, nil
}

// name prefers the common name and falls back to the full distinguished name. A
// certificate with no CN — increasingly common, everything in the SANs — still
// has to be identifiable in the report.
func name(commonName, distinguished string) string {
	if strings.TrimSpace(commonName) != "" {
		return commonName
	}
	return distinguished
}

// daysLeft truncates towards zero, so a certificate that expired five and a bit
// days ago reads -5 rather than -6.
func daysLeft(notAfter, now time.Time) int {
	return int(notAfter.Sub(now).Hours() / 24)
}

// selfSigned requires both halves: the issuer naming the subject, and the
// signature actually verifying against the certificate's own key. The name test
// alone is met by any certificate whose issuer DN happens to match, and the
// signature test alone cannot be run without knowing which key to try.
//
// CheckSignatureFrom is deliberately not used: it also enforces basic
// constraints, so a self-signed leaf without CA:TRUE — which is exactly what a
// hand-rolled snakeoil certificate is — would be reported as not self-signed.
func selfSigned(cert *x509.Certificate) bool {
	if cert.Issuer.String() != cert.Subject.String() {
		return false
	}
	return cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil
}

// --------------------------------------------------------------- who owns it

// managerFor decides who owns the certificate's renewal, from evidence on disk
// and in this order: an explicit binding first, then the tool's own tree, then a
// panel's store. Anything not covered by one of those is unowned, and saying so
// is the point — an unmanaged certificate is a dated liability, and guessing a
// manager for it removes the only signal that would have caught it.
func managerFor(root, path string, certbot, acme map[string]string) string {
	if _, ok := certbot[path]; ok {
		return "certbot"
	}
	if _, ok := certbot[filepath.Dir(path)]; ok {
		return "certbot"
	}
	if _, ok := acme[path]; ok {
		return "acme.sh"
	}
	if _, ok := acme[filepath.Dir(path)]; ok {
		return "acme.sh"
	}
	// Inside certbot's tree but bound by no renewal config: certbot issued it and
	// has since forgotten it, which is worth reporting as certbot's with
	// AutoRenew false rather than as unowned.
	if underAny(root, []string{"etc/letsencrypt"}, path) {
		return "certbot"
	}
	if acmeHomeOf(root, path) != "" {
		return "acme.sh"
	}
	if underAny(root, legoRoots, path) {
		return "lego"
	}
	if underAny(root, panelStoreRoots, path) {
		return "panel"
	}
	return ""
}

// underAny reports whether path sits inside one of the root-relative prefixes.
func underAny(root string, prefixes []string, path string) bool {
	for _, rel := range prefixes {
		base := filepath.Join(root, rel)
		if path == base || strings.HasPrefix(path, base+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// acmeHomes are the ~/.acme.sh directories on the host.
func acmeHomes(root string) []string {
	var homes []string
	candidates := []string{filepath.Join(root, "root/.acme.sh")}
	if matches, err := filepath.Glob(filepath.Join(root, "home", "*", ".acme.sh")); err == nil {
		candidates = append(candidates, matches...)
	}
	for _, candidate := range candidates {
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			homes = append(homes, candidate)
		}
	}
	sort.Strings(homes)
	return homes
}

func acmeHomeOf(root, path string) string {
	for _, home := range acmeHomes(root) {
		if strings.HasPrefix(path, home+string(filepath.Separator)) {
			return home
		}
	}
	return ""
}

// certbotBindings maps a certificate path — and its directory, since a renewal
// config names four files in one — to the renewal config that binds it.
//
// The paths inside a renewal config are absolute host paths and are used as
// written, resolved through symlinks the same way the walk resolves candidates.
// That is what makes the binding exact: "certbot is installed" says nothing about
// this file, while "/etc/letsencrypt/renewal/example.com.conf names it" does.
func certbotBindings(root string, out *scanResult) map[string]string {
	bindings := map[string]string{}

	dir := filepath.Join(root, "etc/letsencrypt/renewal")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if !os.IsNotExist(err) {
			out.notes = append(out.notes, dir+" could not be listed ("+err.Error()+
				"); certbot-managed certificates could not be bound to their renewal "+
				"configs, so their Manager may be blank when it should not be")
		}
		return bindings
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".conf") {
			continue
		}
		conf := filepath.Join(dir, entry.Name())
		raw, readErr := readBounded(conf, maxJobFileBytes)
		if readErr != nil {
			out.notes = append(out.notes, conf+" could not be read ("+readErr.Error()+
				"); the certificates it renews are reported as if it did not exist")
			continue
		}
		for _, line := range strings.Split(raw, "\n") {
			key, value, ok := splitAssignment(line)
			if !ok {
				continue
			}
			switch key {
			case "cert", "fullchain", "chain":
				resolved := resolve(value)
				bindings[resolved] = conf
				bindings[filepath.Dir(resolved)] = conf
			case "archive_dir":
				bindings[resolve(value)] = conf
			}
		}
	}

	return bindings
}

// acmeBindings maps the certificate paths acme.sh installed to the account record
// that describes them. acme.sh copies its issued files to wherever
// `--install-cert` was told to put them and records those destinations in
// ~/.acme.sh/<domain>/<domain>.conf, which is the only way to tie a certificate
// sitting in /etc/nginx/ssl back to acme.sh.
func acmeBindings(root string, out *scanResult) map[string]string {
	bindings := map[string]string{}

	for _, home := range acmeHomes(root) {
		matches, err := filepath.Glob(filepath.Join(home, "*", "*.conf"))
		if err != nil {
			continue
		}
		for _, conf := range matches {
			raw, readErr := readBounded(conf, maxJobFileBytes)
			if readErr != nil {
				out.notes = append(out.notes, conf+" could not be read ("+readErr.Error()+
					"); certificates acme.sh installed elsewhere on the host could not be "+
					"tied back to it")
				continue
			}
			for _, line := range strings.Split(raw, "\n") {
				key, value, ok := splitAssignment(line)
				if !ok {
					continue
				}
				switch key {
				case "Le_RealCertPath", "Le_RealFullChainPath", "Le_RealCACertPath":
					if value == "" {
						continue
					}
					resolved := resolve(value)
					bindings[resolved] = conf
					bindings[filepath.Dir(resolved)] = conf
				}
			}
		}
	}

	return bindings
}

// splitAssignment parses the `key = value`, `key=value` and `key='value'` forms
// that certbot's renewal configs and acme.sh's account files both use.
func splitAssignment(line string) (key, value string, ok bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[") {
		return "", "", false
	}
	parts := strings.SplitN(line, "=", 2)
	if len(parts) != 2 {
		return "", "", false
	}
	key = strings.TrimSpace(parts[0])
	value = strings.TrimSpace(parts[1])
	value = strings.Trim(value, `"'`)
	if key == "" {
		return "", "", false
	}
	return key, value, true
}

// ------------------------------------------------------------ renewal *jobs*

// renewalJobs finds the scheduled work that actually runs a renewal tool, keyed
// by manager. Everything in here is a job — something the host will run on a
// schedule — and nothing in here is an installed package:
//
//   - An enabled systemd timer is a symlink in timers.target.wants. A timer
//     *unit file* shipped by the distribution's certbot package is not counted,
//     because until it is enabled it never fires. That single distinction is the
//     difference between a report that predicts an outage and one that hides it.
//   - A cron entry is a line in /etc/crontab, /etc/cron.d/* or an account's
//     crontab that names the tool, or a script in cron.daily named after it.
//   - The scheduled-job inventory, when the scheduler collector filled it in, is
//     used as well: it holds the timers systemd currently has loaded.
func renewalJobs(root string, jobs []model.ScheduledJob, out *scanResult) map[string][]string {
	found := map[string][]string{}

	add := func(manager, evidence string) {
		for _, existing := range found[manager] {
			if existing == evidence {
				return
			}
		}
		found[manager] = append(found[manager], evidence)
	}

	// The scheduler collector's inventory. It may be empty — that is not evidence
	// of no jobs, which is why the disk is read below regardless.
	for _, job := range jobs {
		haystack := strings.ToLower(job.Command + " " + job.Source)
		for manager, needles := range renewTools {
			for _, needle := range needles {
				if strings.Contains(haystack, needle) {
					add(manager, job.Kind+" "+job.Source)
				}
			}
		}
	}

	// Enabled systemd timers.
	for _, wants := range []string{
		"etc/systemd/system/timers.target.wants",
		"usr/lib/systemd/system/timers.target.wants",
	} {
		dir := filepath.Join(root, wants)
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			lower := strings.ToLower(entry.Name())
			if !strings.HasSuffix(lower, ".timer") {
				continue
			}
			for manager, needles := range renewTools {
				for _, needle := range needles {
					if strings.Contains(lower, needle) {
						add(manager, "enabled timer "+filepath.Join(dir, entry.Name()))
					}
				}
			}
		}
	}

	// Cron.
	cronFiles, cronNotes := cronCandidates(root)
	out.notes = append(out.notes, cronNotes...)
	for _, file := range cronFiles {
		lower := strings.ToLower(filepath.Base(file))
		matchedByName := false
		for manager, needles := range renewTools {
			for _, needle := range needles {
				// A script dropped into cron.daily is a job by virtue of its
				// location; its name is the only thing that has to match.
				if strings.Contains(filepath.ToSlash(file), "/cron.") &&
					strings.Contains(lower, needle) {
					add(manager, "cron script "+file)
					matchedByName = true
				}
			}
		}
		if matchedByName {
			continue
		}

		raw, err := readBounded(file, maxJobFileBytes)
		if err != nil {
			out.notes = append(out.notes, file+" could not be read ("+err.Error()+
				"); a renewal cron entry in it would not have been seen, so AutoRenew "+
				"may read false for a certificate that is in fact renewed")
			continue
		}
		for _, line := range strings.Split(raw, "\n") {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			lowerLine := strings.ToLower(trimmed)
			for manager, needles := range renewTools {
				for _, needle := range needles {
					if strings.Contains(lowerLine, needle) {
						add(manager, "cron entry in "+file)
					}
				}
			}
		}
	}

	if len(jobs) == 0 {
		out.notes = append(out.notes, "the scheduled-job inventory was empty, so renewal "+
			"jobs were established from disk alone (enabled systemd timers and cron files); "+
			"a timer that exists only in systemd's runtime state would have been missed")
	}

	return found
}

// cronCandidates lists the cron files worth reading, and notes the ones that
// could not be listed. Account crontabs are root-readable only, so running
// unprivileged loses them — and that loss is reported rather than absorbed.
func cronCandidates(root string) (files []string, notes []string) {
	single := []string{"etc/crontab"}
	dirs := []string{
		"etc/cron.d",
		"etc/cron.hourly",
		"etc/cron.daily",
		"etc/cron.weekly",
		"etc/cron.monthly",
		"var/spool/cron/crontabs",
		"var/spool/cron",
	}

	for _, rel := range single {
		path := filepath.Join(root, rel)
		if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
			files = append(files, path)
		}
	}

	for _, rel := range dirs {
		dir := filepath.Join(root, rel)
		entries, err := os.ReadDir(dir)
		if err != nil {
			if !os.IsNotExist(err) && !os.IsPermission(err) {
				notes = append(notes, dir+" could not be listed: "+err.Error())
			} else if os.IsPermission(err) {
				notes = append(notes, dir+" is not readable by this account, so any renewal "+
					"job in it was not seen (run as root for a complete answer)")
			}
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			files = append(files, filepath.Join(dir, entry.Name()))
		}
	}

	sort.Strings(files)
	return files, notes
}

// readBounded reads at most limit bytes from a regular file.
func readBounded(path string, limit int64) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", os.ErrInvalid
	}

	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = file.Close() }()

	buf := make([]byte, limit)
	n, err := file.Read(buf)
	if n == 0 && err != nil {
		return "", err
	}
	return string(buf[:n]), nil
}
